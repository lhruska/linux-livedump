// SPDX-License-Identifier: GPL-2.0-or-later
/* filedump.c - Live Dump's filesystem dumping management
 * Copyright (C) 2024 SUSE
 * Author: Lukas Hruska <lhruska@suse.cz>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "core.h"
#include "filedump.h"

#include "trace.h"

#include <asm/wrprotect.h>

#include <linux/crash_core.h>
#include <linux/crash_dump.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/kfifo.h>
#include <linux/delay.h>
#include <linux/sizes.h>
#include <linux/printk.h>
#include <linux/tracepoint.h>

#define SECTOR_SHIFT		9
#define PFN_ELF_HDR			0
#define PFN_ELF_NOTES		1

static const char THREAD_NAME[] = "livedump";
static struct file *filedump_filp;

struct livedump_handler filedump_handler = {
	"filedump",
	&livedump_filedump_sm_init,
	&livedump_filedump_init,
	&livedump_filedump_uninit,
	&livedump_filedump_write_elf_hdr
};

/* ELF metadata */
static unsigned char *vmcoreinfo;
static void *elf_data;
static unsigned long elf_size;
static struct crash_mem *cmem;

/* ELF modification */
static char *elfnotes_buf;
static size_t elfnotes_sz;

/* Queues */
static struct livedump_shared shared;

/***** Kernel thread *****/
static struct filedump_thread {
	struct task_struct *tsk;
	atomic_t is_active;
	bool wait;
	struct completion completion;
} __aligned(PAGE_SIZE) filedump_thread;

static int filedump_thread_func(void *);

static long start_filedump_thread(void)
{
	atomic_set(&filedump_thread.is_active, true);
	filedump_thread.wait = true;
	init_completion(&filedump_thread.completion);
	filedump_thread.tsk = kthread_run(
			filedump_thread_func, NULL, THREAD_NAME);
	if (IS_ERR(filedump_thread.tsk))
		return PTR_ERR(filedump_thread.tsk);
	return 0;
}

static void stop_filedump_thread(bool wait)
{
	if (atomic_cmpxchg(&filedump_thread.is_active, true, false)) {
		filedump_thread.wait = wait;
		wait_for_completion(&filedump_thread.completion);
		pr_info("filedump stopped\n");
	}
}

static int filedump_thread_func(void *_)
{
	bool is_empty = false;
	struct livedump_request req;
	static loff_t pos;

	do {
		/* Process request */
		while (kfifo_get(&shared.page_fault_rq->pend, &req)) {
			pos = req.pfn * PAGE_SIZE;
			kernel_write(filedump_filp, req.p, PAGE_SIZE, &pos);
			spin_lock(&shared.page_fault_rq->pool_w_lock);
			kfifo_put(&shared.page_fault_rq->pool, req);
			spin_unlock(&shared.page_fault_rq->pool_w_lock);

			trace_livedump_handle_page_finished(req.pfn, 0);
		}

		/* Process request for sweep*/
		while (kfifo_is_empty(&shared.page_fault_rq->pend) &&
				kfifo_get(&shared.sweep_rq->pend, &req)) {
			pos = req.pfn * PAGE_SIZE;
			kernel_write(filedump_filp, req.p, PAGE_SIZE, &pos);
			spin_lock(&shared.sweep_rq->pool_w_lock);
			kfifo_put(&shared.sweep_rq->pool, req);
			spin_unlock(&shared.sweep_rq->pool_w_lock);
			wake_up(shared.pool_waiters);

			trace_livedump_handle_page_finished(req.pfn, 1);
		}

		is_empty = kfifo_is_empty(&shared.page_fault_rq->pend) &&
			kfifo_is_empty(&shared.sweep_rq->pend);
		wait_event_timeout(*shared.pend_waiters, true, msecs_to_jiffies(100));
	} while (atomic_read(&filedump_thread.is_active) || (filedump_thread.wait && !is_empty));

	complete(&filedump_thread.completion);
	return 0;
}

static int select_pages(void);

int livedump_filedump_init(struct livedump_shared data)
{
	long ret;

	shared = data;

	/* Get bdev */
	ret = -ENOENT;
	filedump_filp = filp_open(shared.output, O_CREAT | O_RDWR | O_LARGEFILE, 0444);
	if (IS_ERR(filedump_filp))
		return PTR_ERR(filedump_filp);
	if (!(filedump_filp->f_mode & FMODE_CAN_READ)) {
		pr_err("alloc_device: cache file not readable\n");
		ret = -EINVAL;
		goto err_close_filp;
	}
	if (!(filedump_filp->f_mode & FMODE_CAN_WRITE)) {
		pr_err("alloc_device: cache file not writeable\n");
		ret = -EINVAL;
		goto err_close_filp;
	}

	/* Start thread */
	ret = start_filedump_thread();
	if (ret)
		goto err_close_filp;

	/* Allocate space for vmcore info */
	vmcoreinfo = vmalloc(PAGE_SIZE);
	cmem = vzalloc(struct_size(cmem, ranges, 1));
	if (WARN_ON(!vmcoreinfo || !cmem)) {
		ret = -ENOMEM;
		goto err_close_filp;
	}

	/* Select target pages */
	select_pages();

	return 0;

err_close_filp:
	filp_close(filedump_filp, NULL);
	return ret;
}

void livedump_filedump_uninit(bool forced)
{
	pr_info("uninit");
	/* Stop thread */
	stop_filedump_thread(!forced);

	/* Free vmcoreinfo */
	if (vmcoreinfo)
		vfree(vmcoreinfo);
	if (cmem)
		vfree(cmem);

	/* merged notes */
	if (elfnotes_buf)
		vfree(elfnotes_buf);

	/* Put filp */
	if (filedump_filp) {
		filp_close(filedump_filp, NULL);
		filedump_filp = NULL;
	}
}

/* select_pages
 *
 * Eliminate pages that contain filedump's stuffs from bitmap.
 */
static int select_pages(void)
{
	/* Unselect filedump stuffs */
	wrprotect_unselect_pages(
			(unsigned long)&filedump_thread, sizeof(filedump_thread));
	wrprotect_unselect_pages(
			(unsigned long)cmem, PAGE_SIZE);
	wrprotect_unselect_pages(
			(unsigned long)vmcoreinfo, PAGE_SIZE);

	return 0;
}

void livedump_filedump_sm_init(void)
{
	unsigned int cpu;

	for_each_present_cpu(cpu) {
		crash_save_cpu(per_cpu_ptr(livedump_conf.regs, cpu), cpu);
	}

	cmem->max_nr_ranges = 1;
	cmem->nr_ranges = 1;
	cmem->ranges[0].start = SZ_1M;
	cmem->ranges[0].end = ((max_pfn + 1) << PAGE_SHIFT) - 1;
	crash_update_vmcoreinfo_safecopy(vmcoreinfo);
	crash_save_vmcoreinfo();
	crash_prepare_elf64_headers(cmem, 1, &elf_data, &elf_size);
	crash_update_vmcoreinfo_safecopy(NULL);
	merge_note_headers_elf64((char *)elf_data, &elf_size, &elfnotes_buf, &elfnotes_sz);
}

void livedump_filedump_write_elf_hdr(void)
{
	/*
	 * This is possible thanks to elf_data and eflnotes_buf were allocated
	 * using vzalloc and they cover exactly 1 page each.
	 */
	livedump_handle_page(PFN_ELF_HDR, (unsigned long)elf_data, 1);
	livedump_handle_page(PFN_ELF_NOTES, (unsigned long)elfnotes_buf, 1);
}
