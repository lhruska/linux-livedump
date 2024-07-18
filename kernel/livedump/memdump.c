// SPDX-License-Identifier: GPL-2.0-or-later
/* memdump.c - Live Dump's memory dumping management
 * Copyright (C) 2012 Hitachi, Ltd.
 * Copyright (C) 2023 SUSE
 * Author: YOSHIDA Masanori <masanori.yoshida.tv@hitachi.com>
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
#include "memdump.h"

#include "trace.h"

#include <asm/wrprotect.h>

#include <linux/crash_core.h>
#include <linux/crash_dump.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/kfifo.h>
#include <linux/delay.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/sizes.h>
#include <linux/printk.h>
#include <linux/tracepoint.h>

#define SECTOR_SHIFT		9
#define PFN_ELF_HDR			0
#define PFN_ELF_NOTES		1

static const char THREAD_NAME[] = "livedump";
static struct block_device *memdump_bdev;

struct livedump_handler memdump_handler = {
	"memdump",
	&livedump_memdump_sm_init,
	&livedump_memdump_init,
	&livedump_memdump_uninit,
	&livedump_memdump_write_elf_hdr
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
static struct memdump_thread {
	struct task_struct *tsk;
	atomic_t is_active;
	bool wait;
	struct completion completion;
} __aligned(PAGE_SIZE) memdump_thread;

static int memdump_thread_func(void *);

static long start_memdump_thread(void)
{
	atomic_set(&memdump_thread.is_active, true);
	memdump_thread.wait = true;
	init_completion(&memdump_thread.completion);
	memdump_thread.tsk = kthread_run(
			memdump_thread_func, NULL, THREAD_NAME);
	if (IS_ERR(memdump_thread.tsk))
		return PTR_ERR(memdump_thread.tsk);
	return 0;
}

static void stop_memdump_thread(bool wait)
{
	if (atomic_cmpxchg(&memdump_thread.is_active, true, false)) {
		memdump_thread.wait = wait;
		wait_for_completion(&memdump_thread.completion);
		pr_info("memdump stopped\n");
	}
}

static void memdump_endio(struct bio *bio)
{
	unsigned long pfn;
	struct livedump_request req = { .p = page_address(bio_page(bio)) };
	struct livedump_request_queue *queue = (bio->bi_private ?
			shared.sweep_rq : shared.page_fault_rq);

	spin_lock(&queue->pool_w_lock);
	kfifo_put(&queue->pool, req);
	spin_unlock(&queue->pool_w_lock);

	bio_put(bio);

	wake_up(shared.pool_waiters);

	pfn = bio->bi_iter.bi_sector >> (PAGE_SHIFT - SECTOR_SHIFT);
	trace_livedump_handle_page_finished(pfn, (bool)bio->bi_private);
}

static int memdump_thread_func(void *_)
{
	bool is_empty = false;
	struct bio *bio;
	struct livedump_request req;

	do {

		/* Process request */
		while (kfifo_get(&shared.page_fault_rq->pend, &req)) {
			bio = bio_alloc(memdump_bdev, 1, REQ_OP_WRITE, GFP_KERNEL);

			if (WARN_ON(!bio)) {
				spin_lock(&shared.page_fault_rq->pool_w_lock);
				kfifo_put(&shared.page_fault_rq->pool, req);
				spin_unlock(&shared.page_fault_rq->pool_w_lock);
				continue;
			}

			bio->bi_bdev = memdump_bdev;
			bio->bi_end_io = memdump_endio;
			bio->bi_iter.bi_sector = req.pfn << (PAGE_SHIFT - SECTOR_SHIFT);
			bio_add_page(bio, virt_to_page(req.p), PAGE_SIZE, 0);

			submit_bio(bio);
		}

		/* Process request for sweep*/
		while (kfifo_is_empty(&shared.page_fault_rq->pend) &&
				kfifo_get(&shared.sweep_rq->pend, &req)) {
			bio = bio_alloc(memdump_bdev, 1, REQ_OP_WRITE, GFP_KERNEL);

			if (WARN_ON(!bio)) {
				spin_lock(&shared.sweep_rq->pool_w_lock);
				kfifo_put(&shared.sweep_rq->pool, req);
				spin_unlock(&shared.sweep_rq->pool_w_lock);
				continue;
			}

			bio->bi_bdev = memdump_bdev;
			bio->bi_end_io = memdump_endio;
			bio->bi_iter.bi_sector = req.pfn << (PAGE_SHIFT - SECTOR_SHIFT);
			bio->bi_private = (void *)1; /* for sweep */
			bio_add_page(bio, virt_to_page(req.p), PAGE_SIZE, 0);

			submit_bio(bio);
		}

		is_empty = kfifo_is_empty(&shared.page_fault_rq->pend) &&
			kfifo_is_empty(&shared.sweep_rq->pend);
		wait_event_timeout(*shared.pend_waiters, true, msecs_to_jiffies(100));
	} while (atomic_read(&memdump_thread.is_active) || (memdump_thread.wait && !is_empty));

	while (kfifo_len(&shared.sweep_rq->pool) != livedump_conf.buffer_size &&
			kfifo_len(&shared.page_fault_rq->pool) != livedump_conf.buffer_size)
		wait_event_timeout(*shared.pool_waiters, true, msecs_to_jiffies(100));

	complete(&memdump_thread.completion);
	return 0;
}

static int select_pages(void);

int livedump_memdump_init(struct livedump_shared data)
{
	long ret;

	shared = data;

	/* Get bdev */
	ret = -ENOENT;
	memdump_bdev = blkdev_get_by_path(shared.output, FMODE_EXCL, &memdump_bdev);
	if (memdump_bdev < 0)
		goto err;

	/* Start thread */
	ret = start_memdump_thread();
	if (ret)
		goto err_bdev;

	/* Allocate space for vmcore info */
	vmcoreinfo = vmalloc(PAGE_SIZE);
	cmem = vzalloc(struct_size(cmem, ranges, 1));
	if (WARN_ON(!vmcoreinfo || !cmem))
		return -ENOMEM;

	/* Select target pages */
	select_pages();

	return 0;

err_bdev:
	blkdev_put(memdump_bdev, FMODE_EXCL);
err:
	return ret;
}

void livedump_memdump_uninit(bool forced)
{
	/* Stop thread */
	stop_memdump_thread(!forced);

	/* Free vmcoreinfo */
	if (vmcoreinfo) {
		vfree(vmcoreinfo);
		vmcoreinfo = NULL;
	}
	if (cmem) {
		vfree(cmem);
		cmem = NULL;
	}

	/* merged notes */
	if (elfnotes_buf) {
		vfree(elfnotes_buf);
		elfnotes_buf = NULL;
	}

	/* Put bdev */
	if (memdump_bdev) {
		blkdev_put(memdump_bdev, FMODE_EXCL);
		memdump_bdev = NULL;
	}
}

/* select_pages
 *
 * Eliminate pages that contain memdump's stuffs from bitmap.
 */
static int select_pages(void)
{
	/* Unselect memdump stuffs */
	wrprotect_unselect_pages(
			(unsigned long)&memdump_thread, sizeof(memdump_thread));
	wrprotect_unselect_pages(
			(unsigned long)cmem, PAGE_SIZE);
	wrprotect_unselect_pages(
			(unsigned long)vmcoreinfo, PAGE_SIZE);

	return 0;
}

void livedump_memdump_sm_init(void)
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

void livedump_memdump_write_elf_hdr(void)
{
	/*
	 * This is possible thanks to elf_data and eflnotes_buf were allocated
	 * using vzalloc and they cover exactly 1 page each.
	 */
	livedump_handle_page(PFN_ELF_HDR, (unsigned long)elf_data, 1);
	livedump_handle_page(PFN_ELF_NOTES, (unsigned long)elfnotes_buf, 1);
}
