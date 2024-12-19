// SPDX-License-Identifier: GPL-2.0-or-later
/* core.c - Live Dump's main
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

#include <linux/livedump.h>
#include "memdump.h"
#include "filedump.h"

#include <asm/livedump.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

#include <asm/wrprotect.h>

#include <linux/log2.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/printk.h>
#include <linux/reboot.h>
#include <linux/memblock.h>

enum state {
	LIVEDUMP_STATE_UNDEFINED,
	LIVEDUMP_STATE_INIT,
	LIVEDUMP_STATE_START,
	LIVEDUMP_STATE_SWEEP,
	LIVEDUMP_STATE_FINISH,
	LIVEDUMP_STATE_UNINIT,
};

#define LIVEDUMP_SET_STATE(a) atomic_set(&livedump_state.val, (int)a)
#define LIVEDUMP_GET_STATE	  atomic_read(&livedump_state.val)

struct livedump_state {
	atomic_t val;
	atomic_t count;
	spinlock_t state_lock;
	struct mutex sysfs_lock;
	atomic_t failed;
	wait_queue_head_t pool_waiters;
	wait_queue_head_t pend_waiters;
	struct livedump_request_queue page_fault_rq;
	struct livedump_request_queue sweep_rq;
} __aligned(PAGE_SIZE) livedump_state = {
	ATOMIC_INIT(LIVEDUMP_STATE_UNDEFINED),
	ATOMIC_INIT(0),
	__SPIN_LOCK_INITIALIZER(livedump_state.state_lock),
	__MUTEX_INITIALIZER(livedump_state.sysfs_lock),
	ATOMIC_INIT(0),
};

struct livedump_conf livedump_conf;

static const struct livedump_handler * const all_handlers[] = {
	&memdump_handler,
	&filedump_handler,
	NULL
};

static const struct livedump_handler *livedump_handler = all_handlers[0];

static bool livedump_state_inc(void)
{
	bool ret;
	int val;

	spin_lock(&livedump_state.state_lock);
	val = atomic_read(&livedump_state.val);
	ret = (val >= LIVEDUMP_STATE_INIT && val <= LIVEDUMP_STATE_SWEEP);
	if (ret)
		atomic_inc(&livedump_state.count);
	spin_unlock(&livedump_state.state_lock);
	return ret;
}

static void livedump_state_dec(void)
{
	atomic_dec(&livedump_state.count);
}

static void free_req_queue(void)
{
	int i;

	if (livedump_state.page_fault_rq.pages != NULL)
		for (i = 0; i < livedump_conf.buffer_size; i++) {
			if (livedump_state.page_fault_rq.pages[i]) {
				free_page((unsigned long)livedump_state.page_fault_rq.pages[i]);
				livedump_state.page_fault_rq.pages[i] = NULL;
			}
		}
	if (livedump_state.sweep_rq.pages != NULL)
		for (i = 0; i < livedump_conf.buffer_size; i++) {
			if (livedump_state.sweep_rq.pages[i]) {
				free_page((unsigned long)livedump_state.sweep_rq.pages[i]);
				livedump_state.sweep_rq.pages[i] = NULL;
			}
		}

	vfree(livedump_state.page_fault_rq.pages);
	vfree(livedump_state.sweep_rq.pages);
	livedump_state.page_fault_rq.pages = NULL;
	livedump_state.sweep_rq.pages = NULL;

	kfifo_reset_out(&livedump_state.sweep_rq.pend);
	kfifo_reset_out(&livedump_state.sweep_rq.pool);
	kfifo_reset_out(&livedump_state.page_fault_rq.pend);
	kfifo_reset_out(&livedump_state.page_fault_rq.pool);

	vfree(livedump_state.page_fault_rq.pool_buffer);
	vfree(livedump_state.page_fault_rq.pend_buffer);
	vfree(livedump_state.sweep_rq.pool_buffer);
	vfree(livedump_state.sweep_rq.pend_buffer);

	livedump_state.page_fault_rq.pool_buffer = NULL;
	livedump_state.page_fault_rq.pend_buffer = NULL;
	livedump_state.sweep_rq.pool_buffer = NULL;
	livedump_state.sweep_rq.pend_buffer = NULL;

	free_percpu(livedump_conf.regs);
}

#define VZALLOC_AND_CHECK(var, size) \
	do {	\
		var = vzalloc(size); \
		if (!var) {\
			ret = -ENOMEM; \
			goto err; \
		} \
	} while (0)

static long alloc_req_queue(void)
{
	long ret;
	int i;
	struct livedump_request req;

	/* initialize counters */
	atomic_set(&livedump_state.page_fault_rq.inserted_count, 0);
	atomic_set(&livedump_state.page_fault_rq.finished_count, 0);
	atomic_set(&livedump_state.sweep_rq.inserted_count, 0);
	atomic_set(&livedump_state.sweep_rq.finished_count, 0);

	/* initialize spinlocks */
	spin_lock_init(&livedump_state.page_fault_rq.pool_w_lock);
	spin_lock_init(&livedump_state.page_fault_rq.pool_r_lock);
	spin_lock_init(&livedump_state.page_fault_rq.pend_w_lock);
	spin_lock_init(&livedump_state.sweep_rq.pool_w_lock);
	spin_lock_init(&livedump_state.sweep_rq.pool_r_lock);
	spin_lock_init(&livedump_state.sweep_rq.pend_w_lock);

	/* initialize kfifos */
	VZALLOC_AND_CHECK(livedump_state.page_fault_rq.pend_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	VZALLOC_AND_CHECK(livedump_state.page_fault_rq.pool_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	VZALLOC_AND_CHECK(livedump_state.sweep_rq.pend_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	VZALLOC_AND_CHECK(livedump_state.sweep_rq.pool_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);

	ret = kfifo_init(&livedump_state.page_fault_rq.pend,
			livedump_state.page_fault_rq.pend_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	if (ret)
		goto err;
	ret = kfifo_init(&livedump_state.page_fault_rq.pool,
			livedump_state.page_fault_rq.pool_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	if (ret)
		goto err;
	ret = kfifo_init(&livedump_state.sweep_rq.pend,
			livedump_state.sweep_rq.pend_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	if (ret)
		goto err;
	ret = kfifo_init(&livedump_state.sweep_rq.pool,
			livedump_state.sweep_rq.pool_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	if (ret)
		goto err;

	VZALLOC_AND_CHECK(livedump_state.page_fault_rq.pages,
			sizeof(void *) * livedump_conf.buffer_size);
	VZALLOC_AND_CHECK(livedump_state.sweep_rq.pages,
			sizeof(void *) * livedump_conf.buffer_size);

	/* allocate pages and push pages into pool */
	for (i = 0; i < livedump_conf.buffer_size; i++) {
		/* for normal queue */
		livedump_state.page_fault_rq.pages[i]
			= (void *)__get_free_page(GFP_KERNEL);
		if (!livedump_state.page_fault_rq.pages[i]) {
			ret = -ENOMEM;
			goto err;
		}

		req.p = livedump_state.page_fault_rq.pages[i];
		ret = kfifo_put(&livedump_state.page_fault_rq.pool, req);
		BUG_ON(!ret);

		/* for sweep queue */
		livedump_state.sweep_rq.pages[i]
			= (void *)__get_free_page(GFP_KERNEL);
		if (!livedump_state.sweep_rq.pages[i]) {
			ret = -ENOMEM;
			goto err;
		}

		req.p = livedump_state.sweep_rq.pages[i];
		ret = kfifo_put(&livedump_state.sweep_rq.pool, req);
		BUG_ON(!ret);
	}

	livedump_conf.regs = alloc_percpu(struct pt_regs);

	atomic_set(&livedump_state.failed, 0);

	return 0;

err:
	free_req_queue();
	return ret;
}

#undef VZALLOC_AND_CHECK

bool livedump_handle_page(unsigned long pfn, unsigned long addr, int for_sweep)
{
	int ret;
	unsigned long flags, len;
	struct livedump_request req;
	struct livedump_request_queue *queue =
		(for_sweep ? &livedump_state.sweep_rq : &livedump_state.page_fault_rq);
	DEFINE_WAIT(wait);

	BUG_ON(addr & ~PAGE_MASK);

	if (!livedump_state_inc()) {
		atomic_inc(&livedump_state.failed);
		return false;
	}

	/* Get buffer */
retry_after_wait:
	spin_lock_irqsave(&queue->pool_r_lock, flags);
	ret = kfifo_get(&queue->pool, &req);
	spin_unlock_irqrestore(&queue->pool_r_lock, flags);

	if (!ret) {
		if (!for_sweep) {
			WARN_ON_ONCE(livedump_conf.consistent);
			atomic_inc(&livedump_state.failed);
			ret = false;
			goto err;
		} else {
			prepare_to_wait(&livedump_state.pool_waiters, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&livedump_state.pool_waiters, &wait);
			goto retry_after_wait;
		}
	}

	/* Make request */
	req.pfn = pfn;
	memcpy(req.p, (void *)addr, PAGE_SIZE);

	/* Queue request */
	spin_lock_irqsave(&queue->pend_w_lock, flags);
	kfifo_put(&queue->pend, req);
	len = kfifo_len(&queue->pend);
	spin_unlock_irqrestore(&queue->pend_w_lock, flags);

	wake_up(&livedump_state.pend_waiters);

	atomic_inc(&queue->inserted_count);
	trace_livedump_handle_page(pfn, len, for_sweep);

	ret = true;
err:
	livedump_state_dec();
	return ret;
}

/* select_pages
 *
 * Eliminate pages that contain livedump's stuffs from bitmap.
 */
static int select_pages(void)
{
	unsigned long i;

	/* Unselect livedump stuffs */
	wrprotect_unselect_pages(
			(unsigned long)&livedump_state, sizeof(struct livedump_state));
	wrprotect_unselect_pages(
			(unsigned long)livedump_state.page_fault_rq.pages,
			sizeof(void *)*livedump_conf.buffer_size);
	wrprotect_unselect_pages(
			(unsigned long)livedump_state.sweep_rq.pages,
			sizeof(void *)*livedump_conf.buffer_size);
	wrprotect_unselect_pages(
			(unsigned long)livedump_state.page_fault_rq.pend_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	wrprotect_unselect_pages(
			(unsigned long)livedump_state.page_fault_rq.pool_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	wrprotect_unselect_pages(
			(unsigned long)livedump_state.sweep_rq.pend_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	wrprotect_unselect_pages(
			(unsigned long)livedump_state.sweep_rq.pool_buffer,
			sizeof(struct livedump_request)*livedump_conf.buffer_size);
	for (i = 0; i < livedump_conf.buffer_size; i++) {
		wrprotect_unselect_pages(
				(unsigned long)livedump_state.page_fault_rq.pages[i],
				PAGE_SIZE);
		wrprotect_unselect_pages(
				(unsigned long)livedump_state.sweep_rq.pages[i],
				PAGE_SIZE);
		cond_resched();
	}

	return 0;
}

static void do_uninit(bool forced)
{
	wrprotect_uninit();
	livedump_handler->uninit(forced);
	free_req_queue();
}

static int do_init(void)
{
	int ret;
	struct livedump_shared data;

	if (strlen(livedump_conf.bdevpath) == 0) {
		ret = -EINVAL;
		goto err;
	}

	trace_livedump_pre_init(0);

	ret = alloc_req_queue();
	if (ret) {
		pr_warn("livedump: Failed to initialize allocate request queues.\n");
		goto err;
	}

	ret = wrprotect_init(livedump_handle_page, livedump_handler->sm_init);
	if (ret) {
		pr_warn("livedump: Failed to initialize Protection manager.\n");
		goto err;
	}

	data.output = livedump_conf.bdevpath;
	data.page_fault_rq = &livedump_state.page_fault_rq;
	data.sweep_rq = &livedump_state.sweep_rq;
	data.pool_waiters = &livedump_state.pool_waiters;
	data.pend_waiters = &livedump_state.pend_waiters;

	ret = livedump_handler->init(data);
	if (ret) {
		pr_warn("livedump: Failed to initialize Dump manager.\n");
		goto err;
	}

	select_pages();

	trace_livedump_post_init(0);

	return 0;
err:
	do_uninit(true);
	return ret;
}

static int livedump_start(void)
{
	int ret;

	trace_livedump_pre_start(0);

	/* prevent any CPU hot-swap */
	cpus_read_lock();

	ret = arch_livedump_save_registers();
	if (ret)
		goto out;

	if (livedump_conf.use_interrupt)
		ret = wrprotect_start_int();
	else
		ret = wrprotect_start();

out:
	cpus_read_unlock();

	trace_livedump_post_start(0);

	return ret;
}

static long livedump_change_state(unsigned int cmd)
{
	long ret = 0;
	int state;

	if (atomic_read(&livedump_state.count) != 0)
		return -EINVAL;

	state = LIVEDUMP_GET_STATE;
	if (cmd == LIVEDUMP_STATE_UNDEFINED) {
		pr_warn("livedump: you cannot change the livedump state into LIVEDUMP_STATE_UNDEFINED.\n");
		return -EINVAL;
	}

	/* All states except LIVEDUMP_STATE_UNINIT must have an output set. */
	switch (cmd) {
	case LIVEDUMP_STATE_UNINIT:
		break;
	default:
		if (!strlen(livedump_conf.bdevpath)) {
			pr_warn("livedump: The output must be set first before changing the state.\n");
			return -EINVAL;
		}
	}

	switch (cmd) {
	case LIVEDUMP_STATE_INIT:
		if (state != LIVEDUMP_STATE_UNDEFINED &&
			state != LIVEDUMP_STATE_UNINIT) {
			pr_warn("livedump: To initialize a livedump the current state must be "
				"LIVEDUMP_STATE_UNDEFINED or LIVEDUMP_STATE_UNINIT.\n");
			return -EINVAL;
		}
		ret = do_init();
		break;
	case LIVEDUMP_STATE_START:
		if (state != LIVEDUMP_STATE_INIT) {
			pr_warn("livedump: To start a livedump the current state must be "
				"LIVEDUMP_STATE_INIT.\n");
			return -EINVAL;
		}
		livedump_start();
		break;
	case LIVEDUMP_STATE_SWEEP:
		if (state != LIVEDUMP_STATE_START) {
			pr_warn("livedump: To start sweep functionality of livedump the current state must "
				"be LIVEDUMP_STATE_START.\n");
			return -EINVAL;
		}
		trace_livedump_pre_sweep(0);
		ret = wrprotect_sweep();
		trace_livedump_post_sweep(0);
		break;
	case LIVEDUMP_STATE_FINISH:
		if (state != LIVEDUMP_STATE_SWEEP) {
			pr_warn("livedump: To finish a livedump the current state must be "
				"LIVEDUMP_STATE_SWEEP.\n");
			return -EINVAL;
		}
		livedump_handler->finish();
		trace_livedump_finish(0);
		break;
	case LIVEDUMP_STATE_UNINIT:
		if (state < LIVEDUMP_STATE_INIT) {
			pr_warn("livedump: To uninitialize livedump the current state must be at least "
				"LIVEDUMP_STATE_INIT.\n");
			return -EINVAL;
		}
		do_uninit(state != LIVEDUMP_STATE_FINISH);
		trace_livedump_uninit(0);
		break;
	default:
		return -ENOIOCTLCMD;
	}

	if (ret == 0)
		LIVEDUMP_SET_STATE(cmd);

	return ret;
}

/* sysfs */

struct kobject *livedump_root_kobj;
EXPORT_SYMBOL(livedump_root_kobj);

static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int new_state, ret = count;

	mutex_lock(&livedump_state.sysfs_lock);

	ret = kstrtoint(buf, 10, &new_state);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}

	if (new_state < LIVEDUMP_STATE_UNDEFINED ||
			new_state > LIVEDUMP_STATE_UNINIT) {
		ret = -ENOIOCTLCMD;
		goto out;
	}

	ret = livedump_change_state(new_state);
	if (!ret)
		ret = count;

out:
	mutex_unlock(&livedump_state.sysfs_lock);
	return ret;
}

static ssize_t state_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	ssize_t count = 0;

	count += sprintf(buf, "%u\n\n", LIVEDUMP_GET_STATE);
	count += sprintf(buf+count, "LIVEDUMP_STATE_UNDEFINED = 0\n");
	count += sprintf(buf+count, "LIVEDUMP_STATE_INIT = 1\n");
	count += sprintf(buf+count, "LIVEDUMP_STATE_START = 2\n");
	count += sprintf(buf+count, "LIVEDUMP_STATE_SWEEP = 3\n");
	count += sprintf(buf+count, "LIVEDUMP_STATE_FINISH = 4\n");
	count += sprintf(buf+count, "LIVEDUMP_STATE_UNINIT = 5\n");
	buf[count] = '\0';
	return count;
}

static ssize_t output_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int len, state, ret = count;

	mutex_lock(&livedump_state.sysfs_lock);
	state = LIVEDUMP_GET_STATE;

	switch (state) {
	case LIVEDUMP_STATE_UNDEFINED:
	case LIVEDUMP_STATE_UNINIT:
		break;
	default:
		pr_warn("livedump: you cannot change the output in current state of livedump.\n");
		ret = -EINVAL;
		goto out;
	}

	len = strscpy(livedump_conf.bdevpath, buf, sizeof(livedump_conf.bdevpath));
	if (len == 0 || len >= sizeof(livedump_conf.bdevpath)) {
		ret = -EINVAL;
		goto out;
	}
	/* remove the newline character */
	if (livedump_conf.bdevpath[len-1] == '\n')
		livedump_conf.bdevpath[len-1] = '\0';

out:
	mutex_unlock(&livedump_state.sysfs_lock);
	return ret;
}

static ssize_t output_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", livedump_conf.bdevpath);
}

static ssize_t type_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int ret, state, i;

	mutex_lock(&livedump_state.sysfs_lock);
	state = LIVEDUMP_GET_STATE;
	switch (state) {
	case LIVEDUMP_STATE_UNDEFINED:
	case LIVEDUMP_STATE_UNINIT:
		break;
	default:
		pr_warn("livedump: you cannot change the type in current state of livedump.\n");
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; all_handlers[i]; ++i) {
		if (strncmp(buf, all_handlers[i]->name, count-1) == 0) {
			livedump_handler = all_handlers[i];
			ret = count;
			goto out;
		}
	}

	pr_warn("livedump: unknown type.\n");
	ret = -EINVAL;

out:
	mutex_unlock(&livedump_state.sysfs_lock);
	return ret;
}

static ssize_t type_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	ssize_t count = 0, i;

	count += sprintf(buf, "%s\n\n", livedump_handler->name);
	count += sprintf(buf+count, "Possible types:\n");
	for (i = 0; all_handlers[i]; ++i)
		count += sprintf(buf+count, "%s\n", all_handlers[i]->name);
	buf[count] = '\0';
	return count;
}

static ssize_t use_interrupt_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int count;

	mutex_lock(&livedump_state.sysfs_lock);
	count = sprintf(buf, "%d\n", livedump_conf.use_interrupt ? 1 : 0);
	mutex_unlock(&livedump_state.sysfs_lock);

	return count;
}

static ssize_t use_interrupt_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf, size_t count)
{
	int new_state, state, ret = count;

	mutex_lock(&livedump_state.sysfs_lock);
	state = LIVEDUMP_GET_STATE;

	switch (state) {
	case LIVEDUMP_STATE_UNDEFINED:
	case LIVEDUMP_STATE_UNINIT:
		break;
	default:
		pr_warn("livedump: you cannot change the type in current state of livedump.\n");
		ret = -EINVAL;
		goto out;
	}

	ret = kstrtoint(buf, 10, &new_state);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	} else {
		ret = count;
	}

	livedump_conf.use_interrupt = new_state;

out:
	mutex_unlock(&livedump_state.sysfs_lock);
	return ret;
}

static ssize_t buffer_size_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int count;
	unsigned long minimal = 0, recommended = 0;

	mutex_lock(&livedump_state.sysfs_lock);

	/*
	 * wrprotect_sensitive_count only returns manually saved pages.
	 * Unfortunately, the actual kthread, saving the saved pages on
	 * kfifo, will also generate page faults adding more pages on
	 * queue, that could cause a page-fault inside page-fault with
	 * no place to save the data to.
	 * That's why there is the constant multiplying the requirement. This
	 * constant is only an estimation and does not represent some
	 * exact value that can be proven.
	 */
	minimal = wrprotect_sensitive_count() * 2;
	recommended = minimal * 2;

	count = sprintf(buf, "%lu\n\n", livedump_conf.buffer_size);
	count += sprintf(buf+count, "Minimal: %lu\n", minimal);
	count += sprintf(buf+count, "Recommended: %lu\n", recommended);

	mutex_unlock(&livedump_state.sysfs_lock);

	return count;
}

static ssize_t buffer_size_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf, size_t count)
{
	int state, ret;
	unsigned long buffer_size;

	mutex_lock(&livedump_state.sysfs_lock);
	state = LIVEDUMP_GET_STATE;

	switch (state) {
	case LIVEDUMP_STATE_UNDEFINED:
	case LIVEDUMP_STATE_UNINIT:
		break;
	default:
		pr_warn("livedump: you cannot change the buffer size in current state of livedump.\n");
		ret = -EINVAL;
		goto out;
	}

	ret = kstrtol(buf, 10, &buffer_size);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	} else {
		ret = count;
	}

	if (!is_power_of_2(buffer_size))
		buffer_size = roundup_pow_of_two(buffer_size);

	livedump_conf.buffer_size = buffer_size;

out:
	mutex_unlock(&livedump_state.sysfs_lock);
	return ret;
}

static ssize_t consistent_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int count;

	mutex_lock(&livedump_state.sysfs_lock);
	count = sprintf(buf, "%d\n", livedump_conf.consistent);
	mutex_unlock(&livedump_state.sysfs_lock);

	return count;
}

static ssize_t consistent_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf, size_t count)
{
	int state, ret;
	int consistent;

	mutex_lock(&livedump_state.sysfs_lock);
	state = LIVEDUMP_GET_STATE;

	switch (state) {
	case LIVEDUMP_STATE_UNDEFINED:
	case LIVEDUMP_STATE_UNINIT:
		break;
	default:
		pr_warn("livedump: you cannot change the consistency in current state of livedump.\n");
		ret = -EINVAL;
		goto out;
	}

	ret = kstrtoint(buf, 10, &consistent);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	} else {
		ret = count;
	}

	livedump_conf.consistent = consistent != 0;

out:
	mutex_unlock(&livedump_state.sysfs_lock);
	return ret;
}

static ssize_t failed_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int count;

	mutex_lock(&livedump_state.sysfs_lock);
	count = sprintf(buf, "%d\n", atomic_read(&livedump_state.failed));
	mutex_unlock(&livedump_state.sysfs_lock);

	return count;
}

static ssize_t kfifo_debug_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int count = 0;
	count += sprintf(buf+count, "STATE: %u\n\n", LIVEDUMP_GET_STATE);
	count += sprintf(buf+count, "PAGE_FAULT: %u, %d, %d\n", kfifo_len(&livedump_state.page_fault_rq.pend), atomic_read(&livedump_state.page_fault_rq.inserted_count), atomic_read(&livedump_state.page_fault_rq.finished_count));
	count += sprintf(buf+count, "SWEEP: %u, %d, %d\n", kfifo_len(&livedump_state.sweep_rq.pend), atomic_read(&livedump_state.sweep_rq.inserted_count), atomic_read(&livedump_state.sweep_rq.finished_count));

	return count;
}

static struct kobj_attribute state_kobj_attr = __ATTR_RW(state);
static struct kobj_attribute output_kobj_attr = __ATTR_RW(output);
static struct kobj_attribute type_kobj_attr = __ATTR_RW(type);
static struct kobj_attribute use_interrupt_kobj_attr = __ATTR_RW(use_interrupt);
static struct kobj_attribute buffer_size_kobj_attr = __ATTR_RW(buffer_size);
static struct kobj_attribute consistent_kobj_attr = __ATTR_RW(consistent);
static struct kobj_attribute failed_kobj_attr = __ATTR_RO(failed);
static struct kobj_attribute kfifo_debug_kobj_attr = __ATTR_RO(kfifo_debug);
static struct attribute *livedump_attrs[] = {
	&state_kobj_attr.attr,
	&output_kobj_attr.attr,
	&type_kobj_attr.attr,
	&use_interrupt_kobj_attr.attr,
	&buffer_size_kobj_attr.attr,
	&consistent_kobj_attr.attr,
	&failed_kobj_attr.attr,
	&kfifo_debug_kobj_attr.attr,
	NULL
};
ATTRIBUTE_GROUPS(livedump);

static int livedump_exit(struct notifier_block *_, unsigned long __, void *___)
{
	int state = LIVEDUMP_GET_STATE;

	if (livedump_root_kobj)
		kobject_put(livedump_root_kobj);
	if (state != LIVEDUMP_STATE_UNDEFINED && state != LIVEDUMP_STATE_UNINIT)
		do_uninit(true);
	return NOTIFY_DONE;
}
static struct notifier_block livedump_nb = {
	.notifier_call = livedump_exit
};

static int __init livedump_init(void)
{
	int ret;

	livedump_root_kobj = kobject_create_and_add("livedump", kernel_kobj);
	if (!livedump_root_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(livedump_root_kobj, *livedump_groups);
	if (ret) {
		livedump_exit(NULL, 0, NULL);
		return ret;
	}

	ret = register_reboot_notifier(&livedump_nb);
	if (WARN_ON(ret)) {
		livedump_exit(NULL, 0, NULL);
		return ret;
	}

	init_waitqueue_head(&livedump_state.pool_waiters);
	init_waitqueue_head(&livedump_state.pend_waiters);

	livedump_conf.bdevpath[0] = '\0';
	livedump_conf.use_interrupt = false;
	livedump_conf.buffer_size = LIVEDUMP_KFIFO_SIZE_DEFAULT;
	livedump_conf.consistent = true;

	return 0;
}

module_init(livedump_init);
