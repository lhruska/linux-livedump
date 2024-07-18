/* SPDX-License-Identifier: GPL-2.0-or-later */
/* core.h - Live Dump's core
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

#ifndef _LIVEDUMP_CORE_H
#define _LIVEDUMP_CORE_H

#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/kfifo.h>
#include <linux/sysfs.h>

#define LIVEDUMP_KFIFO_SIZE_DEFAULT	32768 /* in pages */

struct livedump_request {
	void *p; /* pointing to buffer (one page) */
	unsigned long pfn;
};

/***** Request queue *****/

/*
 * Request queue consists of 2 kfifos: pend, pool
 *
 * Processing between the two kfifos:
 *  (1)handle_page READs one request from POOL.
 *  (2)handle_page makes the request and WRITEs it to PEND.
 *  (3)kthread READs the request from PEND and submits bio.
 *  (4)endio WRITEs the request to POOL.
 *
 * kfifo permits parallel access by 1 reader and 1 writer.
 * Therefore, (1), (2) and (4) must be serialized.
 * (3) need not be protected since livedump uses only one kthread.
 *
 * (1) is protected by pool_r_lock.
 * (2) is protected by pend_w_lock.
 * (4) is protected by pool_w_lock.
 */

struct livedump_request_queue {
	void **pages;

	DECLARE_KFIFO_PTR(pool, struct livedump_request);
	void *pool_buffer;
	DECLARE_KFIFO_PTR(pend, struct livedump_request);
	void *pend_buffer;

	spinlock_t pool_w_lock;
	spinlock_t pool_r_lock;
	spinlock_t pend_w_lock;
};

struct livedump_conf {
	char bdevpath[PATH_MAX];
	struct pt_regs *regs;
	bool use_interrupt;
	unsigned long buffer_size;
	bool consistent;
};

struct livedump_shared {
	const char *output;
	struct livedump_request_queue *page_fault_rq;
	struct livedump_request_queue *sweep_rq;
	wait_queue_head_t *pool_waiters;
	wait_queue_head_t *pend_waiters;
};

struct livedump_handler {
	char *name;
	void (*sm_init)(void);
	int (*init)(struct livedump_shared data);
	void (*uninit)(bool forced);
	void (*finish)(void);
};

extern struct livedump_conf livedump_conf;
extern struct kobject *livedump_root_kobj;

bool livedump_handle_page(unsigned long pfn, unsigned long addr, int for_sweep);

#endif /* _LIVEDUMP_CORE_H */
