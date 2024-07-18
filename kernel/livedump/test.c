// SPDX-License-Identifier: GPL-2.0-or-later
/* test.c - Live Dump's test module
 * Copyright (C) 2023 SUSE
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

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/maple_tree.h>
#include <asm/wrprotect.h>
#include <linux/pgtable.h>

#include "trace.h"

#define REGISTER_TRACE_FN(trace, idx) \
	do {								\
		if (livedump_all_tests[idx].trace != NULL) \
			register_trace_livedump_##trace(livedump_all_tests[idx].trace, NULL); \
	} while (0)
#define UNREGISTER_TRACE_FN(trace, idx) \
	do {								\
		if (livedump_all_tests[idx].trace != NULL) \
			unregister_trace_livedump_##trace(livedump_all_tests[idx].trace, NULL); \
	} while (0)


typedef void (*livedump_test_fn)(void *, int);

struct livedump_test {
	char *name;
	livedump_test_fn pre_init;
	livedump_test_fn post_init;
	livedump_test_fn pre_start;
	livedump_test_fn post_start;
	livedump_test_fn pre_sweep;
	livedump_test_fn post_sweep;
	livedump_test_fn finish;
	livedump_test_fn uninit;
};

/**********************
 *       TESTS        *
 **********************/

/* tracepoint test */

#define DEFINE_DUMMY_TEST(type) \
	static void test_dummy_##type(void *data, int dummy)	\
	{	\
		pr_info("test");	\
	}

DEFINE_DUMMY_TEST(pre_init)
DEFINE_DUMMY_TEST(post_init)
DEFINE_DUMMY_TEST(pre_start)
DEFINE_DUMMY_TEST(post_start)
DEFINE_DUMMY_TEST(pre_sweep)
DEFINE_DUMMY_TEST(post_sweep)
DEFINE_DUMMY_TEST(finish)
DEFINE_DUMMY_TEST(uninit)

/* value change test */

static unsigned long test_value_change_glob = 0,
					*test_value_change_slab = NULL,
					*test_value_change_vmap = NULL;

#define TEST_VALUE_CHANGE_VAL	(0xdeaddead + 0x1)

static void test_value_change_post_init(void *data, int dummy)
{
	unsigned long *slab_value, *vmap_value, *text_value;

	slab_value = kzalloc(sizeof(unsigned long), GFP_KERNEL);
	vmap_value = vzalloc(sizeof(unsigned long));
	text_value = &test_value_change_glob;
	*text_value = 0;

	pr_info("slab_value(%lx) = %lu\n", (unsigned long) slab_value, *slab_value);
	pr_info("vmap_value(%lx) = %lu\n", (unsigned long) vmap_value, *vmap_value);
	pr_info("text_value(%lx) = %lu\n", (unsigned long) text_value, *text_value);

	test_value_change_slab = slab_value;
	test_value_change_vmap = vmap_value;
}

static void test_value_change_post_start(void *data, int dummy)
{
	unsigned long *slab_value, *vmap_value, *text_value;

	slab_value = test_value_change_slab;
	vmap_value = test_value_change_vmap;
	text_value = &test_value_change_glob;

	*slab_value = TEST_VALUE_CHANGE_VAL;
	*vmap_value = TEST_VALUE_CHANGE_VAL;
	*text_value = TEST_VALUE_CHANGE_VAL;

	pr_info("slab_value(%lx) = %lu\n", (unsigned long) slab_value, *slab_value);
	pr_info("vmap_value(%lx) = %lu\n", (unsigned long) vmap_value, *vmap_value);
	pr_info("text_value(%lx) = %lu\n", (unsigned long) text_value, *text_value);
}

static void test_value_change_uninit(void *data, int dummy)
{
	kfree(test_value_change_slab);
	test_value_change_slab = NULL;
	vfree(test_value_change_vmap);
	test_value_change_vmap = NULL;
}

/* vmap after start */

#define TEST_VMAP_VAL	(0xdeaddead + 0x2)
#define TEST_VMAP_COUNT	3

static unsigned long __aligned(PAGE_SIZE) test_vmap_glob_val = 0,
					 *test_vmap_addrs[TEST_VMAP_COUNT],
					 *test_vmap_vmap_slab	= NULL,
					 *test_vmap_vmap_glob	= NULL;

static void test_vmap_post_init(void *data, int dummy)
{
	int i;

	for (i = 0; i < TEST_VMAP_COUNT; ++i) {
		test_vmap_addrs[i] = (void *)__get_free_page(GFP_KERNEL);
		*test_vmap_addrs[i] = 0;
	}
	test_vmap_glob_val = 0;

	pr_info("glob_value(%lx) = %lu\n",
			(unsigned long) &test_vmap_glob_val, test_vmap_glob_val);
	for (i = 0; i < TEST_VMAP_COUNT; ++i)
		pr_info("slab_value[%d](%lx) = %lu\n",
				i, (unsigned long)test_vmap_addrs[i],
				*test_vmap_addrs[i]);
}

static void test_vmap_post_start(void *data, int dummy)
{
	int i;
	struct page *p1[TEST_VMAP_COUNT];
	struct page *p2;

	for (i = 0; i < TEST_VMAP_COUNT; ++i)
		p1[i] = virt_to_page(test_vmap_addrs[i]);
	p2 = virt_to_page(&test_vmap_glob_val);

	test_vmap_vmap_slab = vmap(p1, TEST_VMAP_COUNT, VM_MAP, PAGE_KERNEL);
	test_vmap_vmap_glob = vmap(&p2, 1, VM_MAP, PAGE_KERNEL);

	for (i = 0; i < TEST_VMAP_COUNT; ++i) {
		int idx = (PAGE_SIZE/sizeof(unsigned long)) * i;

		test_vmap_vmap_slab[idx] = TEST_VMAP_VAL;
	}
	*test_vmap_vmap_glob = TEST_VMAP_VAL;

	pr_info("vmap_slab_value(%lx) = %lu\n",
			(unsigned long) test_vmap_vmap_slab, *test_vmap_vmap_slab);
	pr_info("vmap_glob_value(%lx) = %lu, global_value(%lx) = %lu\n",
			(unsigned long) test_vmap_vmap_glob, *test_vmap_vmap_glob,
			(unsigned long) &test_vmap_glob_val, test_vmap_glob_val);
	for (i = 0; i < TEST_VMAP_COUNT; ++i) {
		int idx = (PAGE_SIZE/sizeof(unsigned long)) * i;

		pr_info("vmap_slab_value[%d](%lx) = %lu, slab_value[%d](%lx) = %lu\n",
				i, (unsigned long)&test_vmap_vmap_slab[idx],
				test_vmap_vmap_slab[idx],
				i, (unsigned long)test_vmap_addrs[i],
				*test_vmap_addrs[i]);
	}
}

static void test_vmap_uninit(void *data, int dummy)
{
	int i;

	if (test_vmap_vmap_slab) {
		vunmap(test_vmap_vmap_slab);
		test_vmap_vmap_slab = NULL;
	}
	if (test_vmap_vmap_glob) {
		vunmap(test_vmap_vmap_glob);
		test_vmap_vmap_glob = NULL;
	}
	for (i = 0; i < TEST_VMAP_COUNT; ++i) {
		if (test_vmap_addrs[i]) {
			free_page((unsigned long)test_vmap_addrs[i]);
			test_vmap_addrs[i] = NULL;
		}
	}
}

static const struct livedump_test livedump_all_tests[] = {
	{
		"dummy",
		test_dummy_pre_init,
		test_dummy_post_init,
		test_dummy_pre_start,
		test_dummy_post_start,
		test_dummy_pre_sweep,
		test_dummy_post_sweep,
		test_dummy_finish,
		test_dummy_uninit,
	},
	{
		"value_change",
		NULL, test_value_change_post_init,
		NULL, test_value_change_post_start,
		NULL, NULL, NULL, test_value_change_uninit,
	},
	{
		"new_vmap",
		NULL, test_vmap_post_init,
		NULL, test_vmap_post_start,
		NULL, NULL, NULL, test_vmap_uninit,
	},
};

/* test management */

static long register_all_tests(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(livedump_all_tests); ++i) {
		REGISTER_TRACE_FN(pre_init, i);
		REGISTER_TRACE_FN(post_init, i);
		REGISTER_TRACE_FN(pre_start, i);
		REGISTER_TRACE_FN(post_start, i);
		REGISTER_TRACE_FN(pre_sweep, i);
		REGISTER_TRACE_FN(post_sweep, i);
		REGISTER_TRACE_FN(finish, i);
		REGISTER_TRACE_FN(uninit, i);
	}

	return 0;
}

static long unregister_all_tests(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(livedump_all_tests); ++i) {
		UNREGISTER_TRACE_FN(pre_init, i);
		UNREGISTER_TRACE_FN(post_init, i);
		UNREGISTER_TRACE_FN(pre_start, i);
		UNREGISTER_TRACE_FN(post_start, i);
		UNREGISTER_TRACE_FN(pre_sweep, i);
		UNREGISTER_TRACE_FN(post_sweep, i);
		UNREGISTER_TRACE_FN(finish, i);
		UNREGISTER_TRACE_FN(uninit, i);
	}

	return 0;
}

/* module functions */

static int livedump_test_exit(struct notifier_block *_, unsigned long __, void *___)
{
	unregister_all_tests();

	return NOTIFY_DONE;
}

static struct notifier_block livedump_test_nb = {
	.notifier_call = livedump_test_exit
};

static int __init livedump_test_init(void)
{
	int ret;

	ret = register_reboot_notifier(&livedump_test_nb);
	if (ret) {
		livedump_test_exit(NULL, 0, NULL);
		return ret;
	}

	ret = register_all_tests();
	if (ret)
		livedump_test_exit(NULL, 0, NULL);

	return ret;
}

module_init(livedump_test_init);
