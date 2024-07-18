// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * wrprotect.c - Kernel space write protection support
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
 *
 */

#include <asm/wrprotect.h>
#include <linux/mm.h>		/* __get_free_page, etc. */
#include <linux/delay.h>	/* mdelay */
#include <linux/bitmap.h>	/* bit operations */
#include <linux/memblock.h> /* max_pfn */
#include <linux/vmalloc.h>	/* vzalloc, vfree */
#include <linux/pagewalk.h>	/* walk_page_range_kernel */
#include <linux/stop_machine.h>	/* stop_machine */
#include <linux/sizes.h>	/* SZ_1M */
#include <asm/sections.h>	/* __per_cpu_* */
#include <asm/set_memory.h> /* set_memory_4k */
#include <asm/e820/api.h>	/* e820__mapped_any */
#include <asm/e820/types.h>	/* E820_TYPE_RAM */
#include <asm/tlbflush.h>	/* __flush_tlb_all */
#ifdef CONFIG_LIVEDUMP_TEST
#include <linux/rmap.h>
#endif /* CONFIG_LIVEDUMP_TEST */

#define PGBMP_LEN           PAGE_ALIGN(sizeof(long) * BITS_TO_LONGS(max_pfn))
#define DIRECT_MAP_SIZE     (max_pfn << PAGE_SHIFT)
#define vaddr_end			CPU_ENTRY_AREA_BASE

enum state {
	WRPROTECT_STATE_UNINIT,
	WRPROTECT_STATE_INITED,
	WRPROTECT_STATE_STARTED,
	WRPROTECT_STATE_SWEPT,
};

/* wrprotect's stuffs */
struct wrprotect_state {
	enum state state;

	/*
	 * r/o bitmap after initialization
	 * 0: there is no virt-address pointing at this pfn which
	 *    this module ever holded
	 * 1: there exists an virt-address pointing at this pfn which
	 *    is wprotect interested in
	 */
	unsigned long *pgbmp_original;
	/*
	 * r/w bitmap
	 * 0: content of this pfn was already saved
	 * 1: content of this pfn was still not saved yet
	 */
	unsigned long *pgbmp_save;
	/*
	 * r/w bitmap
	 * 0: provided handler processed this pfn without any problem
	 * 1: there was a problem processing this pfn using the provided handler
	 */
	unsigned long *pgbmp_fail;

#ifdef CONFIG_LIVEDUMP_TEST

	unsigned long *pgbmp_pf;
	unsigned long *pgbmp_sweep;
	unsigned long *pgbmp_userspace;

#endif /* CONFIG_LIVEDUMP_TEST */

	fn_handle_pfn_t handle_pfn;
	fn_handle_page_t handle_page;
	fn_sm_init_t sm_init;

	/* sensitive counter */
	unsigned long sensitive_counter;
} __aligned(PAGE_SIZE);

int wrprotect_is_on;
EXPORT_SYMBOL(wrprotect_is_on);

int wrprotect_is_init;
EXPORT_SYMBOL(wrprotect_is_init);

struct wrprotect_state wrprotect_state;

#ifdef CONFIG_LIVEDUMP_TEST
void wrprotect_userspace_set_pte(struct mm_struct *mm, pte_t pte)
{
	unsigned long pfn;

	if (mm == &init_mm)
		return;

	pfn = pte_pfn(pte);
	if (test_bit(pfn, wrprotect_state.pgbmp_original))
		set_bit(pfn, wrprotect_state.pgbmp_userspace);
}
EXPORT_SYMBOL_GPL(wrprotect_userspace_set_pte);

void wrprotect_userspace_set_pmd(struct mm_struct *mm, pmd_t pmd)
{
	unsigned long pfn, i;

	if (mm == &init_mm || !pmd_large(pmd))
		return;

	pfn = pmd_pfn(pmd);
	for (i = 0; i < PTRS_PER_PMD; ++i)
		if (test_bit(pfn+i, wrprotect_state.pgbmp_original))
			set_bit(pfn+i, wrprotect_state.pgbmp_userspace);
}
EXPORT_SYMBOL_GPL(wrprotect_userspace_set_pmd);
#endif /* CONFIG_LIVEDUMP_TEST */

static int split_large_pages_walk_pud(pud_t *pud, unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	int ret = 0;

	if (pud_present(*pud) && pud_large(*pud))
		ret = set_memory_4k(addr, 1);
	if (ret)
		return -EFAULT;

	return 0;
}

static int split_large_pages_walk_pmd(pmd_t *pmd, unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	int ret = 0;

	if (pmd_present(*pmd) && pmd_large(*pmd))
		ret = set_memory_4k(addr, 1);
	if (ret)
		return -EFAULT;

	return 0;
}

/* split_large_pages
 *
 * This function splits all large pages in straight mapping area into 4K ones.
 * Currently wrprotect supports only 4K pages, and so this is needed.
 */
static int split_large_pages(void)
{
	int ret;
	struct mm_walk_ops split_large_pages_walk_ops;

	memset(&split_large_pages_walk_ops, 0, sizeof(struct mm_walk_ops));
	split_large_pages_walk_ops.pud_entry = split_large_pages_walk_pud;
	split_large_pages_walk_ops.pmd_entry = split_large_pages_walk_pmd;

	mmap_write_lock(&init_mm);
	ret = walk_page_range_kernel(PAGE_OFFSET, FIXADDR_START,
		&split_large_pages_walk_ops, init_mm.pgd, NULL);
	mmap_write_unlock(&init_mm);

	return ret;
}

struct sm_context {
	int leader_cpu;
	int leader_done;
	int (*fn_leader)(void *arg);
	int (*fn_follower)(void *arg);
	void *arg;
};

static int call_leader_follower(void *data)
{
	int ret;
	struct sm_context *ctx = data;

	if (smp_processor_id() == ctx->leader_cpu) {
		ret = ctx->fn_leader(ctx->arg);
		ctx->leader_done = 1;
	} else {
		while (!ctx->leader_done)
			cpu_relax();
		ret = ctx->fn_follower(ctx->arg);
	}

	return ret;
}

/* stop_machine_leader_follower
 *
 * Calls stop_machine with a leader CPU and follower CPUs
 * executing different codes.
 * At first, the leader CPU is selected randomly and executes its code.
 * After that, follower CPUs execute their codes.
 */
static int stop_machine_leader_follower(
		int (*fn_leader)(void *),
		int (*fn_follower)(void *),
		void *arg)
{
	int cpu;
	struct sm_context ctx;

	preempt_disable();
	cpu = smp_processor_id();
	preempt_enable();

	memset(&ctx, 0, sizeof(ctx));
	ctx.leader_cpu = cpu;
	ctx.leader_done = 0;
	ctx.fn_leader = fn_leader;
	ctx.fn_follower = fn_follower;
	ctx.arg = arg;

	return stop_machine(call_leader_follower, &ctx, cpu_online_mask);
}

/*
 * This functions converts kernel address to it's pfn in most optimal way:
 * direct mapping address -> __pa
 * other address -> lookup_address -> pte_pfn
 */
static unsigned long kernel_address_to_pfn(unsigned long addr, int *level)
{
	pte_t *ptep;
	unsigned long pfn;

	if (addr >= PAGE_OFFSET && addr < PAGE_OFFSET + DIRECT_MAP_SIZE) {
		/* Direct-mapped addresses */
		pfn = __pa(addr) >> PAGE_SHIFT;
	} else {
		/* Non-direct-mapped addresses */
		ptep = lookup_address((unsigned long)addr, level);
		if (ptep && pte_present(*ptep))
			pfn = pte_pfn(*ptep);
		else
			pfn = 0;
	}

	return pfn;
}

/* wrprotect_unselect_pages
 *
 * This function clears bits corresponding to pages that cover a range
 * from start to start+len.
 */
void wrprotect_unselect_pages(
		unsigned long start,
		unsigned long len)
{
	unsigned long addr, pfn;
	int level;

	BUG_ON(start & ~PAGE_MASK);
	BUG_ON(len & ~PAGE_MASK);

	for (addr = start; addr < start + len; addr += PAGE_SIZE) {
		pfn = kernel_address_to_pfn(addr, &level);
		clear_bit(pfn, wrprotect_state.pgbmp_original);
	}
}

/* handle_addr_range
 *
 * This function executes wrprotect_state.handle_page in turns against pages that
 * cover a range from start to start+len.
 * At the same time, it clears bits corresponding to the pages.
 */
static void handle_addr_range(unsigned long start, unsigned long len)
{
	int level;
	unsigned long end = start + len;
	unsigned long pfn;

	start &= PAGE_MASK;
	while (start < end) {
		pfn = kernel_address_to_pfn(start, &level);
		wrprotect_state.handle_pfn(pfn, start);
		start += PAGE_SIZE;
	}
}

/* handle_task
 *
 * This function executes handle_addr_range against task_struct & thread_info.
 */
static void handle_task(struct task_struct *t)
{
	BUG_ON(!t);
	BUG_ON(!t->stack);
	BUG_ON((unsigned long)t->stack & ~PAGE_MASK);
	handle_addr_range((unsigned long)t, sizeof(*t));
	handle_addr_range((unsigned long)t->stack, THREAD_SIZE);
}

/* handle_tasks
 *
 * This function executes handle_task against all tasks (including idle_task).
 */
static void handle_tasks(void)
{
	struct task_struct *p, *t;
	unsigned int cpu;

	do_each_thread(p, t) {
		handle_task(t);
	} while_each_thread(p, t);

	for_each_online_cpu(cpu)
		handle_task(idle_task(cpu));
}

static void handle_pmd(pmd_t *pmd)
{
	unsigned long i;

	handle_addr_range((unsigned long)pmd, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_PMD; i++) {
		if (pmd_present(pmd[i]) && !pmd_large(pmd[i]))
			handle_addr_range(pmd_page_vaddr(pmd[i]), PAGE_SIZE);
	}
}

static void handle_pud(pud_t *pud)
{
	unsigned long i;

	handle_addr_range((unsigned long)pud, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_PUD; i++) {
		if (pud_present(pud[i]) && !pud_large(pud[i]))
			handle_pmd((pmd_t *)pud_pgtable(pud[i]));
	}
}

static void handle_p4d(p4d_t *p4d)
{
	unsigned long i;

	handle_addr_range((unsigned long)p4d, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_P4D; i++) {
		if (p4d_present(p4d[i]))
			handle_pud((pud_t *)p4d_pgtable(p4d[i]));
	}
}

/* handle_page_table
 *
 * This function executes wrprotect_state.handle_page against all pages that make up
 * page table structure and clears all bits corresponding to the pages.
 */
static void handle_page_table(void)
{
	pgd_t *pgd;
	p4d_t *p4d;
	unsigned long i;

	pgd = init_mm.pgd;
	handle_addr_range((unsigned long)pgd, PAGE_SIZE);
	for (i = pgd_index(PAGE_OFFSET); i < PTRS_PER_PGD; i++) {
		if (pgd_present(pgd[i])) {
			if (!pgtable_l5_enabled())
				p4d = (p4d_t *)(pgd+i);
			else
				p4d = (p4d_t *)pgd_page_vaddr(pgd[i]);
			handle_p4d(p4d);
		}
	}
}

/* handle_sensitive_pages
 *
 * This function executes wrprotect_state.handle_page against the following pages and
 * clears bits corresponding to them.
 * - All pages that include task_struct & thread_info
 * - All pages that make up page table structure
 * - All pages that include per_cpu variables
 * - All pages that cover kernel's data section
 */
static void handle_sensitive_pages(void)
{
	unsigned long per_cpu_size;
	int cpu_count;

	handle_tasks();
	handle_page_table();

	cpu_count = atomic_read(&__num_online_cpus);
	if (cpu_count > 1)
		per_cpu_size = (__per_cpu_offset[1] - __per_cpu_offset[0]) * cpu_count;
	else
		per_cpu_size = HPAGE_SIZE;

	handle_addr_range((unsigned long)__per_cpu_offset[0], per_cpu_size);
	handle_addr_range((unsigned long)_sdata, _edata - _sdata);
	handle_addr_range((unsigned long)__bss_start, __bss_stop - __bss_start);
}

static void default_handle_pfn(unsigned long pfn, unsigned long addr)
{
	if (test_bit(pfn, wrprotect_state.pgbmp_original)) {
		if (!wrprotect_state.handle_page(pfn, addr, 0))
			set_bit(pfn, wrprotect_state.pgbmp_fail);
		clear_bit(pfn, wrprotect_state.pgbmp_original);
	}
}

static void default_no_check_handle_pfn(unsigned long pfn, unsigned long addr)
{
	if (!wrprotect_state.handle_page(pfn, addr, 0))
		set_bit(pfn, wrprotect_state.pgbmp_fail);
}

static void sensitive_counter_handle_pfn(unsigned long pfn, unsigned long addr)
{
	++wrprotect_state.sensitive_counter;
}

unsigned long wrprotect_sensitive_count(void)
{
	wrprotect_state.sensitive_counter = 0;
	wrprotect_state.handle_pfn = sensitive_counter_handle_pfn;

	/*
	 * In this case we don't have a full control over all CPUs,
	 * so a proper locking is required.
	 */
	mmap_write_lock(&init_mm);
	read_lock(&tasklist_lock);

	handle_sensitive_pages();

	read_unlock(&tasklist_lock);
	mmap_write_unlock(&init_mm);

	wrprotect_state.handle_pfn = default_handle_pfn;

	return wrprotect_state.sensitive_counter;
}

/* protect_pte
 *
 * Changes a specified page's _PAGE_RW flag and _PAGE_SOFTW1 flag.
 * If the argument protect is non-zero:
 *  - _PAGE_RW flag is cleared
 *  - _PAGE_SOFTW1 flag is set to original value of _PAGE_RW
 * If the argument protect is zero:
 *  - _PAGE_RW flag is set to _PAGE_SOFTW1
 *
 * The change is executed only when all the following are true.
 *  - The page is mapped as 4K page.
 *  - The page is originally writable.
 *
 * Returns 1 if the change is actually executed, otherwise returns 0.
 */

static void __protect_pte(pte_t *ptep, int protect)
{
	if (protect) {
		if (pte_write(*ptep)) {
			*ptep = pte_wrprotect(*ptep);
			*ptep = pte_set_flags(*ptep, _PAGE_SOFTW1);
		} else
			*ptep = pte_clear_flags(*ptep, _PAGE_SOFTW1);
	} else if (pte_flags(*ptep) && _PAGE_SOFTW1)
		*ptep = pte_mkwrite(*ptep);
}

static int protect_pte(unsigned long addr, int protect)
{
	pte_t *ptep;
	unsigned int level;

	ptep = lookup_address(addr, &level);
	if (WARN(!ptep, "livedump: Page=%016lx isn't mapped.\n", addr) ||
	    WARN(!pte_present(*ptep),
		    "livedump: Page=%016lx isn't mapped.\n", addr) ||
	    WARN(level == PG_LEVEL_NONE,
		    "livedump: Page=%016lx isn't mapped.\n", addr) ||
	    WARN(level == PG_LEVEL_2M,
		    "livedump: Page=%016lx is consisted of 2M page.\n", addr) ||
	    WARN(level == PG_LEVEL_1G,
		    "livedump: Page=%016lx is consisted of 1G page.\n", addr)) {
		return 0;
	}

	__protect_pte(ptep, protect);

	return 1;
}

int wrprotect_protect_new_pte(pte_t *ptep)
{
	unsigned long pfn = pte_pfn(*ptep);

	if (WARN(pfn * PAGE_SIZE < SZ_1M || pfn > max_pfn, "Invalid PTE: pfn = %lu\n", pfn))
		return 0;

	if (!test_bit(pfn, wrprotect_state.pgbmp_original))
		return 0;

	if (test_bit(pfn, wrprotect_state.pgbmp_save)) {
		__protect_pte(ptep, 1);
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(wrprotect_protect_new_pte);

void wrprotect_protect_vfree(struct vm_struct *area, unsigned long addr)
{
	int i;

	for (i = 0; i < area->nr_pages; ++i) {
		struct page *page = area->pages[i];
		unsigned long pfn = page_to_pfn(page);

		if (test_bit(pfn, wrprotect_state.pgbmp_original) &&
				test_and_clear_bit(pfn, wrprotect_state.pgbmp_save)) {
			if (!wrprotect_state.handle_page(pfn, addr+i*PAGE_SIZE, 0))
				set_bit(pfn, wrprotect_state.pgbmp_fail);
		}
	}
}
EXPORT_SYMBOL(wrprotect_protect_vfree);

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 */
enum x86_pf_error_code {
	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
};

int wrprotect_page_fault_handler(unsigned long error_code)
{
	unsigned int level;
	unsigned long pfn, addr;

	/*
	 * Handle only kernel-mode write access
	 *
	 * error_code must be:
	 *  (1) PF_PROT
	 *  (2) PF_WRITE
	 *  (3) not PF_USER
	 *  (4) not PF_RSVD
	 *  (5) not PF_INSTR
	 */
	if (!(PF_PROT  & error_code) ||
	    !(PF_WRITE & error_code) ||
	     (PF_USER  & error_code) ||
	     (PF_RSVD  & error_code) ||
	     (PF_INSTR & error_code))
		goto not_processed;

	addr = (unsigned long)read_cr2();
	addr = addr & PAGE_MASK;

	if (addr >= PAGE_OFFSET && addr < PAGE_OFFSET + DIRECT_MAP_SIZE) {
		pfn = __pa(addr) >> PAGE_SHIFT;
	} else {
		pfn = kernel_address_to_pfn(addr, &level);
		if (pfn == 0 || level != PG_LEVEL_4K)
			goto not_processed;
	}

	if (!test_bit(pfn, wrprotect_state.pgbmp_original))
		goto not_processed;

	if (test_and_clear_bit(pfn, wrprotect_state.pgbmp_save)) {
#ifdef CONFIG_LIVEDUMP_TEST
		set_bit(pfn, wrprotect_state.pgbmp_pf);
#endif /* CONFIG_LIVEDUMP_TEST */
		if (!wrprotect_state.handle_page(pfn, addr, 0))
			set_bit(pfn, wrprotect_state.pgbmp_fail);
#ifdef CONFIG_LIVEDUMP_TEST
		if (test_bit(pfn, wrprotect_state.pgbmp_sweep))
			pr_warn("livedump: %lu was already saved by "
					"sweep but now processed even in pf handler\n", pfn);
#endif /* CONFIG_LIVEDUMP_TEST */
	}

	protect_pte(addr, 0);

	return true;

not_processed:
	return false;
}

static int generic_page_walk_pmd(pmd_t *pmd, unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	if (WARN(pmd_large(*pmd), "livedump: Page=%016lx is consisted of 2M page.\n", addr))
		return 0;

	return 0;
}

static int sm_leader_page_walk_pte(pte_t *pte, unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	unsigned long pfn;

	if (!pte || !pte_present(*pte))
		return 0;

	pfn = pte_pfn(*pte);

	if (test_bit(pfn, wrprotect_state.pgbmp_original)) {
		if (!protect_pte(addr, 1))
			clear_bit(pfn, wrprotect_state.pgbmp_original);
	}

	return 0;
}

#ifdef CONFIG_LIVEDUMP_TEST
bool wrprotect_rmap_walk(struct folio *folio, struct vm_area_struct *vma,
				unsigned long addr, void *arg)
{
	int i;

	for (i = 0; i < folio_nr_pages(folio); ++i)
		set_bit(page_to_pfn(folio_page(folio, i)), (unsigned long *)arg);
	return false;
}
#endif /* CONFIG_LIVEDUMP_TEST */

/* sm_leader
 *
 * Is executed by a leader CPU during stop-machine.
 *
 * This function does the following:
 * (1)Handle pages that must not be write-protected.
 * (2)Turn on the callback in the page fault handler.
 * (3)Write-protect pages which are specified by the bitmap.
 * (4)Flush TLB cache of the leader CPU.
 */
static int sm_leader(void *arg)
{
	int ret;
	struct mm_walk_ops sm_leader_walk_ops;
#ifdef CONFIG_LIVEDUMP_TEST
	unsigned long pfn;
	struct folio *folio;
	struct page *page;
	struct rmap_walk_control rwc;

	rwc.arg = wrprotect_state.pgbmp_userspace;
	rwc.rmap_one = wrprotect_rmap_walk;
	rwc.try_lock = false;
	rwc.contended = false;
	rwc.done = NULL;
	rwc.anon_lock = NULL;
	rwc.invalid_vma = NULL;

	for (pfn = 0; pfn < max_pfn; ++pfn) {
		if (!test_bit(pfn, wrprotect_state.pgbmp_original))
			continue;
		page = pfn_to_page(pfn);
		folio = page_folio(page);
		if (!folio || folio_test_reserved(folio))
			continue;
		if (!folio_mapping(folio))
			continue;
		if (folio_test_lru(folio)) {
			set_bit(pfn, wrprotect_state.pgbmp_userspace);
			continue;
		}
		rmap_walk(folio, &rwc);
	}
#endif /* CONFIG_LIVEDUMP_TEST */

	memset(&sm_leader_walk_ops, 0, sizeof(struct mm_walk_ops));
	sm_leader_walk_ops.pmd_entry = generic_page_walk_pmd;
	sm_leader_walk_ops.pte_entry = sm_leader_page_walk_pte;

	handle_sensitive_pages();

	wrprotect_state.sm_init();

	wrprotect_is_on = true;

	mmap_write_lock(&init_mm);
	ret = walk_page_range_kernel(PAGE_OFFSET, FIXADDR_START,
	    &sm_leader_walk_ops, init_mm.pgd, NULL);
	mmap_write_unlock(&init_mm);

	if (ret)
		return ret;

	memcpy(wrprotect_state.pgbmp_save, wrprotect_state.pgbmp_original,
			PGBMP_LEN);

	__flush_tlb_all();

	return 0;
}

/* sm_follower
 *
 * Is executed by follower CPUs during stop-machine.
 * Flushes TLB cache of each CPU.
 */
static int sm_follower(void *arg)
{
	__flush_tlb_all();
	return 0;
}

/* wrprotect_start
 *
 * This function sets up write protection on the kernel space during the
 * stop-machine state.
 */
int wrprotect_start(void)
{
	int ret;

	if (wrprotect_state.state != WRPROTECT_STATE_INITED) {
		pr_warn("livedump: wrprotect isn't initialized yet.\n");
		return 0;
	}

	ret = stop_machine_leader_follower(sm_leader, sm_follower, NULL);
	if (WARN(ret, "livedump: Failed to protect pages w/errno=%d.\n", ret))
		return ret;

	wrprotect_state.state = WRPROTECT_STATE_STARTED;
	return 0;
}

static void interrupt_state(void *info)
{
	unsigned long flags;
	atomic_t *smp_done = (atomic_t *)info;

	/* Save current interrupt state and enable interrupts */
	local_irq_save(flags);

	preempt_disable();

	while (!atomic_read(smp_done))
		mdelay(1);

	preempt_enable();

	/* Restore original interrupt state */
	local_irq_restore(flags);
}

/* wrprotect_start_int
 *
 * This function does the same thing as wrprotect_start but using interrupts
 * instead of stop-machine state
 */
int wrprotect_start_int(void)
{
	int ret;
	unsigned long flags;
	atomic_t smp_done;

	if (wrprotect_state.state != WRPROTECT_STATE_INITED) {
		pr_warn("livedump: wrprotect isn't initialized yet.\n");
		return 0;
	}

	atomic_set(&smp_done, 0);

	/* prevent preemption using cond_resched() */
	preempt_disable();

	smp_call_function(interrupt_state, (void *)&smp_done, 0);

	/* Save current interrupt state and disable all local interrupts */
	local_irq_save(flags);

	ret = sm_leader(NULL);
	if (WARN(ret, "livedump: Failed to protect pages w/errno=%d.\n", ret))
		return ret;

	/* Restore original interrupt state */
	local_irq_restore(flags);

	preempt_enable();

	atomic_set(&smp_done, 1);

	wrprotect_state.state = WRPROTECT_STATE_STARTED;
	return 0;
}

/* save_final_wrprotect_state
 *
 * Even though we want to save state of memory at the start of wrprotect,
 * we save the wrprotect_state memory after the wrprotect finishes.
 * This is only for testing and debugging purposes because this part of
 * memory is unselected from wrprotect's main bitmap anyway.
 */

static void save_final_wrprotect_state(void)
{
	wrprotect_state.handle_pfn = default_no_check_handle_pfn;

	handle_addr_range(
			(unsigned long)&wrprotect_state, sizeof(wrprotect_state));
	handle_addr_range(
			(unsigned long)wrprotect_state.pgbmp_original, PGBMP_LEN);
	handle_addr_range(
			(unsigned long)wrprotect_state.pgbmp_save, PGBMP_LEN);
	handle_addr_range(
			(unsigned long)wrprotect_state.pgbmp_fail, PGBMP_LEN);
#ifdef CONFIG_LIVEDUMP_TEST
	handle_addr_range(
			(unsigned long)wrprotect_state.pgbmp_userspace, PGBMP_LEN);
	handle_addr_range(
			(unsigned long)wrprotect_state.pgbmp_sweep, PGBMP_LEN);
	handle_addr_range(
			(unsigned long)wrprotect_state.pgbmp_pf, PGBMP_LEN);
#endif /* CONFIG_LIVEDUMP_TEST */

	wrprotect_state.handle_pfn = default_handle_pfn;
}

static int sweep_page_walk_pte(pte_t *pte, unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	unsigned long pfn;

	if (!pte || !pte_present(*pte))
		return 0;

	pfn = pte_pfn(*pte);

	if (test_and_clear_bit(pfn, wrprotect_state.pgbmp_save)) {
#ifdef CONFIG_LIVEDUMP_TEST
		set_bit(pfn, wrprotect_state.pgbmp_sweep);
#endif /* CONFIG_LIVEDUMP_TEST */
		if (!wrprotect_state.handle_page(pfn, addr, 1))
			set_bit(pfn, wrprotect_state.pgbmp_fail);
#ifdef CONFIG_LIVEDUMP_TEST
		if (test_bit(pfn, wrprotect_state.pgbmp_pf))
			pr_warn("livedump: %lu was already saved by pf handler but "
					"now processed even in sweep\n", pfn);
#endif /* CONFIG_LIVEDUMP_TEST */
	}
	if (test_bit(pfn, wrprotect_state.pgbmp_original))
		protect_pte(addr, 0);
	if (!(pfn & 0xffUL))
		cond_resched();

	return 0;
}

/* wrprotect_sweep
 *
 * On every page specified by the bitmap, this function executes the following.
 *  - Handle the page by calling wrprotect_state.handle_page.
 *  - Unprotect the page by calling protect_page.
 *
 * The above work may be executed on the same page at the same time
 * by the notifer-call-chain.
 * test_and_clear_bit is used for exclusion control.
 */
int wrprotect_sweep(void)
{
	int ret;
	struct mm_walk_ops sweep_walk_ops;

	memset(&sweep_walk_ops, 0, sizeof(struct mm_walk_ops));
	sweep_walk_ops.pmd_entry = generic_page_walk_pmd;
	sweep_walk_ops.pte_entry = sweep_page_walk_pte;

	if (wrprotect_state.state != WRPROTECT_STATE_STARTED) {
		pr_warn("livedump: Pages aren't protected yet.\n");
		return 0;
	}

	mmap_write_lock(&init_mm);
	ret = walk_page_range_kernel(PAGE_OFFSET, FIXADDR_START,
	    &sweep_walk_ops, init_mm.pgd, NULL);
	mmap_write_unlock(&init_mm);
	if (ret)
		return ret;

	save_final_wrprotect_state();

	wrprotect_state.state = WRPROTECT_STATE_SWEPT;

	return ret;
}

/* wrprotect_create_page_bitmap
 *
 * This function creates bitmap of which each bit corresponds to physical page.
 * Here, all ram pages are selected as being write-protected.
 */
static int wrprotect_create_page_bitmap(void)
{
	unsigned long pfn;

	/* allocate on vmap area */
	wrprotect_state.pgbmp_original = vzalloc(PGBMP_LEN);
	if (!wrprotect_state.pgbmp_original)
		return -ENOMEM;
	wrprotect_state.pgbmp_save = vzalloc(PGBMP_LEN);
	if (!wrprotect_state.pgbmp_save)
		return -ENOMEM;
	wrprotect_state.pgbmp_fail = vzalloc(PGBMP_LEN);
	if (!wrprotect_state.pgbmp_fail)
		return -ENOMEM;
#ifdef CONFIG_LIVEDUMP_TEST
	wrprotect_state.pgbmp_userspace = vzalloc(PGBMP_LEN);
	if (!wrprotect_state.pgbmp_userspace)
		return -ENOMEM;
	wrprotect_state.pgbmp_sweep = vzalloc(PGBMP_LEN);
	if (!wrprotect_state.pgbmp_sweep)
		return -ENOMEM;
	wrprotect_state.pgbmp_pf = vzalloc(PGBMP_LEN);
	if (!wrprotect_state.pgbmp_pf)
		return -ENOMEM;
#endif /* CONFIG_LIVEDUMP_TEST */

	/* select all ram pages */
	for (pfn = 0; pfn < max_pfn; pfn++) {
		if (e820__mapped_any(pfn << PAGE_SHIFT,
				    (pfn + 1) << PAGE_SHIFT,
				    E820_TYPE_RAM))
			set_bit(pfn, wrprotect_state.pgbmp_original);
		if (!(pfn & 0xffUL))
			cond_resched();
	}

	return 0;
}

/* wrprotect_destroy_page_bitmap
 *
 * This function frees both page bitmaps created by wrprotect_create_page_bitmap.
 */
static void wrprotect_destroy_page_bitmap(void)
{
	vfree(wrprotect_state.pgbmp_original);
	vfree(wrprotect_state.pgbmp_save);
	vfree(wrprotect_state.pgbmp_fail);
	wrprotect_state.pgbmp_original = NULL;
	wrprotect_state.pgbmp_save = NULL;
	wrprotect_state.pgbmp_fail = NULL;
#ifdef CONFIG_LIVEDUMP_TEST
	vfree(wrprotect_state.pgbmp_pf);
	vfree(wrprotect_state.pgbmp_sweep);
	vfree(wrprotect_state.pgbmp_userspace);
	wrprotect_state.pgbmp_pf = NULL;
	wrprotect_state.pgbmp_sweep = NULL;
	wrprotect_state.pgbmp_userspace = NULL;
#endif /* CONFIG_LIVEDUMP_TEST */
}

static bool default_handle_page(unsigned long pfn, unsigned long addr, int for_sweep)
{
	return false;
}

/* wrprotect_init
 *
 * fn_handle_page:
 *   This callback is invoked to handle faulting pages.
 *   This function takes 3 arguments.
 *   First one is PFN that tells where is this address physically located.
 *   Second one is address that tells which page caused page fault.
 *   Third one is a flag that tells whether it's called in the sweep phase.
 */
int wrprotect_init(fn_handle_page_t fn_handle_page, fn_sm_init_t fn_sm_init)
{
	int ret;

	if (wrprotect_state.state != WRPROTECT_STATE_UNINIT) {
		pr_warn("livedump: wrprotect is already initialized.\n");
		return 0;
	}

	ret = wrprotect_create_page_bitmap();
	if (ret < 0) {
		pr_warn("livedump: not enough memory for wrprotect bitmaps\n");
		return -ENOMEM;
	}

	wrprotect_is_on = false;
	wrprotect_is_init = true;

	/* split all large pages in straight mapping area */
	ret = split_large_pages();
	if (ret)
		goto err;

	/* unselect internal stuffs of wrprotect */
	wrprotect_unselect_pages(
			(unsigned long)&wrprotect_state, sizeof(wrprotect_state));
	wrprotect_unselect_pages(
			(unsigned long)wrprotect_state.pgbmp_original, PGBMP_LEN);
	wrprotect_unselect_pages(
			(unsigned long)wrprotect_state.pgbmp_save, PGBMP_LEN);
	wrprotect_unselect_pages(
			(unsigned long)wrprotect_state.pgbmp_fail, PGBMP_LEN);
#ifdef CONFIG_LIVEDUMP_TEST
	wrprotect_unselect_pages(
			(unsigned long)wrprotect_state.pgbmp_userspace, PGBMP_LEN);
	wrprotect_unselect_pages(
			(unsigned long)wrprotect_state.pgbmp_pf, PGBMP_LEN);
	wrprotect_unselect_pages(
			(unsigned long)wrprotect_state.pgbmp_sweep, PGBMP_LEN);
#endif /* CONFIG_LIVEDUMP_TEST */

	wrprotect_state.handle_page = fn_handle_page ?: default_handle_page;
	wrprotect_state.handle_pfn = default_handle_pfn;
	wrprotect_state.sm_init = fn_sm_init;

	wrprotect_state.state = WRPROTECT_STATE_INITED;
	return 0;

err:
	return ret;
}

static int uninit_page_walk_pte(pte_t *pte, unsigned long addr, unsigned long next,
	struct mm_walk *walk)
{
	unsigned long pfn;

	if (!pte || !pte_present(*pte))
		return 0;

	pfn = pte_pfn(*pte);

	if (!test_bit(pfn, wrprotect_state.pgbmp_original))
		return 0;
	protect_pte(addr, 0);
	*pte = pte_clear_flags(*pte, _PAGE_SOFTW1);

	if (!(pfn & 0xffUL))
		cond_resched();

	return 0;
}

void wrprotect_uninit(void)
{
	int ret;
	struct mm_walk_ops uninit_walk_ops;
#ifdef CONFIG_LIVEDUMP_TEST
	unsigned long pfn;
#endif /* CONFIG_LIVEDUMP_TEST */

	if (wrprotect_state.state == WRPROTECT_STATE_UNINIT)
		return;

	if (wrprotect_state.state == WRPROTECT_STATE_STARTED) {
		memset(&uninit_walk_ops, 0, sizeof(struct mm_walk_ops));
		uninit_walk_ops.pmd_entry = generic_page_walk_pmd;
		uninit_walk_ops.pte_entry = uninit_page_walk_pte;

		mmap_write_lock(&init_mm);
		ret = walk_page_range_kernel(PAGE_OFFSET, FIXADDR_START,
			&uninit_walk_ops, init_mm.pgd, NULL);
		mmap_write_unlock(&init_mm);

		flush_tlb_all();
	}

	if (wrprotect_state.state >= WRPROTECT_STATE_STARTED) {
		wrprotect_is_on = false;
#ifdef CONFIG_LIVEDUMP_TEST
		pr_warn("livedump_check: start checking...\n");
		for (pfn = 0; pfn < max_pfn; ++pfn) {
			if (!test_bit(pfn, wrprotect_state.pgbmp_original))
				continue;
			if (!test_bit(pfn, wrprotect_state.pgbmp_pf) &&
					!test_bit(pfn, wrprotect_state.pgbmp_sweep))
				pr_warn("livedump_check: %lu was not processed neither by "
						"sweep and pf handler\n", pfn);
			if (test_bit(pfn, wrprotect_state.pgbmp_pf) &&
					test_bit(pfn, wrprotect_state.pgbmp_sweep))
				pr_warn("livedump_check: %lu was processed by both sweep "
						"and pf handler\n", pfn);
		}
		pr_warn("livedump_check: done!\n");
#endif /* CONFIG_LIVEDUMP_TEST */
	}


	wrprotect_is_init = false;

	wrprotect_destroy_page_bitmap();

	wrprotect_state.handle_page = NULL;
	wrprotect_state.state = WRPROTECT_STATE_UNINIT;
}
