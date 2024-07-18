/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * wrprortect.h - Kernel space write protection support
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

#ifndef _WRPROTECT_H
#define _WRPROTECT_H

#include <asm/pgtable_64_types.h>
#include <linux/jump_label.h>

#ifndef __ASSEMBLY__

#include <linux/mm_types.h>

struct vm_struct;

typedef bool (*fn_handle_page_t)(unsigned long pfn, unsigned long addr, int for_sweep);
typedef void (*fn_sm_init_t)(void);
typedef void (*fn_handle_pfn_t)(unsigned long pfn, unsigned long addr);

extern int wrprotect_init(
		fn_handle_page_t fn_handle_page,
		fn_sm_init_t fn_sm_init);
extern void wrprotect_uninit(void);
extern int wrprotect_start(void);
extern int wrprotect_start_int(void);
extern int wrprotect_sweep(void);
extern void wrprotect_unselect_pages(
		unsigned long start,
		unsigned long len);
extern int wrprotect_page_fault_handler(unsigned long error_code);
extern int wrprotect_protect_new_pte(pte_t *ptep);
extern void wrprotect_protect_vfree(struct vm_struct *area, unsigned long addr);
extern void wrprotect_userspace_set_pte(struct mm_struct *mm, pte_t pte);
extern void wrprotect_userspace_set_pmd(struct mm_struct *mm, pmd_t pmd);
extern unsigned long wrprotect_sensitive_count(void);

extern int wrprotect_is_on;
extern int wrprotect_is_init;

#endif /* __ASSEMBLY__ */

#endif /* _WRPROTECT_H */
