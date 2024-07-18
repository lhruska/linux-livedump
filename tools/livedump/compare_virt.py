#!/usr/bin/python3

import sys
import argparse
import drgn
from drgn import Object, sizeof
from drgn.helpers.common import identify_address, member_at_offset
from drgn.helpers.linux import test_bit, pfn_to_page, phys_to_page, page_to_pfn, virt_to_page, \
        page_to_virt, compound_head, PageCompound, PageLRU, PageSwapBacked, PageSlab, PageHead, \
        PageTail, decode_page_flags, list_for_each_entry

PAGE_SIZE = 4096
PAGE_SHIFT = 12
PAGE_MASK = (1 << 64) - (1 << PAGE_SHIFT)
PMD_SHIFT = PAGE_SHIFT + 9
PUD_SHIFT = PMD_SHIFT + 9
PGD_SHIFT = PUD_SHIFT + 9
PTE_FLAGS_MASK = PMD_FLAGS_MASK = PUD_FLAGS_MASK = PGD_FLAGS_MASK = 0xfff0000000000fff
PTE_PFN_MASK = 0xffffffffff000
PAGE_PRESENT = 0x01
PAGE_HUGE = 1 << 7
PAGE_USER = 1 << 2
qemu_prog = None
live_prog = None
match = 0
valid = 0
zero = 0
pgd_idx = 0
pud_idx = 0
pmd_idx = 0
pte_idx = 0
E820_TYPE_RAM = 1
vaddr_end = 0xfffffdffffffffff
VM_ALLOC_OR_MAP = 0x06

# x86 local descriptor table for page table isolation (page_offset is the max value)
PTI_LDT_REMAP_START = 0xffff880000000000

# x86 KASAN area handling additional modules
KASAN_SHADOW_START = 0xffffec0000000000
KASAN_SHADOW_END = 0xfffffc0000000000

KASLR_FLAG = 1<<1
CPU_ENTRY_AREA_START = 0xfffffe0000000000
CPU_ENTRY_AREA_END = 0xfffffe8000000000
ESP_FIXUP_STACKS_START = 0xffffff0000000000
ESP_FIXUP_STACKS_END = 0xffffff8000000000
EFI_REGION_MAPPING_START = 0xffffffef00000000
EFI_REGION_MAPPING_END = 0xffffffff00000000
KERNEL_TEXT_MAPPING_START = 0xffffffff80000000
KERNEL_TEXT_MAPPING_END = 0xffffffffa0000000
MODULE_MAPPING_START = 0xffffffffa0000000
MODULE_MAPPING_END = 0xffffffffff000000
VSYSCALL_ABI_START = 0xffffffffff600000
VSYSCALL_ABI_END = 0xffffffffff601000

# symbols to be loaded
page_offset = None
max_pfn = None
vmalloc_base = None
vmemmap_base = None
wrprotect_state = None
pgbmp_userspace = None

verbose = False
summary = True
is_livedump = True

wrong_pfns = {}

def is_vmap_not_wanted(start, end):
    vmap_area_list_addr = qemu_prog["vmap_area_list"].address_of_()
    if start < vmalloc_base or end > vaddr_end:
        return False
    for el in list_for_each_entry("struct vmap_area", vmap_area_list_addr, "list"):
        if el.va_start <= start and el.va_end >= end:
            if el.vm.flags & VM_ALLOC_OR_MAP == 0:
                return True
    return False

def is_mapped_mem(start, end):
    table = qemu_prog["e820_table"]
    for i in range(0, table.nr_entries):
        entry = table.entries[i]
        if entry.type != E820_TYPE_RAM:
            continue
        if (entry.addr >= end or entry.addr + entry.size <= end):
            continue
        return True
    return False

def current_vaddr():
    return (((((((pgd_idx << 9) | pud_idx) << 9) | pmd_idx) << 9) | pte_idx) << 12) | \
            (((1 << 16)-1) << 48)

def compare_page(vaddr, pfn, flags):
    global valid
    global match
    global zero
    data1 = None
    data2 = None
    if is_livedump:
        if not test_bit(pfn, wrprotect_state.pgbmp_original):
            return
    try:
        data1 = qemu_prog.read(vaddr, PAGE_SIZE)
        data2 = live_prog.read(vaddr, PAGE_SIZE)
    except:
        pass
    if data1 is None and data2 is None:
        return
    if data1 is None and data2 is not None:
        if verbose:
            print(f"ERROR: [{hex(pfn)} <- {hex(vaddr)}] - mapping only on QEMU dump")
        return
    if data1 is not None and data2 is None:
        if verbose:
            print(f"ERROR: [{hex(pfn)} <- {hex(vaddr)}] - mapping only on live dump")
        return
    valid += 1
    page = pfn_to_page(pfn)
    if data1 != data2:
        wrong_pfns.setdefault(pfn, []).append(vaddr)
        if all(x == 0 for x in data2):
            zero += 1
            if verbose:
                print(f"ERROR: [{hex(pfn)} <- {hex(vaddr)}] - data not match - zeroes - " \
                        f"{bin(flags)} - {bin(page.flags)}")
        elif verbose:
            print(f"ERROR: [{hex(pfn)} <- {hex(vaddr)}] - data not match - {bin(flags)} - " \
                    f"{bin(page.flags)}")
    else:
        match += 1


def walk_pte_range(pte_start_addr):
    global pte_idx
    pte_start = Object(qemu_prog, "pte_t[]", address=pte_start_addr)
    for pte_idx in range(0, 1 << 9):
        if pte_start[pte_idx].pte & PAGE_PRESENT == 0:
            continue
        if pte_start[pte_idx].pte & PAGE_USER == PAGE_USER:
            continue
        try:
            page = phys_to_page(pte_start[pte_idx].pte & PTE_PFN_MASK)
            if PageCompound(page):
                page = compound_head(page)
            if page._refcount.counter == 0:
                continue
            if PageLRU(page) or PageSwapBacked(page):
                continue
            if pgbmp_userspace and test_bit(page_to_pfn(page), pgbmp_userspace):
                continue
        except:
            continue
        compare_page(current_vaddr(), int(pte_start[pte_idx].pte & PTE_PFN_MASK)//PAGE_SIZE, \
                pte_start[pte_idx].pte & 0xfff)

def walk_pmd_range(pmd_start_addr):
    global pmd_idx
    global pte_idx
    pmd_start = Object(qemu_prog, "pmd_t[]", address=pmd_start_addr)
    for pmd_idx in range(0, 1 << 9):
        if pmd_start[pmd_idx].pmd & PAGE_PRESENT == 0:
            continue
        if pmd_start[pmd_idx].pmd & PAGE_HUGE == PAGE_HUGE:
            pte_idx = 0
            if not is_vmap_not_wanted(current_vaddr(), current_vaddr() + (1 << 9) - 1):
                if verbose:
                    print("ERROR: pmd: [{} <- {}] - HUGE_PAGE! - {}".format(\
                            hex(pmd_start[pmd_idx].pmd & PTE_PFN_MASK), hex(current_vaddr()), \
                            bin(pmd_start[pmd_idx].pmd & 0xfff)))
            continue
        walk_pte_range((pmd_start[pmd_idx].pmd & PTE_PFN_MASK) + qemu_prog["page_offset_base"])

def walk_pud_range(pud_start_addr):
    global pud_idx
    pud_start = Object(qemu_prog, "pud_t[]", address=pud_start_addr)
    for pud_idx in range(0, 1 << 9):
        if pud_start[pud_idx].pud & PAGE_PRESENT == 0:
            continue
        if pud_start[pud_idx].pud & PAGE_HUGE == PAGE_HUGE:
            if verbose:
                print("ERROR: pud: HUGE_PAGE!")
            continue
        walk_pmd_range((pud_start[pud_idx].pud & PTE_PFN_MASK) + qemu_prog["page_offset_base"])

def walk_pgd_range():
    global pgd_idx
    pgd_start = qemu_prog["init_mm"].pgd
    for pgd_idx in range(0, 1 << 9):
        if pgd_start[pgd_idx].pgd & PAGE_PRESENT == 0:
            continue
        if pgd_start[pgd_idx].pgd & PAGE_HUGE == PAGE_HUGE:
            if verbose:
                print("ERROR: pgd: HUGE_PAGE!")
            continue
        walk_pud_range((pgd_start[pgd_idx].pgd & PTE_PFN_MASK) + qemu_prog["page_offset_base"])

def get_page_diffs(addr):
    addr &= PAGE_MASK
    bytes1 = qemu_prog.read(addr, PAGE_SIZE)
    bytes2 = live_prog.read(addr, PAGE_SIZE)
    in_missmatch = False
    out = []
    for i in range(0, len(bytes1)):
        if bytes1[i] != bytes2[i]:
            if not in_missmatch:
                out.append(addr+i)
                in_missmatch = True
        else:
            in_missmatch = False
    return out

def is_pdt_ldt_remap(addr):
    return PTI_LDT_REMAP_START <= addr and page_offset > addr

def is_direct_map_area(addr):
    return page_offset < addr and page_offset + max_pfn * PAGE_SIZE > addr

def is_vmalloc_area(addr):
    return vmalloc_base <= addr and vmemmap_base > addr

def is_vmemmap_area(addr):
    return vmemmap_base <= addr and KASAN_SHADOW_START > addr

def is_kasan_shadow_area(addr):
    return KASAN_SHADOW_START <= addr and KASAN_SHADOW_END > addr

def is_cpu_entry_area(addr):
    return CPU_ENTRY_AREA_START <= addr and CPU_ENTRY_AREA_END > addr

def is_esp_fixup_stack(addr):
    return ESP_FIXUP_STACKS_START <= addr and ESP_FIXUP_STACKS_END > addr

def is_efi_region_mapping_space(addr):
    return EFI_REGION_MAPPING_START <= addr and EFI_REGION_MAPPING_END > addr

def is_kernel_text_mapping(addr):
    return KERNEL_TEXT_MAPPING_START <= addr and KERNEL_TEXT_MAPPING_END > addr

def is_module_mapping(addr):
    return MODULE_MAPPING_START <= addr and MODULE_MAPPING_END > addr

def is_vsyscall_abi(addr):
    return VSYSCALL_ABI_START <= addr and VSYSCALL_ABI_END > addr

def get_pti_ldt_remap_info(addr):
    return "LDT remap for PTI"

def get_direct_map_info(addr):
    diff = get_page_diffs(addr)
    out = "direct-mapping {"
    last_info = ""
    for i in diff:
        info = identify_address(qemu_prog, i)
        if info is not None and info is not last_info:
            last_info = info
            out += f"{hex(i)} - INFO({info}), "
    out += "}"
    page = virt_to_page(addr)
    out += f" ({decode_page_flags(page)}) "
    if page.mapping.value_() == 0xdead000000000400:
        out += " - mapping 0xdead...400"
    if page.mapping.value_() == 0:
        out += " - mapping NULL"
    if PageCompound(page):
        out += " - compound page"
        if PageHead(page):
            dtor = qemu_prog.type("enum compound_dtor_id") \
                .enumerators[page[1].compound_dtor.value_()].name
            out += f" - head - dtor {dtor}"
        elif PageTail(page):
            out += f" - tail - head flags {decode_page_flags(compound_head(page))}"
    return out

def get_vmalloc_info(addr):
    diff = get_page_diffs(addr)
    out = "vmalloc/ioremap space { "
    for i in diff:
        info = identify_address(qemu_prog, i)
        if info is not None:
            out += f"{hex(i)} - {info}, "
    out += "}"
    return out

def get_vmemmap_info(addr):
    diff = get_page_diffs(addr)
    out = "vmemmap space { "
    last = 0
    page_type = qemu_prog.type("struct page")
    page_sz = sizeof(page_type)
    # is struct page?
    for i in diff:
        if i < vmemmap_base + page_sz * max_pfn and last + page_sz <= i:
            pages = Object(qemu_prog, type="struct page[]", address=vmemmap_base)
            page_idx = (i - vmemmap_base) / page_sz
            page = pages[page_idx].address_of_()
            virt = page_to_virt(page)
            pfn = page_to_pfn(page)
            out += f"{hex(pfn)} ({hex(virt)}) <- "
            if PageCompound(page):
                out += "compound page - "
                if PageHead(page):
                    out += "head"
                elif PageTail(page):
                    out += "tail"
                else:
                    out += "unknown"
            elif PageSlab(page):
                out += "slab page"
            elif PageLRU(page):
                out += "userspace page"
            elif PageSwapBacked(page):
                out += "propably shared page"
            else:
                out += "page"
            out += f" ({decode_page_flags(page)}) - "
            offset = i - page.value_()
            out += member_at_offset(page_type, offset)
            out += ", "
            last = page.value_()
        else:
            for i in diff:
                info = identify_address(qemu_prog, i)
                if info is not None:
                    out += f"{hex(i)} - {info}, "
    out += "}"
    return out

def get_kasan_shadow_area_info(addr):
    return "KASAN shadow area"

def get_cpu_entry_area_info(addr):
    return "cpu_entry_area space"

def get_esp_fixup_stack_info(addr):
    return "%esp fixup stacks"

def get_efi_region_mapping_space_info(addr):
    return "EFI region mapping space"

def get_kernel_text_mapping_info(addr):
    diff = get_page_diffs(addr)
    out = "kernel text mapping space {"
    last_sym = ""
    for i in diff:
        try:
            sym = qemu_prog.symbol(i)
            if sym != last_sym:
                out += f"{hex(i)} - {sym.name}, "
                last_sym = sym
        except LookupError:
            pass
    out += "}"
    return out

def get_module_mapping_space_info(addr):
    return "module mapping space"

def get_legacy_vsyscall_abi_info(addr):
    return "vsyscall_abi_info"

check_info_mapping = [
        { "check": is_pdt_ldt_remap, "info": get_pti_ldt_remap_info },
        { "check": is_direct_map_area, "info": get_direct_map_info },
        { "check": is_vmalloc_area, "info": get_vmalloc_info },
        { "check": is_vmemmap_area, "info": get_vmemmap_info },
        { "check": is_kasan_shadow_area, "info": get_kasan_shadow_area_info },
        { "check": is_cpu_entry_area, "info": get_cpu_entry_area_info },
        { "check": is_esp_fixup_stack, "info": get_esp_fixup_stack_info },
        { "check": is_efi_region_mapping_space, "info": get_efi_region_mapping_space_info },
        { "check": is_kernel_text_mapping, "info": get_kernel_text_mapping_info },
        { "check": is_module_mapping, "info": get_module_mapping_space_info },
        { "check": is_vsyscall_abi, "info": get_legacy_vsyscall_abi_info }
    ]

def print_summary():
    for key in wrong_pfns:
        print(f"{hex(key)} <- ", end="")
        for val in wrong_pfns[key]:
            print(f"{hex(val)} ", end="")
        if len(wrong_pfns[key]) > 1:
            non_direct_addrs = [x for x in wrong_pfns[key] if not is_direct_map_area(x) ]
            if len(non_direct_addrs) == 0:
                print("WARN - two direct mapped vaddrs detected")
            if len(non_direct_addrs) > 1:
                print("WARN - multiple vaddrs from different kernel areas")
            addr = non_direct_addrs[0]
            for handler in check_info_mapping:
                if handler["check"](addr):
                    print(handler["info"](addr))
        else:
            print(get_direct_map_info(wrong_pfns[key][0]))

def load_required_symbols():
    global page_offset
    global max_pfn
    global vmalloc_base
    global vmemmap_base
    global wrprotect_state
    global is_livedump
    global pgbmp_userspace
    page_offset = qemu_prog["page_offset_base"]
    max_pfn = qemu_prog["max_pfn"]
    vmalloc_base = qemu_prog["vmalloc_base"]
    vmemmap_base = qemu_prog["vmemmap_base"]
    try:
        wrprotect_state = qemu_prog["wrprotect_state"]
    except KeyError:
        wrprotect_state = None
    if wrprotect_state is None or wrprotect_state.pgbmp_original.value_() == 0:
        print("Livedump could not be found or was not yet initialized")
        print("Whole kernel memory will be compared")
        is_livedump = False
    try:
        pgbmp_userspace = live_prog["wrprotect_state"].pgbmp_userspace
    except:
        pass

def main():
    parser = argparse.ArgumentParser( \
            description="Comparer of livedump and qemu dump made at the same time.")
    parser.add_argument('qemu_dump', type=str)
    parser.add_argument('live_dump', type=str)
    parser.add_argument('vmlinux', type=str)
    parser.add_argument( \
            '--verbose', action='store_true', help="print all errors during comparision.")
    parser.add_argument( \
            '--nosummary', action='store_true', help="Skip summary, print only stats.")
    args = parser.parse_args()
    global qemu_prog
    global live_prog
    global match
    global valid
    global verbose
    global summary

    verbose = args.verbose
    summary = not args.nosummary

    print("Loading QEMU dump  ... ", end="")
    sys.stdout.flush()
    qemu_prog = drgn.program_from_core_dump(args.qemu_dump)
    print("DONE")
    print("Loading Livedump   ... ", end="")
    sys.stdout.flush()
    live_prog = drgn.program_from_core_dump(args.live_dump)
    print("DONE")
    print("Loading debug info ... ", end="")
    sys.stdout.flush()
    qemu_prog.load_debug_info([args.vmlinux])
    live_prog.load_debug_info([args.vmlinux])
    print("DONE")
    sys.stdout.flush()
    drgn.set_default_prog(qemu_prog)
    load_required_symbols()
    match = 0
    valid = 0
    print("Starting the page walk")
    walk_pgd_range()
    if summary:
        print("Summary:")
        print_summary()
    print(f"all virt: {valid}, match: {match}, rest: {valid - match}, zero: {zero}")

if __name__ == "__main__":
    main()
