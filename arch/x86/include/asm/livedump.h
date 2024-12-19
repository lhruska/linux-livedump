#ifndef _ASM_X86_LIVEDUMP_H
#define _ASM_X86_LIVEDUMP_H

#ifdef CONFIG_ARCH_LIVEDUMP

int arch_livedump_save_registers(void);

#else

static inline int arch_livedump_save_registers() { return -EINVAL; }

#endif /* CONFIG_ARCH_LIVEDUMP */

#endif /* _ASM_X86_LIVEDUMP_H */
