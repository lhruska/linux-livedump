#include <asm/livedump.h>
#include <asm/apic.h>

#include <linux/livedump.h>
#include <linux/nmi.h>
#include <linux/delay.h>

static atomic_t nmi_handled;

/*
 * livedump_nmi_handler - NMI handler to save registers
 * @val - interrupt type
 * @regs - array of registers
 */
static int livedump_nmi_handler(unsigned int val, struct pt_regs *regs)
{
	int cpu;
	unsigned long flags;

	cpu = raw_smp_processor_id();

	local_irq_save(flags);

	memcpy(this_cpu_ptr(livedump_conf.regs), regs, sizeof(struct pt_regs));

	local_irq_restore(flags);

	atomic_dec(&nmi_handled);

	return NMI_HANDLED;
}

int arch_livedump_save_registers() {

	atomic_set(&nmi_handled, num_online_cpus() - 1);

	/* register our temporary NMI handler */
	if (WARN(register_nmi_handler(NMI_LOCAL, livedump_nmi_handler,
			    NMI_FLAG_FIRST, "livedump"),
				"livedump: could not set NMI handler.\n")) {
		return -EINVAL;
	}

	/* make sure it is propagated before triggering the NMI */
	wmb();

	/* trigger NMI on all other CPUs to save registers */
	apic_send_IPI_allbutself(NMI_VECTOR);

	while (atomic_read(&nmi_handled) > 0)
		mdelay(1);

	unregister_nmi_handler(NMI_LOCAL, "livedump");
	return 0;
}
