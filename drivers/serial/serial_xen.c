/*
 * SPDX-License-Identifier:	GPL-2.0+
 *
 * (C) 2018 NXP
 * (C) 2020 EPAM Systems Inc.
 */
#include <common.h>
#include <cpu_func.h>
#include <serial.h>
#include <watchdog.h>

#include <asm/xen/hypercall.h>

DECLARE_GLOBAL_DATA_PTR;

#ifndef CONFIG_DM_SERIAL
static int xen_serial_init(void)
{
	return 0;
}

/*
 * N.B. We may be running with d-cache off at the moment, but
 * according to Xen hypercall ABI (see include/public/arch-arm.h)
 * all the buffers must reside in memory which is mapped as
 * Normal Inner Write-Back Inner-Shareable.
 * So, invalidate the data cache, so Xen sees consistent data.
 */
static void xen_serial_putc(const char c)
{
	invalidate_dcache_range((unsigned long)&c,
				(unsigned long)&c + 1);
	(void)HYPERVISOR_console_io(CONSOLEIO_write, 1, (char *)&c);
}

static void xen_serial_puts(const char *str)
{
	int len = strlen(str);

	invalidate_dcache_range((unsigned long)str,
				(unsigned long)str + len);
	(void)HYPERVISOR_console_io(CONSOLEIO_write, len, (char *)str);
}

static int xen_serial_tstc(void)
{
	return 0;
}

static void xen_serial_setbrg(void)
{
}

static struct serial_device xen_serial_drv = {
	.name	= "xen_serial",
	.start	= xen_serial_init,
	.stop	= NULL,
	.setbrg	= xen_serial_setbrg,
	/*
	 * FIXME: Non-priveleged domain should not try reading characters via
	 * hypercall, but use para-virtualized console instead.
	 */
	.getc	= NULL,
	.putc	= xen_serial_putc,
	.puts	= xen_serial_puts,
	.tstc	= xen_serial_tstc,
};

void xen_serial_initialize(void)
{
	serial_register(&xen_serial_drv);
}

__weak struct serial_device *default_serial_console(void)
{
	return &xen_serial_drv;
}
#endif /* CONFIG_DM_SERIAL */

