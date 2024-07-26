// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 EPAM Systems
 */

#include <tee/optee.h>

static int do_optee_load(struct cmd_tbl *cmdtp, int flag, int argc,
			 char * const argv[])
{
	unsigned long paddr;
	size_t size;
	int ret = 0;

	if (argc != 3)
		return CMD_RET_USAGE;

	paddr = hextoul(argv[1], NULL);
	size = hextoul(argv[2], NULL);


	/* Do not try to load OP-TEE more than once */
	if (flag == CMD_FLAG_REPEAT)
		return CMD_RET_FAILURE;

	printk("Trying to load OP-TEE image at %lx size %lx\n", paddr, size);

	ret = optee_load_image(paddr, size);

	if (ret != 0)
	{
		printk("Failed to load image. SMC ret = %d\n", ret);
		return CMD_RET_FAILURE;
	}

	printk("Image loaded successfully\n");

	return 0;
}

U_BOOT_CMD (
	optee_load, CONFIG_SYS_MAXARGS, 1, do_optee_load,
	"Command to load OP-TEE image to Secure World",
	"<addr> <size> - load OP-TEE image of <size> bytes from <addr>\n"
	)
;
