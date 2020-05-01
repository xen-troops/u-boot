/*
 * SPDX-License-Identifier: GPL-2.0+
 *
 * (C) Copyright 2020 EPAM Systemc Inc.
 */
#ifndef __XENGUEST_ARM64_H
#define __XENGUEST_ARM64_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif
#include <xen/interface/xen.h>

#define CONFIG_BOARD_EARLY_INIT_F

#define CONFIG_EXTRA_ENV_SETTINGS

#undef CONFIG_NR_DRAM_BANKS
/*
 * See for reference:
 * https://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=xen/include/public/arch-arm.h
 */
#define CONFIG_NR_DRAM_BANKS          GUEST_RAM_BANKS
#define CONFIG_SYS_SDRAM_BASE         GUEST_RAM0_BASE

/* Link Definitions */
#define CONFIG_LOADADDR               (CONFIG_SYS_SDRAM_BASE + 0x00080000)
#define CONFIG_SYS_LOAD_ADDR          CONFIG_LOADADDR
#define CONFIG_SYS_INIT_SP_ADDR       (CONFIG_SYS_SDRAM_BASE + 0x00200000)

/* Size of malloc() pool */
#define CONFIG_SYS_MALLOC_LEN         (32 * 1024 * 1024)

/* Monitor Command Prompt */
#define CONFIG_SYS_PROMPT_HUSH_PS2    "> "
#define CONFIG_SYS_CBSIZE             1024
#define CONFIG_SYS_MAXARGS            64
#define CONFIG_SYS_BARGSIZE           CONFIG_SYS_CBSIZE
#define CONFIG_SYS_PBSIZE             (CONFIG_SYS_CBSIZE + \
                                      sizeof(CONFIG_SYS_PROMPT) + 16)

#define CONFIG_OF_SYSTEM_SETUP

#define CONFIG_CMDLINE_TAG            1
#define CONFIG_INITRD_TAG             1

#endif /* __XENGUEST_ARM64_H */
