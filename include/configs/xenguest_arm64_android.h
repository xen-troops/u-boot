/*
 * SPDX-License-Identifier: GPL-2.0+
 *
 * (C) Copyright 2020 EPAM Systemc Inc.
 */
#ifndef __XENGUEST_ARM64_ANDROID_H
#define __XENGUEST_ARM64_ANDROID_H

#include <configs/xenguest_arm64.h>

#define CONFIG_SYS_BOOTM_LEN	      (20 * 1024 * 1024)

#undef CONFIG_EXTRA_ENV_SETTINGS

/* NOTE: In case of bootm * boot , u-boot  will set/append
 * env variable bootargs with boot_img_hdr->cmdline and further overwrite
 * /chosen node of the fdt. Since /chosen node is the main mechanism to pass cmdline
 * from Xen domain config to bootloader and Linux kernel, we will prior to all that 
 * create bootargs variable with /chosen node(using command "fdt get value bootargs /chosen bootargs").
 * So in at the end bootargs will contain /cosen node + boot_img_hdr->cmdline. */

#define CONFIG_EXTRA_ENV_SETTINGS	\
	"fdt_addr=0x48000000\0" \
	"boot_image_addr=0x90000000\0" \
	"blk_device_id=0\0" \
	"blk_deivce_if=pvblock\0" \
	"bootcmd=part number ${blk_deivce_if} ${blk_device_id} misc misc_partition_id; bcb load ${blk_device_id} ${misc_partition_id} ${blk_deivce_if}; if bcb test command = boot-recovery; then echo Booting recovery...; run boot_pvblock_recovery; else echo Booting Android...; run boot_pvblock; fi;\0" \
	"avb_verify=avb init ${blk_device_id} ${blk_deivce_if}; avb verify _${slot};\0" \
	"avb_check=if run avb_verify; then                       \
           echo AVB verification OK. Continue boot; \
           set bootargs $bootargs $avb_bootargs;    \
      else                                          \
           echo AVB verification failed;            \
           set bootargs $bootargs $avb_bootargs;                                    \
      fi;\0" \
	"boot_pvblock=ab_select slot pvblock ${blk_device_id}#misc; run loadimage; fdt addr ${fdt_addr}; fdt get value bootargs /chosen bootargs; run update_bootargs; run avb_check; bootm ${boot_image_addr} ${boot_image_addr} ${fdt_addr};\0"\
	"boot_pvblock_recovery=ab_select slot pvblock ${blk_device_id}#misc; run loadimage; fdt addr ${fdt_addr}; fdt get value bootargs /chosen bootargs; run update_bootargs_recovery; run avb_check; bootm ${boot_image_addr} ${boot_image_addr} ${fdt_addr};\0"\
	"update_bootargs=set bootargs ${bootargs} androidboot.slot_suffix=_${slot} androidboot.force_normal_boot=1;\0" \
	"update_bootargs_recovery= set bootargs ${bootargs} androidboot.slot_suffix=_${slot};\0" \
	"loadimage=run read_bootimage_params; pvblock read ${boot_image_addr} ${boot_image_part_blk} ${boot_image_length_blk};\0" \
	"read_bootimage_params=part start pvblock ${blk_device_id} boot_${slot} boot_image_part_blk ; part size pvblock ${blk_device_id} boot_${slot} boot_image_length_blk;\0"

#endif /* __XENGUEST_ARM64_H */
