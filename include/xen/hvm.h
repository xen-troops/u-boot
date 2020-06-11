/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Simple wrappers around HVM functions
 *
 * Copyright (c) 2002-2003, K A Fraser
 * Copyright (c) 2005, Grzegorz Milos, gm281@cam.ac.uk,Intel Research Cambridge
 * Copyright (c) 2020, EPAM Systems Inc.
 */
#ifndef XEN_HVM_H__
#define XEN_HVM_H__

#include <asm/xen/hypercall.h>
#include <xen/interface/hvm/params.h>
#include <xen/interface/xen.h>

extern struct shared_info *HYPERVISOR_shared_info;

int hvm_get_parameter(int idx, uint64_t *value);
int hvm_set_parameter(int idx, uint64_t value);

struct shared_info *map_shared_info(void *p);
void unmap_shared_info(void);
void force_evtchn_callback(void);
void do_hypervisor_callback(struct pt_regs *regs);
void mask_evtchn(uint32_t port);
void unmask_evtchn(uint32_t port);
void clear_evtchn(uint32_t port);

extern int in_callback;

#define HVM_CALLBACK_VIA_TYPE_VECTOR 0x2
#define HVM_CALLBACK_VIA_TYPE_SHIFT 56
#define HVM_CALLBACK_VECTOR(x) (((uint64_t)HVM_CALLBACK_VIA_TYPE_VECTOR)<<\
		HVM_CALLBACK_VIA_TYPE_SHIFT | (x))

#endif /* XEN_HVM_H__ */
