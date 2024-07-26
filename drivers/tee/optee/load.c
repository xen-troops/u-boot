// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 EPAM Systems
 */

#include <linux/arm-smccc.h>
#include <tee/optee.h>

#include "optee_msg.h"
#include "optee_smc.h"

int optee_load_image(unsigned long paddr, size_t size)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OPTEE_SMC_CALL_LOAD_IMAGE,
		      size << 32, size & 0xFFFFFFFF,
		      paddr << 32, paddr & 0xFFFFFFFF,
		      0, 0, 0, &res);

	return res.a0;
}
