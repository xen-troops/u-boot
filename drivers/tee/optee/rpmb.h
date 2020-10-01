/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, EPAM Systems
 */

#ifndef __OPTEE_RPMB_H
#define __OPTEE_RPMB_H

/* Request */
struct rpmb_req {
	u16 cmd;
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01
	u16 dev_id;
	u16 block_count;
	/* Optional data frames (rpmb_data_frame) follow */
};

#define RPMB_REQ_DATA(req) ((void *)((struct rpmb_req *)(req) + 1))

/* Response to device info request */
struct rpmb_dev_info {
	u8 cid[16];
	u8 rpmb_size_mult;	/* EXT CSD-slice 168: RPMB Size */
	u8 rel_wr_sec_c;	/* EXT CSD-slice 222: Reliable Write Sector */
				/*                    COUNT */
	u8 ret_code;
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01
};

#ifdef CONFIG_OPTEE_RPMB_EMUL
u32 rpmb_emu_process_request(void *req, ulong req_size, void *rsp,
			     ulong rsp_size);
#endif

#endif
