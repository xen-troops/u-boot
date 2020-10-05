#include <common.h>
#include <dm.h>
#include <log.h>
#include <tee.h>
#include <memalign.h>
#include <blk.h>
#include <part.h>

#include "rpmb.h"
#include "optee_msg.h"
#include "optee_private.h"
#include "hmac_sha2.h"

/*
 * This structure is shared with OP-TEE and the MMC ioctl layer.
 * It is the "data frame for RPMB access" defined by JEDEC, minus the
 * start and stop bits.
 */
struct rpmb_data_frame {
	uint8_t stuff_bytes[196];
	uint8_t key_mac[32];
	uint8_t data[256];
	uint8_t nonce[16];
	uint32_t write_counter;
	uint16_t address;
	uint16_t block_count;
	uint16_t op_result;
#define RPMB_RESULT_OK				0x00
#define RPMB_RESULT_GENERAL_FAILURE		0x01
#define RPMB_RESULT_AUTH_FAILURE		0x02
#define RPMB_RESULT_ADDRESS_FAILURE		0x04
#define RPMB_RESULT_AUTH_KEY_NOT_PROGRAMMED	0x07
	uint16_t msg_type;
#define RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM		0x0001
#define RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ	0x0002
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE		0x0003
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_READ		0x0004
#define RPMB_MSG_TYPE_REQ_RESULT_READ			0x0005
#define RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM		0x0100
#define RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ	0x0200
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE		0x0300
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_READ		0x0400
};

/* Emulated rel_wr_sec_c value (reliable write size, *256 bytes) */
#define EMU_RPMB_REL_WR_SEC_C	1
/* Emulated rpmb_size_mult value (RPMB size, *128 kB) */
#define EMU_RPMB_SIZE_MULT	2

#define EMU_RPMB_SIZE_BYTES	(EMU_RPMB_SIZE_MULT * 128 * 1024)

/* Chosen with 4294967296 side dice. Guaranteed to be random*/
#define EMU_RPMB_MAGIC 0x1FD6E23C

/* Emulated eMMC device state */
struct rpmb_emu {
	uint32_t magic;
	uint8_t key[32];
	bool key_set;
	uint8_t nonce[16];
	uint32_t write_counter;
	size_t size;
	struct {
		uint16_t msg_type;
		uint16_t op_result;
		uint16_t address;
	} last_op;
	uint8_t buf[EMU_RPMB_SIZE_BYTES];
};


static lbaint_t rpmb_part_offset;
static struct blk_desc *rpmb_desc;
static char rpmb_emu[PAD_SIZE(sizeof(struct rpmb_emu), 512)];

static bool set_rpmb_partition(void)
{
	struct blk_desc *blk_desc;
	struct disk_partition part;
	int part_num;

	if (rpmb_desc)
		return true;

	blk_desc = blk_get_devnum_by_type(IF_TYPE_PVBLOCK, 0);

	if (!blk_desc)
	{
		log_err("RPMB-EMU: Can't find PVBLOCK device\n");
		return false;
	}

	part_num = part_get_info_by_name(blk_desc, "rpmbemul", &part);
	if (part_num < 0)
	{
		log_err("RPMB-EMU: Can't find 'rpmbemul' partition\n");
		return false;
	}

	if (part.size * part.blksz <
	    EMU_RPMB_SIZE_BYTES + sizeof(struct rpmb_emu))
	{
		log_err("RPMB-EMU: 'rpmbemul' partition is too small\n");
		return false;
	}

	rpmb_part_offset = part.start;
	rpmb_desc = blk_desc;

	return true;
}

static bool rpmb_save_state(void)
{
	unsigned long blk_count;

	if (!set_rpmb_partition())
		return false;

	blk_count = BLOCK_CNT(sizeof(struct rpmb_emu),
			      rpmb_desc);

	if (blk_dwrite(rpmb_desc, rpmb_part_offset, blk_count,
		       &rpmb_emu) != blk_count)
	{
		log_err("RPMB-EMU: Error writing state\n");
		return false;
	}

	return true;
}

static bool rpmb_read_state(void)
{
	static bool read = false;
	unsigned long blk_count;
	struct rpmb_emu *mem = (struct rpmb_emu*)rpmb_emu;

	if (read)
		return true;

	if (!set_rpmb_partition())
		return false;

	blk_count = BLOCK_CNT(sizeof(struct rpmb_emu),
			      rpmb_desc);

	if (blk_dread(rpmb_desc, rpmb_part_offset, blk_count,
		      mem) != blk_count)
	{
		log_err("RPMB-EMU: Error reading state\n");
		return false;
	}

	if (mem->magic != EMU_RPMB_MAGIC)
	{
		log_info("RPMB-EMU: Invalid magic. Reseting state\n");
		memset(mem, 0,  sizeof(struct rpmb_emu));

		mem->magic = EMU_RPMB_MAGIC;
		mem->size = EMU_RPMB_SIZE_BYTES;
	}

	read = true;
	return read;
}

#define CUC(x) ((const unsigned char *)(x))
static void hmac_update_frm(hmac_sha256_ctx *ctx, struct rpmb_data_frame *frm)
{
	hmac_sha256_update(ctx, CUC(frm->data), 256);
	hmac_sha256_update(ctx, CUC(frm->nonce), 16);
	hmac_sha256_update(ctx, CUC(&frm->write_counter), 4);
	hmac_sha256_update(ctx, CUC(&frm->address), 2);
	hmac_sha256_update(ctx, CUC(&frm->block_count), 2);
	hmac_sha256_update(ctx, CUC(&frm->op_result), 2);
	hmac_sha256_update(ctx, CUC(&frm->msg_type), 2);
}

static bool is_hmac_valid(struct rpmb_emu *mem, struct rpmb_data_frame *frm,
			  size_t nfrm)
{
	uint8_t mac[32] = { 0 };
	size_t i = 0;
	hmac_sha256_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	if (!mem->key_set) {
		log_err("Cannot check MAC (key not set)");
		return false;
	}

	hmac_sha256_init(&ctx, mem->key, sizeof(mem->key));
	for (i = 0; i < nfrm; i++, frm++)
		hmac_update_frm(&ctx, frm);
	frm--;
	hmac_sha256_final(&ctx, mac, 32);

	if (memcmp(mac, frm->key_mac, 32)) {
		log_err("Invalid MAC");
		return false;
	}
	return true;
}

static uint16_t gen_msb1st_result(uint8_t byte)
{
	return (uint16_t)byte << 8;
}

static uint16_t compute_hmac(struct rpmb_emu *mem, struct rpmb_data_frame *frm,
			     size_t nfrm)
{
	size_t i = 0;
	hmac_sha256_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	if (!mem->key_set) {
		log_err("Cannot compute MAC (key not set)");
		return gen_msb1st_result(RPMB_RESULT_AUTH_KEY_NOT_PROGRAMMED);
	}

	hmac_sha256_init(&ctx, mem->key, sizeof(mem->key));
	for (i = 0; i < nfrm; i++, frm++)
		hmac_update_frm(&ctx, frm);
	frm--;
	hmac_sha256_final(&ctx, frm->key_mac, 32);

	return gen_msb1st_result(RPMB_RESULT_OK);
}

static uint16_t emu_mem_transfer(struct rpmb_emu *mem,
				 struct rpmb_data_frame *frm,
				 size_t nfrm, int to_mmc)
{
	size_t start = mem->last_op.address * 256;
	size_t size = nfrm * 256;
	size_t i = 0;
	uint8_t *memptr = NULL;

	if (start > mem->size || start + size > mem->size) {
		log_err("Transfer bounds exceeed emulated memory");
		return gen_msb1st_result(RPMB_RESULT_ADDRESS_FAILURE);
	}
	if (to_mmc && !is_hmac_valid(mem, frm, nfrm))
		return gen_msb1st_result(RPMB_RESULT_AUTH_FAILURE);

	debug("Transferring %zu 256-byte data block%s %s MMC (block offset=%zu)",
	      nfrm, (nfrm > 1) ? "s" : "", to_mmc ? "to" : "from", start / 256);
	for (i = 0; i < nfrm; i++) {
		memptr = mem->buf + start + i * 256;
		if (to_mmc) {
			memcpy(memptr, frm[i].data, 256);
			mem->write_counter++;
			frm[i].write_counter = htonl(mem->write_counter);
			frm[i].msg_type =
				htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE);
		} else {
			memcpy(frm[i].data, memptr, 256);
			frm[i].msg_type =
				htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_READ);
			frm[i].address = htons(mem->last_op.address);
			frm[i].block_count = nfrm;
			memcpy(frm[i].nonce, mem->nonce, 16);
		}
		frm[i].op_result = gen_msb1st_result(RPMB_RESULT_OK);
	}

	if (!to_mmc)
		compute_hmac(mem, frm, nfrm);

	if (to_mmc && !rpmb_save_state())
		return gen_msb1st_result(RPMB_RESULT_GENERAL_FAILURE);

	return gen_msb1st_result(RPMB_RESULT_OK);
}

static void emu_get_write_result(struct rpmb_emu *mem,
				 struct rpmb_data_frame *frm)
{
	frm->msg_type =	htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE);
	frm->op_result = mem->last_op.op_result;
	frm->address = htons(mem->last_op.address);
	frm->write_counter = htonl(mem->write_counter);
	compute_hmac(mem, frm, 1);
}

static uint16_t emu_setkey(struct rpmb_emu *mem,
			   struct rpmb_data_frame *frm)
{
	if (mem->key_set) {
		log_err("Key already set");
		return gen_msb1st_result(RPMB_RESULT_GENERAL_FAILURE);
	}
	memcpy(mem->key, frm->key_mac, 32);
	mem->key_set = true;

	if (rpmb_save_state())
		return gen_msb1st_result(RPMB_RESULT_OK);
	else
		return gen_msb1st_result(RPMB_RESULT_GENERAL_FAILURE);
}

static void emu_read_ctr(struct rpmb_emu *mem,
			 struct rpmb_data_frame *frm)
{
	debug("Reading counter");
	frm->msg_type = htons(RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ);
	frm->write_counter = htonl(mem->write_counter);
	memcpy(frm->nonce, mem->nonce, 16);
	frm->op_result = compute_hmac(mem, frm, 1);
}

static uint32_t read_cid(uint16_t dev_id, uint8_t *cid)
{
	/* Taken from an actual eMMC chip */
	static const uint8_t test_cid[] = {
		/* MID (Manufacturer ID): Micron */
		0xfe,
		/* CBX (Device/BGA): BGA */
		0x01,
		/* OID (OEM/Application ID) */
		0x4e,
		/* PNM (Product name) "MMC04G" */
		0x4d, 0x4d, 0x43, 0x30, 0x34, 0x47,
		/* PRV (Product revision): 4.2 */
		0x42,
		/* PSN (Product serial number) */
		0xc8, 0xf6, 0x55, 0x2a,
		/*
		 * MDT (Manufacturing date):
		 * June, 2014
		 */
		0x61,
		/* (CRC7 (0xA) << 1) | 0x1 */
		0x15
	};

	(void)dev_id;
	memcpy(cid, test_cid, sizeof(test_cid));

	return TEE_SUCCESS;
}

static int emu_process_data_req(struct rpmb_data_frame *req_frm,
				int req_nfrm,
				struct rpmb_data_frame *resp_frm,
				int resp_nfrm)
{
	uint16_t msg_type = ntohs(req_frm->msg_type);
	struct rpmb_emu *mem = (struct rpmb_emu*)rpmb_emu;

	rpmb_read_state();

	mem->last_op.msg_type = msg_type;

	switch(msg_type)
	{
	case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
		resp_frm->msg_type = htons(RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM);
		resp_frm->op_result = emu_setkey(mem, req_frm);
		break;
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
		mem->last_op.address = ntohs(req_frm->address);
		mem->last_op.op_result = emu_mem_transfer(mem, req_frm, req_nfrm, 1);
		emu_get_write_result(mem, resp_frm);
		break;
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
		memcpy(mem->nonce, req_frm->nonce, 16);
		mem->last_op.address = ntohs(req_frm->address);
		mem->last_op.op_result = emu_mem_transfer(mem, resp_frm, resp_nfrm, 0);
		break;
	case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
		memcpy(mem->nonce, req_frm->nonce, 16);
		emu_read_ctr(mem, resp_frm);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rpmb_save_state();
	return TEE_SUCCESS;
}

u32 rpmb_emu_process_request(void *req, ulong req_size, void *rsp,
			     ulong rsp_size)
{
	struct rpmb_req *sreq = req;

	if (req_size < sizeof(*sreq))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (sreq->cmd) {
 	case RPMB_CMD_DATA_REQ:
	{
		int req_nfrm = (req_size - sizeof(struct rpmb_req)) / 512;
		int rsp_nfrm = rsp_size / 512;
		return emu_process_data_req(RPMB_REQ_DATA(req), req_nfrm, rsp,
					    rsp_nfrm);
	}
	case RPMB_CMD_GET_DEV_INFO:
	{
		if (req_size != sizeof(struct rpmb_req) ||
		    rsp_size != sizeof(struct rpmb_dev_info)) {
			debug("Invalid req/rsp size\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		struct rpmb_dev_info *info = rsp;

		info->rel_wr_sec_c = EMU_RPMB_REL_WR_SEC_C;
		info->rpmb_size_mult = EMU_RPMB_SIZE_MULT;
		info->ret_code = RPMB_CMD_GET_DEV_INFO_RET_OK;
		return read_cid(0, info->cid);
	}
	return TEE_SUCCESS;
	default:
		debug("Unsupported RPMB command: %d\n", sreq->cmd);
		return TEE_ERROR_BAD_PARAMETERS;
	}

}
