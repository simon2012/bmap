#ifndef __BM_INIT_H
#define __BM_INIT_H

#include <linux/types.h>

#include "mapper.h"

#define BM_HDR_MAGIC "BM_000"

/* the blknr of bmhdr, blknr starting from zero */
#define BM_HDR_BLK_NR	1

/* the offset of bmhdr, in byte */
#define BM_HDR_OFFSET	(BM_HDR_BLK_NR << BM_MAPPING_BLKBITS)

/* the length of bmhdr, in byte */
#define BM_HDR_LENGTH_BYTE	0x1000

/* the start pos of mapblock/datablock, in sectsize. */
#define BM_INIT_POS	((BM_HDR_OFFSET + BM_HDR_LENGTH_BYTE) >> 9)

#define BM_HDR_FLAGS_CLEAN		((unsigned int)0)
#define BM_HDR_FLAGS_DIRTY		((unsigned int)1)

/* 	block mapper primary header, needed to be
	packed within 1024 byte . */

struct bm_header
{

/* 0x00 */

	/* 	signature, only initialzed */

	union
	{
		__le64	h_magic;
		unsigned char h_str[sizeof(__le64)];
	};

/* 0x08 */

	/* 	flags, it shows if the filter
		has been dismounted cleanly. */

	__le32	h_flags;

/* 0x0c */

	/*	devnum of the hook block device. It
		will either be initialized or pickup
		for comfirmation. */

	__le32	h_hkdev;

/* 0x10 */

	/*	devnum of the store block device. It
		will either be initialized or pickup
		for comfirmation. */

	__le32	h_stdev;

/* 0x14 */

	/* 	offset of this block device, in sectsize.
		It will	either be initialized or pickup
		for comfirmation. */

	__le64	h_start;

/* 0x1c*/

	/*	size of block device in sectsize. It will
		either be initialized or pickup for
		confirmation. */

	__le64	h_capacity;

/* 0x24 */

	/*	size of datablksize, it will be either initialized
		or pickup. (no confirmation) */

	__le32	h_blkbits;

/* 0x28 */

	/* 	size of mapblksize in bits, it will be initialized
		or pickup. (no confirmation) */

	__le32	h_mapblkbits;

/* 0x2c */

	/* 	size of entry in bits, initialized or pickup for
		confirmation. */

	__le32 	h_entrybits;

/* 0x30 */

	/*	initialized or pickup (no confirmation) */

	__le64	h_pos;

/* 0x38 */

	/* virtual volume name */

	unsigned char h_vname[BDEVNAME_SIZE];	/* 0x20 */

/* 0x58 */

	/* offset of root entry */

	__le64 h_root;

/* 0x60 */
} __attribute__((__packed__));

struct block_mapper;

int bm_bdev_create(struct block_mapper *bm, dev_t hook, dev_t store);
int bm_bdev_resume(struct block_mapper *bm, dev_t hook, dev_t store);
void bm_bdev_cleanup(struct block_mapper *bm);
int bm_bdev_start(struct block_mapper *bm);
int bm_bdev_stop(struct block_mapper *bm);
void bm_fsck(struct block_mapper *bm);

#endif


