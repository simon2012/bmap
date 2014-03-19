#ifndef __BDEV_MAPPER_H__
#define __BDEV_MAPPER_H__

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>

#include "sche.h"
#include "init.h"

/* 	log 2 of the length of disk offset in byte,
	here, we use 8 byte */

#define BM_ENTRY_LENGTH_BITS 	3	/* 8 bytes */

#define BM_ADDRESS_SHIFT 		9 	/* 	the lower 9 bits are reserved for entry	status flags. */

#define BM_FG_VALID				0	/* 	If set, entry value is valid */
#define BM_FG_BUSY				1	/* 	If set, entry value is being setup */
#define BM_FG_READY				2	/*  If set, copy-on-write is finished,
										Only for data block */
#define BM_FG_MAP				3 	/*	[7], If set, entry is mapblock, otherwise, datablock.
										we use BM_FG_MAP for consistency-check. */

#define BM_MAP_BIO_MAX		20	/* the max number of bio one bm_map operation is able to handle */
#define BM_MAP_BLK_MAX		20	/* the max number of blocknr one bm_map operation is able to handle */

#define BM_DATA_BLKBITS		14	 /* datablocksize in bit */

#define BM_MAPPING_BLKBITS	PAGE_SHIFT	/*  the maximum mapping blocksize,
											one mapping block needs to fit in
											one page, so that we can, using
											buffer head caching mechanims, read
											at least one mapping block at a time
											using buffer head.	*/


#define BM_BLK_NR(nr, obits, nbits)		\
					((obits) <= (nbits)) ?	\
					((nr) >> ((nbits) - (obits))) :	\
					((nr) << ((obits) - (nbits)))

struct bm_addr
{
	loff_t blocknr;		/* blknr to resolve, in datablock size (bm->blkbits)*/
	loff_t entryblk;
	unsigned long ndx;

	loff_t entry;		/* shift right BM_ADDRESS_SHIFT, in mapblock size (bm->mapblksize) */

	unsigned int flags; /* currently used by bm_bpkt_insert */

};

struct bm_map_pkt
{
	sector_t start_blknr;	/* the first blocknr covered by the packet */
	sector_t end_blknr;		/* the last blocknr covered by the packet */

	unsigned long bpos;	/*  current pos of blocknr, initialized as zero,
							no bigger than (end_blknr - start_blknr) + 1.
							It tells if there is blocknr left not having been
							mapped, if so, we need to initiate more mapping. */

	struct bm_addr addr[BM_MAP_BLK_MAX]; /* bm_addr array to receive mapping results */

	unsigned long apos;	/* 	current pos of bm_addr array, also indicate, after
							mapping operation, the valid number of entry in the
							array, initialized as zero, not bigger than
							BM_MAP_BLK_MAX, */

	unsigned long andx;
};

struct bm_bio
{
	struct bio *b;		/* current bio being held */

	sector_t start_blknr;	/* 	the first blocknr covered by bio, derived
								but also different from sector */

	sector_t end_blknr;		/*	the last blocknr covered by bio, notice that
								its not the first blocknr right after bio but the
								last blocknr of bio */

	/* bio parameters, we save them here as they may get changed later */

	sector_t sector;
	unsigned int size;

	unsigned long flags;
	unsigned long rw;

	unsigned short vcnt;
	struct bio_vec *vec;

	/* completion routine and private data */

	void *data;
	bio_end_io_t *completion;

	union
	{
		struct
		{
			struct bio *rbio;

			unsigned int b_size;

		#ifdef __BM_SYNC_BH_WRITEBACK__

			/* [7], save vec array for async_write_bio */

			struct bio *wbio;

		#endif

			int bio_lvl;

			unsigned int io_len;
			int io_err;

		} insert;

		struct
		{
			sector_t cur_blknr;
			unsigned long cur_blkoffset;

			unsigned int vec_idx;
			unsigned int vec_offset;
			unsigned int b_size;

			sector_t src_blknr;
			unsigned long src_blkoffset;
			unsigned long src_bytes;

			sector_t bh_blknr;
			unsigned long bh_offset;

			int bh_lvl;

			struct buffer_head *bh;
			int uptodate;

		#ifdef __BM_PRE_READ__

			struct bio *rbio;

			unsigned int rb_size;
			unsigned int io_len;
			int io_err;

		#endif

		} read;
	};
};

struct bm_bio_pkt
{
	struct list_head list;
	struct bm_map_pkt mpkt;

	struct bm_bio *b[BM_MAP_BIO_MAX];

	unsigned long pos;	/* 	the current pos of b, initialized as zero,
							and no bigger than BM_MAP_BIO_MAX */

	unsigned long bcnt;	/*	the total number of */

	/*	flags indicates the status of this packet

		If bit 0 is set, bpkt is after old mk_rq_fn.
	 	If bit 1 is set, bpkt needs more mapping in both bm_insert/bm_read.
	 	If bit 2 is set, need to initiate the first mapping in bm_insert/bm_read
	 	If bit 3 is set, re-entry, need to trylock bh again in bm_read;
	 	If bit 4 is set, re-entry, wait for BM_FG_READY in bm_insert;
	 	If bit 5 is set, re-entry, wait to write read-out data, in bm_insert; */

	unsigned long flags;

	struct block_mapper *bm;	/* used for async handling, as in bio completion routine,
									we need to pack everything into bio->bi_private. */
};

/*	bm_mapping_fn,
	specific to the type of operation when resolving blocknr;

	return value:
	0, finish, 	we may reach datablock and current blocknr is resolved.
				However, depending upon the type of operation, blocknr resolving
				may just need to stop in the middle.
	1, continue,mapblock, recursively continue resolving current blocknr.
	-1, fail,	blocknr resolving failed. */

typedef int (bm_mapping_fn)(
	struct block_mapper *bm,	/* block_mapper */
	loff_t entryblk,			/* bh's blocknr */
	struct buffer_head *bh,		/* buffer_head, bh is already locked */
	unsigned long ndx,			/* index of which entry within bh to parse */
	unsigned int flags,			/* flags, if bit 0 is set, datablock */
	struct bm_map_pkt *pkt,		/* generic bm_map packet */
	loff_t *nextblk				/* if mapblock, ((loff_t *)bh->data)[ndx] */
	);


struct block_mapper
{
	struct block_device *hook;
	struct block_device *contains;
	struct gendisk *disk;
	request_queue_t *queue;
	make_request_fn *old_mk_rq_fn;

	struct block_device *st_bdev;

	dev_t	hkdev;		/* devnum of hook. */
	dev_t 	stdev;		/* devnum of store. */

	sector_t start; 	/* the start offset of hook, in sectsize */
	sector_t capacity;	/* the size of hook, in sectsize */
	sector_t size;		/* the sizeof hook, in datablock size (1 << BM_DATA_BLKBITS) */

	unsigned int blkbits;		/* data blocksize on bit */
	unsigned int mapblksize;	/* mapping blocksize */
	unsigned int mapblkbits;	/* mapping blocksize on bit */
	unsigned int entrybits;		/* entry length on bit */
	unsigned int maskbits;		/* the initial bits of mask */
	unsigned int bits;			/* number of bits to decrease every time */

	unsigned int lastblksz;		/*  in byte,
									if its the last blocksize, it may not be
									same as 1 << blkbits, it needs to align
									to the bdev capacity. */
	loff_t mapblkmask;

	loff_t pos;		/* allocate pointer ,in sectsize */
	spinlock_t lock;

	loff_t root;	/* root block, default is zero */

	kmem_cache_t *bmb_cachep;
	kmem_cache_t *bpkt_cachep;

	request_queue_t *vq;
	struct gendisk *vd;
	struct block_device *vbd;
	dev_t vdev;

	char vname[BDEVNAME_SIZE];

	struct bm_sche sche;

	struct buffer_head *bh;	/* buffer head of bm primary hdr */
	struct bm_header *hdr;	/* bm hdr */

	unsigned long nfsck;

	struct
	{
		atomic_t insert[20];
		atomic_t read[20];

	} tail;
};

int
bm_map(
	struct block_mapper *bm,
	struct bm_map_pkt *pkt,
	loff_t entryblk,
	unsigned int maskbits,
	bm_mapping_fn map_op
	);

int
bm_alloc_blk(
	struct block_mapper *bm,
	unsigned int flags,
	loff_t *entry
	);

int
bm_bpkt_read(
	struct list_head *list,
	void *data
	);


void
bm_bpkt_read_fail(
	struct list_head *list,
	void *data
	);

int
bm_bpkt_insert(
	struct list_head *list,
	void *data
	);


void
bm_bpkt_insert_fail(
	struct list_head *list,
	void *data
	);

int
bm_bpkt_insert_start(
	struct block_mapper *bm,
	struct bio *b
	);

int bm_mk_rq_fn(request_queue_t *q, struct bio *b);
int bmv_mk_rq_fn(request_queue_t *q, struct bio *b);

#ifdef __BM_SYNC_BH_WRITEBACK__
void bm_sync_bh_writeback(struct buffer_head *bh);
#endif

#endif

