#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>
#include <linux/wait.h>

#include "mapper.h"
#include "sche.h"

#ifdef __BM_SYNC_BH_WRITEBACK__

/* [7] This is just a temporary solution for bh write back,
	we sync writeback, and always assume that writeback successes. */

static void end_bm_sync_bh_writeback(struct buffer_head *bh, int uptodate)
{
	complete((struct completion *)bh->b_private);
	return;
}

/* bh needs to be locked, and marked dirty & uptodate by caller. */

void bm_sync_bh_writeback(struct buffer_head *bh)
{
	struct completion event;
	init_completion(&event);

	bh->b_private = &event;
	bh->b_end_io = end_bm_sync_bh_writeback;

	submit_bh(WRITE, bh);

	wait_for_completion(&event);
	return;
}

#endif

/*	bm_map,
	recursively blocknr resolving,

	return value:

	-1, fail;
	0, success, no blocknr left.
	1, success, blocknr left */

int
bm_map(
	struct block_mapper *bm,	/* block_mapper */
	struct bm_map_pkt *pkt,		/* generic mapping packet */
	loff_t entryblk,			/* the blocknr where to resolve */
	unsigned int maskbits,		/* maskbits, related to blocknr resolving */
	bm_mapping_fn map_op		/* specific to the mapping-related operation */
	)
{
	int retval;
	struct buffer_head *bh;
	unsigned long start_ndx, end_ndx;
	loff_t nextblk;

	BUG_ON(pkt->start_blknr > pkt->end_blknr);
	BUG_ON(pkt->start_blknr + pkt->bpos > pkt->end_blknr + 1);
	BUG_ON(pkt->apos > BM_MAP_BLK_MAX);

	start_ndx = ((pkt->start_blknr + pkt->bpos) >> maskbits) & ((1 << bm->bits) - 1);
	end_ndx = ((pkt->end_blknr >> maskbits) & ((1 << bm->bits) - 1));

	if( end_ndx <= start_ndx &&
		((pkt->start_blknr + pkt->bpos) >> maskbits) < (pkt->end_blknr >> maskbits))
	{
		/* overflow */

		end_ndx = 1 << bm->bits;
	}
	else
	{
		end_ndx ++;
	}

	bh = __bread(bm->st_bdev, entryblk, bm->mapblksize);
	if(! bh)
	{
		printk("__bread fail\n");
		retval = -1;
		goto __return;
	}

	while(start_ndx < end_ndx)
	{
		if(pkt->apos == BM_MAP_BLK_MAX)
		{
			/* reaches the end of bm_addr array, return 1 */

			retval = 1;
			goto __bh_relse;
		}

		lock_buffer(bh);
		retval = map_op(bm, entryblk, bh, start_ndx, maskbits == 0, pkt, &nextblk);
		unlock_buffer(bh);

		if(retval == -1)
		{
			/* fail */

			retval = -1;
			goto __bh_relse;
		}

		if(retval == 1)
		{
			/* 	recursively continue,
				nextblk is the next entryblk to resolve */

			retval = bm_map( bm, pkt, nextblk, maskbits - bm->bits, map_op );

			if(retval == -1)
			{
				/* fail */

				retval = -1;
				goto __bh_relse;
			}

			if(retval == 1)
			{
				/* recursively reaches the end of bm_addr array, return 1 */

				goto __bh_relse;
			}
		}

		/* 	retval == 0, finish.

			Only when retval == 0 will pkt->apos and pkt->bpos increase.

			pkt->bpos is checked by "start_ndx < end_ndx",
			pkt->apos is checked after pkt->bpos by "pkt->apos == BM_MAP_BLK_MAX" */

		start_ndx ++;
	}

	retval = 0;

__bh_relse:
	__brelse(bh);

__return:
	return retval;
}


int
bm_alloc_blk(
	struct block_mapper *bm,
	unsigned int flags,	/* 1 if datablock */
	loff_t *entry
	)
{
	loff_t cur_pos;

	*entry |= ((bm->pos >> (bm->mapblkbits - 9)) << BM_ADDRESS_SHIFT);

	spin_lock(&bm->lock);
	if(flags & 1)
	{
		/* datablock */

		bm->pos += (1 << (bm->blkbits - 9));
	}
	else
	{
		/* mapping block */

		bm->pos += (1 << (bm->mapblkbits - 9));
	}

	bm->pos = (bm->pos + bm->mapblkmask) & ~(bm->mapblkmask);
	cur_pos = bm->pos;

	spin_unlock(&bm->lock);

	lock_buffer(bm->bh);

	bm->hdr->h_pos = cpu_to_le64(cur_pos);

	mark_buffer_dirty(bm->bh);
	set_buffer_uptodate(bm->bh);

#ifdef __BM_SYNC_BH_WRITEBACK__
	bm_sync_bh_writeback(bm->bh);
#endif

	unlock_buffer(bm->bh);

	return 0;
}

extern struct block_mapper bm;

int bm_mk_rq_fn(request_queue_t *q, struct bio *b)
{
	int retval;

	/*  Before we move on, we need to check if bio is meant
		for bm->hook, there could be other bdev sharing the
		same gendisk. */

	if( b->bi_sector < bm.start ||
		b->bi_sector - bm.start + (b->bi_size >> 9) > bm.capacity)
	{
		/*  bio is for other block device which is
			inside the same gendisk, send bio to
			old_mk_rq_fn directly. */

		goto __old_mk_rq_fn;
	}

	if(!(b->bi_rw & WRITE))
	{
		/*	we filter only writes, passthru read rqst */

		goto __old_mk_rq_fn;
	}

	retval = bm_bpkt_insert_start(&bm, b);
	if(! retval)
	{
		goto __return;
	}

__old_mk_rq_fn:
	retval = bm.old_mk_rq_fn(bm.queue, b);

__return:
	return retval;
}

int bmv_mk_rq_fn(request_queue_t *q, struct bio *b)
{
	int retval;
	unsigned int b_size;
	struct bm_bio_pkt *bpkt;
	struct bm_bio *bmb;

	int ndx;

	sector_t start_blocknr, end_blocknr;

	if(b->bi_rw & WRITE)
	{
		b_size = b->bi_size;
		retval = 0;
		goto __end_bio;
	}

	bpkt = kmem_cache_alloc(bm.bpkt_cachep, GFP_KERNEL);
	if(! bpkt)
	{
		printk("bmv_mk_rq_fn bpkt alloc failed\n");

		b_size = 0;
		retval = -ENOMEM;
		goto __end_bio;
	}

	bmb = kmem_cache_alloc(bm.bmb_cachep, GFP_KERNEL);
	if(! bmb)
	{
		printk("bmv_mk_rq_fn bmb alloc failed\n");

		b_size = 0;
		retval = -ENOMEM;
		goto __bpkt_free;
	}

	/* 	start_block and end_block are blocknr of the
		first and last block covered by bio,

		we here convert sectsize to blocksize. */

	start_blocknr = b->bi_sector >> (bm.blkbits - 9);
	end_blocknr = (b->bi_sector + (b->bi_size >> 9) - 1) >> (bm.blkbits - 9);

	memset(bpkt, 0, sizeof(*bpkt));
	memset(bmb, 0, sizeof(*bmb));

	bmb->start_blknr 	= start_blocknr;
	bmb->end_blknr 		= end_blocknr;

	bmb->b 				= b;

	bmb->sector			= b->bi_sector;
	bmb->size			= b->bi_size;

	bmb->vcnt			= b->bi_vcnt;
	bmb->vec 			= b->bi_io_vec;

	bmb->flags			= b->bi_flags;
	bmb->rw				= b->bi_rw;

	bmb->data			= b->bi_private;
	bmb->completion 	= b->bi_end_io;

	/* initialize bmb->read */

	bmb->read.cur_blknr		= start_blocknr;
	bmb->read.cur_blkoffset = (b->bi_sector << 9) & ((1 << bm.blkbits) - 1);
	bmb->read.vec_idx		= 0;
	bmb->read.vec_offset	= 0;
	bmb->read.b_size		= b->bi_size;
	bmb->read.src_bytes		= 0;
	bmb->read.bh_lvl		= BM_BPKT_SLOW_READ_MIN;

	INIT_LIST_HEAD(&bpkt->list);

	bpkt->mpkt.start_blknr 	= start_blocknr;
	bpkt->mpkt.end_blknr	= end_blocknr;
	bpkt->mpkt.bpos 		= 0;
	bpkt->mpkt.apos 		= 0;
	bpkt->mpkt.andx			= 0;

	memset(bpkt->b, 0, BM_MAP_BIO_MAX * sizeof(struct bm_bio *));

	bpkt->b[0] = bmb;
	bpkt->pos = 0;
	bpkt->flags = 4;

	ndx = bpkt->mpkt.end_blknr - bpkt->mpkt.start_blknr;
	if(ndx > 20)
	{
		ndx = 20;
	}

	atomic_inc(bm.tail.read + ndx);

	/* increase outstanding scheduler packet */

	spin_lock_irq(&bm.sche.wlock);
	atomic_inc(&bm.sche.total);
	spin_unlock_irq(&bm.sche.wlock);

	bm_add_dsp(&bpkt->list, bm.sche.dsp + BM_BPKT_READ, &bm.sche);

	goto __return;

__bpkt_free:
	kmem_cache_free(bm.bpkt_cachep, bpkt);

__end_bio:
	bio_endio(b, b_size, retval);

__return:
	return 0;
}


