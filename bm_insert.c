#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>
#include <linux/wait.h>

#include "mapper.h"
#include "sche.h"

/*	bm_mapping_insert,
	bm_map call-back routine,

	return value:
	0, finish,  if blocknr is contained in the vault, the resolved address in return
	1, continue,mapblock, recursively continue resolving current blocknr.
	-1, fail,	blocknr resolving failed. */


static int
bm_mapping_insert(
	struct block_mapper *bm,	/* block_mapper */
	loff_t entryblk,			/* bh's blocknr */
	struct buffer_head *bh,		/* buffer_head, bh is already locked */
	unsigned long ndx,			/* index of which entry within bh to parse */
	unsigned int flags,			/* flags, if bit 0 is set, datablock */
	struct bm_map_pkt *pkt,		/* generic bm_map packet */
	loff_t *nextblk				/* if mapblock, ((loff_t *)bh->data)[ndx] */
	)
{
	int retval;
	loff_t *entry;

	struct buffer_head *new_bh;

__repeat:

	entry = ((loff_t *)bh->b_data) + ndx;

	if(! test_bit(BM_FG_VALID, (unsigned long *)entry))
	{
		/* entry is not valid */

		if(test_and_set_bit(BM_FG_BUSY, (unsigned long *)entry))
		{
			/*  BM_FG_BUSY is set, someone else
				is already working on it.

				We need to unlock bh, wait some time,
				lock bh back, and restart again. */

			printk("bm_mapping_insert race\n");

			unlock_buffer(bh);
			schedule();
			lock_buffer(bh);

			goto __repeat;
		}

		/*  BM_FG_BUSY is not set, we get exclusive control
			of it, will allocate block for it. */

		retval = bm_alloc_blk(bm, flags, entry);

		if(retval)
		{
			/* bm_alloc_blk failed */

			retval = -1;
			goto __out;
		}

		if(flags & 1)
		{
			/*	we just allocate a datablock, finish resolving */

			pkt->addr[pkt->apos].blocknr	= pkt->start_blknr + pkt->bpos;
			pkt->addr[pkt->apos].entryblk	= entryblk;
			pkt->addr[pkt->apos].ndx		= ndx;
			pkt->addr[pkt->apos].entry		= *entry >> BM_ADDRESS_SHIFT;
			pkt->addr[pkt->apos].flags		&= ~1;

			pkt->apos ++;
			pkt->bpos ++;

			clear_bit(BM_FG_BUSY, (unsigned long *)entry);
			set_bit(BM_FG_VALID, (unsigned long *)entry);

			mark_buffer_dirty(bh);
			set_buffer_uptodate(bh);

		#ifdef __BM_SYNC_BH_WRITEBACK

			/* 	for datablock, we do bh writeback
				when setting BM_FG_READY */

		#endif

			retval = 0;
			goto __out;
		}

		/* 	we just allocate a mapping block,
			will initialize it. */

		new_bh = __getblk(bm->st_bdev, *entry >> BM_ADDRESS_SHIFT, bm->mapblksize);

		if(! new_bh)
		{
			/* __getblk failed */

			retval = -1;
			goto __out;
		}

		/*  Here, we unlock bh and lock new_bh to prevent
			possible deadlock, As holding one lock (bh) and
			asking for another lock (new_bh) is always not
			recommended. */

		unlock_buffer(bh);

		lock_buffer(new_bh);

		/*	zero new_bh, set it dirty and uptodate */

		memset(new_bh->b_data, 0, bm->mapblksize);
		mark_buffer_dirty(new_bh);
		set_buffer_uptodate(new_bh);

	#ifdef __BM_SYNC_BH_WRITEBACK__
		bm_sync_bh_writeback(new_bh);
	#endif

		unlock_buffer(new_bh);
		lock_buffer(bh);
		__brelse(new_bh);

		clear_bit(BM_FG_BUSY, (unsigned long *)entry);
		set_bit(BM_FG_VALID, (unsigned long *)entry);

		/* [7], set BM_FG_MAP */
		set_bit(BM_FG_MAP, (unsigned long *)entry);

		mark_buffer_dirty(bh);
		set_buffer_uptodate(bh);

	#ifdef __BM_SYNC_BH_WRITEBACK__
		bm_sync_bh_writeback(bh);
	#endif

	}

	else if( flags & 1 &&
			 (!test_bit(BM_FG_READY, (unsigned long *)entry)))
	{
		/* 	for datablock, BM_FG_VALID is set
			but BM_FG_READY has not been set. */

		pkt->addr[pkt->apos].blocknr	= pkt->start_blknr + pkt->bpos;
		pkt->addr[pkt->apos].entryblk	= entryblk;
		pkt->addr[pkt->apos].ndx		= ndx;
		pkt->addr[pkt->apos].entry		= *entry >> BM_ADDRESS_SHIFT;
		pkt->addr[pkt->apos].flags		|= 1;

		pkt->apos ++;
		pkt->bpos ++;

		retval = 0;
		goto __out;

	}

	if(flags & 1)
	{
		/* 	datablock has already been
			allocated, move on to the
			next blocknr.  */

		pkt->bpos++;

		retval = 0;
	}
	else
	{
		/* mapping block, should continue resolving */

		*nextblk = *entry >> BM_ADDRESS_SHIFT;
		retval = 1;
	}

__out:
	return retval;
}


/*	end_bm_bpkt_insert_resume,
	A helper routine,

	which determines which dispather
	bpkt will go to. */

static void
end_bm_bpkt_insert_resume(
	struct bm_bio_pkt *bpkt,
	struct block_mapper *bm
	)
{
	struct bm_sche *sche;
	struct bm_dsp *dsp;
	struct bm_bio *bmb;
	int bio_lvl;

	sche = &bm->sche;
	dsp = sche->dsp;

	bmb = bpkt->b[bpkt->pos];

	bio_lvl = bmb->insert.bio_lvl;

	if(bmb->insert.bio_lvl < BM_BPKT_SLOW_READ_MAX)
	{
		bmb->insert.bio_lvl ++;
	}

	bm_add_dsp(&bpkt->list, dsp + bio_lvl, sche);

	return;
}

/*	bio completion routine,
	bpkt->bm, bmb->insert.slow_insert
	need to be setup. */

static int
end_bm_bpkt_insert_clone_bio(
	struct bio *b,
	unsigned int len,
	int err
	)
{
	struct block_mapper *bm;
	struct bm_sche *sche;

	struct bm_bio_pkt *bpkt;
	struct bm_bio *bmb;

	bpkt = b->bi_private;
	bm = bpkt->bm;
	sche = &bm->sche;

	bmb = bpkt->b[bpkt->pos];

	bmb->insert.io_len = len;
	bmb->insert.io_err = err;

	end_bm_bpkt_insert_resume(bpkt, bm);

	return 0;
}

int
bm_bpkt_insert(
	struct list_head *list,
	void *data
	)
{
	int retval;

	struct bm_sche *sche;
	struct block_mapper *bm;
	struct bm_bio_pkt *bpkt;
	struct bm_map_pkt *mpkt;
	struct bm_bio *bmb;
	struct bm_addr *bma;
	loff_t *entry;

	struct bio *b;

	unsigned long nvec;
	struct bio_vec *vec;

	unsigned long src_length;
	sector_t dst_blknr, src_blknr, src_offset;

	unsigned int page_offset, page_len;
	unsigned int bv_offset, bv_len;

	struct buffer_head *bh;

	BUG_ON(! data);

	sche = data;
	bm = container_of(sche, struct block_mapper, sche);

	bpkt = container_of(list, struct bm_bio_pkt, list);
	mpkt = &bpkt->mpkt;

	bmb = bpkt->b[bpkt->pos];
	BUG_ON(! bmb);

	if(bpkt->flags & 0x10)
	{
		/* re-entry, wait for BM_FG_READY */

		bpkt->flags &= ~0x10;

		bma = mpkt->addr + mpkt->andx;
		goto __read_bma;
	}

#ifdef __BM_SYNC_BH_WRITEBACK__

	/* [7], async write read-out data.*/

	if(bpkt->flags & 0x20)
	{
		/* re-entry, wait to write read-out data. */

		bpkt->flags &= ~0x20;

		bma = mpkt->addr + mpkt->andx;
		b = bmb->insert.rbio;

		retval = bmb->insert.io_err;

		goto __put_bh;
	}

#endif

	if(!(bpkt->flags & 4))
	{
		/* re-entry, read data for write bio */

		bma = mpkt->addr + mpkt->andx;

		b = bmb->insert.rbio;

		/* retval will be checked after put_bh */

		retval = bmb->insert.io_err;


	#ifdef __BM_SYNC_BH_WRITEBACK__

		/* [7] async write bio */

		if(retval)
		{
			goto __put_bh;
		}
		goto __async_write_bio;

	#else
		goto __put_bh;
	#endif

	}

	bpkt->flags &= ~4;

__remap:

	mpkt->apos = 0;

	retval = bm_map(
				bm,
				mpkt,
				bm->root >> BM_ADDRESS_SHIFT,
				bm->maskbits,
				bm_mapping_insert
				);

	if(retval == -1)
	{
		/* fail */

		printk("bm_bpkt_insert 0x%p bm_map failed\n", list);
		goto __return;
	}

	if(retval == 1)
	{
		BUG_ON(! mpkt->apos);
		bpkt->flags |= 2;
	}
	else
	{
		bpkt->flags &= ~2;
	}

	if(! mpkt->apos)
	{
		retval = 0;
		goto __cleanup;
	}

	mpkt->andx = 0;
	bma = mpkt->addr;

__compare:

	if(bmb->end_blknr >= bma->blocknr)
	{
		goto __read_bma;
	}

	bm->old_mk_rq_fn(bm->queue, bmb->b);
	kmem_cache_free(bm->bmb_cachep, bmb);

	bpkt->pos++;
	bmb = bpkt->b[bpkt->pos];

	BUG_ON(! bmb);

	goto __compare;

__read_bma:

	if(bma->flags & 1)
	{
		/* need to wait for BM_FG_READY to set */

		bh = __bread(bm->st_bdev, bma->entryblk, bm->mapblksize);

		if(! bh)
		{
			printk("bm_bpkt_insert __bread failed");
			retval = -ENOMEM;

			goto __return;
		}

		lock_buffer(bh);
		entry = ((loff_t *)bh->b_data) + bma->ndx;

		if(test_bit(BM_FG_READY, (unsigned long *)entry))
		{
			goto __unlock_bh;
		}

		/* BM_FG_READY hasnt been setup, will check later. */

		unlock_buffer(bh);
		__brelse(bh);

		bmb->insert.bio_lvl = BM_BPKT_SLOW_INSERT_MIN;

		bpkt->flags |= 0x10;	/* setup read_bma flags*/

		schedule();
		end_bm_bpkt_insert_resume(bpkt, bm);

		retval = 0;
		goto __return;
	}

	/* read bma->blocknr */

	dst_blknr = bma->entry;
	src_blknr = bma->blocknr;

	if(src_blknr == bm->size - 1)
	{
		/* the last block */

		src_length = bm->lastblksz;
	}
	else
	{
		src_length = 1 << bm->blkbits;
	}

	src_offset = src_blknr << (bm->blkbits - 9);

	/* 	Here, we can see a not-so-good implementation,
		which however, will get improved shortly.... */

	if(bm->mapblkbits < bm->blkbits)
	{
		nvec = 1 << (bm->blkbits - bm->mapblkbits);
	}
	else
	{
		nvec = 1;
	}

	/*	async bio read,

		. alloc bio according to nvec,
		. get mapping pages, we don't explicitly
		  allocate any page.
		. setup bio completion routine
		. submit bio. */

	b = bio_alloc(GFP_NOIO, nvec);
	if(! b)
	{
		retval = -ENOMEM;
		goto __return;
	}

	b->bi_sector = src_offset;
	b->bi_bdev = bm->hook;

	while(1)
	{
		bmb->insert.b_size = b->bi_size;

		if(! src_length)
		{
			break;
		}

		bh = __getblk(bm->st_bdev, dst_blknr, bm->mapblksize);
		if(! bh)
		{
			retval = -ENOMEM;
			goto __put_bh;
		}

		/*  The reason we here dont lock buffer is that
			we have the assumption that the current
			execution is the first access of buffer, so it
			has exclusive control over bh.

			We use BM_FG_READY to simulate sync access.

			Later on, when BM_FG_READY is set, and we read
			buffer, we may need to have some actual sync
			mechanism. */

		get_bh(bh);

		page_len = (src_length
			<= bm->mapblksize) ? src_length : bm->mapblksize;

		page_offset = bh_offset(bh);

		retval = bio_add_page(b, bh->b_page, page_len, page_offset);
		if(! retval)
		{
			retval = -1;
			goto __put_bh;
		}

		src_length -= page_len;
		dst_blknr ++;
	}

	bpkt->bm = bm;

	bmb->insert.rbio = b;

#ifdef __BM_SYNC_BH_WRITEBACK__

	/* 	[7] async_write_bio.

		We here use bio_clone to create one more bio for
		later write. One thing needs notice is that "b" is
		setup according to hook->queue, which means b->bi_io_vec
		may have been merged by hook->queue when we call bio_add_page,

		By simply redirect bio from hook to st_bdev with no change
		accordingly to bi_io_vec, we may have some potential problems.

		A better solution is to re-do bio_add_page for wbio.	*/

	bmb->insert.wbio = bio_clone(b, GFP_NOIO);

	if(! bmb->insert.wbio)
	{
		retval = -ENOMEM;
		goto __put_bh;
	}

	bmb->insert.wbio->bi_sector	= bma->entry << (bm->mapblkbits - 9);
	bmb->insert.wbio->bi_bdev  	= bm->st_bdev;

#endif

	bmb->insert.bio_lvl = BM_BPKT_SLOW_INSERT_MIN;

	b->bi_private = bpkt;
	b->bi_end_io = end_bm_bpkt_insert_clone_bio;

	submit_bio(READ, b);

	retval = 0;
	goto __return;

#ifdef __BM_SYNC_BH_WRITEBACK__

	/* 	[7] async_write_bio. */

__async_write_bio:

	bmb->insert.wbio->bi_private	= bpkt;
	bmb->insert.wbio->bi_end_io		= end_bm_bpkt_insert_clone_bio;

	/*	setup flags to 0x20 for async back. */

	bpkt->flags |= 0x20;

	submit_bio(WRITE, bmb->insert.wbio);

	retval = 0;
	goto __return;

#endif

__put_bh:

	vec = b->bi_io_vec;

	while(bmb->insert.b_size)
	{
		bh = page_buffers(vec->bv_page);

		bv_offset = vec->bv_offset;
		bv_len = vec->bv_len;

		while(bv_offset)
		{
			bh = bh->b_this_page;

			/*	bv_offset -= bm->mapblksize is not safe.

				we need to memorize that bv_offset
				tells us which buffer bead inside
				the page is the first buffer head.
				if bm->blkbits is no larger than
				bm->mapblkbits, bv_offset is always
				zero. */

			bv_offset -= bm->mapblksize;
		}

		while(bv_len)
		{

			if(! retval)
			{

			#ifndef __BM_SYNC_BH_WRITEBACK__

				/*  by simply mark bh dirty, bh will be
					flushed to disk automatically by kernel
					later some. we dont need to do anything.

					However, snapshot image wont have
					recoverability. */

				mark_buffer_dirty(bh);

			#endif

				/*	For every successful bh io,
					we need to set uptodate. */

				set_buffer_uptodate(bh);
			}

			put_bh(bh);
			__brelse(bh);

			//bv_len -= bm->mapblksize;

			/*	It is possible when bv_len left in vec
				is less than mapblksize,

				One example is that bm->blkbits
				< bm->mapblkbits	*/


			if(bv_len > bm->mapblksize)
			{
				bv_len -= bm->mapblksize;
			}
			else
			{
				bv_len = 0;
			}

			bh = bh->b_this_page;
		}

		bmb->insert.b_size -= vec->bv_len;
		vec ++;
	}

#ifdef __BM_SYNC_BH_WRITEBACK__
	bio_put(bmb->insert.wbio);
#endif

	bio_put(b);

	if(retval)
	{
		printk("bm_bpkt_insert read_bio failed\n");
		goto __return;
	}

	/* turn on BM_FG_READY */

	bh = __bread(bm->st_bdev, bma->entryblk, bm->mapblksize);

	if(! bh)
	{
		printk("bm_bpkt_insert __bread failed");
		retval = -ENOMEM;

		goto __return;
	}

	lock_buffer(bh);
	entry = ((loff_t *)bh->b_data) + bma->ndx;

	set_bit(BM_FG_READY, (unsigned long *)entry);
	mark_buffer_dirty(bh);
	set_buffer_uptodate(bh);

#ifdef __BM_SYNC_BH_WRITEBACK__

	bm_sync_bh_writeback(bh);

#endif

__unlock_bh:

	unlock_buffer(bh);
	__brelse(bh);

	mpkt->andx ++;

	if(mpkt->andx != mpkt->apos)
	{
		bma ++;
		goto __compare;
	}

	if(bpkt->flags & 2)
	{
		goto __remap;
	}

__cleanup:

	do
	{
		bm->old_mk_rq_fn(bm->queue, bmb->b);
		kmem_cache_free(bm->bmb_cachep, bmb);

		bpkt->pos ++;

		if(bpkt->pos == bpkt->bcnt)
		{
			break;
		}

		bmb = bpkt->b[bpkt->pos];

		BUG_ON(! bmb);
	}
	while(1);

	kmem_cache_free(bm->bpkt_cachep, bpkt);

	/* decrease outstanding scheduler packet */

	spin_lock_irq(&bm->sche.wlock);
	atomic_dec(&bm->sche.total);
	spin_unlock_irq(&bm->sche.wlock);

	retval = 0;

__return:
	return retval;
}

void
bm_bpkt_insert_fail(
	struct list_head *list,
	void *data
	)
{
	struct bm_sche *sche;
	struct block_mapper *bm;
	struct bm_bio_pkt *bpkt;
	struct bm_bio *bmb;

	BUG_ON(! list);
	BUG_ON(! data);

	printk("bm_bpkt_insert_fail\n");

	sche = data;

	bm = container_of(sche, struct block_mapper, sche);
	bpkt = container_of(list, struct bm_bio_pkt, list);

	while(bpkt->b[bpkt->pos])
	{
		bmb = bpkt->b[bpkt->pos];

		bm->old_mk_rq_fn(bm->queue, bmb->b);
		kmem_cache_free(bm->bmb_cachep, bmb);

		bpkt->pos ++;
	}

	/* decrease outstanding scheduler packet */

	spin_lock_irq(&sche->wlock);
	atomic_dec(&sche->total);
	spin_unlock_irq(&sche->wlock);

	kmem_cache_free(bm->bpkt_cachep, bpkt);

	return;
}

int
bm_bpkt_insert_start(
	struct block_mapper *bm,
	struct bio *b
	)
{
	int retval;

	struct bm_dsp *dsp;
	struct bm_sche *sche;
	struct bm_bio_pkt *bpkt;
	struct bm_bio *bmb;

	struct list_head *list;

	sector_t start_blocknr, end_blocknr;

	sche = &bm->sche;
	dsp = sche->dsp + BM_BPKT_INSERT;

	start_blocknr = (b->bi_sector - bm->start) >> (bm->blkbits - 9);
	end_blocknr = ((b->bi_sector - bm->start) + (b->bi_size >> 9) - 1) >> (bm->blkbits - 9);

	bmb = kmem_cache_alloc(bm->bmb_cachep, GFP_KERNEL);
	if(! bmb)
	{
		retval = -ENOMEM;
		goto __return;
	}

	memset(bmb, 0, sizeof(*bmb));

	bmb->start_blknr	= start_blocknr;
	bmb->end_blknr		= end_blocknr;
	bmb->b 				= b;

	spin_lock_irq(&dsp->lock);

	if(! list_empty(&dsp->head))
	{
		list = dsp->head.prev;
		bpkt = container_of(list, struct bm_bio_pkt, list);

		if(	bpkt->mpkt.end_blknr == bmb->start_blknr &&
			bpkt->bcnt < BM_MAP_BIO_MAX )
		{
			bpkt->b[bpkt->bcnt] = bmb;
			bpkt->bcnt ++;

			bpkt->mpkt.end_blknr = bmb->end_blknr;

			spin_unlock_irq(&dsp->lock);

			retval = 0;
			goto __return;
		}
	}

	spin_unlock_irq(&dsp->lock);

	bpkt = kmem_cache_alloc(bm->bpkt_cachep, GFP_KERNEL);

	if(! bpkt)
	{
		retval = -ENOMEM;
		goto __free_bmb;
	}

	memset(bpkt, 0, sizeof(*bpkt));
	memset(bpkt->b, 0, BM_MAP_BIO_MAX * sizeof(struct bm_bio *));

	INIT_LIST_HEAD(&bpkt->list);

	bpkt->mpkt.start_blknr		= start_blocknr;
	bpkt->mpkt.end_blknr		= end_blocknr;
	bpkt->mpkt.bpos				= 0;
	bpkt->mpkt.apos				= 0;

	bpkt->b[0] 	= bmb;
	bpkt->pos	= 0;
	bpkt->bcnt	= 1;
	bpkt->flags	= 4;

	spin_lock_irq(&sche->wlock);
	atomic_inc(&sche->total);
	spin_unlock_irq(&sche->wlock);

	bm_add_dsp(&bpkt->list, dsp, sche);

	return 0;

__free_bmb:
	kmem_cache_free(bm->bmb_cachep, bmb);

__return:
	return retval;
}
