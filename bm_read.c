#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>
#include <linux/wait.h>

#include "mapper.h"
#include "sche.h"


/*	bm_mapping_read,
	bm_map call-back routine,

	return value:
	0, finish,  if blocknr is contained in the vault, the resolved address in return
	1, continue,mapblock, recursively continue resolving current blocknr.
	-1, fail,	blocknr resolving failed. */

static int
bm_mapping_read(
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

	entry = ((loff_t *)bh->b_data) + ndx;

	if(! test_bit(BM_FG_VALID, (unsigned long *)entry))
	{
		/* 	entry value is not valid, stop the current
			resolving and move on to the next one. */

		pkt->bpos ++;
		retval = 0;
		goto __return;
	}

	if(!(flags & 1))
	{
		/* mapping block, continue resolving */

		*nextblk = *entry >> BM_ADDRESS_SHIFT;
		retval = 1;
		goto __return;
	}

	if(!test_bit(BM_FG_READY, (unsigned long *)entry))
	{
		/* 	datablock, copy-on-write hasnt finisihed.
			stop the current resolving and move on
			to the next one. */

		pkt->bpos ++;
		retval = 0;
		goto __return;
	}

	/* datablock and BM_FG_READY is set. */

	pkt->addr[pkt->apos].blocknr	= pkt->start_blknr + pkt->bpos;
	pkt->addr[pkt->apos].entryblk	= entryblk;
	pkt->addr[pkt->apos].ndx		= ndx;
	pkt->addr[pkt->apos].entry		= *entry >> BM_ADDRESS_SHIFT;

	pkt->apos ++;
	pkt->bpos ++;

	retval = 0;

__return:
	return retval;
}

/*	end_bm_bpkt_read_resume,
	A helper routine,

	which determines which dispather
	bpkt will go to. */

static void
end_bm_bpkt_read_resume(
	struct bm_bio_pkt *bpkt,
	struct block_mapper *bm
	)
{
	struct bm_sche *sche;
	struct bm_dsp *dsp;
	struct bm_bio *bmb;
	int bh_lvl;

	sche = &bm->sche;
	dsp = sche->dsp;

	bmb = bpkt->b[bpkt->pos];

	bh_lvl = bmb->read.bh_lvl;

	if(bmb->read.bh_lvl < BM_BPKT_SLOW_READ_MAX)
	{
		bmb->read.bh_lvl ++;
	}

	bm_add_dsp(&bpkt->list, dsp + bh_lvl, sche);

	return;
}

static int end_bm_bpkt_read_bio(struct bio *b, unsigned int len, int err)
{
	struct bm_bio_pkt *bpkt = b->bi_private;
	struct bm_bio *bmb = bpkt->b[0];

	INIT_LIST_HEAD(&bpkt->list);

	b->bi_io_vec->bv_offset 	-= bmb->read.vec_offset;
	b->bi_io_vec->bv_len 		+= bmb->read.vec_offset;

	b->bi_io_vec -= bmb->read.vec_idx;
	b->bi_vcnt	+= bmb->read.vec_idx;

	/*  move bpkt to the appropriate
		slow_read according to bmb->read.bh_lvl,
		and increase bmb->read.bh_lvl correspondingly. */

	end_bm_bpkt_read_resume(bpkt, bpkt->bm);

	return 0;
}

#ifdef __BM_PRE_READ__
static int end_bm_bpkt_pre_read_bh( struct bio *b, unsigned int len, int err)
{
	struct bm_bio_pkt *bpkt;
	struct bm_bio *bmb;

	bpkt = b->bi_private;
	bmb = bpkt->b[bpkt->pos];

	bmb->read.io_len = len;
	bmb->read.io_err = err;

	end_bm_bpkt_read_resume(bpkt, bpkt->bm);

	return 0;
}

#else	/* no pre-read */
static void
end_bm_bpkt_read_bh(
	struct buffer_head *bh,
	int uptodate
	)
{
	struct bm_bio_pkt *bpkt;
	struct bm_bio *bmb;

	bpkt = bh->b_private;
	bmb = bpkt->b[bpkt->pos];

	/* 	bmb->read.bh should have
		already been setup to bh. */

	bmb->read.uptodate = uptodate;

	/*  move bpkt to the appropriate
		slow_read according to bmb->read.bh_lvl,
		and increase bmb->read.bh_lvl correspondingly. */

	end_bm_bpkt_read_resume(bpkt, bpkt->bm);

	return;
}
#endif




static int
bm_bpkt_end_bio(
	struct bm_bio *bmb,
	int flags,
	struct block_mapper *bm
	)
{
	int retval;

	struct bio *b;

	b = bmb->b;

	if(flags == 1)
	{
		b->bi_private 	= bmb->data;
		b->bi_end_io	= bmb->completion;

		b->bi_sector	= bmb->sector;
		b->bi_size		= bmb->size;
		b->bi_io_vec	= bmb->vec;
		b->bi_vcnt		= bmb->vcnt;

		bio_endio(b, b->bi_size, 0);
		kmem_cache_free(bm->bmb_cachep, bmb);

		retval = 0;
	}
	else
	{
		struct bm_bio_pkt *new_bpkt;

		new_bpkt = kmem_cache_alloc(bm->bpkt_cachep, GFP_KERNEL);

		if(! new_bpkt)
		{
			retval = -ENOMEM;
			goto __return;
		}

		memset(new_bpkt, 0, sizeof(* new_bpkt));

		b->bi_sector 		= (bmb->read.cur_blknr <<
						(bm->blkbits - 9)) + (bmb->read.cur_blkoffset >> 9);

		b->bi_size	 		= bmb->read.b_size;

		b->bi_io_vec 		+= bmb->read.vec_idx;
		b->bi_vcnt			-= bmb->read.vec_idx;

		b->bi_io_vec->bv_offset 	+= bmb->read.vec_offset;
		b->bi_io_vec->bv_len 		-= bmb->read.vec_offset;

		b->bi_private		= new_bpkt;
		b->bi_end_io		= end_bm_bpkt_read_bio;

		new_bpkt->mpkt.start_blknr	= bmb->read.cur_blknr;
		new_bpkt->mpkt.end_blknr	= bmb->end_blknr;
		new_bpkt->mpkt.bpos			= 0;
		new_bpkt->mpkt.apos			= 0;

		new_bpkt->b[0]		= bmb;
		new_bpkt->pos		= 0;
		new_bpkt->bm		= bm;
		new_bpkt->flags 	= 5;

		b->bi_bdev			= bm->contains;
		b->bi_sector		+= bm->start;

		/* increase outstanding scheduler packet */

		spin_lock_irq(&bm->sche.wlock);
		atomic_inc(&bm->sche.total);
		spin_unlock_irq(&bm->sche.wlock);

		bm->old_mk_rq_fn(bm->queue, b);

		retval = 0;
	}

__return:
	return retval;
}


/*	bm_bpkt_read_bh,
	A helper routine, copy data from
	bh to bio.

	get_bh and lock_buffer has already
	been called on bh.

	Caller should call unlock_buffer,
	put_bh, and __brelse.	*/

static void
bm_bpkt_read_bh(
	struct bm_bio *bmb,
	struct buffer_head *bh,
	struct block_mapper *bm
	)
{
	struct bio_vec *vec;
	unsigned long left, bytes;
	char *src, *dst;

	left = bm->mapblksize - bmb->read.bh_offset;
	if(left > bmb->read.src_bytes)
	{
		left = bmb->read.src_bytes;
	}

	src = ((char *)bh->b_data) + bmb->read.bh_offset;

	while(left)
	{
		vec = bmb->b->bi_io_vec + bmb->read.vec_idx;
		bytes = vec->bv_len - bmb->read.vec_offset;

		if(bytes > left)
		{
			bytes = left;
		}

		dst = kmap_atomic(vec->bv_page, KM_USER0)
				+ bmb->read.vec_offset + vec->bv_offset;

		memcpy(dst, src, bytes);

		kunmap_atomic(vec->bv_page, KM_USER0);

		bmb->read.src_bytes -= bytes;
		bmb->read.b_size -= bytes;

		/* recalculate dst */

		bmb->read.vec_offset += bytes;
		bmb->read.cur_blkoffset += bytes;

		if(bmb->read.vec_offset == vec->bv_len)
		{
			bmb->read.vec_idx ++;
			bmb->read.vec_offset = 0;
		}

		/* update src */

		src += bytes;
		bmb->read.bh_offset += bytes;

		/* decrease left */

		left -= bytes;
	}

	if(bmb->read.bh_offset == bm->mapblksize)
	{
		bmb->read.bh_offset = 0;
		bmb->read.bh_blknr ++;
	}

	return;
}

/*	bm_bpkt_read,
	dispatch routine used to handle read rqst,

	bpkt is in three possible states,
	1. to initiate the first mapping for fast bio;
	2. to initiate the first mapping for slow bio;
	3. continue for slow bh.

	In order to prioritize the bpkt rqst which involves
	slow bh read or slow bio read, there are more than
	one instance of bm_bpkt_read.

	return value,
	0, successful,
	<0, fail. */

int
bm_bpkt_read(
	struct list_head *list,	/* bpkt */
	void *data	/* block_mapper */
	)
{
	int retval;

	struct bm_sche *sche;
	struct block_mapper *bm;
	struct bm_bio_pkt *bpkt;
	struct bm_map_pkt *mpkt;
	struct bm_addr *bma;
	struct bm_bio *bmb;

	struct buffer_head *bh;

	unsigned long distance, blksz;

#ifdef __BM_PRE_READ__

	unsigned int bv_offset;
	unsigned int bv_len;
	struct bio_vec *vec;

#endif

	BUG_ON(! data);

	sche = data;
	bm = container_of(sche, struct block_mapper, sche);

	blksz = (1 << bm->blkbits);

	bpkt = container_of(list, struct bm_bio_pkt, list);
	mpkt = &bpkt->mpkt;

	bmb = bpkt->b[bpkt->pos];
	BUG_ON(! bmb);

	if(bpkt->flags & 8)
	{
		/* trylock bh again */

		bma = mpkt->addr + mpkt->andx;

		bh = bmb->read.bh;
		BUG_ON(! bh);

		bpkt->flags &= ~8;

		goto __trylock_bh;
	}

	if(!(bpkt->flags & 4))
	{

	#ifdef __BM_PRE_READ__

		struct buffer_head *__bh;
		struct bio *rbio;

		/* 	bh is initialized as NULL and will
			be setup as the first bh, the primary
			pre-read bh. */

		bma = mpkt->addr + mpkt->andx;

		bh = NULL;
		rbio = bmb->read.rbio;
		vec = rbio->bi_io_vec;

		while(bmb->read.rb_size)
		{
			__bh = page_buffers(vec->bv_page);

			bv_offset = vec->bv_offset;
			bv_len = vec->bv_len;

			while(bv_offset)
			{
				__bh = __bh->b_this_page;
				bv_offset -= bm->mapblksize;
			}

			while(bv_len)
			{
				if(! bmb->read.io_err)
				{
					/*  successful pre read, mark
						bh uptodate and dirty. */

					mark_buffer_dirty(__bh);
					set_buffer_uptodate(__bh);
				}

				if(! bh)
				{
					/*  save primary pre-read buffer,
						we postpone the release of primary
						buffer after we finish buffer reading */

					bh = __bh;
				}
				else
				{
					clear_buffer_locked(__bh);
					put_bh(__bh);
					__brelse(__bh);
				}

				if(bv_len > bm->mapblksize)
				{
					bv_len -= bm->mapblksize;
				}
				else
				{
					bv_len = 0;
				}

				__bh = __bh->b_this_page;
			}

			bmb->read.rb_size -= vec->bv_len;
			vec ++;
		}

		/* delete pre-read bio */

		bio_put(rbio);

		if(! bmb->read.io_err)
		{
			goto __continue;
		}

	#else

		bma = mpkt->addr + mpkt->andx;

		bh = bmb->read.bh;
		BUG_ON(! bh);

		/*  if bh has been successfully read,
			we continue the work left,
			if not, we return -EIO. */

		if(bmb->read.uptodate)
		{
			set_buffer_uptodate(bh);

			goto __continue;
		}

	#endif

		printk("bm_bpkt_read, 0x%p, read bh failed\n", list);
		clear_buffer_uptodate(bh);

		//unlock_buffer(bh); 05/07/2009

		clear_buffer_locked(bh);
		put_bh(bh);
		__brelse(bh);

		retval = -EIO;
		goto __return;

	}

	/* 	initiate the first mapping for
		for either fast bio or slow bio. */

	bpkt->flags &= ~4;

__remap:

	mpkt->apos = 0;

	retval = bm_map(
				bm,
				mpkt,
				bm->root >> BM_ADDRESS_SHIFT,
				bm->maskbits,
				bm_mapping_read
				);

	if(retval == -1)
	{
		printk("bm_bpkt_read 0x%p bm_map failed\n", list);
		goto __return;
	}

	if(retval == 1)
	{
		BUG_ON(!mpkt->apos);

		bpkt->flags |= 2;
	}
	else
	{
		bpkt->flags &= ~2;
	}

	if(!mpkt->apos)
	{
		retval = 0;

		goto __cleanup;
	}

	bma = mpkt->addr;
	BUG_ON(bma->blocknr < bmb->read.cur_blknr);

	mpkt->andx = 0;

__next_blknr:

	if(bmb->end_blknr < bma->blocknr)
	{
		retval = bm_bpkt_end_bio(bmb, bpkt->flags & 1, bm);

		if(retval)
		{
			goto __return;
		}

		goto __next_bmb;
	}

	if( (bmb->read.cur_blknr != bma->blocknr)
		&& !(bpkt->flags & 1))
	{
		retval = bm_bpkt_end_bio(bmb, 0, bm);

		if(retval)
		{
			goto __return;
		}

		bma ++;
		mpkt->andx ++;

		goto __next_bmb;
	}

	/* 	vec maniuplate.

		DO NOT change following code unless you
		do understand bio and bio_vec. */

	distance = bma->blocknr - bmb->read.cur_blknr;

	if(distance)
	{
		distance = ((distance - 1)
			<< bm->blkbits) + (blksz - bmb->read.cur_blkoffset);
	}

	while(distance >=
		(bmb->b->bi_io_vec[bmb->read.vec_idx].bv_len
		- bmb->read.vec_offset))
	{
		distance -=
			(bmb->b->bi_io_vec[bmb->read.vec_idx].bv_len
			- bmb->read.vec_offset);

		bmb->read.vec_idx ++;
		bmb->read.vec_offset = 0;
	}

	bmb->read.bh_blknr 	= bma->entry
		+ (bmb->read.cur_blkoffset >> bm->mapblkbits);

	bmb->read.bh_offset =
		bmb->read.cur_blkoffset & (bm->mapblksize - 1);

	bmb->read.src_bytes =
		((blksz - bmb->read.cur_blkoffset)
		<= bmb->read.b_size) ? (blksz - bmb->read.cur_blkoffset) : bmb->read.b_size;

	bmb->read.src_blknr = bma->blocknr;

__read_bh:

	/*
	printk("bm_bpkt_read bmb = 0%p, [0x%llx, 0x%llx], sector = 0x%llx, b_size = 0x%x\n",
			bmb, bmb->start_blknr, bmb->end_blknr, bmb->sector, bmb->read.b_size);

	printk("vec vcnt = %u, vec_idx = %u, vec_offset = 0x%x\n", bmb->vcnt, bmb->read.vec_idx, bmb->read.vec_offset);

	printk("vec bv_len = 0x%x, bv_offset = 0x%x\n",
		bmb->b->bi_io_vec[bmb->read.vec_idx].bv_len, bmb->b->bi_io_vec[bmb->read.vec_idx].bv_offset );

	printk("cur_blknr = 0x%llx, cur_blkoffset = 0x%x, bma->entry = 0x%llx\n",
			bmb->read.cur_blknr, (unsigned int)bmb->read.cur_blkoffset, bma->entry);

	printk("src_blknr = 0x%llx, src_blkoffset = 0x%x, src_bytes = 0x%x\n",
		bmb->read.src_blknr, (unsigned int)bmb->read.src_blkoffset, (unsigned int)bmb->read.src_bytes);

	printk("bh_blknr = 0x%llx, bh_offset = 0x%x\n", bmb->read.bh_blknr, (unsigned int)bmb->read.bh_offset);
	*/

	BUG_ON(! bmb->read.src_bytes);

	bh = __getblk(bm->st_bdev, bmb->read.bh_blknr, bm->mapblksize);

	get_bh(bh);

	/*	lock_buffer(bh);

		Here, we MUST NOT call lock_buffer,
		lock_buffer will block if bh has
		already been locked. We can't block here.

		We need to use test_and_set_bit. */

__trylock_bh:

	if(test_set_buffer_locked(bh))
	{
		/* 	buffer has already been locked	*/

		bmb->read.bh 	= bh;
		bpkt->flags 	|= 8;

		schedule();

		end_bm_bpkt_read_resume(bpkt, bm);

		retval = 0;
		goto __return;
	}

	if(! buffer_uptodate(bh))
	{

	#ifdef __BM_PRE_READ__

		/* 	pre read */

		struct bio *b;
		unsigned int nvec = 32;					/* total block count for pre-read */

		b = bio_alloc(GFP_NOIO, nvec);
		if(! b)
		{
			retval = -ENOMEM;
			goto __return;
		}

		/* add primary bh to b */

		b->bi_sector = bh->b_blocknr << (bm->mapblkbits - 9);	/* mapblock to sector */
		b->bi_bdev = bm->st_bdev;

		bmb->read.bh = bh;
		bmb->read.rbio = b;

		while(1)
		{
			/*  we add primary bh first. Primary bh
				has already been locked.

				We here assume that we always succeed
				in adding the first bh.	*/

			retval = bio_add_page( b, bh->b_page,

						/* pre-read blksz is fixed to mapblksize */
						bm->mapblksize,

						bh_offset(bh));

			if(! retval)
			{
				break;
			}

			nvec --;

			if(! nvec)
			{
				break;
			}

			bh = __getblk(bm->st_bdev, bh->b_blocknr + 1, bm->mapblksize);

			get_bh(bh);

			if(buffer_uptodate(bh))
			{
				/* pre-read stop on uptodated buffer */

				break;
			}

			if(test_set_buffer_locked(bh))
			{
				/* pre-read stop on locked buffer */

				put_bh(bh);
				break;
			}
		}

		/*  we take an 8-block-preread approach,
			but there may not necessarily have
			8 block preread-in.

			However, we have at least one block
			read-in, which is the primary bh */

		BUG_ON(! b->bi_size);

		bmb->read.rb_size = b->bi_size;
		bpkt->bm = bm;

		b->bi_private = bpkt;
		b->bi_end_io = end_bm_bpkt_pre_read_bh;

		submit_bio(READ, b);

	#else

		/* 	disk io, async slow_read_bh,

			exection returns after submit_bh,
			and will be picked up when bh is read
			out from disk.	*/

		bpkt->bm = bm;

		bh->b_private	= bpkt;
		bh->b_end_io	= end_bm_bpkt_read_bh;

		bmb->read.bh	= bh;

		submit_bh(READ, bh);

	#endif

		retval = 0;
		goto __return;
	}

__continue:

	/* the actual buffer reading */

	bm_bpkt_read_bh(bmb, bh, bm);

	/*	unlock_buffer(bh);
		Also, instead of using unlock_buffer,
		we can just call clear_buffer_locked as there
		is not other buffer waiting on this bit. */

	clear_buffer_locked(bh);

	put_bh(bh);
	__brelse(bh);

	if(bmb->read.src_bytes)
	{
		goto __read_bh;
	}

	bmb->read.cur_blknr = bmb->read.src_blknr + 1;
	bmb->read.cur_blkoffset = 0;

	mpkt->andx ++;
	bma ++;

	if(bmb->read.b_size)
	{
		if(mpkt->andx == mpkt->apos)
		{
			goto __check_remap;
		}

		goto __next_blknr;
	}

	retval = bm_bpkt_end_bio(bmb, 1, bm);

	BUG_ON(retval);

__next_bmb:

	bpkt->pos ++;
	bmb = bpkt->b[bpkt->pos];

	if(! bmb)
	{
		/* have completed all bmbs, return 0 */

		goto __free_bpkt;
	}

	while( mpkt->andx != mpkt->apos )
	{
		if(bma->blocknr >= bmb->start_blknr)
		{
			goto __next_blknr;
		}

		mpkt->andx ++;
		bma ++;
	}

__check_remap:

	if(bpkt->flags & 2)
	{
		goto __remap;
	}

	/*	cleanup left bmb */

__cleanup:

	do
	{
		bm_bpkt_end_bio(bmb, bpkt->flags & 1, bm);

		bpkt->pos ++;
		bmb = bpkt->b[bpkt->pos];
	}
	while(bmb);

__free_bpkt:

	kmem_cache_free(bm->bpkt_cachep, bpkt);

	/* decrease outstanding scheduler packet */

	spin_lock_irq(&sche->wlock);
	atomic_dec(&sche->total);
	spin_unlock_irq(&sche->wlock);

	retval = 0;

__return:

	return retval;
}

void
bm_bpkt_read_fail(
	struct list_head *list,
	void *data
	)
{
	struct bm_sche *sche;
	struct block_mapper *bm;
	struct bm_bio_pkt *bpkt;

	BUG_ON(! list);
	BUG_ON(! data);

	printk("bm_bpkt_read_fail");

	sche = data;

	bm = container_of(sche, struct block_mapper, sche);
	bpkt = container_of(list, struct bm_bio_pkt, list);

	while(bpkt->b[bpkt->pos])
	{
		struct bm_bio *bmb;
 		struct bio *b;

 		bmb = bpkt->b[bpkt->pos];
 		b = bmb->b;

 		b->bi_private 	= bmb->data;
 		b->bi_end_io	= bmb->completion;

 		b->bi_sector	= bmb->sector;
 		b->bi_size		= bmb->size;
 		b->bi_io_vec	= bmb->vec;
 		b->bi_vcnt		= bmb->vcnt;

 		bio_endio(b, 0, -EIO);
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



