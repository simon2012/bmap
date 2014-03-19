#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>
#include <linux/wait.h>

#include "init.h"
#include "sche.h"
#include "mapper.h"

static int __bmv_open__(struct inode *i, struct file *f)
{
	printk("__bmv_open__\n");
	return 0;
}

static int __bmv_release__(struct inode *i, struct file *f)
{
	printk("__bmv_release__\n");
	return 0;
}

struct block_device_operations __bmv_ops__ =
{
	.owner	= THIS_MODULE,
	.open = __bmv_open__,
	.release = __bmv_release__,
};


/*	bm_bdev_create
	create block mapper

	bm, block mapper;
	hook, bdev where to install filter;
	store, bdev as a storge plc,

	return value,
	0, success;
	fail other than 0

	If success,

	In bm:
	hook, st_bdev, hkdev, stdev, start, capacity,
	blkbits, mapblkbits, entrybits, root, pos, vname
	will be setup.

	root mapblk should be zeroed.

	bm_hdr will be completely initialized.	*/

int bm_bdev_create(struct block_mapper *bm, dev_t hook, dev_t store)
{
	int retval;
	struct buffer_head *root;
	unsigned int mapblkmask;

	printk("bm_bdev_create\n");

	memset(bm, 0, sizeof(*bm));

	bm->hkdev		= hook;
	bm->stdev		= store;

	bm->hook = open_by_devnum(hook, FMODE_READ | FMODE_WRITE);
	if(! bm->hook)
	{
		retval = -1;
		goto __return;
	}

	bm->st_bdev = open_by_devnum(store, FMODE_READ | FMODE_WRITE);
	if(! bm->st_bdev)
	{
		retval = -1;
		goto __put_hook;
	}

	/*	we also need to lock this blocksize, preventing others
		from changing it, otherwise, the mapping will get
		corrupted. */

	set_blocksize(bm->st_bdev, 1 << BM_MAPPING_BLKBITS);

	/*	read bm_hdr, and increase its refcount */


	bm->bh = __bread(
			bm->st_bdev,
			BM_HDR_BLK_NR,
			1 << BM_MAPPING_BLKBITS
			);

	if(! bm->bh)
	{
		retval = -ENOMEM;
		goto __put_store;
	}

	get_bh(bm->bh);
	bm->hdr = (struct bm_header *)(bm->bh->b_data);


	/* initialize vname; we register in bm_bdev_start */

	memcpy(bm->vname, "bmv_", 4);
	bdevname(bm->hook, bm->vname + 4);

	/*	initialize various data bits and data size */

	mapblkmask = (((loff_t)1) << (BM_MAPPING_BLKBITS - 9)) - 1;

	bm->start = bm->hook->bd_contains
		== bm->hook ? 0 : bm->hook->bd_part->start_sect;

	bm->capacity = bm->hook->bd_contains
		== bm->hook ? bm->hook->bd_disk->capacity : bm->hook->bd_part->nr_sects;

	bm->blkbits 	= BM_DATA_BLKBITS;
	bm->mapblkbits 	= BM_MAPPING_BLKBITS;
	bm->entrybits	= BM_ENTRY_LENGTH_BITS;
	bm->pos 		= BM_INIT_POS;

	/* round to map block size */

	bm->pos = (bm->pos + mapblkmask) & ~mapblkmask;

	/* 	initialize root entry and root datablock updated pos. */

	bm->root = (bm->pos >> (BM_MAPPING_BLKBITS - 9)) << BM_ADDRESS_SHIFT;

	root = __getblk(bm->st_bdev, bm->root >> BM_ADDRESS_SHIFT, 1 << BM_MAPPING_BLKBITS);
	if(! root)
	{
		retval = -ENOMEM;
		goto __hdr_brelse;
	}

	lock_buffer(root);
	memset(root->b_data, 0, 1 << BM_MAPPING_BLKBITS);

	mark_buffer_dirty(root);
	set_buffer_uptodate(root);

	unlock_buffer(root);
	__brelse(root);

	bm->pos	+= (1 << (BM_MAPPING_BLKBITS - 9));
	bm->pos = (bm->pos + mapblkmask) & ~mapblkmask;

	set_bit(BM_FG_VALID, (unsigned long *)&bm->root);

	/*	initialize bm_hdr */

	lock_buffer(bm->bh);

	memset(bm->hdr, 0, sizeof(* bm->hdr));

	memcpy(&bm->hdr->h_magic, BM_HDR_MAGIC, strlen(BM_HDR_MAGIC));

	bm->hdr->h_flags		= cpu_to_le32(BM_HDR_FLAGS_DIRTY);

	bm->hdr->h_hkdev		= cpu_to_le32(bm->hkdev);
	bm->hdr->h_stdev		= cpu_to_le32(bm->stdev);

	bm->hdr->h_start		= cpu_to_le64(bm->start);
	bm->hdr->h_capacity		= cpu_to_le64(bm->capacity);

	bm->hdr->h_blkbits		= cpu_to_le32(BM_DATA_BLKBITS);
	bm->hdr->h_mapblkbits	= cpu_to_le32(BM_MAPPING_BLKBITS);
	bm->hdr->h_entrybits	= cpu_to_le32(BM_ENTRY_LENGTH_BITS);

	bm->hdr->h_root			= cpu_to_le64(bm->root);
	bm->hdr->h_pos			= cpu_to_le64(bm->pos);

	memcpy(bm->hdr->h_vname, bm->vname, BDEVNAME_SIZE);

	/* mark buffer uptodate and dirty */

	mark_buffer_dirty(bm->bh);
	set_buffer_uptodate(bm->bh);

	unlock_buffer(bm->bh);

	printk("bm->hook = 0x%p\n", bm->hook);
	printk("bm->st_bdev = 0x%p\n", bm->st_bdev);

	printk("bm->start = 0x%llx\n", bm->start);
	printk("bm->capacity = 0x%llx\n", bm->capacity);

	printk("bm->root = 0x%llx\n", bm->root >> BM_ADDRESS_SHIFT);
	printk("bm->pos = 0x%llx\n", bm->pos);

	printk("bm->blkbits = %d\n", bm->blkbits);
	printk("blksize = 0x%x\n", (unsigned int)(1 << bm->blkbits));

	printk("bm->mapblkbits = %d\n", bm->mapblkbits);
	printk("bm->entrybits = %d\n", bm->entrybits);

	printk("bm->vname = %s\n", bm->vname);
	printk("\n");

	return 0;

__hdr_brelse:

	put_bh(bm->bh);
	__brelse(bm->bh);

__put_store:
	blkdev_put(bm->st_bdev);

__put_hook:
	blkdev_put(bm->hook);

__return:
	return retval;

}

/* 	bm_bdev_resume
	resume block mapper

	bm, block mapper;
	hook, bdev for which to resume filter;
	store, bdev where to pickup resume info.

	return value:
	0 success;
	fail other than 0

	In bm:
	hook, st_bdev, hkdev, stdev, start, capacity,
	blkbits, mapblkbits, entrybits, root, pos, vname
	will be setup.

	root mapblk should not be zeroed.

	And bm_hdr will be used either as source or
	confirmation.	*/

int bm_bdev_resume(struct block_mapper *bm, dev_t hook, dev_t store)
{
	int retval;
	struct bm_header *hdr;
	sector_t start, capacity;

	printk("bm_bdev_resume\n");

	memset(bm, 0, sizeof(*bm));

	bm->hook = open_by_devnum(hook, FMODE_READ | FMODE_WRITE);
	if(! bm->hook)
	{
		retval = -1;
		goto __return;
	}

	bm->st_bdev = open_by_devnum(store, FMODE_READ | FMODE_WRITE);
	if(! bm->st_bdev)
	{
		retval = -1;
		goto __put_hook;
	}

	start = bm->hook->bd_contains
		== bm->hook ? 0 : bm->hook->bd_part->start_sect;

	capacity = bm->hook->bd_contains
		== bm->hook ? bm->hook->bd_disk->capacity : bm->hook->bd_part->nr_sects;

	set_blocksize(bm->st_bdev, 1 << BM_MAPPING_BLKBITS);

	/*	read bm_hdr, and increase its refcount */

	bm->bh = __bread(
			bm->st_bdev,
			BM_HDR_BLK_NR,
			1 << BM_MAPPING_BLKBITS
			);

	if(! bm->bh)
	{
		retval = -ENOMEM;
		goto __put_store;
	}

	get_bh(bm->bh);

	/* lock bh and verify bm_hdr info */

	lock_buffer(bm->bh);

	hdr = (struct bm_header *)bm->bh->b_data;

	bm->hkdev 		= hook;
	bm->stdev 		= store;
	bm->start 		= start;
	bm->capacity 	= capacity;

	bm->blkbits 	= BM_DATA_BLKBITS;
	bm->mapblkbits 	= BM_MAPPING_BLKBITS;
	bm->entrybits	= BM_ENTRY_LENGTH_BITS;

	/* pickup root */

	bm->root = le64_to_cpu(hdr->h_root);

	/* initialize vname */

	memcpy(bm->vname, hdr->h_vname, BDEVNAME_SIZE);

	/* pickup pos */

	bm->pos = le64_to_cpu(hdr->h_pos);

	/* save hdr */

	bm->hdr = hdr;

	/* disk hdr check */

	if(memcmp(&hdr->h_magic, BM_HDR_MAGIC, strlen(BM_HDR_MAGIC)))
	{
		printk("magic = %s\n", hdr->h_str);

		retval = -1;
		goto __unlock_bh;
	}

	if(le32_to_cpu(hdr->h_stdev) != store)
	{
		printk("h_stdev = %u\n", le32_to_cpu(hdr->h_stdev));

		retval = -1;
		goto __unlock_bh;
	}

	if(le32_to_cpu(hdr->h_hkdev) != hook)
	{
		printk("h_hkdev = %u\n", le32_to_cpu(hdr->h_hkdev));

		retval = -1;
		goto __unlock_bh;
	}

	if(le64_to_cpu(hdr->h_start) != start)
	{
		printk("h_start = %u\n", le32_to_cpu(hdr->h_start));

		retval = -1;
		goto __unlock_bh;
	}

	if(le64_to_cpu(hdr->h_capacity) != capacity)
	{
		printk("h_capacity = %u\n", le32_to_cpu(hdr->h_capacity));

		retval = -1;
		goto __unlock_bh;
	}

	if(le32_to_cpu(hdr->h_blkbits) != BM_DATA_BLKBITS)
	{
		printk("h_blkbits = %u\n", le32_to_cpu(hdr->h_blkbits));

		retval = -1;
		goto __unlock_bh;
	}

	if(le32_to_cpu(hdr->h_mapblkbits) != BM_MAPPING_BLKBITS)
	{
		printk("h_mapblkbits = %u\n", le32_to_cpu(hdr->h_mapblkbits));

		retval = -1;
		goto __unlock_bh;
	}

	if(le32_to_cpu(hdr->h_entrybits) != BM_ENTRY_LENGTH_BITS)
	{
		printk("h_entrybits = %u\n", le32_to_cpu(hdr->h_entrybits));

		retval = -1;
		goto __unlock_bh;
	}

	if(le32_to_cpu(hdr->h_flags) != BM_HDR_FLAGS_CLEAN)
	{
		printk("clean = %d, BM_HDR_FLAGS_CLEAN = %d\n",
			le32_to_cpu(hdr->h_flags), BM_HDR_FLAGS_CLEAN);

		/*	[7]  bm_fsck if dirty uninstall */
		bm_fsck(bm);
	}

	/* dirty hdr flags */

	bm->hdr->h_flags = cpu_to_le32(BM_HDR_FLAGS_DIRTY);

	mark_buffer_dirty(bm->bh);
	set_buffer_uptodate(bm->bh);

	unlock_buffer(bm->bh);

	printk("bm->hook = 0x%p\n", bm->hook);
	printk("bm->st_bdev = 0x%p\n", bm->st_bdev);

	printk("bm->start = 0x%llx\n", bm->start);
	printk("bm->capacity = 0x%llx\n", bm->capacity);

	printk("bm->root = 0x%llx\n", bm->root >> BM_ADDRESS_SHIFT);
	printk("bm->pos = 0x%llx\n", bm->pos);

	printk("bm->blkbits = %d\n", bm->blkbits);
	printk("blksize = 0x%x\n", (unsigned int)(1 << bm->blkbits));

	printk("bm->mapblkbits = %d\n", bm->mapblkbits);
	printk("bm->entrybits = %d\n", bm->entrybits);

	printk("bm->vname = %s\n", bm->vname);
	printk("\n");

	return 0;

__unlock_bh:

	unlock_buffer(bm->bh);

	put_bh(bm->bh);
	__brelse(bm->bh);

__put_store:
	blkdev_put(bm->st_bdev);

__put_hook:
	blkdev_put(bm->hook);

__return:
	return retval;

}

/*	bm_bdev_start
	setup the rest fields of block mapper,
	and then start mapping.

	bm, block mapper.

	return value:
	0 success
	fail other than 0	*/

int bm_bdev_start(struct block_mapper *bm)
{
	int retval;
	struct super_block *sb;

	char bmb_cachep_name[BDEVNAME_SIZE + 5];
	char bpkt_cachep_name[BDEVNAME_SIZE + 5];

	printk("bm_bdev_start\n");

	bm->mapblksize		= (1 << bm->mapblkbits);
	bm->contains 		= bm->hook->bd_contains;
	bm->bits 			= bm->mapblkbits - bm->entrybits;
	bm->mapblkmask 		= (((loff_t)1) << (bm->mapblkbits - 9)) - 1;

	bm->disk 			= bm->hook->bd_disk;
	bm->queue 			= bm->disk->queue;
	bm->old_mk_rq_fn 	= bm->queue->make_request_fn;

	sprintf(bmb_cachep_name, "bm_%s", bm->vname + 4);
	sprintf(bpkt_cachep_name, "bp_%s", bm->vname + 4);

	spin_lock_init(&bm->lock);

	bm->bmb_cachep = kmem_cache_create(bmb_cachep_name,
			sizeof(struct bm_bio), 0, SLAB_HWCACHE_ALIGN, NULL, NULL);

	if(! bm->bmb_cachep)
	{
		retval = -ENOMEM;
		goto __return;
	}

	bm->bpkt_cachep = kmem_cache_create(bpkt_cachep_name,
			sizeof(struct bm_bio_pkt), 0, SLAB_HWCACHE_ALIGN, NULL, NULL);

	if(! bm->bpkt_cachep)
	{
		retval = -ENOMEM;
		goto __bmb_cleanup;
	}

	bm->size = (bm->capacity + (1 <<
		(bm->blkbits - 9)) - 1) >> (bm->blkbits - 9);

	bm->lastblksz = (bm->capacity << 9) & ((1 << bm->blkbits) - 1);

	bm->maskbits = 0;

	while(bm->size >> (bm->maskbits + bm->bits))
	{
		bm->maskbits += bm->bits;
	}

	bm->vdev = register_blkdev(0, bm->vname);
	if(bm->vdev < 0)
	{
		retval = bm->vdev;
		goto __bpkt_cleanup;
	}

	bm->vq = blk_alloc_queue(GFP_KERNEL);
	if(! bm->vq)
	{
		retval = -ENOMEM;
		goto __unregister_blkdev;
	}

	bm->vd = alloc_disk(1);
	if(! bm->vd)
	{
		retval = -ENOMEM;
		goto __blk_put_queue;
	}

	blk_queue_make_request(bm->vq, bmv_mk_rq_fn);

	bm->vd->queue		= bm->vq;
	bm->vd->major		= bm->vdev;
	bm->vd->first_minor = 0;
	bm->vd->fops		= &__bmv_ops__;

	set_capacity(bm->vd, bm->capacity);
	sprintf(bm->vd->disk_name, "%s", bm->vname);

	/* io scheduler initialize */

	bm_sche_init(&bm->sche);

	/* we need to sync disk */

	sb = freeze_bdev(bm->hook);

	/* 	we need to lock queue exchange,
		we here exchange queue when bdev is being locked. */

	bm->queue->make_request_fn = bm_mk_rq_fn;


	thaw_bdev(bm->hook, sb);

	/* register virtual volume */

	add_disk(bm->vd);

	printk("bm->disk = 0x%p\n", bm->disk);
	printk("bm->old_mk_rq_fn = 0x%p\n", bm->old_mk_rq_fn);
	printk("bm->queue = 0x%p\n", bm->queue);

	printk("bm->size = 0x%llx\n", bm->size);

	printk("bm->lastblksz = 0x%x\n", (unsigned int)bm->lastblksz);
	printk("bm->mapblksize = %d\n", bm->mapblksize);

	printk("bm->mapblkmask = 0x%llx\n", bm->mapblkmask);

	printk("bm->bits = %d\n", bm->bits);
	printk("bm->maskbits = %d\n", bm->maskbits);

	printk("max_hw_sectors = 0x%x\n", (unsigned int)bm->queue->max_hw_sectors);

	return 0;

__blk_put_queue:
	blk_put_queue(bm->vq);

__unregister_blkdev:
	unregister_blkdev(bm->vdev, bm->vname);

__bpkt_cleanup:
	kmem_cache_destroy(bm->bpkt_cachep);

__bmb_cleanup:
	kmem_cache_destroy(bm->bmb_cachep);

__return:
	return retval;
}

/*	bm_bdev_cleanup
	release resource allocated*/

void bm_bdev_cleanup(struct block_mapper *bm)
{
	printk("bm_bdev_cleanup\n");

	put_bh(bm->bh);
	__brelse(bm->bh);

	blkdev_put(bm->st_bdev);
	blkdev_put(bm->hook);

	printk("pos = 0x%llx\n", bm->pos);

	return;
}

/*	bm_bdev_stop
	stop mapping,

	update h_pos and h_flags.

	return value,
	0 success;
	fail other than 0	*/

int bm_bdev_stop(struct block_mapper *bm)
{
	printk("bm_bdev_stop\n");

	bm->queue->make_request_fn = bm->old_mk_rq_fn;

	bm_sche_cleanup(&bm->sche);

	del_gendisk(bm->vd);
	blk_put_queue(bm->vq);
	put_disk(bm->vd);

	kmem_cache_destroy(bm->bmb_cachep);
	kmem_cache_destroy(bm->bpkt_cachep);

	lock_buffer(bm->bh);

	bm->hdr->h_flags  = cpu_to_le32(BM_HDR_FLAGS_CLEAN);
	bm->hdr->h_pos	  = cpu_to_le64(bm->pos);

	mark_buffer_dirty(bm->bh);
	set_buffer_uptodate(bm->bh);

	unlock_buffer(bm->bh);

	unregister_blkdev( bm->vdev, bm->vname);

	return 0;
}

static void bm_do_fsck(struct block_mapper *bm, loff_t nblk)
{
	int i;
	unsigned char valid, busy, ready, map;

	struct buffer_head *bh;
	loff_t *entry;

	bh = __bread(bm->st_bdev, nblk, 1 << BM_MAPPING_BLKBITS);

	lock_buffer(bh);

	entry = (loff_t *)(bh->b_data);

	for(i = 0; i < (1 << (BM_MAPPING_BLKBITS - BM_ENTRY_LENGTH_BITS)); ++ i, ++ entry)
	{
		valid = test_bit(BM_FG_VALID, (unsigned long *)entry);
		busy = test_bit(BM_FG_BUSY, (unsigned long *)entry);
		ready = test_bit(BM_FG_READY, (unsigned long *)entry);
		map = test_bit(BM_FG_MAP, (unsigned long *)entry);

		if(!((!valid && !busy && !ready && !map) /* free block */
			|| (valid && !busy && !ready && map) /* mapblock */
			|| (valid && !busy && ready && !map))) /* datablock */
		{
			bm->nfsck ++;

			printk("bm_do_fsck, nblk = 0x%llx, ndx = %d, entry = 0x%llx, [%d, %d, %d, %d]\n",
				nblk, i, *entry, valid, busy, ready, map);

			/* empty this entry, mark buffer uptodate and dirty */

			*entry = 0;
			mark_buffer_dirty(bh);
			set_buffer_uptodate(bh);

			continue;
		}

		if(! valid)
		{
			continue;
		}

		if(map)
		{
			unlock_buffer(bh);
			bm_do_fsck(bm, *entry >> BM_ADDRESS_SHIFT);
			lock_buffer(bh);
		}
	}

	unlock_buffer(bh);
	__brelse(bh);
	return;
}

void bm_fsck(struct block_mapper *bm)
{
	/* blksz should have already been setup to mapping block size */
	BUG_ON(bm->st_bdev->bd_block_size != (1 << BM_MAPPING_BLKBITS));

	bm_do_fsck(bm, bm->root >> BM_ADDRESS_SHIFT);
	printk("bm->nfsck = %lu\n", bm->nfsck);
	return;
}



