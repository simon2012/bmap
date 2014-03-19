#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>

#include "mapper.h"
#include "init.h"

MODULE_LICENSE("GPL");

/*	bmap, a snapshot device driver.

	"bmap" stands for block mapper. One of the big differences of
	bmap from imgblk is that bmap utilizes a new back-end data
	structure. Different from the traditional tree(avl, rb, b+) data
	structure, this new data structure doesnt have operations such
	as node collapse, node split, or node deletion. Its underlying
	implementation is similar to IA addressing algorithsm.

	We figure out that in imgblk,
	1). reading from backVault takes much more time than insert,
		although insert is really fast, especially after enhancements
		like bio collectively handling, which makes the insert performance
		almost unbeatable.
	2). since we use avl as the backend data structure, its hard for
		imgblk to have a disk image. disk image of avl is not eazy to
		implement. although we can ignore the metadata and just disk-image
		the acutal copy-on-write data, that would take alot of time to
		rebuild the snapshot since 	everytime we need to reinsert
		copy-on-write data.

	bmap will give us
	1). The better performance of backvault read.
	2). The eazier implementation of caching, we dont need to have our
		own caching, we rely upon kernel.
	3). The eazier implementation of disk-image.


	bmap_2,

	1). sync insert, single disk access in each insert.
	2). sync read, multiple disk access in each read.

	bmap_3,

	1). introduce bm_sche; improve its master scheduler algorithsm.
	2). sync read, single disk access in each read,
	3). incorporate read into bm_sche

	bmap_4,

	1). improve bm_sche scheduler algorithsm, we calculate the quota
		of each dispatcher everytime according to the whole scheduler.
		it will become a prototype to how to handle io request.

	2). incorporate bm_insert into bm_sche, we have now one master
		kernel_thread, the master bm_sche scheduler to handle all
		io request.

	3). introduce the pre-read idea, we enlarge the src blocksize,
		it will not relate to the file system blocksize anymore. A
		larger blocksize will involve pre-read, which together with
		other enhancements, will give us a better performance.

		however, later when we start to have allocated block bitmap,
		we need to compress the block bitmap from fs blksz to src blksz.

	4). async handling of read and insert.

	5). bug fix, last blocksize issue

	6). bug fix, double check and wait for BM_FG_READY in insert.
		in insert, BM_FG_VALID means block has been allocated, but
		copy-on-write data may not have been secured, we need to wait
		for BM_FG_READY to be set.
		We actually have thought about this in imgblk but somehow missed
		it in bm.

	we need to later lock dst blksz, otherwise, if dst blksz gets
	changed after we install filter, the whole mapping will get
	corrupted.

	bmap_5

	1). in flt make_request_fn, we add pre-check to filter out bio which are
	   	not sent for hook, as there will be other block device sharing the
	   	same gendisk.

	   	back port to bmap_4

	2). introduce init, add persistance support,
	   	however, no recoverability from data corruption.

	bmap_6

	1). add "bcnt" to "bpkt"; multi handling in insert
	2). sync bdev while install filter, and "fsck -f" works.
	3). maybe its time to have some comments on read and insert,
		especially for these long threads.
	4). pre-read in bm_read, a big move.

	bmap_7
	1). shadow volume
	2). mapper.h,	BM_ENTRY_LENGTH_BYTE to BM_ENTRY_LENGTH_BITS
				 	BM_HDR_POS_INIT to BM_POS_INIT,
					change bm->pos initialization.

	3). sync recovaribility support. */

#define BDEV_TO_HOOK MKDEV(8, 49)	/* Testing machine, hardcode /dev/sdd1 */
#define BDEV_TO_STORE MKDEV(8, 33)	/* Testing machine, hardcode /dev/sdc1 */

struct block_mapper bm;

static int __init init_bm(void)
{
	int retval = -1;

#ifdef __BM_PRE_READ__
	printk("pre read support\n");
#endif

#ifdef __BM_SYNC_BH_WRITEBACK__
	printk("sync bh wb support\n");
#endif

	retval = bm_bdev_resume(&bm, BDEV_TO_HOOK, BDEV_TO_STORE);
	if(retval)
 	{
		printk("failed to resume bm [%d], restart\n", retval);

		retval = bm_bdev_create(&bm, BDEV_TO_HOOK, BDEV_TO_STORE);

		if(retval)
		{
			printk("failed to create bm [%d], cleanup\n", retval);

			goto __return;
		}
	}

	retval = bm_bdev_start(&bm);

	if(retval)
	{
		printk("failed to start bm [%d]\n", retval);
		bm_bdev_cleanup(&bm);
	}


__return:
	return retval;
}

static void exit_bm(void)
{
	printk("exit_bm\n");

	bm_bdev_stop(&bm);
	bm_bdev_cleanup(&bm);

	return;
}

module_init(init_bm);
module_exit(exit_bm);




