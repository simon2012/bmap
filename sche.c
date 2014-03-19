#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>
#include <linux/wait.h>

#include "sche.h"

//#define __BM_SCHE_DEBUG

void bm_add_dsp(struct list_head *list, struct bm_dsp *dsp, struct bm_sche *sche)
{
	unsigned int flags;

	/* 	we donno under what thread context is
		bm_add_dsp called, it maybe a random
		context. */

	spin_lock_irqsave(&dsp->lock, flags);
	list_add_tail(list, &dsp->head);
	spin_unlock_irqrestore(&dsp->lock, flags);

	spin_lock_irqsave(&sche->wlock, flags);
	atomic_inc(&dsp->cnt);

	if(test_bit(BM_SCHE_WAITING, &sche->flags))
	{
		clear_bit(BM_SCHE_WAITING, &sche->flags);
		complete(&sche->wakeup);

		#ifdef __BM_SCHE_DEBUG
		printk("bm_add_dsp[%ld], 0x%p wakeup\n", dsp - sche->dsp, list);
		#endif

		spin_unlock_irqrestore(&sche->wlock, flags);
	}
	else
	{
		#ifdef __BM_SCHE_DEBUG
		printk("bm_add_dsp[%ld], 0x%p no wakeup\n", dsp - sche->dsp, list);
		#endif

		spin_unlock_irqrestore(&sche->wlock, flags);
	}

	return;
}

static void do_bm_dsp(struct bm_dsp *dsp, struct bm_sche *sche)
{
	int retval;
	struct list_head *list;

	spin_lock_irq(&dsp->lock);

	if(list_empty(&dsp->head))
	{
		spin_unlock_irq(&dsp->lock);
		return;
	}

	list = dsp->head.next;
	list_del_init(list);

	spin_unlock_irq(&dsp->lock);

	spin_lock_irq(&sche->wlock);
	atomic_dec(&dsp->cnt);

	#ifdef __BM_SCHE_DEBUG
	printk("do_bm_dsp[%ld], 0x%p\n", dsp - sche->dsp, list);
	#endif

	spin_unlock_irq(&sche->wlock);


	if(! test_bit(BM_SCHE_STOP, &sche->flags))
	{
		retval = dsp->dispatch(list, dsp->data);

		if(retval)
		{
			/* 	if dispatch failed, we call
				fail on this bpkt. */

			dsp->fail(list, dsp->data);
		}

		#ifdef __BM_SCHE_DEBUG
		printk("do_bm_dsp[%ld], 0x%p, retval = %d\n", dsp - sche->dsp, list, retval);
		#endif
	}
	else
	{
		/*  we fail any outstanding rqst
			after scheduler is called to
			stop. */

		dsp->fail(list, dsp->data);

		#ifdef __BM_SCHE_DEBUG
		printk("do_bm_dsp fail[%ld], 0x%p\n", dsp - sche->dsp, list);
		#endif
	}

	return;
}

static unsigned int
bm_sche_get_quota(
	struct bm_dsp *dsp,
	struct bm_sche *sche
	)
{
	struct bm_dsp *__dsp;

	struct list_head *list, *next;
	unsigned int max_cnt, min_cnt, quota, __quota;

	max_cnt = 0;
	min_cnt = (unsigned int)-1;

	next = sche->head.next;

	spin_lock_irq(&sche->wlock);

	while(next != &sche->head)
	{
		list = next;
		next = next->next;

		__dsp = container_of(list, struct bm_dsp, list);
		__quota = (unsigned int)atomic_read(&__dsp->cnt);

		if(__quota > max_cnt) max_cnt = __quota;
		if(__quota < min_cnt) min_cnt = __quota;
	}

	__quota = (unsigned int)atomic_read(&dsp->cnt);

	spin_unlock_irq(&sche->wlock);

	if(max_cnt != min_cnt)
	{
		quota = QUOTA_MIN
			+ (QUOTA_MAX - QUOTA_MIN)
			* (__quota - min_cnt)
			/ (max_cnt - min_cnt);

		if(quota > __quota)
		{
			quota = __quota;
		}
	}
	else
	{
		quota = __quota;
	}

	return quota;
}

static int bm_sche_handler(void *data)
{
	struct bm_sche *sche;
	struct bm_dsp *dsp;

	struct list_head *list, *next;
	unsigned int total, quota;

	sche = data;
	BUG_ON(! sche);

	set_bit(BM_SCHE_WAITING, &sche->flags);
	init_completion(&sche->wakeup);

	complete(&sche->start);
	printk("bm_sche_handler start\n");

__wait:

	wait_for_completion(&sche->wakeup);

__start:

	/* to calculate max_cnt, min_cnt */

	next = sche->head.next;

	while(next != &sche->head)
	{
		list = next;
		next = next->next;

		dsp = container_of(list, struct bm_dsp, list);

		quota = bm_sche_get_quota(dsp, sche);

		while(quota)
		{
			do_bm_dsp(dsp, sche);
			quota --;
		}
	}

	/*  we here must recaculate "total", and we must hold
		wlock when doing calculation. */

	total = 0;
	spin_lock_irq(&sche->wlock);

	next = sche->head.next;
	while(next != &sche->head)
	{
		list = next;
		next = next->next;

		dsp = container_of(list, struct bm_dsp, list);

		total += atomic_read(&dsp->cnt);
	}

	if(total)
	{
		#ifdef __BM_SCHE_DEBUG
		printk("%u left scheduler packets, go to start\n", total);
		#endif

		spin_unlock_irq(&sche->wlock);
		goto __start;
	}

	total = atomic_read(&sche->total);

	if(total)
	{
		set_bit(BM_SCHE_WAITING, &sche->flags);
		init_completion(&sche->wakeup);

		#ifdef __BM_SCHE_DEBUG
		printk("%u outstanding scheduler packets, goto wait\n", total);
		#endif

		spin_unlock_irq(&sche->wlock);
		goto __wait;
	}

	if(! test_bit(BM_SCHE_STOP, &sche->flags))
	{
		set_bit(BM_SCHE_WAITING, &sche->flags);
		init_completion(&sche->wakeup);

		#ifdef __BM_SCHE_DEBUG
		printk("no stop, go to wait\n");
		#endif

		spin_unlock_irq(&sche->wlock);
		goto __wait;
	}

	spin_unlock_irq(&sche->wlock);

	printk("bm_sche_handler stop\n");

	complete(&sche->stop);
	return 0;
}

static inline void
do_bm_add_dsp(
	struct bm_sche *sche,
	int ndx,
	int (* dispatch)(struct list_head *, void *),
	void (* fail)(struct list_head *, void *),
	unsigned int q,
	void *d
	)
{
	sche->dsp[ndx].dispatch = dispatch;
	sche->dsp[ndx].fail 	= fail;
	sche->dsp[ndx].quota	= q;
	sche->dsp[ndx].data		= d;

	list_add_tail(&sche->dsp[ndx].list, &sche->head);
}

extern int bm_bpkt_read( struct list_head *list, void *data);
extern void bm_bpkt_read_fail( struct list_head *list, void *data);
extern int bm_bpkt_insert( struct list_head *list, void *data);
extern void bm_bpkt_insert_fail( struct list_head *list, void *data);

void bm_sche_init(struct bm_sche *sche)
{
	struct bm_dsp *dsp;
	int i;

	memset(sche, 0, sizeof(*sche));

	init_completion(&sche->start);
	init_completion(&sche->stop);

	spin_lock_init(&sche->wlock);
	atomic_set(&sche->total, 0);

	/*	sche->wakeup will be initialized
		in bm_sche_handler. */

	INIT_LIST_HEAD(&sche->head);

	for(i = 0; i < BM_SCHE_MAX_DSP; ++i)
	{
		dsp = sche->dsp + i;

		INIT_LIST_HEAD(&dsp->list);
		INIT_LIST_HEAD(&dsp->head);

		atomic_set(&dsp->cnt, 0);
		spin_lock_init(&dsp->lock);
	}

	/* insert dispatcher */

	do_bm_add_dsp(sche, BM_BPKT_INSERT,
			bm_bpkt_insert, bm_bpkt_insert_fail, QUOTA_MIN, sche);

	/* slow insert dispatchers */

	for(i = 0; i < (BM_BPKT_SLOW_INSERT_MAX - BM_BPKT_SLOW_INSERT_MIN) + 1; ++ i)
	{
		do_bm_add_dsp(
				sche,
				BM_BPKT_SLOW_INSERT_MIN + i,
				bm_bpkt_insert,
				bm_bpkt_insert_fail,
				QUOTA_MIN,
				sche
				);
	}

	/* read dispatcher */

	do_bm_add_dsp(sche, BM_BPKT_READ,
			bm_bpkt_read, bm_bpkt_read_fail, QUOTA_MIN, sche);

	/* slow read dispatchers */

	for(i = 0; i < (BM_BPKT_SLOW_READ_MAX - BM_BPKT_SLOW_READ_MIN) + 1; ++ i)
	{
		do_bm_add_dsp(
				sche,
				BM_BPKT_SLOW_READ_MIN + i,
				bm_bpkt_read,
				bm_bpkt_read_fail,
				QUOTA_MIN,
				sche
				);
	}

	kernel_thread(bm_sche_handler, sche, CLONE_KERNEL);
	wait_for_completion(&sche->start);
}

void bm_sche_cleanup(struct bm_sche *sche)
{
	printk("bm_sche_cleanup\n");

	set_bit(BM_SCHE_STOP, &sche->flags);
	complete(&sche->wakeup);
	wait_for_completion(&sche->stop);
}



