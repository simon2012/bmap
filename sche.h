#ifndef __BM_SCHE_H__
#define __BM_SCHE_H__

struct bm_dsp
{
	struct list_head list;
	struct list_head head;

	atomic_t cnt;
	spinlock_t lock;

	unsigned int quota;

	void *data;

	void (* feed)(void *, void *);
	int (* dispatch)( struct list_head *, void *);
	void (* fail)( struct list_head *, void *);
};

#define BM_SCHE_WAITING	0
#define BM_SCHE_STOP	1

#define BM_BPKT_READ				0
#define BM_BPKT_SLOW_READ_LVL		5
#define BM_BPKT_SLOW_READ_MIN		(BM_BPKT_READ + 1)
#define BM_BPKT_SLOW_READ_MAX		(BM_BPKT_SLOW_READ_MIN + BM_BPKT_SLOW_READ_LVL)

#define BM_BPKT_INSERT				10
#define BM_BPKT_SLOW_INSERT_LVL		16
#define BM_BPKT_SLOW_INSERT_MIN		(BM_BPKT_INSERT + 1)
#define BM_BPKT_SLOW_INSERT_MAX		(BM_BPKT_SLOW_INSERT_MIN + BM_BPKT_SLOW_INSERT_LVL)

#define BM_SCHE_MAX_DSP	30

struct bm_sche
{
	unsigned long flags;

	struct completion start;
	struct completion stop;

	/*	total is the outstanding scheduler
		packets, scheduler shouldnt terminate
		when total is not zero. Otherwise, user
		mode program may hang. */

	atomic_t total;

	struct completion wakeup;

	/* 	wlock is introduced the
		sync access	among:

		BM_SCHE_WAITING bit of "flags";
		"total";
		"flags";
		and "cnt" of each dsp. */

	spinlock_t wlock;

	struct list_head head;
	struct bm_dsp dsp[BM_SCHE_MAX_DSP];
};

#define QUOTA_MAX	200
#define QUOTA_MIN	1

void
bm_add_dsp(
	struct list_head *list,
	struct bm_dsp *dsp,
	struct bm_sche *sche
	);

void
bm_sche_init(
	struct bm_sche *sche
	);

void
bm_sche_cleanup(
	struct bm_sche *sche
	);

#endif


