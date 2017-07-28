/*
 *  eio_main.c
 *
 *  Copyright (C) 2012 STEC, Inc. All rights not specifically granted
 *   under a license included herein are reserved
 *  Made EnhanceIO specific changes.
 *   Saied Kazemi <skazemi@stec-inc.com>
 *   Siddharth Choudhuri <schoudhuri@stec-inc.com>
 *  Amit Kale <akale@stec-inc.com>
 *   Restructured much of the io code to split bio within map function instead
 *   of letting dm do it.
 *   Simplified queued logic for write through.
 *   Created per-cache spinlocks for reducing contention in IO codepath.
 *  Amit Kale <akale@stec-inc.com>
 *  Harish Pujari <hpujari@stec-inc.com>
 *   Designed and implemented the writeback caching mode
 *  Copyright 2010 Facebook, Inc.
 *   Author: Mohan Srinivasan (mohan@facebook.com)
 *
 *  Based on DM-Cache:
 *   Copyright (C) International Business Machines Corp., 2006
 *   Author: Ming Zhao (mingzhao@ufl.edu)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "eio.h"
#include "eio_ttc.h"

#define CTRACE(X) { }

/*
 * TODO List :
 * 1) sysctls : Create per-cache device sysctls instead of global sysctls.
 * 2) Management of non cache pids : Needs improvement. Remove registration
 * on process exits (with  a pseudo filesstem'ish approach perhaps) ?
 * 3) Breaking up the cache spinlock : Right now contention on the spinlock
 * is not a problem. Might need change in future.
 * 4) Use the standard linked list manipulation macros instead rolling our own.
 * 5) Fix a security hole : A malicious process with 'ro' access to a file can
 * potentially corrupt file data. This can be fixed by copying the data on a
 * cache read miss.
 */

static int eio_read_peek(struct cache_c *dmc, struct eio_bio *ebio);
static int eio_write_peek(struct cache_c *dmc, struct eio_bio *ebio);
static void eio_read(struct cache_c *dmc, struct bio_container *bc,
		     struct eio_bio *ebegin);
static void eio_write(struct cache_c *dmc, struct bio_container *bc,
		      struct eio_bio *ebegin);
static int eio_inval_block(struct cache_c *dmc, sector_t iosector);
static void eio_enqueue_readfill(struct cache_c *dmc, struct kcached_job *job);
static int eio_acquire_set_locks(struct cache_c *dmc, struct bio_container *bc);
static int eio_release_io_resources(struct cache_c *dmc,
				    struct bio_container *bc);
static void 
eio_clean_n_sets(struct cache_c *dmc, index_t set_array[], int nr_set, int force);
static void eio_clean_set(struct cache_c *dmc, index_t set, int whole,
			  int force);
static void eio_do_mdupdate(struct work_struct *work);
static void eio_mdupdate_callback(int error, void *context);
static void eio_enq_mdupdate(struct bio_container *bc);
static void eio_uncached_read_done(struct kcached_job *job);
static void eio_addto_cleanq(struct cache_c *dmc, index_t set, int whole);
static int eio_alloc_mdreqs(struct cache_c *, struct bio_container *);
static void eio_check_dirty_set_thresholds(struct cache_c *dmc, index_t set);
static void eio_check_dirty_cache_thresholds(struct cache_c *dmc);
static void eio_post_mdupdate(struct work_struct *work);
static void eio_post_io_callback(struct work_struct *work);
static int add_to_cleanq_low_io_pressure(struct cache_c *dmc, int count);
#ifdef CONFIG_SKIP_SEQUENTIAL_IO
static int seq_io_md_update(struct cache_c *dmc, 
									struct seqio_set_block *set_block);
static void seq_io_post_callback(struct work_struct *work);
static void seq_io_callback(int error, void *context);
static int seq_io_alloc_mdupdate_mem(struct bio_container *bc);
//static void seq_io_free_mdupdate_mem(struct bio_container *bc);
static void seq_io_free_set_block(struct bio_container *bc);
static void
seq_io_disk_io(struct cache_c *dmc, struct bio_container *bc, struct bio *bio);
#if 0
static void 
seq_io_free_set_block(struct bio_container *bc);
static struct seqio_set_block * 
seq_io_get_set_block(struct bio_container *bc);
#endif
static int seq_io_inval_bio_range(struct cache_c *dmc, 
												struct bio_container *bc);
static int 
seq_io_detect_seqential_io(struct cache_c *dmc, struct bio *bio);
#endif
static void bc_addfb(struct bio_container *bc, struct eio_bio *ebio)
{

	atomic_inc(&bc->bc_holdcount);

	ebio->eb_bc = bc;
}

static void bc_put(struct bio_container *bc, unsigned int doneio)
{
	struct cache_c *dmc;
	int data_dir;
	long elapsed;

	if (atomic_dec_and_test(&bc->bc_holdcount)) {
		if (bc->bc_dmc->mode == CACHE_MODE_WB)
			eio_release_io_resources(bc->bc_dmc, bc);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		bc->bc_bio->bi_iter.bi_size = 0;
#else 
		bc->bc_bio->bi_size = 0;
#endif 
		dmc = bc->bc_dmc;

		/* update iotime for latency */
		data_dir = bio_data_dir(bc->bc_bio);
		elapsed = (long)jiffies_to_msecs(jiffies - bc->bc_iotime);
		#if 0
 		if (data_dir == WRITE) {
			EIO_DBG(ERROR, dmc, "%s:bio_alltime:%lu, bio_locktime:%lu, bio_rwtime:%lu\n",
				(UNCACHED_WRITE == bc->bc_dir) ? "Uncache write" : "Cache write", 
				elapsed, (long)jiffies_to_msecs(bc->bc_locktime - bc->bc_iotime),
				(long)jiffies_to_msecs(jiffies - bc->bc_locktime));
		}
		#endif
		
		if (data_dir == READ)
			atomic64_add(elapsed, &dmc->eio_stats.rdtime_ms);
		else
			atomic64_add(elapsed, &dmc->eio_stats.wrtime_ms);

		bio_endio(bc->bc_bio, bc->bc_error);
		atomic64_dec(&bc->bc_dmc->nr_ios);
		kfree(bc);
		
	}
}

static void eb_endio(struct eio_bio *ebio, int error)
{

	EIO_ASSERT(ebio->eb_bc);

	/*Propagate only main io errors and sizes*/
	if (ebio->eb_iotype == EB_MAIN_IO) {
		if (error)
			ebio->eb_bc->bc_error = error;
		bc_put(ebio->eb_bc, ebio->eb_size);
	} else
		bc_put(ebio->eb_bc, 0);
	ebio->eb_bc = NULL;
	kfree(ebio);
}

static int
eio_io_async_bvec(struct cache_c *dmc, struct eio_io_region *where, int rw,
		  struct bio_vec *pages, unsigned nr_bvecs, eio_notify_fn fn,
		  void *context, int hddio)
{
	struct eio_io_request req;
	int error = 0;

	memset((char *)&req, 0, sizeof(req));

	if (unlikely(CACHE_DEGRADED_IS_SET(dmc))) {
		if (where->bdev != dmc->disk_dev->bdev) {
			pr_err
				("eio_io_async_bvec: Cache is in degraded mode.\n");
			pr_err
				("eio_io_async_Bvec: Can not issue i/o to ssd device.\n");
			return -ENODEV;
		}
	}

	req.mtype = EIO_BVECS;
	req.dptr.pages = pages;
	req.num_bvecs = nr_bvecs;
	req.notify = fn;
	req.context = context;
	req.hddio = hddio;

	error = eio_do_io(dmc, where, rw, &req);

	return error;
}

static void
eio_flag_abios(struct cache_c *dmc, struct eio_bio *abio, int invalidated)
{
	struct eio_bio *nbio;

	while (abio) {
		int invalidate;
		unsigned long flags;
		int cwip_on = 0;
		int dirty_on = 0;
		int callendio = 0;
		nbio = abio->eb_next;

		EIO_ASSERT(!(abio->eb_iotype & EB_INVAL) || abio->eb_index == -1);
		invalidate = !invalidated && (abio->eb_iotype & EB_INVAL);

		spin_lock_irqsave(&dmc->cache_sets[abio->eb_cacheset].cs_lock,
				  flags);

		if (abio->eb_index != -1) {
			if (EIO_CACHE_STATE_GET(dmc, abio->eb_index) & DIRTY)
				dirty_on = 1;

			if (unlikely
				    (EIO_CACHE_STATE_GET(dmc, abio->eb_index) &
				    CACHEWRITEINPROG))
				cwip_on = 1;
		}

		if (dirty_on) {
			/*
			 * For dirty blocks, we don't change the cache state flags.
			 * We however, need to end the ebio, if this was the last
			 * hold on it.
			 */
			if (atomic_dec_and_test(&abio->eb_holdcount)) {
				callendio = 1;
				/* We shouldn't reach here when the DIRTY_INPROG flag
				 * is set on the cache block. It should either have been
				 * cleared to become DIRTY or INVALID elsewhere.
				 */
				EIO_ASSERT(EIO_CACHE_STATE_GET(dmc, abio->eb_index)
					   != DIRTY_INPROG);
			}
		} else if (abio->eb_index != -1) {
			if (invalidate) {
				if (cwip_on)
					EIO_CACHE_STATE_ON(dmc, abio->eb_index,
							   QUEUED);
				else {
					EIO_CACHE_STATE_SET(dmc, abio->eb_index,
							    INVALID);
					atomic64_dec_if_positive(&dmc->
								 eio_stats.
								 cached_blocks);
				}
			} else {
				if (cwip_on)
					EIO_CACHE_STATE_OFF(dmc, abio->eb_index,
							    DISKWRITEINPROG);
				else {
					if (EIO_CACHE_STATE_GET
						    (dmc, abio->eb_index) & QUEUED) {
						EIO_CACHE_STATE_SET(dmc,
								    abio->
								    eb_index,
								    INVALID);
						atomic64_dec_if_positive(&dmc->
									 eio_stats.
									 cached_blocks);
					} else {
						EIO_CACHE_STATE_SET(dmc,
								    abio->
								    eb_index,
								    VALID);
					}
				}
			}
		} else {
			EIO_ASSERT(invalidated || invalidate);
			if (invalidate)
				eio_inval_block(dmc, abio->eb_sector);
		}
		spin_unlock_irqrestore(&dmc->cache_sets[abio->eb_cacheset].
				       cs_lock, flags);
		if (!cwip_on && (!dirty_on || callendio))
			eb_endio(abio, 0);
		abio = nbio;
	}
}

static void eio_disk_io_callback(int error, void *context)
{
	struct kcached_job *job;
	struct eio_bio *ebio;
	struct cache_c *dmc;
	unsigned long flags;
	unsigned eb_cacheset;

	flags = 0;
	job = (struct kcached_job *)context;
	dmc = job->dmc;
	ebio = job->ebio;

	EIO_ASSERT(ebio != NULL);
	eb_cacheset = ebio->eb_cacheset;

	if (unlikely(error))
		dmc->eio_errors.disk_read_errors++;

	spin_lock_irqsave(&dmc->cache_sets[eb_cacheset].cs_lock, flags);
	/* Invalidate the cache block */
	EIO_CACHE_STATE_SET(dmc, ebio->eb_index, INVALID);
	atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
	spin_unlock_irqrestore(&dmc->cache_sets[eb_cacheset].cs_lock, flags);

	if (unlikely(error))
		pr_err("disk_io_callback: io error %d block %llu action %d",
		       error,
		       (unsigned long long)job->job_io_regions.disk.sector,
		       job->action);

	eb_endio(ebio, error);
	ebio = NULL;
	job->ebio = NULL;
	eio_free_cache_job(job);
	job = NULL;
}

static void eio_uncached_read_done(struct kcached_job *job)
{
	struct eio_bio *ebio = job->ebio;
	struct cache_c *dmc = job->dmc;
	struct eio_bio *iebio;
	struct eio_bio *nebio;
	unsigned long flags = 0;

	if (ebio->eb_bc->bc_dir == UNCACHED_READ) {
		EIO_ASSERT(ebio != NULL);
		iebio = ebio->eb_next;
		while (iebio != NULL) {
			nebio = iebio->eb_next;
			if (iebio->eb_index != -1) {
				spin_lock_irqsave(&dmc->
						  cache_sets[iebio->
							     eb_cacheset].
						  cs_lock, flags);
				if (unlikely
					    (EIO_CACHE_STATE_GET(dmc, iebio->eb_index) &
					    QUEUED)) {
					EIO_CACHE_STATE_SET(dmc,
							    iebio->eb_index,
							    INVALID);
					atomic64_dec_if_positive(&dmc->
								 eio_stats.
								 cached_blocks);
				} else
				if (EIO_CACHE_STATE_GET
					    (dmc,
					    iebio->eb_index) & CACHEREADINPROG) {
					/*turn off the cache read in prog flag*/
					EIO_CACHE_STATE_OFF(dmc,
							    iebio->eb_index,
							    BLOCK_IO_INPROG);
				} else
					/*Should never reach here*/
					EIO_ASSERT(0);
				spin_unlock_irqrestore(&dmc->
						       cache_sets[iebio->
								  eb_cacheset].
						       cs_lock, flags);
			}
			eb_endio(iebio, 0);
			iebio = nebio;
		}
		eb_endio(ebio, 0);
		eio_free_cache_job(job);
	} else if (ebio->eb_bc->bc_dir == UNCACHED_READ_AND_READFILL) {
		/*
		 * Kick off the READFILL. It will also do a read
		 * from SSD, in case of ALREADY_DIRTY block
		 */
		job->action = READFILL;
		eio_enqueue_readfill(dmc, job);
	} else
		/* Should never reach here for uncached read */
		EIO_ASSERT(0);
}

static void eio_io_callback(int error, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;

	job->error = error;
	INIT_WORK(&job->work, eio_post_io_callback);
	queue_work(dmc->callback_q, &job->work);
	return;
}

static void eio_post_io_callback(struct work_struct *work)
{
	struct kcached_job *job;
	struct cache_c *dmc;
	struct eio_bio *ebio;
	unsigned long flags = 0;
	index_t index;
	unsigned eb_cacheset;
	u_int8_t cstate;
	int callendio = 0;
	int error;

	job = container_of(work, struct kcached_job, work);
	dmc = job->dmc;
	index = job->index;
	error = job->error;

	EIO_ASSERT(index != -1 || job->action == WRITEDISK
		   || job->action == READDISK);
	ebio = job->ebio;
	EIO_ASSERT(ebio != NULL);
	EIO_ASSERT(ebio->eb_bc);

	eb_cacheset = ebio->eb_cacheset;
	if (error)
		pr_err("io_callback: io error %d block %llu action %d",
		       error,
		       (unsigned long long)job->job_io_regions.disk.sector,
		       job->action);

	switch (job->action) {
	case WRITEDISK:

		atomic64_inc(&dmc->eio_stats.writedisk);
		if (unlikely(error))
			dmc->eio_errors.disk_write_errors++;
		if (unlikely(error) || (ebio->eb_iotype & EB_INVAL))
			eio_inval_range(dmc, ebio->eb_sector, ebio->eb_size);
		if (ebio->eb_next)
			eio_flag_abios(dmc, ebio->eb_next,
				       error || (ebio->eb_iotype & EB_INVAL));
		eb_endio(ebio, error);
		job->ebio = NULL;
		eio_free_cache_job(job);
		return;

	case READDISK:

		if (unlikely(error) || unlikely(ebio->eb_iotype & EB_INVAL)
		    || CACHE_DEGRADED_IS_SET(dmc)) {
			if (error)
				dmc->eio_errors.disk_read_errors++;
			eio_inval_range(dmc, ebio->eb_sector, ebio->eb_size);
			eio_flag_abios(dmc, ebio->eb_next, 1);
		} else if (ebio->eb_next) {
			eio_uncached_read_done(job);
			return;
		}
		eb_endio(ebio, error);
		job->ebio = NULL;
		eio_free_cache_job(job);
		return;

	case READCACHE:

		/*atomic64_inc(&dmc->eio_stats.readcache);*/
		/*SECTOR_STATS(dmc->eio_stats.ssd_reads, ebio->eb_size);*/
		EIO_ASSERT(EIO_DBN_GET(dmc, index) ==
			   EIO_ROUND_SECTOR(dmc, ebio->eb_sector));
		cstate = EIO_CACHE_STATE_GET(dmc, index);
		/* We shouldn't reach here for DIRTY_INPROG blocks. */
		EIO_ASSERT(cstate != DIRTY_INPROG);
		if (unlikely(error)) {
			dmc->eio_errors.ssd_read_errors++;
			/* Retry read from HDD for non-DIRTY blocks. */
			if (cstate != ALREADY_DIRTY) {
				spin_lock_irqsave(&dmc->cache_sets[eb_cacheset].
						  cs_lock, flags);
				EIO_CACHE_STATE_OFF(dmc, ebio->eb_index,
						    CACHEREADINPROG);
				EIO_CACHE_STATE_ON(dmc, ebio->eb_index,
						   DISKREADINPROG);
				spin_unlock_irqrestore(&dmc->
						       cache_sets[eb_cacheset].
						       cs_lock, flags);

				eio_push_ssdread_failures(job);
				schedule_work(&_kcached_wq);

				return;
			}
		}
		callendio = 1;
		break;

	case READFILL:

		/*atomic64_inc(&dmc->eio_stats.readfill);*/
		/*SECTOR_STATS(dmc->eio_stats.ssd_writes, ebio->eb_size);*/
		EIO_ASSERT(EIO_DBN_GET(dmc, index) == ebio->eb_sector);
		if (unlikely(error))
			dmc->eio_errors.ssd_write_errors++;
		if (!(EIO_CACHE_STATE_GET(dmc, index) & CACHEWRITEINPROG)) {
			pr_debug("DISKWRITEINPROG absent in READFILL \
				sector %llu io size %u\n",
				(unsigned long long)ebio->eb_sector,
			       ebio->eb_size);
		}
		callendio = 1;
		break;

	case WRITECACHE:

		/*SECTOR_STATS(dmc->eio_stats.ssd_writes, ebio->eb_size);*/
		/*atomic64_inc(&dmc->eio_stats.writecache);*/
		cstate = EIO_CACHE_STATE_GET(dmc, index);
		EIO_ASSERT(EIO_DBN_GET(dmc, index) ==
			   EIO_ROUND_SECTOR(dmc, ebio->eb_sector));
		/* CWIP is a must for WRITECACHE, except when it is DIRTY */
		EIO_ASSERT(cstate & (CACHEWRITEINPROG | DIRTY));
		if (likely(error == 0)) {
			/* If it is a DIRTY inprog block, proceed for metadata update */
			if (cstate == DIRTY_INPROG) {
				eio_md_write(job);
				return;
			}
		} else {
			/* TODO: ask if this if condition is required */
			if (dmc->mode == CACHE_MODE_WT)
				dmc->eio_errors.disk_write_errors++;
			dmc->eio_errors.ssd_write_errors++;
		}
		job->ebio = NULL;
		break;

	default:
		pr_err("io_callback: invalid action %d", job->action);
		return;
	}

	spin_lock_irqsave(&dmc->cache_sets[eb_cacheset].cs_lock, flags);

	cstate = EIO_CACHE_STATE_GET(dmc, index);
	EIO_ASSERT(!(cstate & INVALID));

	if (unlikely
		    ((job->action == WRITECACHE) && !(cstate & DISKWRITEINPROG))) {
		/*
		 * Can reach here in 2 cases:
		 * 1. Uncached write case, where WRITEDISK has finished first
		 * 2. Cached write case
		 *
		 * For DIRTY or DIRTY inprog cases, use eb holdcount to determine
		 * if end ebio can be called. This is because, we don't set DWIP etc
		 * flags on those and we have to avoid double end ebio call
		 */
		EIO_ASSERT((cstate != DIRTY_INPROG) || error);
		callendio = 1;
		if ((cstate & DIRTY)
		    && !atomic_dec_and_test(&ebio->eb_holdcount))
			callendio = 0;
	}

	if (cstate & DISKWRITEINPROG) {
		/* uncached write and WRITEDISK is not yet finished */
		EIO_ASSERT(!(cstate & DIRTY));      /* For dirty blocks, we can't have DWIP flag */
		if (error)
			EIO_CACHE_STATE_ON(dmc, index, QUEUED);
		EIO_CACHE_STATE_OFF(dmc, index, CACHEWRITEINPROG);
	} else if (unlikely(error || (cstate & QUEUED))) {
		/* Error or QUEUED is set: mark block as INVALID for non-DIRTY blocks */
		if (cstate != ALREADY_DIRTY) {
			EIO_CACHE_STATE_SET(dmc, index, INVALID);
			atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
		}
	} else if (cstate & VALID) {
		EIO_CACHE_STATE_OFF(dmc, index, BLOCK_IO_INPROG);
		/*
		 * If we have NO_SSD_IO_INPROG flag set, then this block needs to be
		 * invalidated. There are three things that can happen -- (i) error,
		 * (ii) IOs are queued on this block, and (iii) success.
		 *
		 * If there was an error or if the QUEUED bit was set, then the logic
		 * in the if part will take care of setting the block to INVALID.
		 * Therefore, this is the success path where we invalidate if need be.
		 */

		/*
		 * TBD
		 * NO_SSD_IO_INPROG need to be differently handled, in case block is DIRTY
		 */
		if ((cstate & NO_SSD_IO_INPROG) == NO_SSD_IO_INPROG)
			EIO_CACHE_STATE_OFF(dmc, index, VALID);
	}

	spin_unlock_irqrestore(&dmc->cache_sets[eb_cacheset].cs_lock, flags);

	if (callendio)
		eb_endio(ebio, error);

	eio_free_cache_job(job);
	job = NULL;

}

/*
 * This function processes the kcached_job that
 * needs to be scheduled on disk after ssd read failures.
 */
void eio_ssderror_diskread(struct kcached_job *job)
{
	struct cache_c *dmc;
	struct eio_bio *ebio;
	index_t index;
	int error;
	unsigned long flags = 0;

	dmc = job->dmc;
	error = 0;

	/*
	 * 1. Extract the ebio which needs to be scheduled on disk.
	 * 2. Verify cache block state is VALID
	 * 3. Make sure that the cache state in not IOINPROG
	 */
	/* Reset the ssd read error in the job. */
	job->error = 0;
	ebio = job->ebio;
	index = ebio->eb_index;

	EIO_ASSERT(index != -1);

	spin_lock_irqsave(&dmc->cache_sets[index / dmc->assoc].cs_lock, flags);
	EIO_ASSERT(EIO_CACHE_STATE_GET(dmc, index) & DISKREADINPROG);
	spin_unlock_irqrestore(&dmc->cache_sets[index / dmc->assoc].cs_lock,
			       flags);

	EIO_ASSERT(ebio->eb_dir == READ);

	atomic64_inc(&dmc->eio_stats.readdisk);
	SECTOR_STATS(dmc->eio_stats.disk_reads, ebio->eb_size);
	job->action = READDISK;

	error = eio_io_async_bvec(dmc, &job->job_io_regions.disk, ebio->eb_dir,
				  ebio->eb_bv, ebio->eb_nbvec,
				  eio_disk_io_callback, job, 1);

	/*
	 * In case of disk i/o submission error clear ebio and kcached_job.
	 * This would return the actual read that was issued on ssd.
	 */
	if (error)
		goto out;

	return;

out:
	/* We failed to submit the I/O to dm layer. The corresponding
	 * block should be marked as INVALID by turning off already set
	 * flags.
	 */
	spin_lock_irqsave(&dmc->cache_sets[index / dmc->assoc].cs_lock, flags);
	EIO_CACHE_STATE_SET(dmc, ebio->eb_index, INVALID);
	spin_unlock_irqrestore(&dmc->cache_sets[index / dmc->assoc].cs_lock,
			       flags);

	atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);

	eb_endio(ebio, error);
	ebio = NULL;
	job->ebio = NULL;
	eio_free_cache_job(job);
}

/* Adds clean set request to clean queue. */
static void eio_addto_cleanq(struct cache_c *dmc, index_t set, int whole)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&dmc->cache_sets[set].cs_lock, flags);

	if (dmc->cache_sets[set].flags & SETFLAG_CLEAN_INPROG) {
		/* Clean already in progress, just add to clean pendings */
		spin_unlock_irqrestore(&dmc->cache_sets[set].cs_lock, flags);
		return;
	}

	dmc->cache_sets[set].flags |= SETFLAG_CLEAN_INPROG;
	if (whole)
		dmc->cache_sets[set].flags |= SETFLAG_CLEAN_WHOLE;

	spin_unlock_irqrestore(&dmc->cache_sets[set].cs_lock, flags);

	spin_lock_irqsave(&dmc->clean_sl, flags);
	list_add_tail(&dmc->cache_sets[set].list, &dmc->cleanq);
	atomic64_inc(&dmc->clean_pendings);
	EIO_SET_EVENT_AND_UNLOCK(&dmc->clean_event, &dmc->clean_sl, flags);
	return;
}

/*
 * Clean thread loops forever in this, waiting for
 * new clean set requests in the clean queue.
 */
int eio_clean_thread_proc(void *context)
{
	struct cache_c *dmc = (struct cache_c *)context;
	unsigned long flags = 0;
	u_int64_t systime;
	index_t index;
	index_t clean_set_array[NR_CLEAN_SET] = {-1, };
	int nr_to_clean = 0;
	int i;
	

	/* Sync makes sense only for writeback cache */
	EIO_ASSERT(dmc->mode == CACHE_MODE_WB);

	dmc->clean_thread_running = 1;

	/*
	 * Using sysctl_fast_remove to stop the clean thread
	 * works for now. Should have another flag specifically
	 * for such notification.
	 */
	for (; !dmc->sysctl_active.fast_remove; ) {
		LIST_HEAD(setlist);
		struct cache_set *set;

		eio_comply_dirty_thresholds(dmc, -1);

		if (dmc->sysctl_active.do_clean) {
			/* pause the periodic clean */
			
			cancel_delayed_work_sync(&dmc->clean_aged_sets_work);
			/* clean all the sets */
			eio_clean_all(dmc);
			/* resume the periodic clean */
			spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
			dmc->is_clean_aged_sets_sched = 0;
			if (dmc->sysctl_active.enable_aged_clean
				&& dmc->sysctl_active.time_based_clean_interval
			    && atomic64_read(&dmc->nr_dirty)) {
				/* there is a potential race here, If a sysctl changes
				   the time_based_clean_interval to 0. However a strong
				   synchronisation is not necessary here
				 */
				schedule_delayed_work(&dmc->
						      clean_aged_sets_work,
						      dmc->sysctl_active.
						      time_based_clean_interval
						      * 60 * HZ);
				dmc->is_clean_aged_sets_sched = 1;
			}
			spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
		}

		if (dmc->sysctl_active.fast_remove)
			break;

		spin_lock_irqsave(&dmc->clean_sl, flags);

		while (!
		       ((!list_empty(&dmc->cleanq))
			|| dmc->sysctl_active.fast_remove
			|| dmc->sysctl_active.do_clean))
			EIO_WAIT_EVENT(&dmc->clean_event, &dmc->clean_sl,
				       flags);

		/*
		 * Move cleanq elements to a private list for processing.
		 */

		list_add(&setlist, &dmc->cleanq);
		list_del(&dmc->cleanq);
		INIT_LIST_HEAD(&dmc->cleanq);

		spin_unlock_irqrestore(&dmc->clean_sl, flags);

		systime = jiffies;
		while (!list_empty(&setlist)) {
			set =
				list_entry((&setlist)->next, struct cache_set,
					   list);
			list_del(&set->list);
			index = set - dmc->cache_sets;
		#ifdef CONFIG_LOW_IO_PRESSURE_CLEAN
			if (atomic_read(&dmc->flag_rm_sets) && !(dmc->sysctl_active.fast_remove)) {
				if (dmc->cache_sets[index].flags & SETFLAG_CLEAN_LOW_IO_PRESSURE) {					
					EIO_DBG(INFO, dmc, 
					"remove set[%lu],SETFLAG_CLEAN_LOW_IO_PRESSUREflag set\n",
					(unsigned long)index);
					/*remove set*/					
					spin_lock_irqsave(&dmc->cache_sets[index].
							  cs_lock, flags);
					dmc->cache_sets[index].flags &=
						~(SETFLAG_CLEAN_INPROG |
						  SETFLAG_CLEAN_WHOLE |
						  SETFLAG_CLEAN_LOW_IO_PRESSURE);
					spin_unlock_irqrestore(&dmc->cache_sets[index].
								   cs_lock, flags);
					spin_lock_irqsave(&dmc->dirty_set_lru_lock,
							  flags);
					lru_touch(dmc->dirty_set_lru, index, systime);
					spin_unlock_irqrestore(&dmc->dirty_set_lru_lock,
							   flags);
					atomic64_dec(&dmc->clean_pendings);
					continue;
				}
			}
		#endif
		
		#ifdef CONFIG_SKIP_SEQUENTIAL_IO
		spin_lock_irqsave(&dmc->cache_sets[index].cs_lock, flags);
		/*this cache set is doing sequetial IO,do not flush*/
		if (dmc->cache_sets[index].flags & SETFLAG_SKIP_SEQUENTIAL_IO) {
			/*clear all flags expect SETFLAG_SKIP_SEQUENTIAL_IO,clear flag 
			SETFLAG_SKIP_SEQUENTIAL_IO when sequentail IO done*/
			dmc->cache_sets[index].flags &=
				~(SETFLAG_CLEAN_INPROG |
				  SETFLAG_CLEAN_WHOLE 
				  #ifdef CONFIG_LOW_IO_PRESSURE_CLEAN
				  |SETFLAG_CLEAN_LOW_IO_PRESSURE
				  #endif
				  );
			atomic64_inc(&dmc->eio_stats.seq_io_dirty);			
			spin_unlock_irqrestore(&dmc->cache_sets[index].cs_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&dmc->cache_sets[index].
					   cs_lock, flags);
		#endif

			clean_set_array[nr_to_clean++] = index;
			
			if (!(dmc->sysctl_active.fast_remove)) {
				if (dmc->sysctl_active.enable_sort_flush) {
					/*sort flush*/
					if (NR_CLEAN_SET == nr_to_clean || list_empty(&setlist)) {
						/*eio_clean_set(dmc, index,
							      set->flags & SETFLAG_CLEAN_WHOLE,
							      0);*/
						eio_clean_n_sets(dmc, clean_set_array, nr_to_clean, 0);
						atomic64_sub(nr_to_clean, &dmc->clean_pendings);
						nr_to_clean = 0;
					}
				} else {
					/*non-sort flush*/
					for (i = 0; i < nr_to_clean; i++) {
						index = clean_set_array[i];
						eio_clean_set(dmc, index,
								  set->flags & SETFLAG_CLEAN_WHOLE,
								  0);
					}					
					atomic64_sub(nr_to_clean, &dmc->clean_pendings);
					nr_to_clean = 0;
				}
			} else {
				#if 0
				/*
				 * Since we are not cleaning the set, we should
				 * put the set back in the lru list so that
				 * it is picked up at a later point.
				 * We also need to clear the clean inprog flag
				 * otherwise this set would never be cleaned.
				 */

				spin_lock_irqsave(&dmc->cache_sets[index].
						  cs_lock, flags);
				dmc->cache_sets[index].flags &=
					~(SETFLAG_CLEAN_INPROG |
					  SETFLAG_CLEAN_WHOLE);
				spin_unlock_irqrestore(&dmc->cache_sets[index].
						       cs_lock, flags);
				spin_lock_irqsave(&dmc->dirty_set_lru_lock,
						  flags);
				lru_touch(dmc->dirty_set_lru, index, systime);
				spin_unlock_irqrestore(&dmc->dirty_set_lru_lock,
						       flags);
				#endif
				
				do {
					index = clean_set_array[--nr_to_clean];
					spin_lock_irqsave(&dmc->cache_sets[index].
							  cs_lock, flags);
					dmc->cache_sets[index].flags &=
						~(SETFLAG_CLEAN_INPROG |
						  SETFLAG_CLEAN_WHOLE
						#ifdef CONFIG_LOW_IO_PRESSURE_CLEAN
							| SETFLAG_CLEAN_LOW_IO_PRESSURE  
						#endif
						);
					spin_unlock_irqrestore(&dmc->cache_sets[index].
								   cs_lock, flags);
					spin_lock_irqsave(&dmc->dirty_set_lru_lock,
							  flags);
					lru_touch(dmc->dirty_set_lru, index, systime);
					spin_unlock_irqrestore(&dmc->dirty_set_lru_lock,
							   flags);
				} while(nr_to_clean > 0);	
				atomic64_sub(nr_to_clean, &dmc->clean_pendings);
				nr_to_clean = 0;
			}
			//atomic64_dec(&dmc->clean_pendings);
		}
	}

	/* notifier for cache delete that the clean thread has stopped running */
	dmc->clean_thread_running = 0;

	eio_thread_exit(0);

	/*Should never reach here*/
	return 0;
}

/*
 * Cache miss support. We read the data from disk, write it to the ssd.
 * To avoid doing 1 IO at a time to the ssd, when the IO is kicked off,
 * we enqueue it to a "readfill" queue in the cache in cache sector order.
 * The worker thread can then issue all of these IOs and do 1 unplug to
 * start them all.
 *
 */
static void eio_enqueue_readfill(struct cache_c *dmc, struct kcached_job *job)
{
	unsigned long flags = 0;
	struct kcached_job **j1, *next;
	int do_schedule = 0;

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	/* Insert job in sorted order of cache sector */
	j1 = &dmc->readfill_queue;
	while (*j1 != NULL && (*j1)->job_io_regions.cache.sector <
	       job->job_io_regions.cache.sector)
		j1 = &(*j1)->next;
	next = *j1;
	*j1 = job;
	job->next = next;
	do_schedule = (dmc->readfill_in_prog == 0);
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
	if (do_schedule)
		schedule_work(&dmc->readfill_wq);
}

void eio_do_readfill(struct work_struct *work)
{
	struct kcached_job *job, *joblist;
	struct eio_bio *ebio;
	unsigned long flags = 0;
	struct kcached_job *nextjob = NULL;
	struct cache_c *dmc = container_of(work, struct cache_c, readfill_wq);

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	if (dmc->readfill_in_prog)
		goto out;
	dmc->readfill_in_prog = 1;
	while (dmc->readfill_queue != NULL) {
		joblist = dmc->readfill_queue;
		dmc->readfill_queue = NULL;
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		for (job = joblist; job != NULL; job = nextjob) {
			struct eio_bio *iebio;
			struct eio_bio *next;

			nextjob = job->next;    /* save for later because 'job' will be freed */
			EIO_ASSERT(job->action == READFILL);
			/* Write to cache device */
			ebio = job->ebio;
			iebio = ebio->eb_next;
			EIO_ASSERT(iebio);
			/* other iebios are anchored on this bio. Create
			 * jobs for them and then issue ios
			 */
			do {
				struct kcached_job *job;
				int err;
				unsigned long flags;
				index_t index;
				next = iebio->eb_next;
				index = iebio->eb_index;
				if (index == -1) {
					CTRACE("eio_do_readfill:1\n");
					/* Any INPROG(including DIRTY_INPROG) case would fall here */
					eb_endio(iebio, 0);
					iebio = NULL;
				} else {
					spin_lock_irqsave(&dmc->
							  cache_sets[iebio->
								     eb_cacheset].
							  cs_lock, flags);
					/* If this block was already  valid, we don't need to write it */
					if (unlikely
						    (EIO_CACHE_STATE_GET(dmc, index) &
						    QUEUED)) {
						/*An invalidation request is queued. Can't do anything*/
						CTRACE("eio_do_readfill:2\n");
						EIO_CACHE_STATE_SET(dmc, index,
								    INVALID);
						spin_unlock_irqrestore(&dmc->
								       cache_sets
								       [iebio->
									eb_cacheset].
								       cs_lock,
								       flags);
						atomic64_dec_if_positive(&dmc->
									 eio_stats.
									 cached_blocks);
						eb_endio(iebio, 0);
						iebio = NULL;
					} else
					if ((EIO_CACHE_STATE_GET(dmc, index)
					     & (VALID | DISKREADINPROG))
					    == (VALID | DISKREADINPROG)) {
						/* Do readfill. */
						EIO_CACHE_STATE_SET(dmc, index,
								    VALID |
								    CACHEWRITEINPROG);
						EIO_ASSERT(EIO_DBN_GET(dmc, index)
							   == iebio->eb_sector);
						spin_unlock_irqrestore(&dmc->
								       cache_sets
								       [iebio->
									eb_cacheset].
								       cs_lock,
								       flags);
						job =
							eio_new_job(dmc, iebio,
								    iebio->
								    eb_index);
						if (unlikely(job == NULL))
							err = -ENOMEM;
						else {
							err = 0;
							job->action = READFILL;
							atomic_inc(&dmc->
								   nr_jobs);
							SECTOR_STATS(dmc->
								     eio_stats.
								     ssd_readfills,
								     iebio->
								     eb_size);
							SECTOR_STATS(dmc->
								     eio_stats.
								     ssd_writes,
								     iebio->
								     eb_size);
							atomic64_inc(&dmc->
								     eio_stats.
								     readfill);
							atomic64_inc(&dmc->
								     eio_stats.
								     writecache);
							err =
								eio_io_async_bvec
									(dmc,
									&job->
									job_io_regions.
									cache, WRITE,
									iebio->eb_bv,
									iebio->eb_nbvec,
									eio_io_callback,
									job, 0);
						}
						if (err) {
							pr_err
								("eio_do_readfill: IO submission failed, block %llu",
								EIO_DBN_GET(dmc,
									    index));
							spin_lock_irqsave(&dmc->
									  cache_sets
									  [iebio->
									   eb_cacheset].
									  cs_lock,
									  flags);
							EIO_CACHE_STATE_SET(dmc,
									    iebio->
									    eb_index,
									    INVALID);
							spin_unlock_irqrestore
								(&dmc->
								cache_sets[iebio->
									   eb_cacheset].
								cs_lock, flags);
							atomic64_dec_if_positive
								(&dmc->eio_stats.
								cached_blocks);
							eb_endio(iebio, err);

							if (job) {
								eio_free_cache_job
									(job);
								job = NULL;
							}
						}
					} else
					if (EIO_CACHE_STATE_GET(dmc, index)
					    == ALREADY_DIRTY) {

						spin_unlock_irqrestore(&dmc->
								       cache_sets
								       [iebio->
									eb_cacheset].
								       cs_lock,
								       flags);

						/*
						 * DIRTY block handling:
						 * Read the dirty data from the cache block to update
						 * the data buffer already read from the disk
						 */
						job =
							eio_new_job(dmc, iebio,
								    iebio->
								    eb_index);
						if (unlikely(job == NULL))
							err = -ENOMEM;
						else {
							job->action = READCACHE;
							SECTOR_STATS(dmc->
								     eio_stats.
								     ssd_reads,
								     iebio->
								     eb_size);
							atomic64_inc(&dmc->
								     eio_stats.
								     readcache);
							err =
								eio_io_async_bvec
									(dmc,
									&job->
									job_io_regions.
									cache, READ,
									iebio->eb_bv,
									iebio->eb_nbvec,
									eio_io_callback,
									job, 0);
						}

						if (err) {
							pr_err
								("eio_do_readfill: dirty block read IO submission failed, block %llu",
								EIO_DBN_GET(dmc,
									    index));
							/* can't invalidate the DIRTY block, just return error */
							eb_endio(iebio, err);
							if (job) {
								eio_free_cache_job
									(job);
								job = NULL;
							}
						}
					} else
					if ((EIO_CACHE_STATE_GET(dmc, index)
					     & (VALID | CACHEREADINPROG))
					    == (VALID | CACHEREADINPROG)) {
						/*turn off the cache read in prog flag
						   don't need to write the cache block*/
						CTRACE("eio_do_readfill:3\n");
						EIO_CACHE_STATE_OFF(dmc, index,
								    BLOCK_IO_INPROG);
						spin_unlock_irqrestore(&dmc->
								       cache_sets
								       [iebio->
									eb_cacheset].
								       cs_lock,
								       flags);
						eb_endio(iebio, 0);
						iebio = NULL;
					} else {
						panic("Unknown condition");
						spin_unlock_irqrestore(&dmc->
								       cache_sets
								       [iebio->
									eb_cacheset].
								       cs_lock,
								       flags);
					}
				}
				iebio = next;
			} while (iebio);
			eb_endio(ebio, 0);
			ebio = NULL;
			eio_free_cache_job(job);
		}
		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	}
	dmc->readfill_in_prog = 0;
out:
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
	atomic64_inc(&dmc->eio_stats.ssd_readfill_unplugs);
	eio_unplug_cache_device(dmc);
}

/*
 * Map a block from the source device to a block in the cache device.
 */
static u_int32_t hash_block(struct cache_c *dmc, sector_t dbn)
{
	u_int32_t set_number;

	set_number = eio_hash_block(dmc, dbn);
	return set_number;
}

static void
find_valid_dbn(struct cache_c *dmc, sector_t dbn,
	       index_t start_index, index_t *index)
{
	index_t i;
	index_t end_index = start_index + dmc->assoc;

	for (i = start_index; i < end_index; i++) {
		if ((EIO_CACHE_STATE_GET(dmc, i) & VALID)
		    && EIO_DBN_GET(dmc, i) == dbn) {
			*index = i;
			if ((EIO_CACHE_STATE_GET(dmc, i) & BLOCK_IO_INPROG) ==
			    0)
				eio_policy_reclaim_lru_movetail(dmc, i,
								dmc->
								policy_ops);
			return;
		}
	}
	*index = -1;
}

static index_t find_invalid_dbn(struct cache_c *dmc, index_t start_index)
{
	index_t i;
	index_t end_index = start_index + dmc->assoc;

	/* Find INVALID slot that we can reuse */
	for (i = start_index; i < end_index; i++) {
		if (EIO_CACHE_STATE_GET(dmc, i) == INVALID) {
			eio_policy_reclaim_lru_movetail(dmc, i,
							dmc->policy_ops);
			return i;
		}
	}
	return -1;
}

/* Search for a slot that we can reclaim */
static void
find_reclaim_dbn(struct cache_c *dmc, index_t start_index, index_t *index)
{
	eio_find_reclaim_dbn(dmc->policy_ops, start_index, index);
}

void eio_set_warm_boot(void)
{
	eio_force_warm_boot = 1;
	return;
}

/*
 * dbn is the starting sector.
 */
static int
eio_lookup(struct cache_c *dmc, struct eio_bio *ebio, index_t *index)
{
	sector_t dbn = EIO_ROUND_SECTOR(dmc, ebio->eb_sector);
	u_int32_t set_number;
	index_t invalid, oldest_clean = -1;
	index_t start_index;

	/*ASK it is assumed that the lookup is being done for a single block*/
	set_number = hash_block(dmc, dbn);
	start_index = dmc->assoc * set_number;
	find_valid_dbn(dmc, dbn, start_index, index);
	if (*index >= 0)
		/* We found the exact range of blocks we are looking for */
		return VALID;

	invalid = find_invalid_dbn(dmc, start_index);
	if (invalid == -1)
		/* We didn't find an invalid entry, search for oldest valid entry */
		find_reclaim_dbn(dmc, start_index, &oldest_clean);
	/*
	 * Cache miss :
	 * We can't choose an entry marked INPROG, but choose the oldest
	 * INVALID or the oldest VALID entry.
	 */
	*index = start_index + dmc->assoc;
	if (invalid != -1) {
		*index = invalid;
		return INVALID;
	} else if (oldest_clean != -1) {
		*index = oldest_clean;
		return VALID;
	}
	return -1;
}

/* Do metadata update for a set */
static void eio_do_mdupdate(struct work_struct *work)
{
	struct mdupdate_request *mdreq;
	struct cache_set *set;
	struct cache_c *dmc;
	unsigned long flags;
	index_t i;
	index_t start_index;
	index_t end_index;
	index_t min_index;
	index_t max_index;
	struct flash_cacheblock *md_blocks;
	struct eio_bio *ebio;
	u_int8_t cstate;
	struct eio_io_region region;
	unsigned pindex;
	int error, j;
	index_t blk_index;
	int k;
	void *pg_virt_addr[2] = { NULL };
	u_int8_t sector_bits[2] = { 0 };
	int startbit, endbit;
	int rw_flags = 0;

	mdreq = container_of(work, struct mdupdate_request, work);
	dmc = mdreq->dmc;
	set = &dmc->cache_sets[mdreq->set];

	mdreq->error = 0;
	EIO_ASSERT(mdreq->mdblk_bvecs);

	/*
	 * md_size = dmc->assoc * sizeof(struct flash_cacheblock);
	 * Currently, md_size is 8192 bytes, mdpage_count is 2 pages maximum.
	 */

	EIO_ASSERT(mdreq->mdbvec_count && mdreq->mdbvec_count <= 2);
	EIO_ASSERT((dmc->assoc == 512) || mdreq->mdbvec_count == 1);
	for (k = 0; k < (int)mdreq->mdbvec_count; k++)
		pg_virt_addr[k] = kmap(mdreq->mdblk_bvecs[k].bv_page);

	spin_lock_irqsave(&set->cs_lock, flags);

	start_index = mdreq->set * dmc->assoc;
	end_index = start_index + dmc->assoc;

	pindex = 0;
	md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];
	j = MD_BLOCKS_PER_PAGE;

	/* initialize the md blocks to write */
	for (i = start_index; i < end_index; i++) {
		cstate = EIO_CACHE_STATE_GET(dmc, i);
		md_blocks->dbn = cpu_to_le64(EIO_DBN_GET(dmc, i));
		if (cstate == ALREADY_DIRTY)
			md_blocks->cache_state = cpu_to_le64((VALID | DIRTY));
		else
			md_blocks->cache_state = cpu_to_le64(INVALID);
		md_blocks++;
		j--;

		if ((j == 0) && (++pindex < mdreq->mdbvec_count)) {
			md_blocks =
				(struct flash_cacheblock *)pg_virt_addr[pindex];
			j = MD_BLOCKS_PER_PAGE;
		}

	}

	/* Update the md blocks with the pending mdlist */
	min_index = start_index;
	max_index = start_index;

	pindex = 0;
	md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];

	ebio = mdreq->pending_mdlist;
	while (ebio) {
		EIO_ASSERT(EIO_CACHE_STATE_GET(dmc, ebio->eb_index) ==
			   DIRTY_INPROG);

		blk_index = ebio->eb_index - start_index;
		pindex = INDEX_TO_MD_PAGE(blk_index);
		blk_index = INDEX_TO_MD_PAGE_OFFSET(blk_index);
		sector_bits[pindex] |= (1 << INDEX_TO_MD_SECTOR(blk_index));

		md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];
		md_blocks[blk_index].cache_state = (VALID | DIRTY);

		if (min_index > ebio->eb_index)
			min_index = ebio->eb_index;

		if (max_index < ebio->eb_index)
			max_index = ebio->eb_index;

		ebio = ebio->eb_next;
	}

	/*
	 * Below code may be required when selective pages need to be
	 * submitted for metadata update. Currently avoiding the optimization
	 * for correctness validation.
	 */

	/*
	   min_cboff = (min_index - start_index) / MD_BLOCKS_PER_CBLOCK(dmc);
	   max_cboff = (max_index - start_index) / MD_BLOCKS_PER_CBLOCK(dmc);
	   write_size = ((uint32_t)(max_cboff - min_cboff + 1)) << dmc->block_shift;
	   EIO_ASSERT(write_size && (write_size <= eio_to_sector(mdreq->md_size)));
	 */

	/* Move the pending mdlist to inprog list */
	mdreq->inprog_mdlist = mdreq->pending_mdlist;
	mdreq->pending_mdlist = NULL;

	spin_unlock_irqrestore(&set->cs_lock, flags);

	for (k = 0; k < (int)mdreq->mdbvec_count; k++)
		kunmap(mdreq->mdblk_bvecs[k].bv_page);

	/*
	 * Initiate the I/O to SSD for on-disk md update.
	 * TBD. Optimize to write only the affected blocks
	 */

	region.bdev = dmc->cache_dev->bdev;
	/*region.sector = dmc->md_start_sect + INDEX_TO_MD_SECTOR(start_index) +
	   (min_cboff << dmc->block_shift); */

	atomic_set(&mdreq->holdcount, 1);
	for (i = 0; i < mdreq->mdbvec_count; i++) {
		if (!sector_bits[i])
			continue;
		startbit = -1;
		j = 0;
		while (startbit == -1) {
			if (sector_bits[i] & (1 << j))
				startbit = j;
			j++;
		}
		endbit = -1;
		j = 7;
		while (endbit == -1) {
			if (sector_bits[i] & (1 << j))
				endbit = j;
			j--;
		}
		EIO_ASSERT(startbit <= endbit && startbit >= 0 && startbit <= 7 &&
			   endbit >= 0 && endbit <= 7);
		EIO_ASSERT(dmc->assoc != 128 || endbit <= 3);
		region.sector =
			dmc->md_start_sect + INDEX_TO_MD_SECTOR(start_index) +
			i * SECTORS_PER_PAGE + startbit;
		region.count = endbit - startbit + 1;
		mdreq->mdblk_bvecs[i].bv_offset = to_bytes(startbit);
		mdreq->mdblk_bvecs[i].bv_len = to_bytes(region.count);

		EIO_ASSERT(region.sector <=
			   (dmc->md_start_sect + INDEX_TO_MD_SECTOR(end_index)));
		atomic64_inc(&dmc->eio_stats.md_ssd_writes);
		SECTOR_STATS(dmc->eio_stats.ssd_writes, to_bytes(region.count));
		atomic_inc(&mdreq->holdcount);

		/*
		 * Set SYNC for making metadata
		 * writes as high priority.
		 */
		rw_flags = WRITE | REQ_SYNC;
		error = eio_io_async_bvec(dmc, &region, rw_flags,
					  &mdreq->mdblk_bvecs[i], 1,
					  eio_mdupdate_callback, work, 0);
		if (error && !(mdreq->error))
			mdreq->error = error;
	}
	if (atomic_dec_and_test(&mdreq->holdcount)) {
		INIT_WORK(&mdreq->work, eio_post_mdupdate);
		queue_work(dmc->mdupdate_q, &mdreq->work);
	}
}

/* Callback function for ondisk metadata update */
static void eio_mdupdate_callback(int error, void *context)
{
	struct work_struct *work = (struct work_struct *)context;
	struct mdupdate_request *mdreq;

	mdreq = container_of(work, struct mdupdate_request, work);
	if (error && !(mdreq->error))
		mdreq->error = error;
	if (!atomic_dec_and_test(&mdreq->holdcount))
		return;
	INIT_WORK(&mdreq->work, eio_post_mdupdate);
	queue_work(mdreq->dmc->mdupdate_q, &mdreq->work);
}

static void eio_post_mdupdate(struct work_struct *work)
{
	struct mdupdate_request *mdreq;
	struct cache_set *set;
	struct cache_c *dmc;
	unsigned long flags;
	struct eio_bio *ebio;
	struct eio_bio *nebio;
	int more_pending_mdupdates = 0;
	int error;
	index_t set_index;

	mdreq = container_of(work, struct mdupdate_request, work);

	dmc = mdreq->dmc;
	EIO_ASSERT(dmc);
	set_index = mdreq->set;
	set = &dmc->cache_sets[set_index];
	error = mdreq->error;

	/* Update in-core cache metadata */

	spin_lock_irqsave(&set->cs_lock, flags);

	/*
	 * Update dirty inprog blocks.
	 * On error, convert them to INVALID
	 * On success, convert them to ALREADY_DIRTY
	 */
	ebio = mdreq->inprog_mdlist;
	while (ebio) {
		EIO_ASSERT(EIO_CACHE_STATE_GET(dmc, ebio->eb_index) ==
			   DIRTY_INPROG);
		if (unlikely(error)) {
			EIO_CACHE_STATE_SET(dmc, ebio->eb_index, INVALID);
			atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
		} else {
			EIO_CACHE_STATE_SET(dmc, ebio->eb_index, ALREADY_DIRTY);
			set->nr_dirty++;
			atomic64_inc(&dmc->nr_dirty);
			atomic64_inc(&dmc->eio_stats.md_write_dirty);
		}
		ebio = ebio->eb_next;
	}

	/*
	 * If there are more pending requests for md update,
	 * need to pick up those using the current mdreq.
	 */
	if (mdreq->pending_mdlist)
		more_pending_mdupdates = 1;
	else
		/* No request pending, we can free the mdreq */
		set->mdreq = NULL;

	/*
	 * After we unlock the set, we need to end the I/Os,
	 * which were processed as part of this md update
	 */

	ebio = mdreq->inprog_mdlist;
	mdreq->inprog_mdlist = NULL;

	spin_unlock_irqrestore(&set->cs_lock, flags);

	/* End the processed I/Os */
	while (ebio) {
		nebio = ebio->eb_next;
		eb_endio(ebio, error);
		ebio = nebio;
	}

	/*
	 * if dirty block was added
	 * 1. update the cache set lru list
	 * 2. check and initiate cleaning if thresholds are crossed
	 */
	if (!error) {
		eio_touch_set_lru(dmc, set_index);
		eio_comply_dirty_thresholds(dmc, set_index);
	}

	if (more_pending_mdupdates) {
		/*
		 * Schedule work to process the new
		 * pending mdupdate requests
		 */
		INIT_WORK(&mdreq->work, eio_do_mdupdate);
		queue_work(dmc->mdupdate_q, &mdreq->work);
	} else {
		/*
		 * No more pending mdupdates.
		 * Free the mdreq.
		 */
		if (mdreq->mdblk_bvecs) {
			eio_free_wb_bvecs(mdreq->mdblk_bvecs,
					  mdreq->mdbvec_count,
					  SECTORS_PER_PAGE);
			kfree(mdreq->mdblk_bvecs);
		}

		kfree(mdreq);
	}
}

/* Enqueue metadata update for marking dirty blocks on-disk/in-core */
static void eio_enq_mdupdate(struct bio_container *bc)
{
	unsigned long flags = 0;
	index_t set_index;
	struct eio_bio *ebio;
	struct cache_c *dmc = bc->bc_dmc;
	struct cache_set *set = NULL;
	struct mdupdate_request *mdreq;
	int do_schedule;

	ebio = bc->bc_mdlist;
	set_index = -1;
	do_schedule = 0;
	while (ebio) {
		if (ebio->eb_cacheset != set_index) {
			set_index = ebio->eb_cacheset;
			set = &dmc->cache_sets[set_index];
			spin_lock_irqsave(&set->cs_lock, flags);
		}
		EIO_ASSERT(ebio->eb_cacheset == set_index);

		bc->bc_mdlist = ebio->eb_next;

		if (!set->mdreq) {
			/* Pick up one mdreq from bc */
			mdreq = bc->mdreqs;
			EIO_ASSERT(mdreq != NULL);
			bc->mdreqs = bc->mdreqs->next;
			mdreq->next = NULL;
			mdreq->pending_mdlist = ebio;
			mdreq->dmc = dmc;
			mdreq->set = set_index;
			set->mdreq = mdreq;
			ebio->eb_next = NULL;
			do_schedule = 1;
		} else {
			mdreq = set->mdreq;
			EIO_ASSERT(mdreq != NULL);
			ebio->eb_next = mdreq->pending_mdlist;
			mdreq->pending_mdlist = ebio;
		}

		ebio = bc->bc_mdlist;
		if (!ebio || ebio->eb_cacheset != set_index) {
			spin_unlock_irqrestore(&set->cs_lock, flags);
			if (do_schedule) {
				INIT_WORK(&mdreq->work, eio_do_mdupdate);
				queue_work(dmc->mdupdate_q, &mdreq->work);
				do_schedule = 0;
			}
		}
	}

	EIO_ASSERT(bc->bc_mdlist == NULL);
}

/* Kick-off a cache metadata update for marking the blocks dirty */
void eio_md_write(struct kcached_job *job)
{
	struct eio_bio *ebio = job->ebio;
	struct eio_bio *nebio;
	struct eio_bio *pebio;
	struct bio_container *bc = ebio->eb_bc;
	unsigned long flags;
	int enqueue = 0;

	/*
	 * ebios are stored in ascending order of cache sets.
	 */

	spin_lock_irqsave(&bc->bc_lock, flags);
	EIO_ASSERT(bc->bc_mdwait > 0);
	nebio = bc->bc_mdlist;
	pebio = NULL;
	while (nebio) {
		if (nebio->eb_cacheset > ebio->eb_cacheset)
			break;
		pebio = nebio;
		nebio = nebio->eb_next;
	}
	ebio->eb_next = nebio;
	if (!pebio)
		bc->bc_mdlist = ebio;
	else
		pebio->eb_next = ebio;
	bc->bc_mdwait--;
	if (bc->bc_mdwait == 0)
		enqueue = 1;
	spin_unlock_irqrestore(&bc->bc_lock, flags);

	eio_free_cache_job(job);

	if (enqueue)
		eio_enq_mdupdate(bc);
}

/* Ensure cache level dirty thresholds compliance. If required, trigger cache-wide clean */
static void eio_check_dirty_cache_thresholds(struct cache_c *dmc)
{
	if (DIRTY_CACHE_THRESHOLD_CROSSED(dmc)) {
		int64_t required_cleans;
		int64_t enqueued_cleans;
		u_int64_t set_time;
		index_t set_index;
		unsigned long flags;

		spin_lock_irqsave(&dmc->clean_sl, flags);
		if (atomic64_read(&dmc->clean_pendings)
		    || dmc->clean_excess_dirty) {
			/* Already excess dirty block cleaning is in progress */
			spin_unlock_irqrestore(&dmc->clean_sl, flags);
			return;
		}
		dmc->clean_excess_dirty = 1;
		spin_unlock_irqrestore(&dmc->clean_sl, flags);

		/* Clean needs to be triggered on the cache */
		required_cleans = atomic64_read(&dmc->nr_dirty) -
				  (EIO_DIV((dmc->sysctl_active.dirty_low_threshold * dmc->size),
					   100));
		enqueued_cleans = 0;

		spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
		do {
			lru_rem_head(dmc->dirty_set_lru, &set_index, &set_time);
			if (set_index == LRU_NULL)
				break;

			enqueued_cleans += dmc->cache_sets[set_index].nr_dirty;
			spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
			EIO_DBG(INFO, dmc, "++++++add set[0x%lx] to clean:dirty threshold crossed", set_index);
			eio_addto_cleanq(dmc, set_index, 1);
			spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
		} while (enqueued_cleans <= required_cleans);
		spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
		spin_lock_irqsave(&dmc->clean_sl, flags);
		dmc->clean_excess_dirty = 0;
		spin_unlock_irqrestore(&dmc->clean_sl, flags);
	}
}

/* Ensure set level dirty thresholds compliance. If required, trigger set clean */
static void eio_check_dirty_set_thresholds(struct cache_c *dmc, index_t set)
{
	if (DIRTY_SET_THRESHOLD_CROSSED(dmc, set)) {		
		EIO_DBG(INFO, dmc, "++++++add set[0x%lx] to clean:dirty block threshold crossed[whole=1], nr_dirty:%u",\
				set, dmc->cache_sets[set].nr_dirty);
		eio_addto_cleanq(dmc, set, 1);
		return;
	}
}

/* Ensure various cache thresholds compliance. If required trigger clean */
void eio_comply_dirty_thresholds(struct cache_c *dmc, index_t set)
{
	/*
	 * 1. Don't trigger new cleanings if
	 *      - cache is not wb
	 *      - autoclean threshold is crossed
	 *      - fast remove in progress is set
	 *      - cache is in failed mode.
	 * 2. Initiate set-wide clean, if set level dirty threshold is crossed
	 * 3. Initiate cache-wide clean, if cache level dirty threshold is crossed
	 */

	if (unlikely(CACHE_FAILED_IS_SET(dmc))) {
		pr_debug
			("eio_comply_dirty_thresholds: Cache %s is in failed mode.\n",
			dmc->cache_name);
		return;
	}

	if (AUTOCLEAN_THRESHOLD_CROSSED(dmc) || (dmc->mode != CACHE_MODE_WB))
		return;

	if (set != -1)
		eio_check_dirty_set_thresholds(dmc, set);
	eio_check_dirty_cache_thresholds(dmc);
}

/* Do read from cache */
static void
eio_cached_read(struct cache_c *dmc, struct eio_bio *ebio, int rw_flags)
{
	struct kcached_job *job;
	index_t index = ebio->eb_index;
	int err = 0;

	job = eio_new_job(dmc, ebio, index);

	if (unlikely(job == NULL))
		err = -ENOMEM;
	else {
		job->action = READCACHE;        /* Fetch data from cache */
		atomic_inc(&dmc->nr_jobs);

		SECTOR_STATS(dmc->eio_stats.read_hits, ebio->eb_size);
		SECTOR_STATS(dmc->eio_stats.ssd_reads, ebio->eb_size);
		atomic64_inc(&dmc->eio_stats.readcache);
		err =
			eio_io_async_bvec(dmc, &job->job_io_regions.cache, rw_flags,
					  ebio->eb_bv, ebio->eb_nbvec,
					  eio_io_callback, job, 0);

	}
	if (err) {
		unsigned long flags;
		pr_err("eio_cached_read: IO submission failed, block %llu",
		       EIO_DBN_GET(dmc, index));
		spin_lock_irqsave(&dmc->cache_sets[ebio->eb_cacheset].cs_lock,
				  flags);
		/*
		 * For already DIRTY block, invalidation is too costly, skip it.
		 * For others, mark the block as INVALID and return error.
		 */
		if (EIO_CACHE_STATE_GET(dmc, ebio->eb_index) != ALREADY_DIRTY) {
			EIO_CACHE_STATE_SET(dmc, ebio->eb_index, INVALID);
			atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
		}
		spin_unlock_irqrestore(&dmc->cache_sets[ebio->eb_cacheset].
				       cs_lock, flags);
		eb_endio(ebio, err);
		ebio = NULL;
		if (job) {
			job->ebio = NULL;
			eio_free_cache_job(job);
			job = NULL;
		}
	}
}

/*
 * Invalidate any colliding blocks if they are !BUSY and !DIRTY.  In BUSY case,
 * we need to wait until the underlying IO is finished, and then proceed with
 * the invalidation, so a QUEUED flag is added.
 */
static int
eio_inval_block_set_range(struct cache_c *dmc, int set, sector_t iosector,
			  unsigned iosize, int multiblk)
{
	int start_index, end_index, i;
	sector_t endsector = iosector + eio_to_sector(iosize);

	start_index = dmc->assoc * set;
	end_index = start_index + dmc->assoc;
	for (i = start_index; i < end_index; i++) {
		sector_t start_dbn;
		sector_t end_dbn;

		if (EIO_CACHE_STATE_GET(dmc, i) & INVALID)
			continue;
		start_dbn = EIO_DBN_GET(dmc, i);
		end_dbn = start_dbn + dmc->block_size;

		if (!(endsector <= start_dbn || iosector >= end_dbn)) {

			if (!
			    (EIO_CACHE_STATE_GET(dmc, i) &
			     (BLOCK_IO_INPROG | DIRTY | QUEUED))) {
				EIO_CACHE_STATE_SET(dmc, i, INVALID);
				atomic64_dec_if_positive(&dmc->eio_stats.
							 cached_blocks);
				if (multiblk)
					continue;
				return 0;
			}

			/* Skip queued flag for DIRTY(inprog or otherwise) blocks. */
			if (!(EIO_CACHE_STATE_GET(dmc, i) & (DIRTY | QUEUED)))
				/* BLOCK_IO_INPROG is set. Set QUEUED flag */
				EIO_CACHE_STATE_ON(dmc, i, QUEUED);

			if (!multiblk)
				return 1;
		}
	}
	return 0;
}

int
eio_invalidate_sanity_check(struct cache_c *dmc, u_int64_t iosector,
			    u_int64_t *num_sectors)
{
	u_int64_t disk_size;

	/*
	 * Sanity check the arguements
	 */
	if (unlikely(*num_sectors == 0)) {
		pr_info
			("invaldate_sector_range: nothing to do because number of sectors specified is zero");
		return -EINVAL;
	}

	disk_size = eio_to_sector(eio_get_device_size(dmc->disk_dev));
	if (iosector >= disk_size) {
		pr_err
			("eio_inval_range: nothing to do because starting sector is past last sector (%lu > %lu)",
			(long unsigned int)iosector, (long unsigned int)disk_size);
		return -EINVAL;
	}

	if ((iosector + (*num_sectors)) > disk_size) {
		pr_info
			("eio_inval_range: trimming range because there are less sectors to invalidate than requested. (%lu < %lu)",
			(long unsigned int)(disk_size - iosector),
			(long unsigned int)*num_sectors);
		*num_sectors = (disk_size - iosector);
	}

	return 0;
}

void eio_inval_range(struct cache_c *dmc, sector_t iosector, unsigned iosize)
{
	u_int32_t bset;
	sector_t snum;
	sector_t snext;
	unsigned ioinset;
	unsigned long flags;
	int totalsshift = dmc->block_shift + dmc->consecutive_shift;

	snum = iosector;
	while (iosize) {
		bset = hash_block(dmc, snum);
		snext = ((snum >> totalsshift) + 1) << totalsshift;
		ioinset = (unsigned)to_bytes(snext - snum);
		if (ioinset > iosize)
			ioinset = iosize;
		spin_lock_irqsave(&dmc->cache_sets[bset].cs_lock, flags);
		eio_inval_block_set_range(dmc, bset, snum, ioinset, 1);
		spin_unlock_irqrestore(&dmc->cache_sets[bset].cs_lock, flags);
		snum = snext;
		iosize -= ioinset;
	}
}

/*
 * Invalidates all cached blocks without waiting for them to complete
 * Should be called with incoming IO suspended
 */
int eio_invalidate_cache(struct cache_c *dmc)
{
	u_int64_t i = 0;
	unsigned long flags = 0;
	sector_t disk_dev_size = to_bytes(eio_get_device_size(dmc->disk_dev));

	/* invalidate the whole cache */
	for (i = 0; i < (dmc->size >> dmc->consecutive_shift); i++) {
		spin_lock_irqsave(&dmc->cache_sets[i].cs_lock, flags);
		/* TBD. Apply proper fix for the cast to disk_dev_size */
		(void)eio_inval_block_set_range(dmc, (int)i, 0,
						(unsigned)disk_dev_size, 0);
		spin_unlock_irqrestore(&dmc->cache_sets[i].cs_lock, flags);
	}                       /* end - for all cachesets (i) */

	return 0;               /* i suspect we may need to return different statuses in the future */
}                               /* eio_invalidate_cache */

static int eio_inval_block(struct cache_c *dmc, sector_t iosector)
{
	u_int32_t bset;
	int queued;

	/*Chop lower bits of iosector*/
	iosector = EIO_ROUND_SECTOR(dmc, iosector);
	bset = hash_block(dmc, iosector);
	queued = eio_inval_block_set_range(dmc, bset, iosector,
					   (unsigned)to_bytes(dmc->block_size),
					   0);

	return queued;
}

/* Serving write I/Os, that involves both SSD and HDD */
static int eio_uncached_write(struct cache_c *dmc, struct eio_bio *ebio)
{
	struct kcached_job *job;
	int err = 0;
	index_t index = ebio->eb_index;
	unsigned long flags = 0;
	u_int8_t cstate;

	if (index == -1) {
		/*
		 * No work, if block is not allocated.
		 * Ensure, invalidation of the block at the end
		 */
		ebio->eb_iotype |= EB_INVAL;
		return 0;
	}

	spin_lock_irqsave(&dmc->cache_sets[ebio->eb_cacheset].cs_lock, flags);
	cstate = EIO_CACHE_STATE_GET(dmc, index);
	EIO_ASSERT(cstate & (DIRTY | CACHEWRITEINPROG));
	if (cstate == ALREADY_DIRTY) {
		/*
		 * Treat the dirty block cache write failure as
		 * I/O failure for the entire I/O
		 * TBD
		 * Can we live without this restriction
		 */
		ebio->eb_iotype = EB_MAIN_IO;

		/*
		 * We don't set inprog flag on dirty block.
		 * In lieu of the inprog flag, we are using the
		 * eb_holdcount for dirty block, so that the
		 * endio can be called, only when the write to disk
		 * and the write to cache both complete for the ebio
		 */
		atomic_inc(&ebio->eb_holdcount);
	} else
		/* ensure DISKWRITEINPROG for uncached write on non-DIRTY blocks */
		EIO_CACHE_STATE_ON(dmc, index, DISKWRITEINPROG);

	spin_unlock_irqrestore(&dmc->cache_sets[ebio->eb_cacheset].cs_lock,
			       flags);

	job = eio_new_job(dmc, ebio, index);
	if (unlikely(job == NULL))
		err = -ENOMEM;
	else {
		job->action = WRITECACHE;
		SECTOR_STATS(dmc->eio_stats.ssd_writes, ebio->eb_size);
		atomic64_inc(&dmc->eio_stats.writecache);
		err = eio_io_async_bvec(dmc, &job->job_io_regions.cache, WRITE,
					ebio->eb_bv, ebio->eb_nbvec,
					eio_io_callback, job, 0);
	}

	if (err) {
		pr_err("eio_uncached_write: IO submission failed, block %llu",
		       EIO_DBN_GET(dmc, index));
		spin_lock_irqsave(&dmc->cache_sets[ebio->eb_cacheset].cs_lock,
				  flags);
		if (EIO_CACHE_STATE_GET(dmc, ebio->eb_index) == ALREADY_DIRTY)
			/*
			 * Treat I/O failure on a DIRTY block as failure of entire I/O.
			 * TBD
			 * Can do better error handling by invalidation of the dirty
			 * block, if the cache block write failed, but disk write succeeded
			 */
			ebio->eb_bc->bc_error = err;
		else {
			/* Mark the block as INVALID for non-DIRTY block. */
			EIO_CACHE_STATE_SET(dmc, ebio->eb_index, INVALID);
			atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
			/* Set the INVAL flag to ensure block is marked invalid at the end */
			ebio->eb_iotype |= EB_INVAL;
			ebio->eb_index = -1;
		}
		spin_unlock_irqrestore(&dmc->cache_sets[ebio->eb_cacheset].
				       cs_lock, flags);
		if (job) {
			job->ebio = NULL;
			eio_free_cache_job(job);
			job = NULL;
		}
	}

	return err;
}

/* Serving write I/Os that can be fulfilled just by SSD */
static int
eio_cached_write(struct cache_c *dmc, struct eio_bio *ebio, int rw_flags)
{
	struct kcached_job *job;
	int err = 0;
	index_t index = ebio->eb_index;
	unsigned long flags = 0;
	u_int8_t cstate;

	/*
	 * WRITE (I->DV)
	 * WRITE (V->DV)
	 * WRITE (V1->DV2)
	 * WRITE (DV->DV)
	 */

	/* Possible only in writeback caching mode */
	EIO_ASSERT(dmc->mode == CACHE_MODE_WB);

	/*
	 * TBD
	 * Possibly don't need the spinlock-unlock here
	 */
	spin_lock_irqsave(&dmc->cache_sets[ebio->eb_cacheset].cs_lock, flags);
	cstate = EIO_CACHE_STATE_GET(dmc, index);
	if (!(cstate & DIRTY)) {
		EIO_ASSERT(cstate & CACHEWRITEINPROG);
		/* make sure the block is marked DIRTY inprogress */
		EIO_CACHE_STATE_SET(dmc, index, DIRTY_INPROG);
	}
	spin_unlock_irqrestore(&dmc->cache_sets[ebio->eb_cacheset].cs_lock,
			       flags);

	job = eio_new_job(dmc, ebio, index);
	if (unlikely(job == NULL))
		err = -ENOMEM;
	else {
		job->action = WRITECACHE;

		SECTOR_STATS(dmc->eio_stats.ssd_writes, ebio->eb_size);
		atomic64_inc(&dmc->eio_stats.writecache);
		EIO_ASSERT((rw_flags & 1) == WRITE);
		err =
			eio_io_async_bvec(dmc, &job->job_io_regions.cache, rw_flags,
					  ebio->eb_bv, ebio->eb_nbvec,
					  eio_io_callback, job, 0);

	}

	if (err) {
		pr_err("eio_cached_write: IO submission failed, block %llu",
		       EIO_DBN_GET(dmc, index));
		spin_lock_irqsave(&dmc->cache_sets[ebio->eb_cacheset].cs_lock,
				  flags);
		cstate = EIO_CACHE_STATE_GET(dmc, index);
		if (cstate == DIRTY_INPROG) {
			/* A DIRTY(inprog) block should be invalidated on error */
			EIO_CACHE_STATE_SET(dmc, ebio->eb_index, INVALID);
			atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
		} else
			/* An already DIRTY block don't have an option but just return error. */
			EIO_ASSERT(cstate == ALREADY_DIRTY);
		spin_unlock_irqrestore(&dmc->cache_sets[ebio->eb_cacheset].
				       cs_lock, flags);
		eb_endio(ebio, err);
		ebio = NULL;
		if (job) {
			job->ebio = NULL;
			eio_free_cache_job(job);
			job = NULL;
		}
	}

	return err;
}

static struct eio_bio *eio_new_ebio(struct cache_c *dmc, struct bio *bio,
				    unsigned *presidual_biovec, sector_t snum,
				    int iosize, struct bio_container *bc,
				    int iotype)
{
	struct eio_bio *ebio;
	int residual_biovec = *presidual_biovec;
	int numbvecs = 0;
	int ios;

	if (residual_biovec) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		int bvecindex = bio->bi_iter.bi_idx;
#else 
		int bvecindex = bio->bi_idx;
#endif 
		int rbvindex;

		/* Calculate the number of bvecs required */
		ios = iosize;
		while (ios > 0) {
			int len;

			if (ios == iosize)
				len =
					bio->bi_io_vec[bvecindex].bv_len -
					residual_biovec;
			else
				len = bio->bi_io_vec[bvecindex].bv_len;

			numbvecs++;
			if (len > ios)
				len = ios;
			ios -= len;
			bvecindex++;
		}
		ebio =
			kmalloc(sizeof(struct eio_bio) +
				numbvecs * sizeof(struct bio_vec), GFP_NOWAIT);

		if (!ebio)
			return ERR_PTR(-ENOMEM);

		rbvindex = 0;
		ios = iosize;
		while (ios > 0) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
			ebio->eb_rbv[rbvindex].bv_page =
				bio->bi_io_vec[bio->bi_iter.bi_idx].bv_page;
			ebio->eb_rbv[rbvindex].bv_offset =
				bio->bi_io_vec[bio->bi_iter.bi_idx].bv_offset +
				residual_biovec;
			ebio->eb_rbv[rbvindex].bv_len =
				bio->bi_io_vec[bio->bi_iter.bi_idx].bv_len -
				residual_biovec;
#else 
			ebio->eb_rbv[rbvindex].bv_page =
				bio->bi_io_vec[bio->bi_idx].bv_page;
			ebio->eb_rbv[rbvindex].bv_offset =
				bio->bi_io_vec[bio->bi_idx].bv_offset +
				residual_biovec;
			ebio->eb_rbv[rbvindex].bv_len =
				bio->bi_io_vec[bio->bi_idx].bv_len -
				residual_biovec;
#endif 
			if (ebio->eb_rbv[rbvindex].bv_len > (unsigned)ios) {
				residual_biovec += ios;
				ebio->eb_rbv[rbvindex].bv_len = ios;
			} else {
				residual_biovec = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
				bio->bi_iter.bi_idx++;
#else 
				bio->bi_idx++;
#endif 
			}
			ios -= ebio->eb_rbv[rbvindex].bv_len;
			rbvindex++;
		}
		EIO_ASSERT(rbvindex == numbvecs);
		ebio->eb_bv = ebio->eb_rbv;
	} else {
		ebio = kmalloc(sizeof(struct eio_bio), GFP_NOWAIT);

		if (!ebio)
			return ERR_PTR(-ENOMEM);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		ebio->eb_bv = bio->bi_io_vec + bio->bi_iter.bi_idx;
#else 
		ebio->eb_bv = bio->bi_io_vec + bio->bi_idx;
#endif 
		ios = iosize;
		while (ios > 0) {
			numbvecs++;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
			if ((unsigned)ios < bio->bi_io_vec[bio->bi_iter.bi_idx].bv_len) {
#else 
			if ((unsigned)ios < bio->bi_io_vec[bio->bi_idx].bv_len) {
#endif 
				residual_biovec = ios;
				ios = 0;
			} else {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
				ios -= bio->bi_io_vec[bio->bi_iter.bi_idx].bv_len;
				bio->bi_iter.bi_idx++;
#else 
				ios -= bio->bi_io_vec[bio->bi_idx].bv_len;
				bio->bi_idx++;
#endif 
			}
		}
	}
	EIO_ASSERT(ios == 0);
	EIO_ASSERT(numbvecs != 0);
	*presidual_biovec = residual_biovec;

	ebio->eb_sector = snum;
	ebio->eb_cacheset = hash_block(dmc, snum);
	ebio->eb_size = iosize;
	ebio->eb_dir = bio_data_dir(bio);
	ebio->eb_next = NULL;
	ebio->eb_index = -1;
	ebio->eb_iotype = iotype;
	ebio->eb_nbvec = numbvecs;

	bc_addfb(bc, ebio);

	/* Always set the holdcount for eb to 1, to begin with. */
	atomic_set(&ebio->eb_holdcount, 1);

	return ebio;
}

/* Issues HDD I/O */
static void
eio_disk_io(struct cache_c *dmc, struct bio *bio,
	    struct eio_bio *anchored_bios, struct bio_container *bc,
	    int force_inval)
{
	struct eio_bio *ebio;
	struct kcached_job *job;
	int residual_biovec = 0;
	int error = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	/*disk io happens on whole bio. Reset bi_iter.bi_idx*/
	bio->bi_iter.bi_idx = 0;
	ebio =
		eio_new_ebio(dmc, bio, &residual_biovec, bio->bi_iter.bi_sector,
				 bio->bi_iter.bi_size, bc, EB_MAIN_IO);
#else 
	/*disk io happens on whole bio. Reset bi_idx*/
	bio->bi_idx = 0;
	ebio =
		eio_new_ebio(dmc, bio, &residual_biovec, bio->bi_sector,
			     bio->bi_size, bc, EB_MAIN_IO);
#endif 

	if (unlikely(IS_ERR(ebio))) {
		bc->bc_error = error = PTR_ERR(ebio);
		ebio = NULL;
		goto errout;
	}

	if (force_inval)
		ebio->eb_iotype |= EB_INVAL;
	ebio->eb_next = anchored_bios;  /*Anchor the ebio list to this super bio*/
	job = eio_new_job(dmc, ebio, -1);

	if (unlikely(job == NULL)) {
		error = -ENOMEM;
		goto errout;
	}
	atomic_inc(&dmc->nr_jobs);
	if (ebio->eb_dir == READ) {
		job->action = READDISK;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		SECTOR_STATS(dmc->eio_stats.disk_reads, bio->bi_iter.bi_size);
#else 
		SECTOR_STATS(dmc->eio_stats.disk_reads, bio->bi_size);
#endif 
		atomic64_inc(&dmc->eio_stats.readdisk);
	} else {
		job->action = WRITEDISK;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		SECTOR_STATS(dmc->eio_stats.disk_writes, bio->bi_iter.bi_size);
#else 
		SECTOR_STATS(dmc->eio_stats.disk_writes, bio->bi_size);
#endif 
		atomic64_inc(&dmc->eio_stats.writedisk);
	}

	/*
	 * Pass the original bio flags as is, while doing
	 * read / write to HDD.
	 */
	VERIFY_BIO_FLAGS(ebio);
	error = eio_io_async_bvec(dmc, &job->job_io_regions.disk,
				  GET_BIO_FLAGS(ebio),
				  ebio->eb_bv, ebio->eb_nbvec,
				  eio_io_callback, job, 1);

	if (error) {
		job->ebio = NULL;
		eio_free_cache_job(job);
		goto errout;
	}
	return;

errout:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	eio_inval_range(dmc, bio->bi_iter.bi_sector, bio->bi_iter.bi_size);
#else 
	eio_inval_range(dmc, bio->bi_sector, bio->bi_size);
#endif 
	eio_flag_abios(dmc, anchored_bios, error);

	if (ebio)
		eb_endio(ebio, error);
	return;
}

/*Given a sector number and biosize, returns cache io size*/
static unsigned int
eio_get_iosize(struct cache_c *dmc, sector_t snum, unsigned int biosize)
{
	unsigned int iosize;
	unsigned int swithinblock = snum & (dmc->block_size - 1);

	/*Check whether io starts at a cache block boundary*/
	if (swithinblock)
		iosize = (unsigned int)to_bytes(dmc->block_size - swithinblock);
	else
		iosize = (unsigned int)to_bytes(dmc->block_size);
	if (iosize > biosize)
		iosize = biosize;
	return iosize;
}

/* Insert a new set sequence in sorted order to existing set sequence list */
static int
insert_set_seq(struct set_seq **seq_list, index_t first_set, index_t last_set)
{
	struct set_seq *cur_seq = NULL;
	struct set_seq *prev_seq = NULL;
	struct set_seq *new_seq = NULL;

	EIO_ASSERT((first_set != -1) && (last_set != -1)
		   && (last_set >= first_set));

	for (cur_seq = *seq_list; cur_seq;
	     prev_seq = cur_seq, cur_seq = cur_seq->next) {
		if (first_set > cur_seq->last_set)
			/* go for the next seq in the sorted seq list */
			continue;

		if (last_set < cur_seq->first_set)
			/* break here to insert the new seq to seq list at this point */
			break;

		/*
		 * There is an overlap of the new seq with the current seq.
		 * Adjust the first_set field of the current seq to consume
		 * the overlap.
		 */
		if (first_set < cur_seq->first_set)
			cur_seq->first_set = first_set;

		if (last_set <= cur_seq->last_set)
			/* The current seq now fully encompasses the first and last sets */
			return 0;

		/* Increment the first set so as to start from, where the current seq left */
		first_set = cur_seq->last_set + 1;
	}

	new_seq = kmalloc(sizeof(struct set_seq), GFP_NOWAIT);
	if (new_seq == NULL)
		return -ENOMEM;
	new_seq->first_set = first_set;
	new_seq->last_set = last_set;
	if (prev_seq) {
		new_seq->next = prev_seq->next;
		prev_seq->next = new_seq;
	} else {
		new_seq->next = *seq_list;
		*seq_list = new_seq;
	}

	return 0;
}

/* Acquire read/shared lock for the sets covering the entire I/O range */
static int eio_acquire_set_locks(struct cache_c *dmc, struct bio_container *bc)
{
	struct bio *bio = bc->bc_bio;
	sector_t round_sector;
	sector_t end_sector;
	sector_t set_size;
	index_t cur_set;
	index_t first_set;
	index_t last_set;
	index_t i;
	struct set_seq *cur_seq;
	struct set_seq *next_seq;
	int error;
	unsigned long before_lock;
	unsigned long after_lock;

	/*
	 * Find first set using start offset of the I/O and lock it.
	 * Find next sets by adding the set offsets to the previous set
	 * Identify all the sequences of set numbers that need locking.
	 * Keep the sequences in sorted list.
	 * For each set in each sequence
	 * - acquire read lock on the set.
	 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	round_sector = EIO_ROUND_SET_SECTOR(dmc, bio->bi_iter.bi_sector);
	set_size = dmc->block_size * dmc->assoc;
	end_sector = bio->bi_iter.bi_sector + eio_to_sector(bio->bi_iter.bi_size);
#else 
	round_sector = EIO_ROUND_SET_SECTOR(dmc, bio->bi_sector);
	set_size = dmc->block_size * dmc->assoc;
	end_sector = bio->bi_sector + eio_to_sector(bio->bi_size);
#endif 
	first_set = -1;
	last_set = -1;
	cur_set = -1;
	bc->bc_setspan = NULL;

	while (round_sector < end_sector) {
		cur_set = hash_block(dmc, round_sector);
		if (first_set == -1) {
			first_set = cur_set;
			last_set = cur_set;
		} else if (cur_set == (last_set + 1))
			last_set = cur_set;
		else {
			/*
			 * Add the seq of start, end set to sorted (first, last) seq list
			 * and reinit the first and last set
			 */
			error =
				insert_set_seq(&bc->bc_setspan, first_set,
					       last_set);
			if (error)
				goto err_out;
			first_set = cur_set;
			last_set = cur_set;
		}

		round_sector += set_size;
	}

	/* Add the remaining first, last set sequence */

	EIO_ASSERT((first_set != -1) && (last_set == cur_set));

	if (bc->bc_setspan == NULL) {
		/* No sequence was added, can use singlespan */
		cur_seq = &bc->bc_singlesspan;
		cur_seq->first_set = first_set;
		cur_seq->last_set = last_set;
		cur_seq->next = NULL;
		bc->bc_setspan = cur_seq;
	} else {
		error = insert_set_seq(&bc->bc_setspan, first_set, last_set);
		if (error)
			goto err_out;
	}

	/* Acquire read locks on the sets in the set span */
	for (cur_seq = bc->bc_setspan; cur_seq; cur_seq = cur_seq->next)
		for (i = cur_seq->first_set; i <= cur_seq->last_set; i++) {
			before_lock = jiffies;
			down_read(&dmc->cache_sets[i].rw_lock);
			after_lock = jiffies;
			//EIO_DBG(INFO, dmc, "------set[%u] get read lock:%u ms------,", (unsigned int)i, 
				//jiffies_to_msecs(after_lock - before_lock));
		}
		
		//EIO_DBG(INFO, dmc, "---\n");

	bc->bc_locktime = jiffies;
	return 0;

err_out:

	/* Free the seqs in the seq list, unless it is just the local seq */
	if (bc->bc_setspan != &bc->bc_singlesspan) {
		for (cur_seq = bc->bc_setspan; cur_seq; cur_seq = next_seq) {
			next_seq = cur_seq->next;
			kfree(cur_seq);
		}
	}
	return error;
}

/*
 * Allocate mdreq and md_blocks for each set.
 */
static int eio_alloc_mdreqs(struct cache_c *dmc, struct bio_container *bc)
{
	index_t i;
	struct mdupdate_request *mdreq;
	int nr_bvecs, ret;
	struct set_seq *cur_seq;

	bc->mdreqs = NULL;

	for (cur_seq = bc->bc_setspan; cur_seq; cur_seq = cur_seq->next) {
		for (i = cur_seq->first_set; i <= cur_seq->last_set; i++) {
			mdreq = kzalloc(sizeof(*mdreq), GFP_NOWAIT);
			if (mdreq) {
				mdreq->md_size =
					dmc->assoc *
					sizeof(struct flash_cacheblock);
				nr_bvecs =
					IO_BVEC_COUNT(mdreq->md_size,
						      SECTORS_PER_PAGE);

				mdreq->mdblk_bvecs =
					(struct bio_vec *)
					kmalloc(sizeof(struct bio_vec) * nr_bvecs,
						GFP_KERNEL);
				if (mdreq->mdblk_bvecs) {

					ret =
						eio_alloc_wb_bvecs(mdreq->
								   mdblk_bvecs,
								   nr_bvecs,
								   SECTORS_PER_PAGE);
					if (ret) {
						pr_err
							("eio_alloc_mdreqs: failed to allocated pages\n");
						kfree(mdreq->mdblk_bvecs);
						mdreq->mdblk_bvecs = NULL;
					}
					mdreq->mdbvec_count = nr_bvecs;
				}
			}

			if (unlikely
				    ((mdreq == NULL) || (mdreq->mdblk_bvecs == NULL))) {
				struct mdupdate_request *nmdreq;

				mdreq = bc->mdreqs;
				while (mdreq) {
					nmdreq = mdreq->next;
					if (mdreq->mdblk_bvecs) {
						eio_free_wb_bvecs(mdreq->
								  mdblk_bvecs,
								  mdreq->
								  mdbvec_count,
								  SECTORS_PER_PAGE);
						kfree(mdreq->mdblk_bvecs);
					}
					kfree(mdreq);
					mdreq = nmdreq;
				}
				bc->mdreqs = NULL;
				return -ENOMEM;
			} else {
				mdreq->next = bc->mdreqs;
				bc->mdreqs = mdreq;
			}
		}
	}

	return 0;

}

/*
 * Release:
 * 1. the set locks covering the entire I/O range
 * 2. any previously allocated memory for md update
 */
static int
eio_release_io_resources(struct cache_c *dmc, struct bio_container *bc)
{
	index_t i;
	struct mdupdate_request *mdreq;
	struct mdupdate_request *nmdreq;
	struct set_seq *cur_seq;
	struct set_seq *next_seq;

	/* Release read locks on the sets in the set span */
	for (cur_seq = bc->bc_setspan; cur_seq; cur_seq = cur_seq->next)
		for (i = cur_seq->first_set; i <= cur_seq->last_set; i++)
			up_read(&dmc->cache_sets[i].rw_lock);

	/* Free the seqs in the set span, unless it is single span */
	if (bc->bc_setspan != &bc->bc_singlesspan) {
		for (cur_seq = bc->bc_setspan; cur_seq; cur_seq = next_seq) {
			next_seq = cur_seq->next;
			kfree(cur_seq);
		}
	}

	mdreq = bc->mdreqs;
	while (mdreq) {
		nmdreq = mdreq->next;
		if (mdreq->mdblk_bvecs) {
			eio_free_wb_bvecs(mdreq->mdblk_bvecs,
					  mdreq->mdbvec_count,
					  SECTORS_PER_PAGE);
			kfree(mdreq->mdblk_bvecs);
		}
		kfree(mdreq);
		mdreq = nmdreq;
	}
	bc->mdreqs = NULL;

	return 0;
}

/*
 * Decide the mapping and perform necessary cache operations for a bio request.
 */
int eio_map(struct cache_c *dmc, struct request_queue *rq, struct bio *bio)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	sector_t sectors = eio_to_sector(bio->bi_iter.bi_size);
#else 
	sector_t sectors = eio_to_sector(bio->bi_size);
#endif 
	struct eio_bio *ebio = NULL;
	struct bio_container *bc;
	sector_t snum;
	unsigned int iosize;
	unsigned int totalio;
	unsigned int biosize;
	unsigned int residual_biovec;
	unsigned int force_uncached = 0;	
	unsigned int skip_flag1 = 0;
	unsigned int skip_flag2 = 0;
	int data_dir = bio_data_dir(bio);	
	unsigned long flags;
	unsigned long wr_ioc; 
	unsigned long wr_ioc_small;

	/*bio list*/
	struct eio_bio *ebegin = NULL;
	struct eio_bio *eend = NULL;
	struct eio_bio *enext = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	EIO_ASSERT(bio->bi_iter.bi_idx == 0);
#else 
	EIO_ASSERT(bio->bi_idx == 0);
#endif 

	pr_debug("this needs to be removed immediately\n");

	if (bio_rw_flagged(bio, REQ_DISCARD)) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		pr_debug
			("eio_map: Discard IO received. Invalidate incore start=%lu totalsectors=%d.\n",
			(unsigned long)bio->bi_iter.bi_sector,
			(int)eio_to_sector(bio->bi_iter.bi_size));
#else 
		pr_debug
			("eio_map: Discard IO received. Invalidate incore start=%lu totalsectors=%d.\n",
			(unsigned long)bio->bi_sector,
			(int)eio_to_sector(bio->bi_size));
#endif 
		bio_endio(bio, 0);
		pr_err
			("eio_map: I/O with Discard flag received. Discard flag is not supported.\n");
		return 0;
	}

	if (unlikely(dmc->cache_rdonly)) {
		if (data_dir != READ) {
			bio_endio(bio, -EPERM);
			pr_debug
				("eio_map: cache is read only, write not permitted\n");
			return 0;
		}
	}

	if (sectors < SIZE_HIST)
		atomic64_inc(&dmc->size_hist[sectors]);

	if (data_dir == READ) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		SECTOR_STATS(dmc->eio_stats.reads, bio->bi_iter.bi_size);
#else 
		SECTOR_STATS(dmc->eio_stats.reads, bio->bi_size);
#endif 
		atomic64_inc(&dmc->eio_stats.readcount);
	} else {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		SECTOR_STATS(dmc->eio_stats.writes, bio->bi_iter.bi_size);
#else 
		SECTOR_STATS(dmc->eio_stats.writes, bio->bi_size);
#endif 
		atomic64_inc(&dmc->eio_stats.writecount);
	}

	/*
	 * Cache FAILED mode is like Hard failure.
	 * Dont allow I/Os to go through.
	 */
	if (unlikely(CACHE_FAILED_IS_SET(dmc))) {
		/*ASK confirm that once failed is set, it's never reset*/
		/* Source device is not available. */
		CTRACE
			("eio_map:2 source device is not present. Cache is in Failed state\n");
		bio_endio(bio, -ENODEV);
		bio = NULL;
		return DM_MAPIO_SUBMITTED;
	}

	/* WB cache will never be in degraded mode. */
	if (unlikely(CACHE_DEGRADED_IS_SET(dmc))) {
		EIO_ASSERT(dmc->mode != CACHE_MODE_WB);
		force_uncached = 1;
	} else if (data_dir == WRITE && dmc->mode == CACHE_MODE_RO) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		if (to_sector(bio->bi_iter.bi_size) != dmc->block_size)
#else
		if (to_sector(bio->bi_size) != dmc->block_size)
#endif
			atomic64_inc(&dmc->eio_stats.uncached_map_size);
		else
			atomic64_inc(&dmc->eio_stats.uncached_map_uncacheable);
		force_uncached = 1;
	}

	/*
	 * Process zero sized bios by passing original bio flags
	 * to both HDD and SSD.
	 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	if (bio->bi_iter.bi_size == 0) {
#else 
	if (bio->bi_size == 0) {
#endif 
		eio_process_zero_size_bio(dmc, bio);
		return DM_MAPIO_SUBMITTED;
	}
	
	/* Create a bio container */

	bc = kzalloc(sizeof(struct bio_container), GFP_NOWAIT);
	if (!bc) {
		bio_endio(bio, -ENOMEM);
		return DM_MAPIO_SUBMITTED;
	}
	bc->bc_iotime = jiffies;
	bc->bc_bio = bio;
	bc->bc_dmc = dmc;
	spin_lock_init(&bc->bc_lock);
	atomic_set(&bc->bc_holdcount, 1);
	bc->bc_error = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	snum = bio->bi_iter.bi_sector;
	totalio = bio->bi_iter.bi_size;
	biosize = bio->bi_iter.bi_size;
#else 
	snum = bio->bi_sector;
	totalio = bio->bi_size;
	biosize = bio->bi_size;
#endif 
	residual_biovec = 0;
	//EIO_DBG(ERROR, dmc, "----biosize:[%u]KByte\n", TO_KB(totalio));

#ifdef CONFIG_SKIP_SEQUENTIAL_IO
	bc->set_block = NULL;
	/*Check sequential write io*/
	if (data_dir == WRITE && dmc->mode == CACHE_MODE_WB &&
			dmc->sysctl_active.seqio_threshold_len_kb > 0) {
		/*caculate the percent of small IO(io size < 32KB)*/
		//spin_lock_irqsave(&dmc->seq_io_lock, flags);
		atomic64_inc(&dmc->wr_ioc);
		if (TO_KB(biosize) <= SEQIO_SKIP_DECTECT_BIO_SIZE) {
			atomic64_inc(&dmc->wr_ioc_small);
		}
		
		if (time_after(jiffies, 
				dmc->pct_update_time + SEQIO_UPDATE_PCT_INTERVAL)) {
			wr_ioc = atomic64_read(&dmc->wr_ioc);
			if (wr_ioc >= SEQIO_SMALL_IO_COUNT) {
				int percent;				
				wr_ioc_small = atomic64_read(&dmc->wr_ioc_small);
				percent = EIO_CALCULATE_PERCENTAGE(wr_ioc_small, wr_ioc);			
				dmc->detect_flag = (percent < SEQIO_SMALL_IO_PCT) ? (int)1 : (int)0;
				EIO_DBG(ERROR, dmc, "small IO percent is %u, flag is %u\n",
						percent, dmc->detect_flag);
				atomic64_set(&dmc->wr_ioc, 0);
				atomic64_set(&dmc->wr_ioc_small, 0);
				dmc->pct_update_time = jiffies;
			}
		}

		if (dmc->detect_flag) {
		
			spin_lock_irqsave(&dmc->seq_io_lock, flags);
			skip_flag1 = seq_io_detect_seqential_io(dmc, bio);
			spin_unlock_irqrestore(&dmc->seq_io_lock, flags);

			if (skip_flag1) {
				skip_flag2 = seq_io_inval_bio_range(dmc, bc);
			}
		}
	}
#endif

	if (dmc->mode == CACHE_MODE_WB && !skip_flag2) {
		int ret;
		/*
		 * For writeback, the app I/O and the clean I/Os
		 * need to be exclusive for a cache set. Acquire shared
		 * lock on the cache set for app I/Os and exclusive
		 * lock on the cache set for clean I/Os.
		 */
		ret = eio_acquire_set_locks(dmc, bc);
		if (ret) {
			bio_endio(bio, ret);
			kfree(bc);
			return DM_MAPIO_SUBMITTED;
		}
	}

	atomic64_inc(&dmc->nr_ios);

	/*
	 * Prepare for I/O processing.
	 * - Allocate ebios.
	 * - For reads, identify if we need to do uncached read
	 * - If force uncached I/O is set, invalidate the cache blocks for the I/O
	 */

	if (skip_flag2 || force_uncached) {
		if (force_uncached) {
			eio_inval_range(dmc, snum, totalio);
		}
	} else {
		
		//print bio
		//int i;
		//struct bio_vec *bv;
		//pr_err("----------------------------------------\n");
		//pr_err("---bio_sector:0x%lx, bio_size:0x%x,bvec_cnt:0x%x\n", bio->bi_sector, bio->bi_size, bio->bi_vcnt);
		
		//bio_for_each_segment(bv, bio, i) {	
		//	pr_err("---bvec[%d]:bvec_len:0x%x,bvec_offset:0x%x\n", i, bv->bv_len, bv->bv_offset);
		//}

		//i = 0;
		
		while (biosize) {
			iosize = eio_get_iosize(dmc, snum, biosize);
			ebio = eio_new_ebio(dmc, bio, &residual_biovec, snum,
					iosize, bc, EB_SUBORDINATE_IO);
			if (IS_ERR(ebio)) {
				bc->bc_error = -ENOMEM;
				break;
			}

			/* Anchor this ebio on ebio list. Preserve the order */
			if (ebegin)
				eend->eb_next = ebio;
			else
				ebegin = ebio;
			eend = ebio;

			biosize -= iosize;
			snum += eio_to_sector(iosize);
			
			//pr_err("---ebio[%d]:eb_size:0x%x,eb_sector:0x%lx,eb_nbvec:0x%x\n", i, ebio->eb_size, ebio->eb_sector, ebio->eb_nbvec);
			//i++;
		}
	}

	if (bc->bc_error) {
		/* Error. Do ebio and bc cleanup. */
		ebio = ebegin;
		while (ebio) {
			enext = ebio->eb_next;
			eb_endio(ebio, bc->bc_error);
			ebio = enext;
		}

		/* By now, the bc_holdcount must be 1 */
		EIO_ASSERT(atomic_read(&bc->bc_holdcount) == 1);

		/* Goto out to cleanup the bc(in bc_put()) */
		goto out;
	}

	/*
	 * Start processing of the ebios.
	 *
	 * Note: don't return error from this point on.
	 *      Error handling would be done as part of
	 *      the processing of the ebios internally.
	 */
	 if (skip_flag2) {
	 	atomic64_inc(&dmc->eio_stats.seq_io_write_count);
		atomic64_add(eio_to_sector(bio->bi_size), &dmc->eio_stats.seq_io_write_size);
		seq_io_disk_io(dmc, bc, bio);
	 }else if (force_uncached) {
		EIO_ASSERT(dmc->mode != CACHE_MODE_WB);
		if (data_dir == READ)
			atomic64_inc(&dmc->eio_stats.uncached_reads);
		else
			atomic64_inc(&dmc->eio_stats.uncached_writes);
		eio_disk_io(dmc, bio, ebegin, bc, 1);
	} else if (data_dir == READ) {

		/* read io processing */
		eio_read(dmc, bc, ebegin);
	} else
		/* write io processing */
		eio_write(dmc, bc, ebegin);

out:

	if (bc)
		bc_put(bc, 0);

	return DM_MAPIO_SUBMITTED;
}

/*
 * Checks the cache block state, for deciding cached/uncached read.
 * Also reserves/allocates the cache block, wherever necessary.
 *
 * Return values
 * 1: cache hit
 * 0: cache miss
 */
static int eio_read_peek(struct cache_c *dmc, struct eio_bio *ebio)
{
	index_t index;
	int res;
	int retval = 0;
	unsigned long flags;
	u_int8_t cstate;

	spin_lock_irqsave(&dmc->cache_sets[ebio->eb_cacheset].cs_lock, flags);

	res = eio_lookup(dmc, ebio, &index);
	ebio->eb_index = -1;

	if (res < 0) {
		atomic64_inc(&dmc->eio_stats.noroom);
		goto out;
	}

	cstate = EIO_CACHE_STATE_GET(dmc, index);

	if (cstate & (BLOCK_IO_INPROG | QUEUED))
		/*
		 * We found a valid or invalid block but an io is on, so we can't
		 * proceed. Don't invalidate it. This implies that we'll
		 * have to read from disk.
		 * Read on a DIRTY | INPROG block (block which is going to be DIRTY)
		 * is also redirected to read from disk.
		 */
		goto out;

	if (res == VALID) {
		EIO_ASSERT(cstate & VALID);
		if ((EIO_DBN_GET(dmc, index) ==
		     EIO_ROUND_SECTOR(dmc, ebio->eb_sector))) {
			/*
			 * Read/write should be done on already DIRTY block
			 * without any inprog flag.
			 * Ensure that a failure of DIRTY block read is propagated to app.
			 * non-DIRTY valid blocks should have inprog flag.
			 */
			if (cstate == ALREADY_DIRTY) {
				ebio->eb_iotype = EB_MAIN_IO;
				/*
				 * Set to uncached read and readfill for now.
				 * It may change to CACHED_READ later, if all
				 * the blocks are found to be cached
				 */
				ebio->eb_bc->bc_dir =
					UNCACHED_READ_AND_READFILL;
			} else
				EIO_CACHE_STATE_ON(dmc, index, CACHEREADINPROG);
			retval = 1;
			ebio->eb_index = index;
			goto out;
		}

		/* cache is marked readonly. Do not allow READFILL on SSD */
		if (unlikely(dmc->cache_rdonly))
			goto out;

		/*
		 * Found a block to be recycled.
		 * Its guranteed that it will be a non-DIRTY block
		 */
		EIO_ASSERT(!(cstate & DIRTY));
		if (eio_to_sector(ebio->eb_size) == dmc->block_size) {
			/*We can recycle and then READFILL only if iosize is block size*/
			atomic64_inc(&dmc->eio_stats.rd_replace);
			EIO_CACHE_STATE_SET(dmc, index, VALID | DISKREADINPROG);
			EIO_DBN_SET(dmc, index, (sector_t)ebio->eb_sector);
			ebio->eb_index = index;
			ebio->eb_bc->bc_dir = UNCACHED_READ_AND_READFILL;
		}
		goto out;
	}
	EIO_ASSERT(res == INVALID);

	/* cache is marked readonly. Do not allow READFILL on SSD */
	if (unlikely(dmc->cache_rdonly))
		goto out;
	/*
	 * Found an invalid block to be used.
	 * Can recycle only if iosize is block size
	 */
	if (eio_to_sector(ebio->eb_size) == dmc->block_size) {
		EIO_ASSERT(cstate & INVALID);
		EIO_CACHE_STATE_SET(dmc, index, VALID | DISKREADINPROG);
		atomic64_inc(&dmc->eio_stats.cached_blocks);
		EIO_DBN_SET(dmc, index, (sector_t)ebio->eb_sector);
		ebio->eb_index = index;
		ebio->eb_bc->bc_dir = UNCACHED_READ_AND_READFILL;
	}

out:

	spin_unlock_irqrestore(&dmc->cache_sets[ebio->eb_cacheset].cs_lock,
			       flags);

	/*
	 * Enqueue clean set if there is no room in the set
	 * TBD
	 * Ensure, a force clean
	 */
	if (res < 0)
		eio_comply_dirty_thresholds(dmc, ebio->eb_cacheset);

	return retval;
}

/*
 * Checks the cache block state, for deciding cached/uncached write.
 * Also reserves/allocates the cache block, wherever necessary.
 *
 * Return values
 * 1: cache block is available or newly allocated
 * 0: cache block could not be got for the ebio
 */
static int eio_write_peek(struct cache_c *dmc, struct eio_bio *ebio)
{
	index_t index;
	int res;
	int retval;
	u_int8_t cstate;
	unsigned long flags;

	spin_lock_irqsave(&dmc->cache_sets[ebio->eb_cacheset].cs_lock, flags);

	res = eio_lookup(dmc, ebio, &index);
	ebio->eb_index = -1;
	retval = 0;

	if (res < 0) {
		/* cache block not found and new block couldn't be allocated */
		atomic64_inc(&dmc->eio_stats.noroom);
		ebio->eb_iotype |= EB_INVAL;
		goto out;
	}

	cstate = EIO_CACHE_STATE_GET(dmc, index);

	if (cstate & (BLOCK_IO_INPROG | QUEUED)) {
		ebio->eb_iotype |= EB_INVAL;
		/* treat as if cache block is not available */
		goto out;
	}

	if ((res == VALID) && (EIO_DBN_GET(dmc, index) ==
			       EIO_ROUND_SECTOR(dmc, ebio->eb_sector))) {
		/*
		 * Cache hit.
		 * All except an already DIRTY block should have an INPROG flag.
		 * If it is a cached write, a DIRTY flag would be added later.
		 */
		SECTOR_STATS(dmc->eio_stats.write_hits, ebio->eb_size);
		if (cstate != ALREADY_DIRTY)
			EIO_CACHE_STATE_ON(dmc, index, CACHEWRITEINPROG);
		else
			atomic64_inc(&dmc->eio_stats.dirty_write_hits);
		ebio->eb_index = index;
		/*
		 * A VALID block should get upgraded to DIRTY, only when we
		 * are updating the entire cache block(not partially).
		 * Otherwise, 2 sequential partial writes can lead to missing
		 * data when one write upgrades the cache block to DIRTY, while
		 * the other just writes to HDD. Subsequent read would be
		 * served from the cache block, which won't have the data from
		 * 2nd write.
		 */
		if ((cstate == ALREADY_DIRTY) ||
		    (eio_to_sector(ebio->eb_size) == dmc->block_size))
			retval = 1;
		else
			retval = 0;
		goto out;

	}

	/*
	 * cache miss with a new block allocated for recycle.
	 * Set INPROG flag, if the ebio size is equal to cache block size
	 */
	EIO_ASSERT(!(EIO_CACHE_STATE_GET(dmc, index) & DIRTY));
	if (eio_to_sector(ebio->eb_size) == dmc->block_size) {
		if (res == VALID)
			atomic64_inc(&dmc->eio_stats.wr_replace);
		else
			atomic64_inc(&dmc->eio_stats.cached_blocks);
		EIO_CACHE_STATE_SET(dmc, index, VALID | CACHEWRITEINPROG);
		EIO_DBN_SET(dmc, index, (sector_t)ebio->eb_sector);
		ebio->eb_index = index;
		retval = 1;
	} else {
		/*
		 * eb iosize smaller than cache block size shouldn't
		 * do cache write on a cache miss
		 */
		retval = 0;
		ebio->eb_iotype |= EB_INVAL;
	}

out:
	if ((retval == 1) && (dmc->mode == CACHE_MODE_WB) &&
	    (cstate != ALREADY_DIRTY))
		ebio->eb_bc->bc_mdwait++;

	spin_unlock_irqrestore(&dmc->cache_sets[ebio->eb_cacheset].cs_lock,
			       flags);

	/*
	 * Enqueue clean set if there is no room in the set
	 * TBD
	 * Ensure, a force clean
	 */
	if (res < 0)
		eio_comply_dirty_thresholds(dmc, ebio->eb_cacheset);

	return retval;
}

/* Top level read function, called from eio_map */
static void
eio_read(struct cache_c *dmc, struct bio_container *bc, struct eio_bio *ebegin)
{
	int ucread = 0;
	struct eio_bio *ebio;
	struct eio_bio *enext;

	bc->bc_dir = UNCACHED_READ;
	ebio = ebegin;
	while (ebio) {
		enext = ebio->eb_next;
		if (eio_read_peek(dmc, ebio) == 0)
			ucread = 1;
		ebio = enext;
	}

	if (ucread) {
		/*
		 * Uncached read.
		 * Start HDD I/O. Once that is finished
		 * readfill or dirty block re-read would start
		 */
		atomic64_inc(&dmc->eio_stats.uncached_reads);
		eio_disk_io(dmc, bc->bc_bio, ebegin, bc, 0);
	} else {
		/* Cached read. Serve the read from SSD */

		/*
		 * Pass all orig bio flags except UNPLUG.
		 * Unplug in the end if flagged.
		 */
		int rw_flags;

		rw_flags = 0;

		bc->bc_dir = CACHED_READ;
		ebio = ebegin;

		VERIFY_BIO_FLAGS(ebio);

		EIO_ASSERT((rw_flags & 1) == READ);
		while (ebio) {
			enext = ebio->eb_next;
			ebio->eb_iotype = EB_MAIN_IO;

			eio_cached_read(dmc, ebio, rw_flags);
			ebio = enext;
		}
	}
}

/* Top level write function called from eio_map */
static void
eio_write(struct cache_c *dmc, struct bio_container *bc, struct eio_bio *ebegin)
{
	int ucwrite = 0;
	int error = 0;
	struct eio_bio *ebio;
	struct eio_bio *enext;

	if ((dmc->mode != CACHE_MODE_WB) ||
	    (dmc->sysctl_active.do_clean & EIO_CLEAN_KEEP))
		ucwrite = 1;

	ebio = ebegin;
	while (ebio) {
		enext = ebio->eb_next;
		if (eio_write_peek(dmc, ebio) == 0)
			ucwrite = 1;
		ebio = enext;
	}

	if (ucwrite) {
		/*
		 * Uncached write.
		 * Start both SSD and HDD writes
		 */
		atomic64_inc(&dmc->eio_stats.uncached_writes);
		bc->bc_mdwait = 0;
		bc->bc_dir = UNCACHED_WRITE;
		ebio = ebegin;
		while (ebio) {
			enext = ebio->eb_next;
			eio_uncached_write(dmc, ebio);
			ebio = enext;
		}

		eio_disk_io(dmc, bc->bc_bio, ebegin, bc, 0);
	} else {
		/* Cached write. Start writes to SSD blocks */

		int rw_flags;
		rw_flags = 0;

		bc->bc_dir = CACHED_WRITE;
		if (bc->bc_mdwait) {

			/*
			 * mdreqs are required only if the write would cause a metadata
			 * update.
			 */

			error = eio_alloc_mdreqs(dmc, bc);
		}

		/*
		 * Pass all orig bio flags except UNPLUG.
		 * UNPLUG in the end if flagged.
		 */
		ebio = ebegin;
		VERIFY_BIO_FLAGS(ebio);

		while (ebio) {
			enext = ebio->eb_next;
			ebio->eb_iotype = EB_MAIN_IO;

			if (!error) {

				eio_cached_write(dmc, ebio, WRITE | rw_flags);

			} else {
				unsigned long flags;
				u_int8_t cstate;

				pr_err
					("eio_write: IO submission failed, block %llu",
					EIO_DBN_GET(dmc, ebio->eb_index));
				spin_lock_irqsave(&dmc->
						  cache_sets[ebio->eb_cacheset].
						  cs_lock, flags);
				cstate =
					EIO_CACHE_STATE_GET(dmc, ebio->eb_index);
				if (cstate != ALREADY_DIRTY) {

					/*
					 * A DIRTY(inprog) block should be invalidated on error.
					 */

					EIO_CACHE_STATE_SET(dmc, ebio->eb_index,
							    INVALID);
					atomic64_dec_if_positive(&dmc->
								 eio_stats.
								 cached_blocks);
				}
				spin_unlock_irqrestore(&dmc->
						       cache_sets[ebio->
								  eb_cacheset].
						       cs_lock, flags);
				eb_endio(ebio, error);
			}
			ebio = enext;
		}
	}
}

/*
 * Synchronous clean of all the cache sets. Callers of this function needs
 * to handle the situation that clean operation was aborted midway.
 */

void eio_clean_all(struct cache_c *dmc)
{
	unsigned long flags = 0;

	EIO_ASSERT(dmc->mode == CACHE_MODE_WB);
	for (atomic_set(&dmc->clean_index, 0);
	     (atomic_read(&dmc->clean_index) <
	      (s32)(dmc->size >> dmc->consecutive_shift))
	     && (dmc->sysctl_active.do_clean & EIO_CLEAN_START)
	     && (atomic64_read(&dmc->nr_dirty) > 0)
	     && (!(dmc->cache_flags & CACHE_FLAGS_SHUTDOWN_INPROG)
		 && !dmc->sysctl_active.fast_remove);
	     atomic_inc(&dmc->clean_index)) {

		if (unlikely(CACHE_FAILED_IS_SET(dmc))) {
			pr_err("clean_all: CACHE \"%s\" is in FAILED state.",
			       dmc->cache_name);
			break;
		}

		eio_clean_set(dmc, (index_t)(atomic_read(&dmc->clean_index)),
				/* whole */ 1, /* force */ 1);
	}

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	dmc->sysctl_active.do_clean &= ~EIO_CLEAN_START;
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
}

/*
 * Do unconditional clean of a cache.
 * Useful for a cold enabled writeback cache.
 */
void eio_clean_for_reboot(struct cache_c *dmc)
{
	index_t i;

	for (i = 0; i < (index_t)(dmc->size >> dmc->consecutive_shift); i++)
		eio_clean_set(dmc, i, /* whole */ 1, /* force */ 1);
}

/*
 * Used during the partial cache set clean.
 * Uses reclaim policy(LRU/FIFO) information to
 * identify the cache blocks that needs cleaning.
 * The number of such cache blocks is determined
 * by the high and low thresholds set.
 */
static void
eio_get_setblks_to_clean(struct cache_c *dmc, index_t set, int *ncleans)
{
	int i = 0;
	int max_clean;
	index_t start_index;
	int nr_writes = 0;

	*ncleans = 0;
	
	max_clean = dmc->cache_sets[set].nr_dirty -
		    ((dmc->sysctl_active.dirty_set_low_threshold * dmc->assoc) / 100);
	if (max_clean <= 0)
		/* Nothing to clean */
		return;

	start_index = set * dmc->assoc;

	/*
	 * Spinlock is not required here, as we assume that we have
	 * taken a write lock on the cache set, when we reach here
	 */
	if (dmc->policy_ops == NULL) {
		/* Scan sequentially in the set and pick blocks to clean */
		while ((i < (int)dmc->assoc) && (nr_writes < max_clean)) {
			if ((EIO_CACHE_STATE_GET(dmc, start_index + i) &
			     (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
				EIO_CACHE_STATE_ON(dmc, start_index + i,
						   DISKWRITEINPROG);
				nr_writes++;
			}
			i++;
		}
	} else
		nr_writes =
			eio_policy_clean_set(dmc->policy_ops, set, max_clean);

	*ncleans = nr_writes;
}

/* Callback function, when synchronous I/O completes */
static void eio_sync_io_callback(int error, void *context)
{
	struct sync_io_context *sioc = (struct sync_io_context *)context;

	if (error)
		sioc->sio_error = error;
	up_read(&sioc->sio_lock);
}

/*
 * Setup biovecs for preallocated biovecs per cache set.
 */

struct bio_vec *setup_bio_vecs(struct bio_vec *bvec, index_t block_index,
			       unsigned block_size, unsigned total,
			       unsigned *num_bvecs)
{
	struct bio_vec *data = NULL;
	index_t iovec_index;

	switch (block_size) {
	case BLKSIZE_2K:
		*num_bvecs = total;
		iovec_index = block_index;
		data = &bvec[iovec_index];
		break;

	case BLKSIZE_4K:
		*num_bvecs = total;
		iovec_index = block_index;
		data = &bvec[iovec_index];
		break;

	case BLKSIZE_8K:
		/*
		 * For 8k data block size, we need 2 bio_vecs
		 * per data block.
		 */
		*num_bvecs = total * 2;
		iovec_index = block_index * 2;
		data = &bvec[iovec_index];
		break;
	}

	return data;
}

static void 
//eio_clean_n_sets(struct cache_c *dmc, index_t set_array[], int nr_set, int whole, int force)
eio_clean_n_sets(struct cache_c *dmc, index_t set_array[], int nr_set, int force)

{
	struct eio_io_region where;
	int error;
	index_t i;
	index_t j;
	index_t start_index;
	index_t end_index;
	struct sync_io_context sioc;
	int ncleans = 0;
	int alloc_size;
	struct flash_cacheblock *md_blocks = NULL;
	unsigned long flags;

	int pindex, k;
	index_t blkindex;
	struct bio_vec *bvecs;
	unsigned nr_bvecs = 0, total;
	void *pg_virt_addr[2] = { NULL };

	int bindex, tmp;
	index_t set;
	int ttl_cleans = 0;	
	int nr_sort = 0;
	int ttl_nr_dirty = 0;	
	
	unsigned long start_read;	
	unsigned long read_completed;
	unsigned long start_sort;	
	unsigned long end_sort;
	unsigned long start_flush;	
	unsigned long end_flush;
	unsigned long io_completed;
	unsigned long start_write_md;	
	unsigned long end_write_md;

	/* Cache is failed mode, do nothing. */
	if (unlikely(CACHE_FAILED_IS_SET(dmc))) {
		pr_debug("clean_set: CACHE \"%s\" is in FAILED state.",
			 dmc->cache_name);
		EIO_DBG(ERROR, dmc, "CACHE \"%s\" is in FAILED state.",
			 dmc->cache_name);
		goto err_out1;
	}

	/* If this is not the suitable time to clean, postpone it */
	if ((!force) && AUTOCLEAN_THRESHOLD_CROSSED(dmc)) {
		goto err_out1;
	}

	/*
	 * 1. Take exclusive lock on all cache sets
	 * 2. Verify that there are dirty blocks to clean
	 * 3. Identify the cache blocks to clean
	 * 4. add CLEAN_INPROG cache block to sort_array
	 * 5. Read the cache blocks data from ssd
	 * 6. HeapSort	 
	 * 7. write to hdd
	 * 8. update on-disk cache metadata
	 */

	for (k = 0; k < nr_set; k++) {		
		set = set_array[k];

		/* 1. exclusive lock. Let the ongoing writes to finish. Pause new writes */
		down_write(&dmc->cache_sets[set].rw_lock);

		/* 2. Verify that there are dirty blocks to clean */
		//EIO_ASSERT(dmc->cache_sets[set].nr_dirty != 0);
		if (0 == dmc->cache_sets[set].nr_dirty) {
			EIO_DBG(DEBUG, dmc, "------CACHESET[0x%lx] no dirty block------\n", set);
		}
		ttl_nr_dirty += dmc->cache_sets[set].nr_dirty;
	}
	if (0 == ttl_nr_dirty) {
		//pr_err("------no dirty block------\n");
		goto err_out2;
	}

	start_read = jiffies;
	EIO_DBG(DEBUG, dmc, "------START READ:%ums------\n", jiffies_to_msecs(start_read));
	for (k = 0; k < nr_set; k++) {
		set = set_array[k];
		if (0 == dmc->cache_sets[set].nr_dirty) {
			continue;
		}
		start_index = set * dmc->assoc;
		end_index = start_index + dmc->assoc;
		
		/* 3. identify and mark cache blocks to clean */
		if (!(dmc->cache_sets[set].flags & SETFLAG_CLEAN_WHOLE))
			eio_get_setblks_to_clean(dmc, set, &ncleans);
		else {
			for (i = start_index; i < end_index; i++) {
				if (EIO_CACHE_STATE_GET(dmc, i) == ALREADY_DIRTY) {
					EIO_CACHE_STATE_SET(dmc, i, CLEAN_INPROG);
					ncleans++;				
				}
			}
		}
		//EIO_ASSERT(ncleans != 0);
		ttl_cleans += ncleans;
		
		EIO_DBG(DEBUG, dmc, "------CLEAN set[0x%lx], ncleans[0x%x]------", set, ncleans);
		ncleans = 0;
		/*4. add CLEAN_INPROG cache block to sort_array*/
		for (i = start_index; i < end_index; i++) {
			if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG) {
				dmc->sort_array[nr_sort].dbn = EIO_DBN_GET(dmc, i);
				dmc->sort_array[nr_sort].index = (i - start_index) + dmc->assoc * k;
				nr_sort++;
			}
		}
		
		/* 5. read cache set data */
		init_rwsem(&sioc.sio_lock);
		sioc.sio_error = 0;

		for (i = start_index; i < end_index; i++) {
			if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG) {
				
				for (j = i; ((j < end_index) &&
					(EIO_CACHE_STATE_GET(dmc, j) == CLEAN_INPROG));
					j++);
		
				blkindex = (i - start_index);
				blkindex += (dmc->assoc * k);
				total = (j - i);
				
				/*
				 * Get the correct index and number of bvecs
				 * setup from dmc->clean_n_sets_dbvecs before issuing i/o.
				 */
				bvecs =
					setup_bio_vecs(dmc->clean_n_sets_dbvecs, blkindex,
							   dmc->block_size, total, &nr_bvecs);
				EIO_ASSERT(bvecs != NULL);
				EIO_ASSERT(nr_bvecs > 0);
		
				where.bdev = dmc->cache_dev->bdev;
				where.sector =
					(i << dmc->block_shift) + dmc->md_sectors;
				where.count = total * dmc->block_size;
		
				SECTOR_STATS(dmc->eio_stats.ssd_reads,
						 to_bytes(where.count));
				down_read(&sioc.sio_lock);
				error =
					eio_io_async_bvec(dmc, &where, READ, bvecs,
							  nr_bvecs, eio_sync_io_callback,
							  &sioc, 0);
				if (error) {
					sioc.sio_error = error;
					up_read(&sioc.sio_lock);
				}
		
				bvecs = NULL;
				i = j;
			}
		}
		/*
		 * In above for loop, submit all READ I/Os to SSD
		 * and unplug the device for immediate submission to
		 * underlying device driver.
		 */
		eio_unplug_cache_device(dmc);
		
		//end_read = jiffies;
		//EIO_DBG("------END READ:%dms------\n", end_read);
		/* wait for all I/Os to complete and release sync lock */
		down_write(&sioc.sio_lock);
		up_write(&sioc.sio_lock);
				
		error = sioc.sio_error;
		if (error)
			goto err_out3;
	}

	read_completed = jiffies;
	EIO_DBG(DEBUG, dmc, "------READ COMPLETED:%ums, READ TIME:%ums------\n", \
		jiffies_to_msecs(read_completed),\
		jiffies_to_msecs(read_completed - start_read));

	EIO_DBG(DEBUG, dmc, "------BEFORE SORT------, nr_sort:%d\n", nr_sort);
	#if 0
	for (k = 0; k < nr_sort/8; k++) {
		EIO_DBG("------sort_idx:%d, block_idx:%ld, dbn:%lx------\n", k, 
			dmc->sort_array[k].index, dmc->sort_array[k].dbn);
	}
	#endif
	/* 6. HeapSort */
	EIO_ASSERT(ttl_cleans == nr_sort);
	//heap_sort(dmc->sort_array, nr_sort);
	start_sort = jiffies;
	EIO_DBG(DEBUG, dmc, "------START SORT:%ums------\n", jiffies_to_msecs(start_sort));
	sort(dmc->sort_array, nr_sort, sizeof(dmc->sort_array[0]), cmp_dbn, NULL);
	end_sort = jiffies;
	EIO_DBG(DEBUG, dmc, "------END SORT:%ums, SORT TIME:%ums------\n", \
		jiffies_to_msecs(end_sort), \
		jiffies_to_msecs(end_sort - start_sort));

	EIO_DBG(DEBUG, dmc, "------AFTER SORT------\n");
	#if 0
	for (k = 0; k < nr_sort; k++) {
		EIO_DBG("------sort_idx:%d, block_idx:%ld, dbn:%lx------\n", k, 
			dmc->sort_array[k].index, dmc->sort_array[k].dbn);
	}
	#endif
	/* 7. write to hdd */
	/*
	 * While writing the data to HDD, explicitly enable
	 * BIO_RW_SYNC flag to hint higher priority for these
	 * I/Os.
	 */
	start_flush = jiffies;
	EIO_DBG(INFO, dmc, "------START FLUSH:%ums-----\n", jiffies_to_msecs(start_flush));
	for (k = 0; k < nr_sort; k++) {	
		blkindex = dmc->sort_array[k].index;				
		total = 1;
		bvecs =
			setup_bio_vecs(dmc->clean_n_sets_dbvecs, blkindex,
				       dmc->block_size, total, &nr_bvecs);
		EIO_ASSERT(bvecs != NULL);
		EIO_ASSERT(nr_bvecs > 0);

		where.bdev = dmc->disk_dev->bdev;
		where.sector = dmc->sort_array[k].dbn;
		where.count = dmc->block_size;
		//EIO_DBG("write hdd-blkindex:%lx, dbn:%lx\n", blkindex, dmc->sort_array[k].dbn);
		SECTOR_STATS(dmc->eio_stats.disk_writes,
			     to_bytes(where.count));
		down_read(&sioc.sio_lock);
		error = eio_io_async_bvec(dmc, &where, WRITE | REQ_SYNC,
					  bvecs, nr_bvecs,
					  eio_sync_io_callback, &sioc,
					  1);
		if (error) {
			sioc.sio_error = error;
			up_read(&sioc.sio_lock);
			EIO_DBG(ERROR, dmc, "CACHEBLOCK:%u write to hdd error!!!\n", (unsigned int)blkindex);
		}
		bvecs = NULL;
		/*test*/
		//msleep(10);
	}
	/* wait for all I/Os to complete and release sync lock */	
	end_flush = jiffies;
	EIO_DBG(INFO, dmc, "------SUBMIT ALL IO:%ums-----\n", jiffies_to_msecs(end_flush));

    //error = sync_blockdev(dmc->disk_dev->bdev);
	//if (error) {
	//	pr_err("sync error!!!\n");
	//}

	down_write(&sioc.sio_lock);
	up_write(&sioc.sio_lock);
	
	io_completed = jiffies;
	EIO_DBG(INFO, dmc, "------ALL IO COMPLETED:%ums-----\n", jiffies_to_msecs(io_completed));	
	EIO_DBG(INFO, dmc, "------IO COUNT:%u, FLUSH TIME:%ums, SUBMIT TIME:%ums, WAIT TIME:%ums-----\n", \
		nr_sort, jiffies_to_msecs(io_completed - start_flush), \
		jiffies_to_msecs(end_flush - start_flush), \
		jiffies_to_msecs(io_completed - end_flush));
	error = sioc.sio_error;
	if (error) {
		EIO_DBG(ERROR, dmc, "FLUSH error!!!\n");
		goto err_out3;
	}

	/* 8. update on-disk cache metadata */

	/* TBD. Do we have to consider sector alignment here ? */

	/*
	 * md_size = dmc->assoc * sizeof(struct flash_cacheblock);
	 * Currently, md_size is 8192 bytes, mdpage_count is 2 pages maximum.
	 */

	EIO_ASSERT(dmc->mdpage_count <= 2);

	start_write_md = jiffies;
	EIO_DBG(DEBUG, dmc, "------START WRITE MD:%ums------\n", jiffies_to_msecs(start_write_md));
#if 1
	alloc_size = dmc->assoc * sizeof(struct flash_cacheblock);
	
	for (k = 0; k < nr_set; k++) {
		set = set_array[k];	
		if (0 == dmc->cache_sets[set].nr_dirty) {
			continue;
		}
		start_index = set * dmc->assoc;
		end_index = start_index + dmc->assoc;
		
		for (tmp = 0; tmp < dmc->mdpage_count; tmp++) {
			pg_virt_addr[tmp] = kmap(dmc->clean_mdpages[tmp]);
		}
		pindex = 0;
		md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];
		bindex = MD_BLOCKS_PER_PAGE;
		
		for (i = start_index; i < end_index; i++) {

			md_blocks->dbn = cpu_to_le64(EIO_DBN_GET(dmc, i));

			if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG)
				md_blocks->cache_state = cpu_to_le64(INVALID);
			else if (EIO_CACHE_STATE_GET(dmc, i) == ALREADY_DIRTY)
				md_blocks->cache_state = cpu_to_le64((VALID | DIRTY));
			else
				md_blocks->cache_state = cpu_to_le64(INVALID);

			/* This was missing earlier. */
			md_blocks++;
			bindex--;

			if (bindex == 0) {
				md_blocks =
					(struct flash_cacheblock *)pg_virt_addr[++pindex];
				bindex = MD_BLOCKS_PER_PAGE;
			}
		}
		
		for (tmp = 0; tmp < dmc->mdpage_count; tmp++) {
			kunmap(dmc->clean_mdpages[tmp]);
		}
		
		where.bdev = dmc->cache_dev->bdev;
		where.sector = dmc->md_start_sect + INDEX_TO_MD_SECTOR(start_index);
		where.count = eio_to_sector(alloc_size);
		error =
			eio_io_sync_pages(dmc, &where, WRITE, dmc->clean_mdpages,
					  dmc->mdpage_count);

		if (error) {
			for (tmp = 0; tmp < dmc->mdpage_count; tmp++)
				kunmap(dmc->clean_mdpages[tmp]);
			
			goto err_out3;
		}
	}
	end_write_md = jiffies;
	EIO_DBG(DEBUG, dmc, "------END WRITE MD:%ums, WRITE TIME:%ums------\n", \
		jiffies_to_msecs(end_write_md), \
		jiffies_to_msecs(end_write_md - start_write_md));
#endif

	err_out3:
	
		/*
		 * 7. update in-core cache metadata for clean_inprog blocks.
		 * If there was an error, set them back to ALREADY_DIRTY
		 * If no error, set them to VALID
		 */
		 
		for (k = 0; k < nr_set; k++) {
			set = set_array[k];		
			if (0 == dmc->cache_sets[set].nr_dirty) {
				continue;
			}
			start_index = set * dmc->assoc;
			end_index = start_index + dmc->assoc;
			for (i = start_index; i < end_index; i++) {
				if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG) {
					if (error)
						EIO_CACHE_STATE_SET(dmc, i, ALREADY_DIRTY);
					else {
						EIO_CACHE_STATE_SET(dmc, i, VALID);
						EIO_ASSERT(dmc->cache_sets[set].nr_dirty > 0);
						dmc->cache_sets[set].nr_dirty--;
						atomic64_dec(&dmc->nr_dirty);
					}
				}
			}
		}
	
	err_out2:
		for (k = 0; k < nr_set; k++) {
			set = set_array[k];
			up_write(&dmc->cache_sets[set].rw_lock);
		}

	err_out1:
		/* Reset clean flags on the set */
		for (k = 0; k < nr_set; k++) {
			set = set_array[k];
			if (!force) {
				spin_lock_irqsave(&dmc->cache_sets[set].cs_lock, flags);
				dmc->cache_sets[set].flags &=
					~(SETFLAG_CLEAN_INPROG | SETFLAG_CLEAN_WHOLE
					#ifdef CONFIG_LOW_IO_PRESSURE_CLEAN
						| SETFLAG_CLEAN_LOW_IO_PRESSURE  
					#endif
					);
				spin_unlock_irqrestore(&dmc->cache_sets[set].cs_lock, flags);
			}

			if (dmc->cache_sets[set].nr_dirty) {
				/*
				 * Lru touch the set, so that it can be picked
				 * up for whole set clean by clean thread later
				 */
				eio_touch_set_lru(dmc, set);
			}
		}
		
	return;
}
/* Cleans a given cache set */
static void
eio_clean_set(struct cache_c *dmc, index_t set, int whole, int force)
{
	struct eio_io_region where;
	int error;
	index_t i;
	index_t j;
	index_t start_index;
	index_t end_index;
	struct sync_io_context sioc;
	int ncleans = 0;
	int alloc_size;
	struct flash_cacheblock *md_blocks = NULL;
	unsigned long flags;

	int pindex, k;
	index_t blkindex;
	struct bio_vec *bvecs;
	unsigned nr_bvecs = 0, total;
	void *pg_virt_addr[2] = { NULL };

	/*IOÅÅÐò*/
	//struct dbn_index_pair sort_array[512] = {{0, 0}};
	//int nr_sort = 0;

	/* Cache is failed mode, do nothing. */
	if (unlikely(CACHE_FAILED_IS_SET(dmc))) {
		pr_debug("clean_set: CACHE \"%s\" is in FAILED state.",
			 dmc->cache_name);
		goto err_out1;
	}

	/* Nothing to clean, if there are no dirty blocks */
	if (dmc->cache_sets[set].nr_dirty == 0)
		goto err_out1;

	/* If this is not the suitable time to clean, postpone it */
	if ((!force) && AUTOCLEAN_THRESHOLD_CROSSED(dmc)) {
		eio_touch_set_lru(dmc, set);
		goto err_out1;
	}

	/*
	 * 1. Take exclusive lock on the cache set
	 * 2. Verify that there are dirty blocks to clean
	 * 3. Identify the cache blocks to clean
	 * 4. Read the cache blocks data from ssd
	 * 5. Write the cache blocks data to hdd
	 * 6. Update on-disk cache metadata
	 * 7. Update in-core cache metadata
	 */

	start_index = set * dmc->assoc;
	end_index = start_index + dmc->assoc;

	/* 1. exclusive lock. Let the ongoing writes to finish. Pause new writes */
	down_write(&dmc->cache_sets[set].rw_lock);

	/* 2. Return if there are no dirty blocks to clean */
	if (dmc->cache_sets[set].nr_dirty == 0)
		goto err_out2;

	/* 3. identify and mark cache blocks to clean */
	if (!whole)
		eio_get_setblks_to_clean(dmc, set, &ncleans);
	else {
		for (i = start_index; i < end_index; i++) {
			if (EIO_CACHE_STATE_GET(dmc, i) == ALREADY_DIRTY) {
				EIO_CACHE_STATE_SET(dmc, i, CLEAN_INPROG);
				ncleans++;				
			}
		}
	}

	/* If nothing to clean, return */
	if (!ncleans)
		goto err_out2;
	#if 0
	EIO_DBG(DEBUG, dmc, "------CLEAN set[0x%lx], whole[%d], ncleans[0x%x]------", set, whole, ncleans);
	/*add CLEAN_INPROG cache block to sort_array*/
	for (i = start_index; i < end_index; i++) {
		if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG) {
			sort_array[nr_sort].dbn = EIO_DBN_GET(dmc, i);
			sort_array[nr_sort].index = i;
			nr_sort++;
		}
	}
	EIO_ASSERT(nr_sort == ncleans);
	#endif
	#if 0
	EIO_DBG("------BEFORE SORT------");
	for (k = 0; k < nr_sort; k++) {
		EIO_DBG("---block index[0x%lx], dbn[0x%lx]", \
				sort_array[k].index, sort_array[k].dbn);
	}
	#endif
	/*
	 * From this point onwards, make sure to reset
	 * the clean inflag on cache blocks before returning
	 */

	/* 4. read cache set data */

	init_rwsem(&sioc.sio_lock);
	sioc.sio_error = 0;

	for (i = start_index; i < end_index; i++) {
		if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG) {
			
			for (j = i; ((j < end_index) &&
				(EIO_CACHE_STATE_GET(dmc, j) == CLEAN_INPROG));
				j++);

			blkindex = (i - start_index);
			total = (j - i);

			/*
			 * Get the correct index and number of bvecs
			 * setup from dmc->clean_dbvecs before issuing i/o.
			 */
			bvecs =
				setup_bio_vecs(dmc->clean_dbvecs, blkindex,
					       dmc->block_size, total, &nr_bvecs);
			EIO_ASSERT(bvecs != NULL);
			EIO_ASSERT(nr_bvecs > 0);

			where.bdev = dmc->cache_dev->bdev;
			where.sector =
				(i << dmc->block_shift) + dmc->md_sectors;
			where.count = total * dmc->block_size;

			SECTOR_STATS(dmc->eio_stats.ssd_reads,
				     to_bytes(where.count));
			down_read(&sioc.sio_lock);
			error =
				eio_io_async_bvec(dmc, &where, READ, bvecs,
						  nr_bvecs, eio_sync_io_callback,
						  &sioc, 0);
			if (error) {
				sioc.sio_error = error;
				up_read(&sioc.sio_lock);
			}

			bvecs = NULL;
			i = j;
		}
	}
	/*
	 * In above for loop, submit all READ I/Os to SSD
	 * and unplug the device for immediate submission to
	 * underlying device driver.
	 */
	eio_unplug_cache_device(dmc);

	/* wait for all I/Os to complete and release sync lock */
	down_write(&sioc.sio_lock);
	up_write(&sioc.sio_lock);

	error = sioc.sio_error;
	if (error)
		goto err_out3;

	/* 5. write to hdd */
	/*
	 * While writing the data to HDD, explicitly enable
	 * BIO_RW_SYNC flag to hint higher priority for these
	 * I/Os.
	 */

	/*heapsort sort_array*/
	//heap_sort(sort_array, ncleans);
	//sort(sort_array, ncleans, sizeof(sort_array[0]), cmp_dbn, NULL);
	
	#if 0
	EIO_DBG("------AFTER SORT------");
	for (k = 0; k < nr_sort; k++) {
		EIO_DBG("---block index[0x%lx], dbn[0x%lx]", \
				sort_array[k].index, sort_array[k].dbn);
	}
	#endif

	#if 0
	for (k = 0; k < nr_sort; k++) {
		
		blkindex = sort_array[k].index - start_index;
		total = 1;
		
		EIO_ASSERT(blkindex < dmc->assoc);
		bvecs = setup_bio_vecs(dmc->clean_dbvecs, blkindex,
					   dmc->block_size, total, &nr_bvecs);

		EIO_ASSERT(bvecs != NULL);
		EIO_ASSERT(bvecs->bv_page != NULL);
		EIO_ASSERT(nr_bvecs > 0);
		
		where.bdev = dmc->disk_dev->bdev;
		where.sector = sort_array[k].dbn;
		where.count = dmc->block_size;
		
		SECTOR_STATS(dmc->eio_stats.disk_writes,
				 to_bytes(where.count));
		down_read(&sioc.sio_lock);
		error = eio_io_async_bvec(dmc, &where, WRITE | REQ_SYNC,
					  bvecs, nr_bvecs,
					  eio_sync_io_callback, &sioc,
					  1);
		
		if (error) {
			sioc.sio_error = error;
			up_read(&sioc.sio_lock);
		}
		bvecs = NULL;
	}
	#endif
	#if 1
	for (i = start_index; i < end_index; i++) {
		if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG) {

			blkindex = (i - start_index);
			total = 1;

			bvecs =
				setup_bio_vecs(dmc->clean_dbvecs, blkindex,
					       dmc->block_size, total, &nr_bvecs);
			EIO_ASSERT(bvecs != NULL);
			EIO_ASSERT(nr_bvecs > 0);

			where.bdev = dmc->disk_dev->bdev;
			where.sector = EIO_DBN_GET(dmc, i);
			where.count = dmc->block_size;

			SECTOR_STATS(dmc->eio_stats.disk_writes,
				     to_bytes(where.count));
			down_read(&sioc.sio_lock);
			error = eio_io_async_bvec(dmc, &where, WRITE | REQ_SYNC,
						  bvecs, nr_bvecs,
						  eio_sync_io_callback, &sioc,
						  1);

			if (error) {
				sioc.sio_error = error;
				up_read(&sioc.sio_lock);
			}
			bvecs = NULL;
		}
	}
	#endif
	/* wait for all I/Os to complete and release sync lock */
	down_write(&sioc.sio_lock);
	up_write(&sioc.sio_lock);

	error = sioc.sio_error;
	if (error)
		goto err_out3;

	/* 6. update on-disk cache metadata */

	/* TBD. Do we have to consider sector alignment here ? */

	/*
	 * md_size = dmc->assoc * sizeof(struct flash_cacheblock);
	 * Currently, md_size is 8192 bytes, mdpage_count is 2 pages maximum.
	 */

	EIO_ASSERT(dmc->mdpage_count <= 2);
	for (k = 0; k < dmc->mdpage_count; k++)
		pg_virt_addr[k] = kmap(dmc->clean_mdpages[k]);

	alloc_size = dmc->assoc * sizeof(struct flash_cacheblock);
	pindex = 0;
	md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];
	k = MD_BLOCKS_PER_PAGE;

	for (i = start_index; i < end_index; i++) {

		md_blocks->dbn = cpu_to_le64(EIO_DBN_GET(dmc, i));

		if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG)
			md_blocks->cache_state = cpu_to_le64(INVALID);
		else if (EIO_CACHE_STATE_GET(dmc, i) == ALREADY_DIRTY)
			md_blocks->cache_state = cpu_to_le64((VALID | DIRTY));
		else
			md_blocks->cache_state = cpu_to_le64(INVALID);

		/* This was missing earlier. */
		md_blocks++;
		k--;

		if (k == 0) {
			md_blocks =
				(struct flash_cacheblock *)pg_virt_addr[++pindex];
			k = MD_BLOCKS_PER_PAGE;
		}
	}

	for (k = 0; k < dmc->mdpage_count; k++)
		kunmap(dmc->clean_mdpages[k]);

	where.bdev = dmc->cache_dev->bdev;
	where.sector = dmc->md_start_sect + INDEX_TO_MD_SECTOR(start_index);
	where.count = eio_to_sector(alloc_size);
	error =
		eio_io_sync_pages(dmc, &where, WRITE, dmc->clean_mdpages,
				  dmc->mdpage_count);

	if (error)
		goto err_out3;

err_out3:

	/*
	 * 7. update in-core cache metadata for clean_inprog blocks.
	 * If there was an error, set them back to ALREADY_DIRTY
	 * If no error, set them to VALID
	 */
	for (i = start_index; i < end_index; i++) {
		if (EIO_CACHE_STATE_GET(dmc, i) == CLEAN_INPROG) {
			if (error)
				EIO_CACHE_STATE_SET(dmc, i, ALREADY_DIRTY);
			else {
				EIO_CACHE_STATE_SET(dmc, i, VALID);
				EIO_ASSERT(dmc->cache_sets[set].nr_dirty > 0);
				dmc->cache_sets[set].nr_dirty--;
				atomic64_dec(&dmc->nr_dirty);
			}
		}
	}

err_out2:

	up_write(&dmc->cache_sets[set].rw_lock);

err_out1:

	/* Reset clean flags on the set */

	if (!force) {
		spin_lock_irqsave(&dmc->cache_sets[set].cs_lock, flags);
		dmc->cache_sets[set].flags &=
			~(SETFLAG_CLEAN_INPROG | SETFLAG_CLEAN_WHOLE
		#ifdef CONFIG_LOW_IO_PRESSURE_CLEAN
				| SETFLAG_CLEAN_LOW_IO_PRESSURE  
		#endif
		);
		spin_unlock_irqrestore(&dmc->cache_sets[set].cs_lock, flags);
	}

	if (dmc->cache_sets[set].nr_dirty)
		/*
		 * Lru touch the set, so that it can be picked
		 * up for whole set clean by clean thread later
		 */
		eio_touch_set_lru(dmc, set);

	return;
}

/*
 * Enqueues the dirty sets for clean, which had got dirtied long
 * time back(aged). User tunable values to determine if a set has aged
 */
void eio_clean_aged_sets(struct work_struct *work)
{
	struct cache_c *dmc;
	unsigned long flags = 0;
	index_t set_index;
	u_int64_t set_time;
	u_int64_t cur_time;

	dmc = container_of(work, struct cache_c, clean_aged_sets_work.work);

	/*
	 * In FAILED state, dont schedule cleaning of sets.
	 */
	if (unlikely(CACHE_FAILED_IS_SET(dmc))) {
		pr_debug("clean_aged_sets: Cache \"%s\" is in failed mode.\n",
			 dmc->cache_name);
		/*
		 * This is to make sure that this thread is rescheduled
		 * once CACHE is ACTIVE again.
		 */
		spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
		dmc->is_clean_aged_sets_sched = 0;
		spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);

		return;
	}
	
	cur_time = jiffies;

	/* Use the set LRU list to pick up the most aged sets. */
	spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
	do {
		lru_read_head(dmc->dirty_set_lru, &set_index, &set_time);
		if (set_index == LRU_NULL)
			break;

		if ((EIO_DIV((cur_time - set_time), HZ)) <
		    (dmc->sysctl_active.time_based_clean_interval * 60))
			break;		
		EIO_DBG(INFO, dmc, "++++++add set[0x%lx] to clean:aged", set_index);		
		lru_rem(dmc->dirty_set_lru, set_index);

		if (dmc->cache_sets[set_index].nr_dirty > 0) {
			spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
			eio_addto_cleanq(dmc, set_index, 1);
			spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
		}
	} while (1);
	spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);

	/* Re-schedule the aged set clean, unless the clean has to stop now */

	if (dmc->sysctl_active.time_based_clean_interval == 0)
		goto out;

	schedule_delayed_work(&dmc->clean_aged_sets_work,
			      dmc->sysctl_active.time_based_clean_interval *
			      60 * HZ);
out:
	return;
}

#ifdef CONFIG_LOW_IO_PRESSURE_CLEAN
static int 
add_to_cleanq_low_io_pressure(struct cache_c *dmc, int count)
{
	int i;	
	unsigned long flags = 0;	
	index_t set_index;	
	
	if (!dmc->set_dirty_sort || 0 == count) {		
		EIO_DBG(INFO, dmc, "set_dirty_sort null or count is 0\n");
		return -1;
	}

	i = 0;
	do {
		#if 0
		/*test dirty percent*/
		if (dmc->set_dirty_sort[i].nr_dirty < per_to_nr) {			
			EIO_DBG(INFO, dmc, "dirty percent is under 10,quit\n");
			break;
		}
		#endif
		set_index = dmc->set_dirty_sort[i].set_index;
		/*set flag*/
		spin_lock_irqsave(&dmc->cache_sets[set_index].cs_lock, flags);
		dmc->cache_sets[set_index].flags |= SETFLAG_CLEAN_LOW_IO_PRESSURE;
		spin_unlock_irqrestore(&dmc->cache_sets[set_index].cs_lock, flags);
		EIO_DBG(INFO, dmc, "++++++add set[%lu] to clean:low IO pressure", 
				(unsigned long)set_index);
		
		spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
		lru_rem(dmc->dirty_set_lru, set_index);		
		spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
		if (dmc->cache_sets[set_index].nr_dirty > 0) {
			eio_addto_cleanq(dmc, set_index, 1);
		}
	} while (++i < count);

	return 0;
}
void eio_clean_low_io_pressure(struct work_struct *work)
{
	struct cache_c *dmc;
	unsigned long flags = 0;
	index_t set_index;	
	unsigned int dirty_blk_pct;
	u_int64_t curr_ioc = 0;
	u_int64_t diff_ioc;	
	u_int64_t curr_rwms = 0;
	u_int64_t diff_rwms;
	int scanned_count;
	//int per_to_nr;
	int ret;	
	int tmp;
	int i;

	dmc = container_of(work, struct cache_c, low_pressure_clean_work.work);	
	/*
	 * In FAILED state, dont schedule cleaning of sets.
	 */
	if (unlikely(CACHE_FAILED_IS_SET(dmc))) {
		pr_debug("eio_clean_low_io_pressure: Cache \"%s\" is in failed mode.\n",
			 dmc->cache_name);
		dmc->is_low_pressure_clean_work_sched = 0;
		return;
	}
	
	/*test some conditions*/
	if (unlikely(dmc->sysctl_active.fast_remove 
		|| dmc->sysctl_active.do_clean 
		|| (atomic64_read(&dmc->nr_dirty) == 0)
		|| (dmc->cache_flags & CACHE_FLAGS_SHUTDOWN_INPROG))) {
		
		//dmc->is_low_pressure_clean_work_sched = 0;
		//return;
		goto out;
	}
	
	/*test dirty_set_lru*/
	spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
	if (lru_empty(dmc->dirty_set_lru)) {
		spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
		EIO_DBG(INFO, dmc, "dirty_set_lru is empty, skip....\n");		
		goto out;
	}
	spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
	
	/*test threshold*/
	dirty_blk_pct = EIO_CALCULATE_PERCENTAGE(atomic64_read(&dmc->nr_dirty), 
												dmc->size);
	EIO_DBG(INFO, dmc, "dirty_blk_pct is %d\n", dirty_blk_pct);
	if (dirty_blk_pct < dmc->sysctl_active.low_io_pressure_dirty_threshold) {
		EIO_DBG(INFO, dmc, "dirty_blk_pct is under %d, skip....\n", 
			     dmc->sysctl_active.low_io_pressure_dirty_threshold);
		goto out;
	}

    if (-1 == dmc->last_ioc) {
		EIO_DBG(INFO, dmc, "last_ioc is -1\n");
		dmc->last_ioc = atomic64_read(&dmc->eio_stats.writecount) + \
			       atomic64_read(&dmc->eio_stats.readcount);
		dmc->last_rwms =  atomic64_read(&dmc->eio_stats.wrtime_ms) + \
			       atomic64_read(&dmc->eio_stats.rdtime_ms);
		goto out;
    }
	
	curr_ioc = atomic64_read(&dmc->eio_stats.writecount) + \
			       atomic64_read(&dmc->eio_stats.readcount);
	curr_rwms =  atomic64_read(&dmc->eio_stats.wrtime_ms) + \
			   atomic64_read(&dmc->eio_stats.rdtime_ms);
	EIO_DBG(INFO, dmc, "curr_ioc:%lu, last_ioc:%lu, curr_rwms:%lu, last_rwms:%lu\n", 
				(unsigned long)curr_ioc, (unsigned long)dmc->last_ioc, 
				(unsigned long)curr_rwms, (unsigned long)dmc->last_rwms);

	/*if sched_interval is 5 second, skip this time*/
	if (WORK_SCHED_INTERVAL_HIGH == dmc->low_io_pressure_sched_interval) {		
		EIO_DBG(INFO, dmc, "sched_interval is %d, skip check\n", WORK_SCHED_INTERVAL_HIGH);		
		dmc->low_io_pressure_sched_interval = WORK_SCHED_INTERVAL;
		goto out;
	}

	/*caculate diff_ioc and diff_rwms*/
	diff_ioc = curr_ioc - dmc->last_ioc;
	diff_rwms = curr_rwms - dmc->last_rwms;
	if (diff_ioc > 0) {
		do_div(diff_rwms, diff_ioc);/*calc lantency per IO*/
	}
	do_div(diff_ioc, dmc->low_io_pressure_sched_interval);/*calc IO count per second*/

	if (0 == diff_ioc ||
		(diff_ioc < dmc->sysctl_active.low_io_pressure_threshold &&
		diff_rwms < dmc->sysctl_active.low_io_pressure_latency)) {
		EIO_DBG(INFO, dmc, "diff_ioc:%lu, diff_rwms:%lu, IO pressure is low!\n",
		(unsigned long)diff_ioc, (unsigned long)diff_rwms);		
		dmc->low_io_pressure_sched_interval = WORK_SCHED_INTERVAL;
		dmc->lowp_cnt++;
		if (dmc->lowp_cnt < LOW_IO_PRESSURE_TIMES) {
			goto out;
		} else {
			atomic_set(&dmc->flag_rm_sets, 0);
			EIO_DBG(INFO, dmc, "low IO pressure confirm.\n");
		}
	} else {
		EIO_DBG(INFO, dmc, "diff_ioc is %lu, diff_rwms:%lu, IO pressure is high!\n", 
			(unsigned long)diff_ioc, (unsigned long)diff_rwms);
		dmc->lowp_cnt = 0;
		dmc->low_io_pressure_sched_interval = WORK_SCHED_INTERVAL_HIGH;
		atomic_set(&dmc->flag_rm_sets, 1);
		goto out;
	}

	/*if cleanq not empty ,just return*/
	spin_lock_irqsave(&dmc->clean_sl, flags);
	if (!list_empty(&dmc->cleanq)) {
		spin_unlock_irqrestore(&dmc->clean_sl, flags);
		EIO_DBG(DEBUG, dmc, "list cleanq not empty,return\n");		
		goto out;
	}
	spin_unlock_irqrestore(&dmc->clean_sl, flags);

	EIO_DBG(INFO, dmc, "%s\n", dmc->scan_head ? "scan_head" : "scan_tail");
	/*scan dirty lru list, get SORT_SET_NR sets */ 
	spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
	ret = lru_scan(dmc->dirty_set_lru, dmc->set_dirty_sort, 
					SORT_SET_NR, &scanned_count, dmc->scan_head);	
	spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);

	if (unlikely(ret || (0 == scanned_count))) {
		pr_info("%s:lru_scan failed!!!, ret:%d, scanned_count:%d, nr_dirty:%lu\n", 
				dmc->cache_name, ret, scanned_count,
				(unsigned long)atomic64_read(&dmc->nr_dirty));
		goto out;
	}

	/*get dirty_nr for all sets*/	
	for (i = 0; i < scanned_count; i++) {
		set_index = dmc->set_dirty_sort[i].set_index;		
		dmc->set_dirty_sort[i].nr_dirty = 
				dmc->cache_sets[set_index].nr_dirty;
		if (unlikely(0 == dmc->cache_sets[set_index].nr_dirty)) {
			EIO_DBG(INFO, dmc, "set[%lu] nr_dirty is 0\n", (unsigned long)set_index);
		}
	}
	
	/*sort all the sets by dirty_nr*/
	sort(dmc->set_dirty_sort, scanned_count, 
			sizeof(dmc->set_dirty_sort[0]), cmp_dirty_nr, NULL);
	
	EIO_DBG(INFO, dmc, "AFTER SORT, scanned_count[%u]\n", scanned_count);
	tmp = (scanned_count > dmc->sysctl_active.low_io_pressure_clean_set_nr) ? 
				dmc->sysctl_active.low_io_pressure_clean_set_nr : scanned_count;
	for (i = 0; i < tmp; i++) {
		EIO_DBG(INFO, dmc, "set[%lu], dirty:[%u]\n", 
				(unsigned long)dmc->set_dirty_sort[i].set_index,\
				dmc->set_dirty_sort[i].nr_dirty);
	}
	#if 0
	per_to_nr = dmc->assoc * dmc->sysctl_active.low_io_pressure_dirty_threshold;
	do_div(per_to_nr, 100);
	/*test the 1st dirty percent, if < 10%, try lru_scan_tail*/
	if (dmc->set_dirty_sort[0].nr_dirty < per_to_nr) {
		dmc->scan_head = (dmc->scan_head) ? (int)0 : (int)1;
		EIO_DBG(INFO, dmc,   
			"the 1st dirty percent < 10%%, switch lru_scan, scan_head:%d\n",
				dmc->scan_head);
		goto out;
	}
	#endif

	/*insert scaned_count sets to cleanq*/
	scanned_count = (scanned_count < dmc->sysctl_active.low_io_pressure_clean_set_nr) ? 
					scanned_count : dmc->sysctl_active.low_io_pressure_clean_set_nr;

	add_to_cleanq_low_io_pressure(dmc, scanned_count);

out:
	if (curr_ioc) {		
		dmc->last_ioc = curr_ioc;
		dmc->last_rwms= curr_rwms;
	}
	schedule_delayed_work(&dmc->low_pressure_clean_work, \
					dmc->low_io_pressure_sched_interval * HZ);
	
	return;
}
#endif


/* Move the given set at the head of the set LRU list */
void eio_touch_set_lru(struct cache_c *dmc, index_t set)
{
	u_int64_t systime;
	unsigned long flags;

	systime = jiffies;
	spin_lock_irqsave(&dmc->dirty_set_lru_lock, flags);
	lru_touch(dmc->dirty_set_lru, set, systime);
	
	if (dmc->sysctl_active.enable_aged_clean &&
		(dmc->sysctl_active.time_based_clean_interval > 0) &&
	    (dmc->is_clean_aged_sets_sched == 0)) {
		schedule_delayed_work(&dmc->clean_aged_sets_work,
				      dmc->sysctl_active.
				      time_based_clean_interval * 60 * HZ);
		dmc->is_clean_aged_sets_sched = 1;
	}
	spin_unlock_irqrestore(&dmc->dirty_set_lru_lock, flags);
	
#ifdef CONFIG_LOW_IO_PRESSURE_CLEAN
	if (dmc->sysctl_active.enable_low_io_pressure_clean) {
		/*sched low io presssure clean work*/
		if (0 == dmc->is_low_pressure_clean_work_sched) {
			schedule_delayed_work(&dmc->low_pressure_clean_work, \
									dmc->low_io_pressure_sched_interval * HZ);
			dmc->is_low_pressure_clean_work_sched = 1;
		}
	}
#endif
}
int cmp_dbn(const void *a, const void *b)
{
	const struct dbn_index_pair * ap = a;
	const struct dbn_index_pair * bp = b;

	return (ap->dbn > bp->dbn) ? 1 : -1;
}

#ifdef CONFIG_LOW_IO_PRESSURE_CLEAN 
int cmp_dirty_nr(const void *a, const void *b)
{
	const struct set_nr_dirty_pair * ap = a;
	const struct set_nr_dirty_pair * bp = b;

	return (ap->nr_dirty < bp->nr_dirty) ? 1 : -1;
}
#endif

#ifdef CONFIG_SKIP_SEQUENTIAL_IO
#if 0
struct seqio_node *wssc_search_seqio(struct cache_c *dmc, sector_t sect)
{
	unsigned long flags;
	struct rb_node *node;

	/*Get seqio_rbtree_lock*/
	spin_lock_irqsave(&dmc->seqio_rbtree_lock, flags);
	node = dmc->seqio_rbroot.rb_node;

	/*Search the rbtree*/
	while (node) {
		struct seqio_node *seqio = container_of(node, struct seqio_node, rb);

		/*Found seqential IO or write the same sector*/
		if (sect == (seqio->most_recent_sector + seqio->last_bio_size)
			  || sect == seqio->most_recent_sector) {

			if (sect == seqio->most_recent_sector) {
				EIO_DBG(INFO, dmc, "wssc_search_seqio: write the same sector\n");
			} else {
				EIO_DBG(INFO, dmc, "wssc_search_seqio: sequential io found\n");
			}
			
			spin_unlock_irqrestore(&dmc->seqio_rbtree_lock, flags);
			return seqio;
		} 

		/*Search left or right*/
		if (sect < seqio->most_recent_sector) {
			node = node->rb_left;
		} else {		
			node = node->rb_right;
		}
 	}
	spin_unlock_irqrestore(&dmc->seqio_rbtree_lock, flags);

	return NULL;
}
struct seqio_node wssc_remove_seqio(struct cache_c *dmc, sector_t sect)
{
}
struct seqio_node wssc_insert_seqio(struct cache_c *dmc, sector_t sect)
{
}
int wssc_detect_seqential_io(struct cache_c *dmc, struct bio *bio)
{
	struct seqio_node *seqio;

	/*Search the rbtree to find sequential IO*/
	seqio = wssc_search_seqio(dmc, bio->bi_sector);
	if (seqio) {
		/*Found sequential io, check if sequential_size_bytes gets threshold*/
		seqio->most_recent_sector = bio->bi_sector;
		seqio->sequential_size_bytes += to_bytes(bio->bi_size);
		seqio->last_bio_size = bio->bi_size;
	}
	
}
#endif
#if 0
static void seq_io_post_mdupdate(struct work_struct *work)
{
	struct seqio_set_block *set_block;
	struct bio_container *bc;
	struct cache_c *dmc;
	u_int32_t i;
	index_t set, blk_index;

	set_block = container_of(work, struct seqio_set_block, work);
	bc = set_block->bc;
	dmc = bc->bc_dmc;

	/*update statistic*/
	for (i = 0; i < set_block->block_nr; i++) {
		blk_index = set_block->dirty_blocks[i];
		if (EIO_CACHE_STATE_GET(dmc, blk_index) == ALREADY_DIRTY) {
			EIO_ASSERT(dmc->cache_sets[set].nr_dirty > 0);
			dmc->cache_sets[set].nr_dirty--;
			EIO_ASSERT(atomic64_read(&dmc->nr_dirty) > 0);
			atomic64_dec(&dmc->nr_dirty);
		}
	}

}
/* Callback function for ondisk metadata update when trigger seqential io*/
static void seq_io_mdupdate_callback(int error, void *context)
{
	struct seqio_set_block *set_block = (struct seqio_set_block *)context;
	struct cache_c *dmc = set_block->bc->bc_dmc;

	if (error && !(set_block->error)) {
		set_block->error = error;
	}
	
	if (!atomic_dec_and_test(&set_block->holdcount)) {
		return;
	}
	
	INIT_WORK(&set_block->work, seq_io_post_mdupdate);
	queue_work(dmc->mdupdate_q, &set_block->work);
}
#endif

/*function to update on-ssd-disk metadata*/
static int seq_io_md_update(struct cache_c *dmc, 
									struct seqio_set_block *set_block)
{	
	index_t set_index;
	index_t start_index, end_index, i;
	index_t blk_index;
	int j, k;
	int pindex;
	void *pg_virt_addr[2] = { NULL };	
	u_int8_t sector_bits[2] = { 0 };
	struct flash_cacheblock *md_blocks;
	//int md_size;
	int startbit, endbit;
	int rw_flags = 0;	
	struct eio_io_region region;
	int error;
	unsigned long flags;

	EIO_ASSERT(dmc != NULL && set_block != NULL);	
	//EIO_ASSERT((dmc->assoc == 256) || (dmc->assoc == 512));
	EIO_ASSERT(set_block->block_nr <= 256);	
	EIO_ASSERT(set_block->mdbvec_count && set_block->mdbvec_count <= 2);
	set_index = set_block->set_index;
	start_index = set_index * dmc->assoc;
	end_index = start_index + dmc->assoc;
	

	for (k = 0; k < set_block->mdbvec_count; k++) {
		pg_virt_addr[k] = kmap(set_block->mdblk_bvecs[k].bv_page);

	}

	spin_lock_irqsave(&dmc->cache_sets[set_index].cs_lock, flags);

	pindex = 0;
	md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];
	j = MD_BLOCKS_PER_PAGE;
	/* initialize the md blocks to write */
	for (i = start_index; i < end_index; i++) {
		md_blocks->dbn = cpu_to_le64(EIO_DBN_GET(dmc, i));	
		if (EIO_CACHE_STATE_GET(dmc, i) == ALREADY_DIRTY) {
			md_blocks->cache_state = cpu_to_le64((VALID | DIRTY));
		} else {
			md_blocks->cache_state = cpu_to_le64(INVALID);
		}
		md_blocks++;
		j--;
	
		if (j == 0 && ++pindex < set_block->mdbvec_count) {
			md_blocks =
				(struct flash_cacheblock *)pg_virt_addr[pindex];
			j = MD_BLOCKS_PER_PAGE;
		}
	}

	/*update dirty block to invalid*/	
	pindex = 0;
	md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];
	for (i = 0; i < set_block->block_nr; i++) {
		/*the cache block state may change before get rwlock, so we 
		check again*/
		if (EIO_CACHE_STATE_GET(dmc, set_block->block_index[i]) ==
				ALREADY_DIRTY) {
			blk_index = set_block->block_index[i] - start_index;
			EIO_VERIFY((blk_index >= 0) && (blk_index <= 512));
			pindex = INDEX_TO_MD_PAGE(blk_index);
			EIO_VERIFY(pindex == 0 || pindex == 1);			
			blk_index = INDEX_TO_MD_PAGE_OFFSET(blk_index);
			sector_bits[pindex] |= (1 << INDEX_TO_MD_SECTOR(blk_index));
			md_blocks = (struct flash_cacheblock *)pg_virt_addr[pindex];
			/*invalidate the dirty cache block*/
			//md_blocks += (blk_index % MD_BLOCKS_PER_PAGE);
			md_blocks[blk_index].cache_state = INVALID;
		}
	}

	spin_unlock_irqrestore(&dmc->cache_sets[set_index].cs_lock, flags);

	/*unmap bv_page*/
	for (k = 0; k < set_block->mdbvec_count; k++) {
		kunmap(set_block->mdblk_bvecs[k].bv_page);
	}
	//atomic_set(&set_block->holdcount, 1);
	
	region.bdev = dmc->cache_dev->bdev;
	for (i = 0; i < set_block->mdbvec_count; i++) {
		if (!sector_bits[i]) {
			continue;
		}
		startbit = -1;
		j = 0;
		while (startbit == -1) {
			if (sector_bits[i] & (1 << j))
				startbit = j;
			j++;
		}
		endbit = -1;
		j = 7;
		while (endbit == -1) {
			if (sector_bits[i] & (1 << j))
				endbit = j;
			j--;
		}
		EIO_ASSERT(startbit <= endbit && startbit >= 0 && startbit <= 7 &&
			   endbit >= 0 && endbit <= 7);
		EIO_ASSERT(dmc->assoc != 128 || endbit <= 3);
		region.sector =
			dmc->md_start_sect + INDEX_TO_MD_SECTOR(start_index) +
			i * SECTORS_PER_PAGE + startbit;
		region.count = endbit - startbit + 1;
		set_block->mdblk_bvecs[i].bv_offset = to_bytes(startbit);
		set_block->mdblk_bvecs[i].bv_len = to_bytes(region.count);

		EIO_ASSERT(region.sector <=
			   (dmc->md_start_sect + INDEX_TO_MD_SECTOR(end_index)));
		atomic64_inc(&dmc->eio_stats.md_ssd_writes);		
		atomic64_inc(&dmc->eio_stats.seq_io_mdwrite);
		SECTOR_STATS(dmc->eio_stats.ssd_writes, to_bytes(region.count));
		//atomic_inc(&set_block->holdcount);
		rw_flags = WRITE | REQ_SYNC;
		error = eio_io_async_bvec(dmc, &region, rw_flags,
					  &set_block->mdblk_bvecs[i], 1,
					  NULL, set_block, 0);
		
		if (error) {
			atomic64_inc(&dmc->eio_stats.seq_io_mdwrite_error);
			dmc->eio_errors.ssd_write_errors++;
			set_block->error = error;
			pr_err("seq_io_md_update: write md error\n");
			return error;
		}
	}

	#if 0
		/*if mdupdate succeed, update statistic*/
		for (i = 0; i < set_block->block_nr; i++) {
			blk_index = set_block->block_index[i];
			set_index = set_block->set_index;
			if (EIO_CACHE_STATE_GET(dmc, blk_index) == ALREADY_DIRTY) {
				EIO_ASSERT(dmc->cache_sets[set].nr_dirty > 0);
				dmc->cache_sets[set].nr_dirty--;
				EIO_ASSERT(atomic64_read(&dmc->nr_dirty) > 0);
				atomic64_dec(&dmc->nr_dirty);
			}
		}
	#endif

	return 0;
}

static void seq_io_callback(int error, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;

	job->error = error;
	INIT_WORK(&job->work, seq_io_post_callback);
	queue_work(dmc->mdupdate_q, &job->work);
	return;
}

static void seq_io_post_callback(struct work_struct *work)
{
	struct kcached_job *job;
	struct cache_c *dmc;
	struct bio_container *bc;	
	struct eio_bio *ebio;
	struct seqio_set_block *set_block;
	index_t blk_index;
	index_t set_index;
	u_int8_t cache_state;
	int error;
	int ret;
	int i;	
	long elapsed;
	unsigned long flags;
	
	job = container_of(work, struct kcached_job, work);
	dmc = job->dmc;
	ebio = job->ebio;
	bc = ebio->eb_bc;
	error = job->error;

	EIO_DBG(INFO, dmc, "seq_io_post_callback called\n");
	if (job->action != WRITEDISK) {
		pr_err("seq_io_callback: invalid action\n");
		return;
	}
	
	if (error) {
		dmc->eio_errors.disk_write_errors++;
		pr_err("seq_io_callback:error:%d,block:%llu,action:%d", error,
			(unsigned long long)job->job_io_regions.disk.sector, job->action);
		/*TODO*/
	} else if(bc->set_block) {
		/*update on-disk metadata first*/
		for (set_block = bc->set_block; set_block; set_block = set_block->next) {
				
			ret = seq_io_md_update(dmc, set_block);
			if (ret) {
				pr_err("seq_io_callback: md update error, set[%lu]\n", 
							(long)set_block->set_index);
				/*this bio return error*/
				error = ret;
				goto err_out;
			}

			set_index = set_block->set_index;
			EIO_ASSERT(set_index >= 0);		
			/*then update in-core metadata*/
			spin_lock_irqsave(&dmc->cache_sets[set_index].cs_lock, flags);
			for (i = 0; i < set_block->block_nr; i++) {
				blk_index = set_block->block_index[i];
				EIO_ASSERT(blk_index >= 0);
				cache_state = EIO_CACHE_STATE_GET(dmc, blk_index);
				if (cache_state == ALREADY_DIRTY) {
					EIO_CACHE_STATE_SET(dmc, blk_index, INVALID);
					EIO_ASSERT(dmc->cache_sets[set_index].nr_dirty > 0);
					dmc->cache_sets[set_index].nr_dirty--;
					EIO_ASSERT(atomic64_read(&dmc->nr_dirty) > 0);
					atomic64_dec(&dmc->nr_dirty);
					atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
				} else {
					pr_err("seq_io_callback:this cann't happen!!!, cache_state:%u\n", cache_state);
					EIO_ASSERT(0);
				}
				#if 0
				} else {
					if(!(cache_state & QUEUED)) {
						EIO_CACHE_STATE_ON(dmc, blk_index, QUEUED);
					}
				}
				#endif
			}
			spin_unlock_irqrestore(&dmc->cache_sets[set_index].cs_lock, flags);
		}
	}

err_out:

	if (bc->set_block) {
		/*release lock*/
		#if 0
		for (set_block = bc->set_block; 
			set_block; set_block = set_block->next) {
			up_write(&dmc->cache_sets[set_block->set_index].rw_lock);
		}
			#endif
		/*free set_lock resource*/
		seq_io_free_set_block(bc);
	}
	elapsed = (long)jiffies_to_msecs(jiffies - bc->bc_iotime);
	EIO_DBG(INFO, dmc, "bio_comptime:%lu, bio_locktime:%lu, bio_rwtime:%lu\n",
		elapsed, (long)jiffies_to_msecs(bc->bc_locktime - bc->bc_iotime),
		(long)jiffies_to_msecs(jiffies - bc->bc_locktime));
	/*calc io latency every 100IOs*/
	atomic64_inc(&dmc->seq_io_count);
	atomic64_add(elapsed, &dmc->seq_io_ms);
	if (1000 == atomic64_read(&dmc->seq_io_count)) {
		long io_ms = atomic64_read(&dmc->seq_io_ms);
		long io_count = atomic64_read(&dmc->seq_io_count);	
		EIO_DBG(INFO, dmc, "seq_io_ms:%lu, seq_io_count:%lu\n",io_ms, io_count);
		dmc->eio_stats.seq_io_latency = EIO_DIV(io_ms, io_count);
		atomic64_set(&dmc->seq_io_count, 0);
		atomic64_set(&dmc->seq_io_ms, 0);
	}
	/*return bio*/	
	eb_endio(ebio, error);
	job->ebio = NULL;
	eio_free_cache_job(job);
}

static void
seq_io_disk_io(struct cache_c *dmc, struct bio_container *bc, struct bio *bio)
{
	struct eio_bio *ebio;
	struct kcached_job *job;
	//struct seqio_set_block *set_block;
	int residual_biovec = 0;
	int error = 0;

	EIO_DBG(INFO, dmc, "seq_io_disk_io called\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
	/*disk io happens on whole bio. Reset bi_iter.bi_idx*/
	bio->bi_iter.bi_idx = 0;
	ebio =
		eio_new_ebio(dmc, bio, &residual_biovec, bio->bi_iter.bi_sector,
				 bio->bi_iter.bi_size, bc, EB_MAIN_IO);
#else 
	/*disk io happens on whole bio. Reset bi_idx*/
	bio->bi_idx = 0;
	ebio =
		eio_new_ebio(dmc, bio, &residual_biovec, bio->bi_sector,
			     bio->bi_size, bc, EB_MAIN_IO);
#endif 
	if (unlikely(IS_ERR(ebio))) {
		bc->bc_error = error = PTR_ERR(ebio);
		ebio = NULL;
		goto errout;
	}
	job = eio_new_job(dmc, ebio, -1);
	if (unlikely(job == NULL)) {
		error = -ENOMEM;
		goto errout;
	}
	atomic_inc(&dmc->nr_jobs);
	if (ebio->eb_dir == READ) {
		job->action = READDISK;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		SECTOR_STATS(dmc->eio_stats.disk_reads, bio->bi_iter.bi_size);
#else 
		SECTOR_STATS(dmc->eio_stats.disk_reads, bio->bi_size);
#endif 
		atomic64_inc(&dmc->eio_stats.readdisk);
	} else {
		job->action = WRITEDISK;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		SECTOR_STATS(dmc->eio_stats.disk_writes, bio->bi_iter.bi_size);
#else 
		SECTOR_STATS(dmc->eio_stats.disk_writes, bio->bi_size);
#endif 
		atomic64_inc(&dmc->eio_stats.writedisk);
	}

	/*
	 * Pass the original bio flags as is, while doing
	 * read / write to HDD.
	 */
	VERIFY_BIO_FLAGS(ebio);
	error = eio_io_async_bvec(dmc, &job->job_io_regions.disk,
				  GET_BIO_FLAGS(ebio),
				  ebio->eb_bv, ebio->eb_nbvec,
				  seq_io_callback, job, 1);

	if (error) {
		pr_err("seq_io_disk_io: disk write error\n");
		job->ebio = NULL;
		eio_free_cache_job(job);
		goto errout;
	}
	return;

errout:
	if (bc) {
		/*release lock and other resource*/
		#if 0
		set_block = bc->set_block;
		while (set_block) {
			EIO_VERIFY(set_block->set_index > 0);
			up_write(&dmc->cache_sets[set_block->set_index].rw_lock);
			set_block = set_block->next;
		}
		#endif
		if (bc->set_block) {
			seq_io_free_set_block(bc);
		}
	}
	
	if (ebio) {
		eb_endio(ebio, error);
	}
	return;
}

void seq_io_remove_from_lru(struct seqio_hash_node *hash_node, 
									   struct seqio_lru_node *lru_node)
{
	if (lru_node->prev != NULL) 
		lru_node->prev->next = lru_node->next;
	else {
		EIO_VERIFY(hash_node->lru_node_head == lru_node);
		hash_node->lru_node_head = lru_node->next;
	}
	if (lru_node->next != NULL)
		lru_node->next->prev = lru_node->prev;
	else {
		EIO_VERIFY(hash_node->lru_node_tail == lru_node);
		hash_node->lru_node_tail = lru_node->prev;
	}
}

void seq_io_move_to_lruhead(struct seqio_hash_node *hash_node, 
                                       struct seqio_lru_node *lru_node)
{
	//EIO_VERIFY(hash_node);
	//EIO_VERIFY(lru_node);
	if (likely(lru_node->prev != NULL || lru_node->next != NULL))
		seq_io_remove_from_lru(hash_node, lru_node);
	/* Add it to LRU head */
	if (hash_node->lru_node_head != NULL)
		hash_node->lru_node_head->prev = lru_node;
	lru_node->next = hash_node->lru_node_head;
	lru_node->prev = NULL;
	hash_node->lru_node_head = lru_node;
}

int seq_io_move_to_hash_node(struct seqio_hash_node *old_hash_node, 
							  struct seqio_hash_node *new_hash_node, 
							  struct seqio_lru_node *lru_node)
{
	if (!old_hash_node || !new_hash_node || !lru_node) {
		return -EINVAL;
	}

	/*Remove from old hash node*/
	seq_io_remove_from_lru(old_hash_node, lru_node);

	/*Clear prev and next*/
	lru_node->next = NULL;
	lru_node->prev = NULL;

	/*Add to the head of new hash node*/
	seq_io_move_to_lruhead(new_hash_node, lru_node);

	return 0;
}

/*function to allocate resource for updating metadata*/
static int seq_io_alloc_mdupdate_mem(struct bio_container *bc)
{
	struct seqio_set_block *curr;
	unsigned int md_size, nr_bvecs;
	int ret;

	if (!bc || !bc->set_block) {
		pr_err("seq_io_alloc_mdupdate_mem:bc or set_block null\n");
		return -1;
	}

	for (curr = bc->set_block; curr; curr = curr->next) {
		if (curr->set_index < 0 || curr->block_nr == 0) {
			pr_err("seq_io_alloc_mdupdate_mem:invalid set_block\n");
			seq_io_free_set_block(bc);
			return -1;
		}
		/*alloc memory to update metadata*/
		md_size = bc->bc_dmc->assoc * sizeof(struct flash_cacheblock);
		nr_bvecs = IO_BVEC_COUNT(md_size, SECTORS_PER_PAGE);
		curr->mdblk_bvecs = (struct bio_vec *)
						kmalloc(sizeof(struct bio_vec) * nr_bvecs, GFP_KERNEL);
		if(!curr->mdblk_bvecs) {
			pr_err("seq_io_alloc_mdupdate_mem:alloc mdblk_bvecs failed\n");
			seq_io_free_set_block(bc);
			return -1;
		}
		ret = eio_alloc_wb_bvecs(curr->mdblk_bvecs,
								nr_bvecs,
								SECTORS_PER_PAGE);
		if (ret) {
			pr_err("seq_io_alloc_mdupdate_mem:alloc mdblk_bvecs page failed\n");
			seq_io_free_set_block(bc);
			return -1;
		}
		curr->mdbvec_count = nr_bvecs;
		curr->bc = bc;		
		bc->nr_set_block++;
		//atomic_inc(&bc->nr_set_block);
	}
	return 0;
}

#if 0
/*function to allocate resource for updating metadata*/
static struct seqio_set_block * seq_io_get_set_block(struct bio_container *bc)
{
	struct seqio_set_block *set_block;
	unsigned int md_size, nr_bvecs;
	int ret;

	if (!bc) {
		pr_err("seq_io_get_set_block:bc is null\n");
		return NULL;
	}
	set_block = kzalloc(sizeof(struct seqio_set_block), GFP_NOWAIT);
	if (!set_block) {
		pr_err("seq_io_get_set_block:alloc set_block failed\n");
		seq_io_free_set_block(bc);
		return NULL;
	}
	/*alloc memory to save dirty block index*/
	set_block->dirty_blocks = kzalloc(sizeof(index_t) * bc->bc_dmc->assoc,
										GFP_NOWAIT);
	if (!set_block->dirty_blocks) {
		pr_err("seq_io_get_set_block:alloc dirty_blocks failed\n");
		seq_io_free_set_block(bc);
		return NULL;
	}
	
	/*alloc memory to update metadata*/
	md_size = bc->bc_dmc->assoc * sizeof(struct flash_cacheblock);
	nr_bvecs = IO_BVEC_COUNT(md_size,SECTORS_PER_PAGE);
	set_block->mdblk_bvecs = (struct bio_vec *)
					kmalloc(sizeof(struct bio_vec) * nr_bvecs,
						GFP_KERNEL);
	if(!set_block->mdblk_bvecs) {
		pr_err("seq_io_get_set_block:alloc mdblk_bvecs failed\n");
		seq_io_free_set_block(bc);
		return NULL;
	}
	ret = eio_alloc_wb_bvecs(set_block->mdblk_bvecs,
							nr_bvecs,
							SECTORS_PER_PAGE);
	if (ret) {
		pr_err("seq_io_get_set_block:alloc mdblk_bvecs page failed\n");
		seq_io_free_set_block(bc);
		return NULL;
	}
	set_block->mdbvec_count = nr_bvecs;
	set_block->bc = bc;
	atomic_inc(&bc->nr_set_block);
	
	return set_block;
}
static void seq_io_free_mdupdate_mem(struct bio_container *bc)
{
	struct seqio_set_block *curr;

	if (!bc) {
		pr_err("bc null!!!")
		return;
	}
	for (curr = bc->set_block; curr; curr = curr->next) {
		if (curr->mdblk_bvecs) {
			eio_free_wb_bvecs(curr->mdblk_bvecs, curr->mdbvec_count,
							SECTORS_PER_PAGE);
			kfree(curr->mdblk_bvecs);
		}
		kfree(curr);
	}
	bc->set_block = NULL;
}
#endif
static void seq_io_free_set_block(struct bio_container *bc)
{
	struct seqio_set_block *curr;
	struct seqio_set_block *next;
	struct cache_c *dmc;
	index_t set_index;
	unsigned long flags;

	if (!bc) {
		pr_err("bc null!!!");
		return;
	}
	dmc = bc->bc_dmc;	
	EIO_VERIFY(dmc);
	curr = bc->set_block;	
	while (curr) {
		next = curr->next;
		if (curr->mdblk_bvecs) {
			eio_free_wb_bvecs(curr->mdblk_bvecs,
					  curr->mdbvec_count,
					  SECTORS_PER_PAGE);
			kfree(curr->mdblk_bvecs);
			curr->mdblk_bvecs = NULL;
		}		
		set_index = curr->set_index;
		EIO_VERIFY(set_index >= 0);
		/*clear flag */
		spin_lock_irqsave(&dmc->cache_sets[set_index].cs_lock, flags);
		dmc->cache_sets[set_index].flags &= ~SETFLAG_SKIP_SEQUENTIAL_IO;
		spin_unlock_irqrestore(&dmc->cache_sets[set_index].cs_lock, flags);
		kfree(curr);
		curr = next;
	}
	#if 0
	for (curr = bc->set_block; curr; curr = curr->next) {
		/*free bvec*/
		if (curr->mdblk_bvecs) {
			EIO_ASSERT(curr->mdbvec_count == 1);
			eio_free_wb_bvecs(curr->mdblk_bvecs, curr->mdbvec_count,
							SECTORS_PER_PAGE);
			kfree(curr->mdblk_bvecs);
			curr->mdblk_bvecs = NULL;
		}
		set_index = curr->set_index;
		EIO_VERIFY(set_index >= 0);
		/*clear flag */
		spin_lock_irqsave(&dmc->cache_sets[set_index].cs_lock, flags);
		dmc->cache_sets[set_index].flags &= ~SETFLAG_SKIP_SEQUENTIAL_IO;
		spin_unlock_irqrestore(&dmc->cache_sets[set_index].cs_lock, flags);
		kfree(curr);
	}
	#endif
	bc->set_block = NULL;
}
#if 0
static void seq_io_free_set_block(struct bio_container *bc)
{
	struct seqio_set_block *set_block;

	if (!bc) {
		return;
	}
	
	for (set_block = bc->set_block; set_block; set_block = set_block->next) {
		if (set_block->dirty_blocks) {
			kfree(set_block->dirty_blocks);
		}
		if (set_block->mdblk_bvecs) {
			eio_free_wb_bvecs(set_block->mdblk_bvecs,
								  set_block->mdbvec_count,
								  SECTORS_PER_PAGE);
			kfree(set_block->mdblk_bvecs);
		}
		kfree(set_block);
	}
	bc->set_block = NULL;
}
#endif
static int seq_io_inval_bio_range(struct cache_c *dmc, 
										struct bio_container *bc)
{
	sector_t snum = bc->bc_bio->bi_sector;
	unsigned iosize = bc->bc_bio->bi_size;
	sector_t snext;
	unsigned ioinset;
	unsigned long cs_lock_flags;	
	int totalsshift = dmc->block_shift + dmc->consecutive_shift;

	index_t set_index, start_index, end_index, i;
	sector_t endsector = snum + eio_to_sector(iosize);

	struct seqio_set_block *new_set_block = NULL;	
	struct seqio_set_block *curr = NULL;
	//struct seqio_set_block *next = NULL;
	struct seqio_set_block *prev = NULL;
	
	//unsigned long before_lock;
	//unsigned long after_lock;

	int skip_seqio = 1;
	int ret;

	while (iosize) {
		/*get set number*/
		set_index = hash_block(dmc, snum);
		snext = ((snum >> totalsshift) + 1) << totalsshift;
		ioinset = (unsigned)to_bytes(snext - snum);
		/*test if this bio span 2 sets*/
		if (ioinset > iosize)
			ioinset = iosize;
		
		EIO_DBG(INFO, dmc, "wssc_inval_seqential_io_range:get lock\n");
		spin_lock_irqsave(&dmc->cache_sets[set_index].cs_lock, cs_lock_flags);

		#if 0
		/*Test if this dirty set is flushing...*/
		if(dmc->cache_sets[set_index].flags & SETFLAG_CLEAN_INPROG) { 						
			skip_seqio = 0;
			atomic64_inc(&dmc->eio_stats.seq_io_flushing);
			goto out;
		}
		#endif
		
		start_index = dmc->assoc * set_index;
		end_index = start_index + dmc->assoc;

		/*traverse all cache block in the set*/
		for (i = start_index; i < end_index; i++) {			
			sector_t start_dbn;
			sector_t end_dbn;
			u_int8_t cache_state;

			cache_state = EIO_CACHE_STATE_GET(dmc, i);
			
			if (cache_state & INVALID) {
				atomic64_inc(&dmc->eio_stats.seq_io_invalid);
				continue;
			}
			
			start_dbn = EIO_DBN_GET(dmc, i);
			end_dbn = start_dbn + dmc->block_size;

			if (!(endsector <= start_dbn || snum >= end_dbn)) {
				/*invalidate VALID block*/
				if (cache_state == VALID) {	
					EIO_DBG(INFO, dmc, "wssc_inval_seqential_io_range:"
					 	"valid block %lu\n", (long)i);
					EIO_CACHE_STATE_SET(dmc, i, INVALID);
					atomic64_dec_if_positive(&dmc->eio_stats.cached_blocks);
					atomic64_inc(&dmc->eio_stats.seq_io_valid);
				/*invalidate ALREADY_DIRTY block*/
				} else if (cache_state == ALREADY_DIRTY) {
					/*check if this bio contain this dirty block completely*/
					if (start_dbn >= snum && end_dbn <= endsector) {

						/*Test if this dirty set is being flush...*/
						if(dmc->cache_sets[set_index].flags & 
							SETFLAG_CLEAN_INPROG) {							
							skip_seqio = 0;
							atomic64_inc(&dmc->eio_stats.seq_io_flushing);
							goto out;
						}

						/*Add flag to set*/
						dmc->cache_sets[set_index].flags |= 
							SETFLAG_SKIP_SEQUENTIAL_IO;
						
						/*alloc new_set_block*/
						if (!new_set_block) {
							/*before alloc memory, release spin lock*/
							spin_unlock_irqrestore(
								&dmc->cache_sets[set_index].cs_lock, 
									cs_lock_flags);
							//new_set_block = seq_io_get_set_block(bc);
							new_set_block = 
								kzalloc(sizeof(struct seqio_set_block),
								GFP_KERNEL);
							spin_lock_irqsave(
								&dmc->cache_sets[set_index].cs_lock, 
									cs_lock_flags);
							if (!new_set_block ) {
								skip_seqio = 0;
								goto out;
							}	
				
							new_set_block->set_index = set_index;
							new_set_block->bc = NULL;
							new_set_block->mdbvec_count = 0;
							new_set_block->mdblk_bvecs = NULL;
							new_set_block->next = NULL;
							
							/*insert new_set_block to set_block list*/
							if (bc->set_block) {
								curr = bc->set_block;
								prev = NULL;
								while (curr) {
									prev = curr;
									curr = curr->next;
								}
								prev->next = new_set_block;
							} else {
								bc->set_block = new_set_block;
							}
						}
				
						/*get dirty cache block index in this cache set*/						
						new_set_block->block_index[new_set_block->block_nr] = i ;	
						new_set_block->block_nr++;
						atomic64_inc(&dmc->eio_stats.seq_io_dirty);
					} else {
						/*this dirty block is just part of this bio*/
						skip_seqio = 0;
						atomic64_inc(&dmc->eio_stats.seq_io_partdirty);
						goto out;
					}
				} else if (!(cache_state & DIRTY )) {
					/*
						1.VALID | CACHEWRITEINPROG
						a.when cached write,->DIRTY_INPROG->ALREADY_DIRTY
						b.when uncached write,->VALID | CACHEWRITEINPROG | DISKWRITEINPROG ->
						                    VALID | DISKWRITEINPROG -> VALID
						c.when read fill,->VALID

						when we found a cache block with this state,do not add QUEUED to it,
						and we can not skip this bio
						
						2.VALID | CACHEWRITEINPROG | DISKWRITEINPROG
						a.when uncache write-> VALID | DISKWRITEINPROG -> VALID
						3.VALID | CACHEREADINPROG
						a.when cached read, -> VALID
						b.when uncached read,-> VALID
						4.VALID | DISKWRITEINPROG
						a.when uncache write,-> VALID
						5.VALID | DISKREADINPROG
						a.when uncache read and read fill,->VALID | CACHEWRITEINPROG -> VALID
						when we found a cache block with these states,we can add QUEUED on it

					*/
					EIO_DBG(INFO, dmc, "wssc_inval_seqential_io_range:"
					 	"queue block %lu\n", (long)i);					
					if(!(cache_state & QUEUED)) {
						/*no QUEUED flag*/
						if (cache_state == (VALID | CACHEWRITEINPROG)) {							
							atomic64_inc(&dmc->eio_stats.seq_io_ioinp_cw);
							skip_seqio = 0;
							goto out;
						}
						EIO_CACHE_STATE_ON(dmc, i, QUEUED);
					}
					atomic64_inc(&dmc->eio_stats.seq_io_ioinp);
				/*if cache block is DIRTY_INPROG or CLEAN_INPROG, do not skip seq io*/
				} else if (cache_state == DIRTY_INPROG || 
							cache_state == CLEAN_INPROG) {
					skip_seqio = 0;
					if (cache_state == DIRTY_INPROG) {
						atomic64_inc(&dmc->eio_stats.seq_io_dirtyinp);
					} else {
						atomic64_inc(&dmc->eio_stats.seq_io_cleaninp);
					}
					goto out;					
				} else {
					pr_err("wssc_inval_seqential_io_range:unkown cache stat:%x!!!\n", 
						cache_state);
					skip_seqio = 0;
					goto out;					
				}
			}
		}

		new_set_block = NULL;
		spin_unlock_irqrestore(&dmc->cache_sets[set_index].cs_lock, cs_lock_flags);
		EIO_DBG(INFO, dmc, "wssc_inval_seqential_io_range:release lock\n");

		/*next set*/
		snum = snext;
		iosize -= ioinset;
	}

out:
	if(0 == skip_seqio) {
		spin_unlock_irqrestore(&dmc->cache_sets[set_index].cs_lock, cs_lock_flags);
		/*if skip_seqio=0, release resource*/
		if (bc->set_block) {
			seq_io_free_set_block(bc);
		}
	} else {
		/*skip_seqio confirm, alloc memory to update metadate, and get rw lock*/		
		if (bc->set_block) {
			ret = seq_io_alloc_mdupdate_mem(bc);
			if (0 != ret) {
				pr_err("seq_io_inval_bio_range:alloc mdupdate mem failed\n");
				//seq_io_free_set_block(bc);
				skip_seqio = 0;
				#if 0
				curr = bc->set_block;
				while (curr) {
					EIO_VERIFY(curr->set_index >= 0);
					/*TODO:maybe deadlock with eio_acquire_set_locks()*/
					before_lock = jiffies;
					down_write(&dmc->cache_sets[curr->set_index].rw_lock);
					after_lock = jiffies;
					EIO_DBG(ERROR, dmc, "------set[%u] get write lock:%u ms,bio size:%u------,", 
						(unsigned int)curr->set_index, 
						jiffies_to_msecs(after_lock - before_lock), 
						TO_KB(bc->bc_bio->bi_size));
					curr = curr->next;
				}
				EIO_DBG(ERROR, dmc, "---\n");
				bc->bc_locktime = jiffies;
				#endif
			}
		}
	}
	
	return skip_seqio;
}

/*function to update io prediction info*/
static int 
seq_io_update_iopredict(struct cache_c *dmc, int sequential, 
						struct seqio_lru_node *lru_node, struct bio *bio)
{	
	EIO_ASSERT(dmc);
	EIO_ASSERT(lru_node);
	EIO_ASSERT(bio);

#if 0
	/*1.Update io count info*/
	if (lru_node->bypass_flag) {
		/*the sequential size already reachs seqio_threshold_bypass_kb*/
		dmc->io_predict.bypass_io_count++;
		dmc->io_predict.threshold_io_count++;
	} else if (lru_node->threshold_flag) {
		/*the sequential size reachs seqio_low_threshold_kb*/
		dmc->io_predict.threshold_io_count++;
		if (TO_KB(lru_node->sequential_size_bytes) >= 
									dmc->seqio_threshold_bypass_kb) {
			lru_node->bypass_flag = 1;
			dmc->io_predict.bypass_io_count += lru_node->io_count;
		}
	} else {
		/*the IO is sequential, check the sequential size*/
		if (TO_KB(lru_node->sequential_size_bytes) >= 
				dmc->sysctl_active.seqio_threshold_len_kb) {
			lru_node->threshold_flag = 1;
			//dmc->io_predict.threshold_io_count += lru_node->io_count;
			dmc->io_predict.threshold_io_count++;
			if (TO_KB(lru_node->sequential_size_bytes) >=	
										dmc->seqio_threshold_bypass_kb) {
				lru_node->bypass_flag = 1;
				//dmc->io_predict.bypass_io_count += lru_node->io_count;
				dmc->io_predict.bypass_io_count++;
			}
		}
	}
#endif

	if (!lru_node->threshold_flag) {
		/*the IO is sequential, check the sequential size*/
		if (TO_KB(lru_node->sequential_size_bytes) >= 
				dmc->sysctl_active.seqio_threshold_len_kb) {
			lru_node->threshold_flag = 1;
			dmc->io_predict.threshold_io_count++;
			if (TO_KB(lru_node->sequential_size_bytes) >=	
								dmc->seqio_threshold_bypass_kb) {
				lru_node->bypass_flag = 1;
				dmc->io_predict.bypass_io_count++;
			}
		}
	} else if (lru_node->threshold_flag && !lru_node->bypass_flag) {
		if (TO_KB(lru_node->sequential_size_bytes) >= 
					dmc->seqio_threshold_bypass_kb) {
			lru_node->bypass_flag = 1;
			dmc->io_predict.bypass_io_count++;
		}
	} else {
		/*do nothing*/
	}
	
	/*2.Update percent*/
	if (time_after(jiffies, 
			dmc->io_predict.calc_time + SEQIO_UPDATE_PCT_INTERVAL) &&
			dmc->io_predict.threshold_io_count >= SEQIO_UPDATE_PCT_COUNT) {
		unsigned int percent;
 		percent = EIO_CALCULATE_PERCENTAGE(
				dmc->io_predict.bypass_io_count,
				dmc->io_predict.threshold_io_count);
		dmc->io_predict.skip = 
			(percent >= SEQIO_SKIP_PCT_THRESHOLD) ? (int)1 : (int)0;
		EIO_DBG(ERROR, dmc, "threshold_io_count:%u, bypass_io_count:%u"
			",percent:%u\n", dmc->io_predict.threshold_io_count, 
		dmc->io_predict.bypass_io_count, percent);
		/*clear io count*/
		dmc->io_predict.bypass_io_count = 0;
		dmc->io_predict.threshold_io_count = 0;
		dmc->io_predict.calc_time = jiffies;
	}

	/*3.Determine skip this IO or not*/
	if (TO_KB(bio->bi_size) >= dmc->sysctl_active.seqio_threshold_len_kb) {
//	if (TO_KB(bio->bi_size) >= SEQIO_SINGLE_IO_BYPASS_LEN_KB) {
		/*a single IO,and its length reachs seqio_bypass_len_kb, 
		just skip this IO, ignore the value of io_predict.skip,
		I found that the largest bio size is 128KB*/
		atomic64_inc(&dmc->eio_stats.seq_singleio_count);
		return 1;
	}
	#if 0
	if (!sequential && 
			(TO_KB(bio->bi_size) >= dmc->sysctl_active.seqio_bypass_len_kb)) {
		/*a single IO,and its length reachs seqio_bypass_len_kb, 
		just skip this IO, ignore the value of io_predict.skip*/
		return 1;
	}
	#endif

	if (dmc->io_predict.skip && lru_node->threshold_flag) {
		return 1;
	}
	
	return 0;
}

/*function to detect sequential io*/
static int 
seq_io_detect_seqential_io(struct cache_c *dmc, struct bio *bio)
{
	//u_int32_t hash_node_idx;
	//u_int32_t new_hash_node_idx;
	struct seqio_hash_node *hash_node;
	//struct seqio_hash_node *new_hash_node;
	struct seqio_lru_node *lru_node;
	int sequential = 0;

	/*check threshold*/
	//if (0 == dmc->sysctl_active.seqio_threshold_len_kb) {
	//	EIO_DBG(INFO, dmc, "seqio_threshold_len_kb 0\n");
	//	return 0;
	//}
	
	/*1.Get hash node*/
	//hash_node_idx = to_bytes(bio->bi_sector) >> SEQIO_HAZE_SIZE_1GB_SHIFT;
	//hash_node_idx %= (SEQIO_HASH_TBL_SIZE - 1);
 	//hash_node = &dmc->seqio_hashtbl[hash_node_idx];
	//EIO_VERIFY(hash_node);	
 	hash_node = &dmc->seqio;
	/*2.Scan the LRU list*/
	for (lru_node = hash_node->lru_node_head; 
			lru_node != NULL; lru_node = lru_node->next) {
		EIO_VERIFY(lru_node);
		/*Write the same sector*/
		if (lru_node->most_recent_sector == bio->bi_sector) {
			EIO_DBG(INFO, dmc, "write the same sector\n");
			sequential = 1;
			if (bio->bi_size > lru_node->last_bio_size) {				
				lru_node->sequential_size_bytes += 
						(bio->bi_size - lru_node->last_bio_size);
				lru_node->last_bio_size = bio->bi_size;
				lru_node->io_count++;
				EIO_DBG(INFO, dmc, "id:%lu, io_count:%lu, sequential_size_bytes:%lu\n", 
						lru_node->node_id, lru_node->io_count, 
							TO_KB(lru_node->sequential_size_bytes));
			}			
		}		
		/*This IO is sequential*/
		else if (bio->bi_sector == 
		  	(lru_node->most_recent_sector + eio_to_sector(lru_node->last_bio_size))) {				
			EIO_DBG(INFO, dmc, "sequential io found\n");
			lru_node->most_recent_sector = bio->bi_sector;
			lru_node->last_bio_size = bio->bi_size;
			lru_node->sequential_size_bytes += bio->bi_size;
			lru_node->io_count++;
			sequential = 1;
			EIO_DBG(INFO, dmc, "id:%lu, io_count:%lu, sequential_size_bytes:%lu\n", 
					lru_node->node_id, lru_node->io_count, 
					TO_KB(lru_node->sequential_size_bytes));
		}

		if (sequential) {break;}
	}

	/*3.Non-seqential IO, get a new lru_node from tail*/
	if (!sequential) {
		EIO_DBG(INFO, dmc, "not a sequential io\n");
		//lru_node = hash_node->lru_node_tail;
		lru_node = hash_node->lru_node_tail;
		EIO_VERIFY(lru_node);
		/*Replace the last lru node with this bio*/
		lru_node->most_recent_sector = bio->bi_sector;
		lru_node->last_bio_size = bio->bi_size;
		lru_node->sequential_size_bytes = bio->bi_size;
		lru_node->node_id = dmc->node_id;
		lru_node->io_count = 1;	
		lru_node->threshold_flag = 0;
		lru_node->bypass_flag = 0;
		dmc->node_id++;
		EIO_DBG(INFO, dmc, "id:%lu, io_count:%lu, sequential_size_bytes:%lu\n", 
				lru_node->node_id, lru_node->io_count, 
				TO_KB(lru_node->sequential_size_bytes));
	}

	if (lru_node != hash_node->lru_node_head) {
		EIO_DBG(INFO, dmc, "wssc_detect_seqential_io: move to lru head\n");
		seq_io_move_to_lruhead(hash_node, lru_node);
	}

#if 0
	/*4.Check if it needs to move hash node*/	
	new_hash_node_idx = (to_bytes(bio->bi_sector) + bio->bi_size) 
							>> SEQIO_HAZE_SIZE_1GB_SHIFT;
	new_hash_node_idx %= (SEQIO_HASH_TBL_SIZE - 1);
	if (new_hash_node_idx != hash_node_idx) {
		/*Move this lru_node to new hash node*/
		EIO_DBG(INFO, dmc, "wssc_detect_seqential_io: move to new hash node\n");
		EIO_VERIFY(new_hash_node_idx == 
				(hash_node_idx + 1) % (SEQIO_HASH_TBL_SIZE - 1));
		new_hash_node = &dmc->seqio_hashtbl[new_hash_node_idx];
		seq_io_move_to_hash_node(hash_node, new_hash_node, lru_node);
	} else {
		/*Move to the head of the current hash node if needed*/
		if (lru_node != hash_node->lru_node_head) {
			EIO_DBG(INFO, dmc, "wssc_detect_seqential_io: move to lru head\n");
			seq_io_move_to_lruhead(hash_node, lru_node);
		}
	}
#endif
	/*5.Update IO predict info*/
	 return seq_io_update_iopredict(dmc, sequential, lru_node, bio);
}
#endif
