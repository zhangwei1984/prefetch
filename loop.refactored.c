/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` fusexmp.c -o fusexmp
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#define _GNU_SOURCE /* for O_DIRECT */
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h> /* for posix_memalign */
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <pthread.h>
#include "circ.h"
#include <sys/types.h>
#include <limits.h>

/* Despite what the man page for dbopen says, the correct prototypes
 * are in db_185.h 
 */
#include <db_185.h>
#include "utlist.h"
#include <semaphore.h>

static FILE *fp_sync;
static size_t max_block_size = 1048576;
static pthread_cond_t req_condition;
static pthread_mutex_t req_queue_lock;
static pthread_mutex_t cache_lock;
static circ_buf_t req_queue;
static int exit_flag = 0;
static int prefetch_aggressiveness = 1;

struct loop_file_info {
	int fd;
	ino_t ino;
	struct stat st_buf;
};


struct elm_read_req {
	int fd;
	ino_t ino;
	size_t size;
	off_t offset;
	unsigned int refcnt; /* initial refcnt 0 for prefetch ops */
	sem_t *sem;
	struct cache_entry *p_response;
};

struct cache_key {
	/* Requested */
	ino_t ino;
	size_t size;
	off_t offset;
};

struct cache_entry {
	struct cache_key key;

	/* Actual results from a read op */
	ssize_t rc;
	void *data;
	unsigned int *refcnt;

	/* Pointer to node in lru_list */
	struct lru_entry *lru_ent;
};

struct lru_entry {
	struct cache_entry *ent;
	/* lru list managment */
	struct lru_entry *next, *prev;
};

struct lru_entry *lru_list = NULL;

static unsigned long long cached_bytes;
static unsigned long long cache_limit = 300000000;
static unsigned long long cache_hit_bytes;
static unsigned long long cache_miss_bytes;


static DB *db_bt = NULL;
static struct cache_ops *cache;

void cache_report(FILE *fp, unsigned long long cache_hit_bytes, unsigned long long cache_miss_bytes)

{
	double hit_rate = (double) cache_hit_bytes / (cache_hit_bytes + cache_miss_bytes);

	fprintf(fp,
		"cache_hit_bytes = %llu cache_miss_bytes = %llu rate = %lf\n",
		cache_hit_bytes,
		cache_miss_bytes,
		hit_rate);
	fflush(fp);
}


struct cache_ops {
	void *opaque;

	int (*cache_insert)(struct cache_ops *ops,
			    struct cache_entry *ent);
	int (*cache_lookup)(struct cache_ops *ops,
			    const struct elm_read_req *p_req,
			    struct cache_entry **p_ent);

	int (*cache_purge)(struct cache_ops *ops,
			   unsigned long long *cached_bytes, unsigned long long cache_limit);
	void (*cache_destroy)(struct cache_ops *ops);
};


int cache_insert(struct cache_ops *ops,
		 struct cache_entry *ent)
{
	int rc;

	DBT key_record;
	DBT val_record;

	DB *db_bt = (DB *) ops->opaque;

	key_record.data = &ent->key;
	key_record.size = sizeof(struct cache_key);

	val_record.data = ent;
	val_record.size = sizeof(struct cache_entry);

	struct lru_entry *lru_ent 
		= calloc(1, sizeof(struct lru_entry));

	if (!lru_ent) {
		return -1;
	}

	lru_ent->ent = ent;
	ent->lru_ent = lru_ent;

	DL_APPEND(lru_list, lru_ent);

	/* Since insert into the db copies the structure all members
	 * must be filled in before inserting.
	 */

	rc = db_bt->put(db_bt,
			&key_record,
			&val_record,
			R_SETCURSOR);

	if (rc < 0) {
		DL_DELETE(lru_list, lru_ent);
		free(lru_ent);
	}

	if (ent->rc > 0) {
		cached_bytes += ent->rc;
	}

	return rc;
}

int cache_lookup(struct cache_ops *ops,
		 const struct elm_read_req *p_req,
		 struct cache_entry **p_ent)
{
	DB *db_bt = (DB *) ops->opaque;

	struct cache_key key = {
		.ino = p_req->ino,
		.size = p_req->size,
		.offset = p_req->offset
	};

	DBT lookup_key = {
		.data = &key,
		.size = sizeof(struct cache_key)
	};

	DBT lookup_result;

	int get_rc;

	get_rc = db_bt->get(db_bt, &lookup_key,
			    &lookup_result, 0);

	if (get_rc == 0) {
		*p_ent = (struct cache_entry *)
			    lookup_result.data;

		struct lru_entry *lru_ent = (*p_ent)->lru_ent;

		/* Move to front of lru_list */
		DL_DELETE(lru_list, lru_ent);
		DL_APPEND(lru_list, lru_ent);
	}

	/* Returns 0 if found, 1 if not found, -1 if error. 
	 */

	return get_rc;
}


int cache_purge(struct cache_ops *ops,
		 unsigned long long *cached_bytes, unsigned long long cache_limit)
{
	DB *db_bt = (DB *) ops->opaque;

	struct lru_entry *lru_ent, *tmp;
	struct cache_entry *ent;
	int del_rc;

	DL_FOREACH_SAFE(lru_list, lru_ent, tmp)
	{
		ent = lru_ent->ent;

		if (*ent->refcnt > 0) {
			continue;
		}

		DL_DELETE(lru_list, lru_ent);

		DBT lookup_key = {
			.data = &ent->key,
			.size = sizeof(struct cache_key)
		};

		del_rc = db_bt->del(db_bt,
				    &lookup_key,
				    0 /* flags */
			);

		if (lru_ent->ent->rc > 0) {
			*cached_bytes -= lru_ent->ent->rc;
			free(lru_ent->ent->data);
		}

		free(lru_ent);

		if (*cached_bytes <= cache_limit)
			break;
	}

	return del_rc;
}

void cache_destroy(struct cache_ops *ops)
{
	return;
}


int cache_db_init(struct cache_ops *ops)
{

	DB *db_bt = dbopen(NULL, /* file not on disk */
			   O_CREAT | O_RDWR, /* flags */
			   0666, /* mode */
			   DB_BTREE, /* DBTYPE */
			   NULL);

	struct cache_ops db_ops = {
		.opaque = db_bt,
		.cache_insert = cache_insert,
		.cache_lookup = cache_lookup,
		.cache_purge = cache_purge,
		.cache_destroy = cache_destroy,
	};

	*ops = db_ops;
	return 0;
}


static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(path, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	int rc = 0;

	struct loop_file_info *info = malloc(sizeof(struct loop_file_info));

	if (!info) {
		return -errno;
	}

	fd = open(path, fi->flags | O_DIRECT);

	if (fd == -1) {
		rc = -errno;
	}
	else {
		struct stat sbuf;

		if (fstat(fd, &sbuf)) {
			rc = -errno;
		}
		else {
			info->fd = fd;
			info->ino = sbuf.st_ino;
			info->st_buf = sbuf;
			fi->fh = (unsigned long) info;
		}
	}

	return rc;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	ino_t ino;
	int res = 0;
	static int cnt = 0;

	struct loop_file_info *info
		= (struct loop_file_info *) (unsigned long) fi->fh;

	fd = info->fd;
	ino = info->ino;

	if (fd == -1)
		return -errno;

	if (size > max_block_size) {
		return -ENOMEM;
	}

	if (fp_sync) {
		fprintf(fp_sync, "cnt %d read %s inode %llu size %lu off %ld\n", cnt, path, (unsigned long long) ino, size, offset);
		fflush(fp_sync);
		cnt++;
	}

	/* fill in the request */
	sem_t sem;
	sem_init(&sem, 0, 0);
	struct cache_entry response;

	struct elm_read_req req = {
		.fd = fd,
		.ino = ino,
		.size = size,
		.offset = offset,
		.sem = &sem,
		.refcnt = 1,
		.p_response = &response
	};

	/* check for already cached */
	pthread_mutex_lock(&cache_lock);

	int get_rc;

	struct cache_entry *result;

	get_rc = cache->cache_lookup(cache,
				     &req,
				     &result);

	if (get_rc == 0 && result->rc > 0) {
		memcpy(buf, result->data, result->rc);

		fprintf(fp_sync,
			"Found record already cached "
			"ref = %d data = %p rc = %ld\n",
			*result->refcnt,
			result->data, 
			result->rc);

		fflush(fp_sync);

		if (result->rc > 0) {
			cache_hit_bytes += result->rc;
		}

		cache_report(fp_sync, cache_hit_bytes, cache_miss_bytes);

		res = result->rc;
		pthread_mutex_unlock(&cache_lock);
	}
	else if (get_rc == -1) {
		pthread_mutex_unlock(&cache_lock);
		return -EIO;
	}
	else {
		pthread_mutex_unlock(&cache_lock);
		pthread_mutex_lock(&req_queue_lock);

		if (circ_enq(&req_queue, &req)) {
			return -EBUSY;
		}
	}

	int i;

	struct elm_read_req prefetch_req = req;

	for (i=0; i<prefetch_aggressiveness; i++) {

		prefetch_req.offset += prefetch_req.size;
		prefetch_req.sem = NULL;
		prefetch_req.refcnt = 0;
		prefetch_req.p_response = NULL;

		if (prefetch_req.offset + prefetch_req.size
		    > info->st_buf.st_size)
		{
			/* XXX */
			break;
		}


		/* Prefetch requests are advisory only. 
		 * If the queue is full, it may not be an error.
		 */

		if (circ_enq(&req_queue, &prefetch_req)) {
			break;
		}
	}

	int q_cnt = circ_cnt(&req_queue);

	fprintf(fp_sync, "req_queue_cnt = %d\n", q_cnt);

	fflush(fp_sync);

	pthread_cond_signal(&req_condition);

	pthread_mutex_unlock(&req_queue_lock);

	if (get_rc == 0) {
		/* If it was already in cache no need to wait.
		 */
		return res;
	}

	/* Wait for the response */

	sem_wait(&sem);

	fprintf(fp_sync, "got response\n");
	fflush(fp_sync);

	pthread_mutex_lock(&cache_lock);

	/* Check the response */

	result = &response;

	if (result->rc >= 0) {
		memcpy(buf,
		       result->data,
		       result->rc);
	}

	res = result->rc;

	if (*result->refcnt > 0) {
		*result->refcnt -= 1;
	}

	cache_report(fp_sync, cache_hit_bytes, cache_miss_bytes);

	pthread_mutex_unlock(&cache_lock);

	sem_destroy(&sem);

	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
#if 0
	int fd, rc;

	struct loop_file_info *info
		= (struct loop_file_info *) (unsigned long) fi->fh;

	fd = info->fd;

	rc = close(fd);

	if (rc == -1)
		return -errno;

	return 0;
#else
	return 0;
#endif
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

struct prefetch_thread_args {
	FILE *fp;
	pthread_cond_t *req_cond;
	pthread_mutex_t *req_queue_lock;
	pthread_mutex_t *cache_lock;
	circ_buf_t *req_queue;
	DB *db_bt;
	int pagesize;
	struct cache_ops *cache_ops;
};



void *prefetch_thread(void *arg)
{
	struct prefetch_thread_args *args = (struct prefetch_thread_args *) arg;

	FILE *fp = fopen("fuse_fetch_loop.log", "w");
	pthread_cond_t *req_cond = args->req_cond;
	pthread_mutex_t *req_queue_lock = args->req_queue_lock;
	pthread_mutex_t *cache_lock = args->cache_lock;
	circ_buf_t *queue = args->req_queue;
	int alignment = args->pagesize;
	struct elm_read_req req;
	int cnt = 0;
	struct cache_ops *cache = args->cache_ops;

	for (;;) {

		pthread_mutex_lock(req_queue_lock);

		int queued_cnt = circ_cnt(queue);

		if (queued_cnt == 0) {

			fprintf(fp, "Wait cnt %d\n", cnt);
			fflush(fp);

			pthread_cond_wait(req_cond, req_queue_lock);

			fprintf(fp, "Wakeup cnt %d\n", cnt);
			fflush(fp);
		}

		cnt++;

		if (circ_deq(queue, &req)) {
		}
		else {
			fprintf(fp, "Request fd %d inode %llu ref %d size %ld offset %ld\n", req.fd, (unsigned long long) req.ino, req.refcnt, req.size, req.offset);
			fflush(fp);
		}

		pthread_mutex_unlock(req_queue_lock);

		if (exit_flag)
			break;

		pthread_mutex_lock(cache_lock);

		/* Check in the cache. */

		struct cache_entry *ent;
		int get_rc;

		get_rc = cache->cache_lookup(cache,
					     &req,
					     &ent);

		if (get_rc == 0) {

			fprintf(fp, "Read request already cached.\n");
			fflush(fp);

			*ent->refcnt += req.refcnt;

			if (req.p_response) {
				*req.p_response = *ent;
			}

			if (ent->rc > 0 && req.refcnt > 0) {
				cache_hit_bytes += ent->rc;
			}

			if (req.sem) {
				sem_post(req.sem);
			}
		}
		else if (get_rc == 1) {

		fprintf(fp, "Read request not yet in cache.\n");
		fflush(fp);


		ssize_t res;
		void *aligned_buf;

		res = posix_memalign(&aligned_buf, alignment, req.size);

		if (res == 0) {


			pthread_mutex_unlock(cache_lock);

			res = pread(req.fd, aligned_buf, req.size, req.offset);
			pthread_mutex_lock(cache_lock);

			if (res > 0 && req.refcnt > 0) {
				cache_miss_bytes += res;
			}


			ent = calloc(1,
				     sizeof(struct cache_entry));

			if (ent) {
			ent->refcnt = malloc(sizeof(*ent->refcnt));
			}

			if (ent && ent->refcnt) {
				/* Copy into cache record. */
				ent->key.ino = req.ino;
				ent->key.size = req.size;
				ent->key.offset = req.offset;

				*ent->refcnt = req.refcnt;
				ent->data = aligned_buf;
				ent->rc = res;
				res = cache->cache_insert(cache, ent);

				if (req.p_response) {
					*req.p_response = *ent;
				}
			}
			else {
				free(ent);
				res = -1;
			}
		}
		else {
			res = -1;
			errno = ENOMEM;
		}

		if (res < 0) {
			ent->rc = -errno;
			free(aligned_buf);
			ent->data = NULL;

			fprintf(fp, "Failed to read %s:\n", strerror(errno));
			fflush(fp);
		}
		else {
			fprintf(fp, "Copied %ld bytes data to p = %p\n", ent->rc, aligned_buf);
			fflush(fp);
		}

		/* Wake up any waiting thread. */
		if (req.sem) {
			sem_post(req.sem);
		}

		} /* end not found in cache */


		pthread_mutex_unlock(cache_lock);

		/* Check for memory limit and evict as needed. */
		pthread_mutex_lock(cache_lock);

		fprintf(fp, "Cached bytes now %llu\n",
			cached_bytes);
		fflush(fp);

		fprintf(fp, "Broadcast response condition\n");
		fflush(fp);

		if (cached_bytes > cache_limit) {
			
			fprintf(fp, "Evicting since cached_bytes %llu > limit %llu\n", cached_bytes, cache_limit);
			fflush(fp);


			cache->cache_purge(cache, &cached_bytes, cache_limit);

			fprintf(fp, "After eviction cached bytes now %llu\n",
				cached_bytes);
			fflush(fp);

#if 0
			int i = 0;
			DL_FOREACH(lru_list, lru_ent)
			{
				ent = lru_ent->ent;

				fprintf(fp, "Cache record %d ref %d inode %llu size %u off %lld\n",
					i,
					*ent->refcnt,
					ent->key.ino,
					ent->key.size,
					ent->key.offset);
				fflush(fp);
				ent = lru_ent->ent;
				i++;
			}
#endif

		}

		pthread_mutex_unlock(cache_lock);
	}

	fclose(fp);

	pthread_exit(NULL);
}


static void* xmp_init(struct fuse_conn_info *conn)
{
	return NULL;
}

static void xmp_destroy(void* private_data)
{
	pthread_mutex_lock(&req_queue_lock);
	pthread_cond_signal(&req_condition);
	exit_flag = 1;
}


static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
	.init           = xmp_init,
	.destroy        = xmp_destroy
};

int main(int argc, char *argv[])
{
	umask(0);

	fp_sync = fopen("fuse_sync_loop.log", "w");

	if (!fp_sync) {
		perror("fopen");
		exit(1);
	}

	if (getenv("AGGRESSIVENESS")) {
		prefetch_aggressiveness = strtol(
			getenv("AGGRESSIVENESS"), NULL, 0);

		fprintf(stderr,
			"Set aggressiveness = %d\n",
			prefetch_aggressiveness);
	}

	if (circ_init(&req_queue, 256, sizeof(struct elm_read_req))) {
		perror("circ_buf_init");
	}

	int pagesize = getpagesize();

	struct prefetch_thread_args args = {
		.req_queue_lock = &req_queue_lock,
		.cache_lock = &cache_lock,
		.req_cond = &req_condition,
		.req_queue = &req_queue,
		.db_bt = db_bt,
		.pagesize = pagesize
	};

	struct cache_ops ops;

	cache_db_init(&ops);

	args.cache_ops = &ops;
	cache = &ops;

	if (pthread_mutex_init(&req_queue_lock, NULL)) {
		perror("pthread_mutex_init");
	}

	if (pthread_mutex_init(&cache_lock, NULL)) {
		perror("pthread_mutex_init");
	}

	if (pthread_cond_init(&req_condition, NULL)) {
		perror("pthread_cond_init");
	}

	pthread_t thread;

	if (pthread_create(&thread, NULL, prefetch_thread, &args) < 0) {
		fprintf(stderr, "error creating thread\n");
	}

	fprintf(fp_sync, "entering fuse_main\n");
	fflush(fp_sync);

	fuse_main(argc, argv, &xmp_oper, NULL);

	pthread_join(thread, NULL);

	exit(0);
}
