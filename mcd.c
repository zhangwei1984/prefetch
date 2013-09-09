#if HAVE_MCD

#include <stdio.h>
#include <string.h>

#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <math.h>

#include <linux/mcd.h>
#include <errno.h>

#include "libmcd.h"

ssize_t mcd_getsize(const void *key, size_t key_size)
{
    int ret_val = 0;
    void *cast_key = (void *) key;
    mcd_verbose(XENMCD_cache_check, MCDOPT_shared, key_size, cast_key, 0 /* val_size */ , &ret_val, NULL);

    return ret_val;
}

int mcd_get(const void* key, size_t key_size, void **p_value)
{
    void *cast_key = (void *) key;
    ssize_t r_val_size = mcd_getsize(key, key_size);
    int rc;

    if (r_val_size < 0) {
        if (r_val_size == -2000) {
            errno = ENOENT;
        }

        return r_val_size;
    }

    void *p = malloc(rc);

    if (!p) {
        return -1;
    }

    mcd_verbose(XENMCD_cache_get, MCDOPT_shared, key_size, cast_key, r_val_size, &rc, p);

    if (rc < 0) {
        free(p);
        p = NULL;
    }

    *p_value = p;

    return rc;
}

int mcd_get_fill(const void* key, size_t key_size, void *buf, size_t buf_size)
{
    void *cast_key = (void *) key;

    int rc;

#if 0
    /* Check first to avoid a memory leak in the ioctl implementation. */
    mcd_verbose(XENMCD_cache_check, MCDOPT_shared, key_size, cast_key, 0, &rc, NULL);

    if (rc > 0)  /* > 0 means exists */
    {
        mcd_verbose(XENMCD_cache_get, MCDOPT_shared, key_size, cast_key, buf_size, &rc, buf);
    }
#else
    mcd_verbose(XENMCD_cache_get, MCDOPT_shared, key_size, cast_key, buf_size, &rc, buf);
#endif

    return rc;
}


int mcd_put(const void *key, size_t key_size, const void *val, size_t val_size)
{
    int ret_val;
    void *cast_key = (void *) key;
    void *cast_val = (void *) val;
    mcd_verbose(XENMCD_cache_put, MCDOPT_shared, key_size, cast_key, val_size, &ret_val, cast_val);
    return ret_val;
}

int mcd_remove(const void *key, size_t key_size)
{
    int ret_val;
    void *cast_key = (void *) key;
    mcd_verbose(XENMCD_cache_remove, MCDOPT_shared, key_size, cast_key,
                0 /* val_size */, &ret_val, NULL);
    return ret_val;
}

int mcd_flush()
{
    int ret_val = 0;
    mcd_verbose(XENMCD_cache_flush, MCDOPT_shared, 0, NULL, 0, &ret_val, NULL);
    return ret_val;
}


int mcd_stat()
{
    char buf[1024];
    int r_val_size = 0;
    unsigned long cache_size, cache_free, cache_used;

    memset(buf, 0, sizeof(buf));
    mcd_verbose(XENMCD_stat_get, MCDOPT_shared, 0, 0, sizeof(buf), &r_val_size, buf);

	printf("r_val_size = %d\n", r_val_size);

    if (r_val_size > 0) {
        sscanf(buf, "%lu,%lu\n", &cache_size, &cache_free);
        cache_used = cache_size - cache_free;
        double used = (double) cache_used / cache_size;
        printf("cache_size = %lu cache_free = %lu cache_used = %lu used = %lf\n", cache_size, cache_free, cache_used, used);
        return 0;
    }

    return -1;
}


#ifdef BUILD_MCD_MAIN

void usage(int exit_code)
{
    fprintf(stderr, "Usage: mcd (get|put|remove|flush) [value]\n");
    exit(exit_code);
}

int main(int argc, char *argv[])
{
    int rc;

    if (argc < 2) {
        usage(1);
    }

    char *cmd = argv[1];
    char *key = argv[2];

    printf("mcd cmd is %s\n", cmd);

    if (!strcmp(cmd, "get")) {
        void *buf;

        rc = mcd_get(key, strlen(key), &buf);

        printf("rc = %d\n", rc);

        if (rc > 0) {
            printf("%s\n", (char *) buf);
            free(buf);
        }
    }
    else if (!strcmp(cmd, "put")) {
        if (argc < 4) {
            usage(1);
        }

        char *val = argv[3];
        rc = mcd_put(key, strlen(key), val, strlen(val));
    }
    else if (!strcmp(cmd, "remove") || !strcmp(cmd, "rm")) {
        rc = mcd_remove(key, strlen(key));
    }
    else if (!strcmp(cmd, "flush")) {
        rc = mcd_flush();
    }
    else if (!strcmp(cmd, "stat")) {
        rc = mcd_stat();
    }
    else {
        usage(1);
    }

    if (rc < 0) {
        perror("mcd");
        exit(1);
    }

    return 0;
}

#endif

#endif /* HAVE_MCD */
