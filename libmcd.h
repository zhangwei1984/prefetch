#ifndef LIBMCD_H
#define LIBMCD_H

#include <stdlib.h>

ssize_t mcd_getsize(const void *key, size_t key_size);
int mcd_get(const void* key, size_t key_size, void **p_value);
int mcd_get_fill(const void* key, size_t key_size, void *buf, size_t buf_size);
int mcd_put(const void *key, size_t key_size, const void *val, size_t val_size);
int mcd_remove(const void *key, size_t key_size);
int mcd_flush();

#endif
