#include <stdio.h>
#include <stdlib.h>
#include <uthash.h>


struct elm_read_req {
	int fd;
	size_t size;
	off_t offset;
};


typedef struct {
	struct elm_read_req key;
	void *data;
	UT_hash_handle hh;
} record_t;

record_t *cache;


int main (int argc, char *argv)
{
	struct elm_read_req req = {
		.fd = 1,
		.size = 2,
		.offset = 3,
	};

	record_t *r = calloc(1, sizeof(record_t));

//	r->key = req;
	r->key.fd = 1;
	r->key.size = 2;
	r->key.offset = 3;

	r->data = NULL;
	HASH_ADD(hh, cache, key, sizeof(req), r);


	record_t l;
	memset(&l, 0, sizeof(l));
//	l.key = req;

	l.key.fd = 1;
	l.key.size = 2;
	l.key.offset = 3;

	record_t *p;
	HASH_FIND(hh, cache, &l.key, sizeof(struct elm_read_req), p);

	if (p) {
		fprintf(stdout, "p = %p\n", p);
	}

	return 0;
}
