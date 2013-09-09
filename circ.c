#include "circ.h"
#include <stdlib.h>
#include <string.h>

int circ_init(circ_buf_t *b, unsigned int len, unsigned int size)
{
	b->buf = malloc((len + 1) * size);

	if (!b->buf) {
		return -1;
	}

	b->len = (len + 1);
	b->size = size;
	b->head = 0;
	b->tail = 0;
	b->count = 0;

	return 0;
}

int circ_enq(circ_buf_t *b, const void *elm)
{
	int head = (b->head + 1) % b->len;

	if (head == b->tail) {
		return -1;
	}

	memcpy(b->buf + b->head * b->size, elm, b->size);
	b->head = head;
	b->count++;
	return 0;
}

int circ_deq(circ_buf_t *b, void *elm)
{
	if (b->head == b->tail) {
		return -1;
	}

	if (elm) {
		memcpy(elm, &b->buf[b->tail * b->size], b->size);
	}

	b->tail = (b->tail + 1) % b->len;
	b->count--;
	return 0;
}

const void *circ_peek(circ_buf_t *b, int index)
{
	if (index >= b->count)
		return NULL;

	int i = (b->head + index) % b->len;
	return &b->buf[i * b->size];
}

unsigned int circ_cnt(circ_buf_t *b)
{
	return b->count;
}

void circ_free(circ_buf_t *b)
{
	if (b) {
		free(b->buf);
	}
}
