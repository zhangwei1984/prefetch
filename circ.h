#ifndef CIRC_H
#define CIRC_H

typedef struct circ_buf_t {
	int head;
	int tail;
	unsigned int count;
	unsigned int len;
	unsigned int size;
	char *buf;
} circ_buf_t;

int circ_init(circ_buf_t *b, unsigned int len, unsigned int size);
int circ_enq(circ_buf_t *b, const void *elm);
int circ_deq(circ_buf_t *b, void *elm);
const void *circ_peek(circ_buf_t *b, int index);
unsigned int circ_cnt(circ_buf_t *b);
void circ_free(circ_buf_t *b);

#endif
