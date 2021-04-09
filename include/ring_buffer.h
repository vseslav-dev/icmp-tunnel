#ifndef RING_BUFFER_H
#define RING_BUFFER_H 1

#include <main.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define RB_SIZE 32

typedef enum {
	RB_ERROR = -2,
	RB_EMPTY = -1,
	RB_SUCCESS = 0,
} RC_RB_t;

typedef struct {
	uint16_t icmp_sequence;
} RBData_t;

typedef struct {
	uint32_t mask;
	size_t cnt;
	size_t size;
	uint32_t head, tail;
	RBData_t *data;
} RingBuf_t;

#define RB_DATA_SIZE 32

RC_RB_t rb_del(RingBuf_t *buf);

void rb_put(RingBuf_t *buf, RBData_t val);

RC_RB_t rb_get(RingBuf_t *buf, RBData_t *val);

RingBuf_t *rb_init(size_t size);

#endif /*RING_BUFFER_H*/
