#include <ring_buffer.h>

#include <math.h>

RC_RB_t rb_del(RingBuf_t *buf)
{
	if (buf) {
		if (buf->data) {
			free(buf->data);
			free(buf);
		} else {
			free(buf);
			return RB_ERROR;
		}
	} else {
		return RB_ERROR;
	}
	return RB_SUCCESS;
}

void rb_put(RingBuf_t *buf, RBData_t val)
{
	if ((buf->head == buf->tail) && (buf->cnt == buf->size)) {
		buf->data[(buf->head)++] = val;
		(buf->tail)++;
		buf->tail &= buf->mask;
		buf->head &= buf->mask;
		return;
	}
	buf->data[(buf->head)++] = val;
	buf->head &= buf->mask;
	buf->cnt++;
	return;
}

RC_RB_t rb_get(RingBuf_t *buf, RBData_t *val)
{
	if (buf->cnt == 0) {
		return RB_EMPTY;
	}
	*val = buf->data[(buf->tail)++];
	buf->tail &= buf->mask;
	buf->cnt--;
	return RB_SUCCESS;
}

RingBuf_t *rb_init(size_t size)
{
	RingBuf_t *buf;
	if ((buf = malloc(sizeof(RingBuf_t))) == NULL) {
		perror("malloc cannot allocate ring buffer");
		return NULL;
	}

	size = pow(2, ceil(log(size)/log(2)));
	if ((buf->data = malloc(sizeof(RBData_t) * size)) == NULL) {
		perror("malloc cannot allocate ring buffer memory");
		free(buf);
		return NULL;
	}
	buf->size = size;
	buf->mask = size - 1;
	buf->cnt = 0;
	PR_DEBUG("size of buffer is: %zu\n", size);
	PR_DEBUG("buffer mask is: %zu\n", size - 1);
	buf->head = buf->tail = 0;
	return buf;
}
