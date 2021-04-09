#ifndef READ_WRITE_H
#define READ_WRITE_H 1

RC_t write_all(int fd, void *buf, int32_t n, int32_t * tot_write);

RC_t read_all(int fd, void *buf, int32_t n, int32_t * tot_read);

#endif
