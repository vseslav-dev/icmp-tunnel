#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include <main.h>

RC_t write_all(int fd, void *buf, int32_t n, int32_t * tot_write)
{
	/* n is size of buffer, tot_write is the number of bytes write */
	int32_t tot, c;
	for (tot = 0; tot < n;) {
		c = write(fd, (char *)buf + tot, n - tot);
		tot += c;
		if ((c == -1 || c == 0) && tot != n) {
			perror("write write_all");
			*tot_write = tot;
			return ERROR;
		}
	}
	*tot_write = tot;
	return SUCCESS;
}

RC_t read_all(int fd, void *buf, int32_t n, int32_t * tot_read)
{
	/* n is size of buffer, tot_read is the number of bytes read */
	int32_t tot, c;
	for (tot = 0; tot < n;) {
		c = read(fd, (char *)buf + tot, n - tot);
		tot += c;
		if ((c == -1 || c == 0) && tot != n) {
			perror("read read_all");
			*tot_read = tot;
			return ERROR;
		}
	}
	*tot_read = tot;
	return SUCCESS;
}
