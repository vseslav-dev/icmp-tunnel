#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>

#include <linux/if_tun.h>

#include <fcntl.h>

#include <main.h>

RC_t get_tun_fd(NetFD_t ** fds, CMD_t * args)
{
	int fd, err;
	struct ifreq ifr;
	if ((*fds = calloc(1, sizeof(NetFD_t))) == NULL) {
		perror("calloc fds");
		return ERROR;
	}
	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		free(*fds);
		perror("open /dev/net/tun");
		return ERROR;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	strcpy(ifr.ifr_name, args->tun_name);
	PR_DEBUG("tun name is: \"%s\"\n", ifr.ifr_name);
	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		perror("ioctl TUNSETIFF set tun name");
		free(*fds), close(fd);
		return ERROR;
	}


	(*fds)->tun_fd = fd;
	return SUCCESS;
}
