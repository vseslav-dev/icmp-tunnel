#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>

#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <sys/types.h>
#include <sys/stat.h>
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
	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		free(*fds), close(fd);
		perror("ioctl TUNSETIFF set tun name");
		return ERROR;
	}

	PR_DEBUG("tun name is: \"%s\"\n", ifr.ifr_name);

	(*fds)->tun_fd = fd;
	return SUCCESS;
}
