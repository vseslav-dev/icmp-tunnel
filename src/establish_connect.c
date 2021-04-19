#include <main.h>

RC_t establish_connect(NetFD_t * fds)
{
	int sock_fd;
	if ((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		perror("socket raw socket");
		return ERROR;
	}
	fds->net_fd = sock_fd;

	return SUCCESS;
}
