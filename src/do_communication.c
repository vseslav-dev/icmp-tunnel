#include <main.h>

RC_t do_communication(NetFD_t * fds, CMD_t * args)
{
	return do_icmp_communication(fds, args);
}
