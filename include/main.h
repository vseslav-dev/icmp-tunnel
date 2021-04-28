#ifndef MAIN_H
#define MAIN_H 1

#include <stdio.h>

#include <net/if.h>
#include <netdb.h>

#define PROGRAM_NAME "icmp-tunnel"
#define DEFAULT_TUN_NAME "tun50"

#ifdef DEBUG
#define PR_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define PR_DEBUG(...)
#endif

typedef enum {
	NO_ICMP_SEQ = -3,
	PARSING_ERR = -2,
	ERROR = -1,
	SUCCESS = 0,
	HELP_RET = 1,
} RC_t;

typedef enum {
	SERVER = 0,
	CLIENT = 1,
} Role_t;

typedef struct {
	Role_t role;
	char tun_name[IFNAMSIZ + 1];
	uint16_t session_id;
	union {
		struct in_addr remote_ip;
		struct in_addr local_ip;
	} ip_addr;
} CMD_t;

typedef struct {
	int tun_fd;
	int net_fd;
} NetFD_t;

RC_t do_communication(NetFD_t * fds, CMD_t * args);

RC_t establish_connect(NetFD_t * fds);

RC_t get_tun_fd(NetFD_t ** fds, CMD_t * args);

RC_t do_icmp_communication(NetFD_t * fds, CMD_t * args);

RC_t write_all(int fd, void *buf, int32_t n, int32_t * tot_write);

RC_t read_all(int fd, void *buf, int32_t n, int32_t * tot_read);

#endif /*_MAIN_H*/
