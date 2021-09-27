#ifndef COMMUNICATION_ROUTINES_H
#define COMMUNICATION_ROUTINES_H 1

#include <main.h>
#include <ring_buffer.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#include <stdbool.h>

#include <stdint.h>

#define PAYLOAD_SIZE (ETHERMTU - (ETHER_HDR_LEN \
			+ sizeof(struct iphdr) \
			+ sizeof(struct icmphdr) \
			+ sizeof(uint32_t) \
			+ (sizeof(uint16_t) * 3) \
			+ (sizeof(bool) * 4)))

struct pkt {
	struct icmphdr hdr;
	uint32_t ack_num;
	uint16_t len; /* len of PAYLOAD_SIZE */
	uint16_t cwnd;
	uint16_t session_id;
	bool need_icmp_fl, need_ack, hangup, first_packet;
	uint8_t data[PAYLOAD_SIZE];
} __attribute__((packed));

typedef struct {
	int32_t nr, nw, len, tun_nr;
	uint16_t old_seq, seq, pkt_id;
	uint16_t cwnd;
	double rto;
	bool need_icmp;
	uint8_t *buffer;
	RingBuf_t *rb;
	struct sockaddr_in *client_addr, *server_addr;
	struct pkt *send_pkt;
	void *recv_pkt;
} IcmpStuff_t;

#define ATTEMPT_CNT 3
#define INITIAL_CWND_SIZE 1
#define INITIAL_RTO 3.5
#define MAX_CWND_SIZE 2
#define BUF_SIZE (PAYLOAD_SIZE * MAX_CWND_SIZE)
#define PKT_STUFF_SIZE (sizeof(struct pkt) - PAYLOAD_SIZE)

#define GET_IP_HDR_LEN(pkt_p) (((struct iphdr *)pkt_p)->ihl * sizeof(int))
#define GET_ICMP_LEN(pkt_p) (ntohs(((struct iphdr *)pkt_p)->tot_len) - iphdrlen)
#define GET_IP_CKSUM(pkt_p) (((struct iphdr *)pkt_p)->check)
#define SET_IPHDR_CKSUM_0(pkt_p) (((struct iphdr *)pkt_p)->check = 0)
#define GET_ICMP_CKSUM(pkt_p) \
	(((struct icmphdr *)((uint8_t *)pkt_p + iphdrlen))->checksum)
#define SET_ICMPHDR_CKSUM_0(pkt_p) \
	(((struct icmphdr *)((uint8_t *)pkt_p + iphdrlen))->checksum = 0)
#define CHECK_IP_CKSUM(pkt_p, cksum) \
	(in_cksum((uint16_t *)pkt_p, iphdrlen) == cksum)
#define CHECK_ICMP_CKSUM(pkt_p, cksum) \
	(in_cksum(((uint16_t *)((uint8_t *)pkt_p + iphdrlen)), icmplen) == \
	 cksum)
#define CHECK_ECHO_ID(pkt_p, pkt_id) \
	(ntohs(((struct pkt *)((uint8_t *)pkt_p + iphdrlen))->hdr.un.echo.id) \
	== pkt_id)
#define CHECK_SESSION_ID(pkt_p, pkt_id) \
	(ntohs(((struct pkt *)((uint8_t *)pkt_p + iphdrlen))-> \
	session_id) == pkt_id)
#define CHECK_OLD_SEQ(pkt_p, pkt_id) \
	(pkt_id == ntohs(((struct pkt *)((uint8_t *)pkt_p + \
					  iphdrlen))->hdr.un.echo.sequence))
#define GET_NEED_ICMP(pkt_p) \
	(((struct pkt *)((uint8_t *)pkt_p + iphdrlen))->need_icmp_fl)
#define CHECK_FIRST_PACKET(pkt_p) \
	(((struct pkt *)((uint8_t *)pkt_p + \
			 iphdrlen))->first_packet == true)
#define GET_SEQ(pkt_p) \
	(ntohs(((struct pkt *)((uint8_t *)stuffs->recv_pkt + iphdrlen))-> \
			hdr.un.echo.sequence))

RC_t do_client_communication(NetFD_t * fds, CMD_t * args);

RC_t do_server_communication(NetFD_t * fds, CMD_t * args);

RC_t send_icmp(int net_fd, struct pkt * send_pkt, struct sockaddr_in * addr,
		uint32_t * pkt_size);

uint16_t in_cksum(uint16_t * addr, size_t len);

void free_icmp_stuffs(IcmpStuff_t * stuffs);

RC_t write_all(int fd, void *buf, int32_t n, int32_t * tot_write);

RC_t read_all(int fd, void *buf, int32_t n, int32_t * tot_read);

#endif
