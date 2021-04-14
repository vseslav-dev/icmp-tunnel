#ifndef DI_ICMP_COMMUNICATION_H
#define DO_ICMP_COMMUNICATION_H 1

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
			+ sizeof(uint16_t) * 2 \
			+ sizeof(bool) * 4))

struct pkt {
	struct icmphdr hdr;
	uint16_t len; /* len of PAYLOAD_SIZE */
	uint16_t cwnd;
	uint32_t ack_num;
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
	struct pkt *send_pkt, *recv_pkt;
} IcmpStuff_t;

#define INITIAL_CWND_SIZE 2
#define INITIAL_RTO 3.5
#define MAX_CWND_SIZE 2
#define BUF_SIZE (PAYLOAD_SIZE * MAX_CWND_SIZE)
#define PKT_STUFF_SIZE (sizeof(struct pkt) - PAYLOAD_SIZE)

uint16_t in_cksum(uint16_t * addr, size_t len);

#endif /* DO_ICMP_COMMUNICATION_H */
