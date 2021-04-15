#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <errno.h>
#include <sys/select.h>

#include <main.h>
#include <ring_buffer.h>
#include <do_icmp_communication.h>
#include <read_write.h>

RC_t do_client_icmp_communication(NetFD_t * fds, CMD_t * args);

RC_t do_server_icmp_communication(NetFD_t * fds, CMD_t * args);

RC_t send_to_client(int net_fd, IcmpStuff_t * stuffs);

RC_t recieve_from_client(int net_fd, int tun_fd, IcmpStuff_t * stuffs);

RC_t recieve_from_server(int net_fd, IcmpStuff_t * stuffs);

RC_t send_to_server(int net_fd, IcmpStuff_t * stuffs);

RC_t send_icmp(int net_fd, struct pkt * send_pkt, struct sockaddr_in * addr,
		uint32_t * pkt_size);

RC_t get_first_packet(int net_fd, IcmpStuff_t * stuffs);

RC_t send_first_packet(int net_fd, IcmpStuff_t * stuffs);

uint16_t in_cksum(uint16_t * addr, size_t len);

void free_icmp_stuffs(IcmpStuff_t * stuffs);

#define ATTEMPT_CNT 3

RC_t do_icmp_communication(NetFD_t * fds, CMD_t * args)
{
	if (args->role == CLIENT)
		return do_client_icmp_communication(fds, args);
	else
		return do_server_icmp_communication(fds, args);
}

RC_t do_server_icmp_communication(NetFD_t * fds, CMD_t * args)
{
	int net_fd = fds->net_fd, tun_fd = fds->tun_fd;
	int maxfd = net_fd > tun_fd ? net_fd : tun_fd;
	int ret;
	fd_set rfds;
	bool err_fl = false;
	struct timeval sel_to; /* select() timeout */
	IcmpStuff_t *stuffs = calloc(1, sizeof(IcmpStuff_t));
	if (stuffs == NULL) {
		perror("calloc stuffs");
		return ERROR;
	}
	if ((stuffs->client_addr = malloc(sizeof(struct sockaddr_in)))
			== NULL) {
		perror("calloc client_addr");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	if ((stuffs->buffer = malloc(BUF_SIZE)) == NULL) {
		perror("malloc buffer");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	if ((stuffs->rb = rb_init(RB_DATA_SIZE)) == NULL) {
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	if ((stuffs->send_pkt = calloc(1, sizeof(struct pkt))) == NULL) {
		perror("calloc send_pkt");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	if ((stuffs->recv_pkt = malloc(sizeof(struct pkt))) == NULL) {
		perror("malloc recv_pkt");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	stuffs->send_pkt->hdr.type = ICMP_ECHOREPLY;
	stuffs->send_pkt->hdr.code = 0;
	/* need receive first packet and fill un.echo.id */
	stuffs->pkt_id = args->session_id;

	stuffs->client_addr->sin_family = AF_INET;
	stuffs->client_addr->sin_port = 0;

	stuffs->rto = INITIAL_RTO;

	sel_to.tv_sec = 1;
	sel_to.tv_usec = 0;

	if (get_first_packet(net_fd, stuffs) == ERROR) {
		fprintf(stderr, "reading the first packet from client "
				"returned an error\n");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}

	free_icmp_stuffs(stuffs);
	return SUCCESS;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(net_fd, &rfds);
		FD_SET(tun_fd, &rfds);
		ret = select(maxfd + 1, &rfds, NULL, NULL, &sel_to);
		if (ret == -1 && errno == EINTR) {
			continue;
		}
		if (ret == -1) {
			perror("select");
			err_fl = true;
			break;
		}

		if (FD_ISSET(tun_fd, &rfds) == true) {
			/* read from tun_fd */
			if (read_all(tun_fd, stuffs->buffer,
						BUF_SIZE, &stuffs->tun_nr)
					== ERROR) {
				if (stuffs->tun_nr == 0) {
					err_fl = true;
					break;
				}
			}
			stuffs->need_icmp = true;
		} else if (FD_ISSET(net_fd, &rfds) == true) {
			/* receive icmp packets */
			if (recieve_from_client(net_fd, tun_fd, stuffs)
					== ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
			/* send icmp packets reply */
			stuffs->send_pkt->need_icmp_fl = true;
			if (send_to_client(net_fd, stuffs) == ERROR) {
				if (stuffs->nw == 0) {
					err_fl = true;
					break;
				}
			}
			if (stuffs->tun_nr == stuffs->nw) {
				stuffs->need_icmp = false;
				sel_to.tv_sec = 1;
				sel_to.tv_usec = 0;
				stuffs->send_pkt->need_icmp_fl = false;
			} else {
				stuffs->need_icmp = true;
				sel_to.tv_sec = 0;
				sel_to.tv_usec = 0;
				stuffs->send_pkt->need_icmp_fl = true;
			}
		} else {
			/* idle, if no data */
			continue;
		}
	}			/*for (;;) */

	free_icmp_stuffs(stuffs);
	/*free(cwnd_buf);*/
	if (err_fl == true)
		return ERROR;
	else
		return SUCCESS;

	return SUCCESS;
}

RC_t do_client_icmp_communication(NetFD_t * fds, CMD_t * args)
{
	int net_fd = fds->net_fd, tun_fd = fds->tun_fd, ret;
	int maxfd = net_fd > tun_fd ? net_fd : tun_fd;
	fd_set rfds;
	uint32_t pkt_size = PKT_STUFF_SIZE;
	bool err_fl = false;
	struct timeval sel_to; /* select() timeout */
	struct pkt *send_pkt;
	/*uint32_t ack_num = 0;*/
	IcmpStuff_t *stuffs = calloc(1, sizeof(IcmpStuff_t));
	if (stuffs == NULL) {
		return ERROR;
	}
	stuffs->server_addr = calloc(1, sizeof(struct sockaddr_in));
	if (stuffs->server_addr == NULL) {
		perror("calloc server_addr");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	stuffs->buffer = malloc(BUF_SIZE);
	if (stuffs->buffer == NULL) {
		perror("malloc buffer");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	stuffs->send_pkt = calloc(1, sizeof(struct pkt));
	if (stuffs->send_pkt == NULL) {
		perror("calloc send_pkt");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	send_pkt = stuffs->send_pkt;
	stuffs->recv_pkt = malloc(sizeof(struct pkt));
	if (stuffs->recv_pkt == NULL) {
		perror("malloc recv_pkt");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	/* uint8_t *cwnd_buf = malloc(INITIAL_CWND_SIZE * PAYLOAD_SIZE);
	if (!cwnd_buf) {
		parror("malloc");
		err_fl = true;
	} */

	stuffs->send_pkt->hdr.un.echo.id = htons(stuffs->pkt_id);
	stuffs->send_pkt->hdr.type = ICMP_ECHO;
	stuffs->send_pkt->hdr.code = ICMP_ECHOREPLY;

	stuffs->server_addr->sin_family = AF_INET;
	stuffs->server_addr->sin_port = 0;
	stuffs->server_addr->sin_addr = args->ip_addr.remote_ip;

	if (send_first_packet(net_fd, stuffs) == ERROR) {
		fprintf(stderr, "sending the first packet to client "
				"returned an error\n");

		free_icmp_stuffs(stuffs);
		return ERROR;
	}

	free_icmp_stuffs(stuffs);
	return SUCCESS;

	sel_to.tv_sec = 1;
	sel_to.tv_usec = 0;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(net_fd, &rfds);
		FD_SET(tun_fd, &rfds);
		ret = select(maxfd + 1, &rfds, NULL, NULL, &sel_to);
		if (ret == -1 && errno == EINTR) {
			continue;
		}
		if (ret == -1) {
			perror("select");
			err_fl = true;
			break;
		}

		if (FD_ISSET(tun_fd, &rfds) == true) {
			/* read from tun_fd */
			if (read_all(tun_fd, &stuffs->buffer, BUF_SIZE,
						&stuffs->nr) == ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
			/* send icmp packets */
			stuffs->old_seq = stuffs->seq;
			if (send_to_server(net_fd, stuffs) == ERROR) {
				if (stuffs->nw == 0) {
					err_fl = true;
					break;
				}
			}
		} else if (FD_ISSET(net_fd, &rfds) == true) {
			/* recieve icmp packets */
			if (recieve_from_server(net_fd, stuffs) == ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
			/* write to tun_fd */
			if (write_all(tun_fd, stuffs->buffer, stuffs->nr,
						&stuffs->nw) == ERROR) {
				if (stuffs->nw == 0) {
					err_fl = true;
					break;
				}
			}
		} else {
			/* idle, if no data */
			if (stuffs->need_icmp == true) {
				sel_to.tv_sec = 0;
				sel_to.tv_usec = 0;
			} else {
				PR_DEBUG("Idle, no data\n");
				sel_to.tv_sec = 1;
				sel_to.tv_usec = 0;
			}
			send_pkt->hdr.un.echo.sequence = htons(stuffs->seq++);
			send_pkt->len = 0;
			send_pkt->cwnd = htons(stuffs->cwnd);
			send_pkt->hdr.checksum = 0;
			send_pkt->hdr.checksum
				= htons(in_cksum((uint16_t *)send_pkt,
							pkt_size));
			send_icmp(net_fd, send_pkt, stuffs->server_addr,
					&pkt_size);
		}
	}			/*for (;;) */

	free_icmp_stuffs(stuffs);
	/*free(cwnd_buf);*/
	if (err_fl == true)
		return ERROR;
	else
		return SUCCESS;
}

RC_t get_first_packet(int net_fd, IcmpStuff_t * stuffs)
{
	socklen_t sock_len = sizeof(struct sockaddr);
	uint32_t i, pkt_size = sizeof(struct pkt) - PKT_STUFF_SIZE;
	ssize_t nr;
	uint16_t cksum;
	for (i = 0; i < ATTEMPT_CNT; i++) {
		if ((nr = recvfrom(net_fd, &stuffs->recv_pkt,
					sizeof(struct pkt) -
					PAYLOAD_SIZE, MSG_WAITALL,
					(struct sockaddr *)&stuffs->client_addr,
					&sock_len)) == -1) {
			perror("recvfrom firts packet");
			continue;
		}
		cksum = ntohs(stuffs->recv_pkt->hdr.checksum);
		stuffs->recv_pkt->hdr.checksum = 0;
		if (cksum != in_cksum((uint16_t *)&stuffs->recv_pkt,
				nr)) {
			PR_DEBUG("wrong checksum in incoming packet\n");
			continue;
		}
		PR_DEBUG("first packet size is %zu should be %zu\n",
				nr,
				(sizeof(struct pkt) - PAYLOAD_SIZE));
		if (stuffs->recv_pkt->first_packet != true) {
			PR_DEBUG("first packet is not \"first packet\"\n");
			continue;
		}
		stuffs->seq
			= ntohs(stuffs->recv_pkt->hdr.un.echo.sequence);
		stuffs->send_pkt->hdr.un.echo.sequence = htons(stuffs->seq);
		stuffs->send_pkt->first_packet = true;
		stuffs->send_pkt->len = 0;
		stuffs->send_pkt->hdr.checksum = 0;
		stuffs->send_pkt->hdr.checksum =
			htons(in_cksum((uint16_t *)&stuffs->send_pkt,
						sizeof(struct pkt)));
		if (send_icmp(net_fd, stuffs->send_pkt,
					stuffs->client_addr,
					&pkt_size) == ERROR) {
			fprintf(stderr, "cannot send answer to first packet\n");
			return ERROR;
		}
	}
	return SUCCESS;
}

RC_t send_first_packet(int net_fd, IcmpStuff_t * stuffs)
{
	struct timeval tv, optval;
	socklen_t sock_len = sizeof(struct sockaddr),
		  setsockopt_len = sizeof(optval);
	double integer;
	uint32_t i, pkt_size = sizeof(struct pkt) - PKT_STUFF_SIZE;
	ssize_t nr;
	uint16_t cksum, seq;
	tv.tv_usec = modf(stuffs->rto, &integer) * 1000000;
	tv.tv_sec = integer;
	if (getsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO, &optval,
				&setsockopt_len) == -1) {
		perror("getsockopt");
		return ERROR;
	}
	for (i = 0; i < ATTEMPT_CNT; i++) {
		seq = stuffs->seq;
		stuffs->send_pkt->hdr.un.echo.sequence = htons(stuffs->seq++);
		stuffs->send_pkt->len = 0;
		stuffs->send_pkt->first_packet = true;
		stuffs->send_pkt->hdr.checksum = 0;
		stuffs->send_pkt->hdr.checksum = htons(in_cksum((uint16_t *)
					&stuffs->send_pkt,
					(sizeof(struct pkt) - PAYLOAD_SIZE)));
		if (send_icmp(net_fd, stuffs->send_pkt, stuffs->client_addr,
					&pkt_size) == ERROR) {
			fprintf(stderr, "send first packet error\n");
			return ERROR;
		}
		if (setsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO,
					(const void *)&tv,
					sizeof(tv)) == -1) {
			perror("setsockopt");
			return ERROR;
		}
		if ((nr = recvfrom(net_fd, &stuffs->recv_pkt,
					sizeof(struct pkt) -
					PAYLOAD_SIZE, MSG_WAITALL,
					(struct sockaddr *)&stuffs->server_addr,
					&sock_len)) == -1) {
			perror("recvfrom firts packet");
			continue;
		}
		if (setsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO, &optval,
					setsockopt_len) == -1) {
			perror("setsockopt");
			return ERROR;
		}
		if (stuffs->server_addr->sin_addr.s_addr !=
				stuffs->client_addr->sin_addr.s_addr) {
			PR_DEBUG("packet was received from wrong address: %s\n",
					inet_ntoa(stuffs->
						server_addr->sin_addr));
			PR_DEBUG("valid address is: %s\n",
					inet_ntoa(stuffs->
						client_addr->sin_addr));
			continue;
		}
		cksum = ntohs(stuffs->recv_pkt->hdr.checksum);
		stuffs->recv_pkt->hdr.checksum = 0;
		if (cksum != in_cksum((uint16_t *)&stuffs->recv_pkt,
				nr)) {
			PR_DEBUG("wrong checksum in incoming packet\n");
			continue;
		}
		PR_DEBUG("first packet size is %zu should be %zu\n",
				nr,
				(sizeof(struct pkt) - PAYLOAD_SIZE));
		if (stuffs->recv_pkt->first_packet != true) {
			PR_DEBUG("first packet is not \"first packet\"\n");
			continue;
		}
		if (seq != ntohs(stuffs->recv_pkt->hdr.un.echo.sequence)) {
			PR_DEBUG("sequence %hu is not a valid sequence %hu\n",
					ntohs(stuffs->
						recv_pkt->hdr.un.echo.sequence),
					seq);
		}

	}
	return SUCCESS;
}

RC_t send_to_client(int net_fd, IcmpStuff_t * stuffs)
{
	struct sockaddr_in addr = *(stuffs->client_addr);
	struct pkt *pkt_p = stuffs->send_pkt;
	RingBuf_t *rb = stuffs->rb;
	RBData_t rbdata;
	uint8_t *buf = stuffs->buffer;
	/*bool need_icmp = stuffs->need_icmp;*/
	int buf_len = stuffs->nr;
	int i = (buf_len / PAYLOAD_SIZE), n, send_cnt;
	unsigned int tot = sizeof(struct pkt);
	uint16_t cwnd = stuffs->cwnd;
	uint32_t rem = (buf_len % PAYLOAD_SIZE);
	pkt_p->len = htons(PAYLOAD_SIZE);
	pkt_p->cwnd = htons(cwnd);
	for (n = 0, send_cnt = 0; n < i; n++) {
		if (rb_get(rb, &rbdata) != RB_SUCCESS) {
			PR_DEBUG("ring buffer error or empty\n");
			if (send_cnt == 0) {
				stuffs->nw = 0;
				return ERROR;
			} else {
				stuffs->nw = send_cnt;
				return SUCCESS;
			}
		}
		pkt_p->hdr.un.echo.sequence = rbdata.icmp_sequence;
		memcpy((void *)pkt_p->data,
				(const void *)(buf + send_cnt), PAYLOAD_SIZE);
		pkt_p->hdr.checksum = 0;
		pkt_p->hdr.checksum = htons(in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt)));

		if (send_icmp(net_fd, pkt_p, &addr, &tot) == ERROR) {
			if (send_cnt == 0) {
				stuffs->nw = 0;
				return ERROR;
			} else {
				stuffs->nw = send_cnt;
				return SUCCESS;
			}
		}
		send_cnt += tot - PKT_STUFF_SIZE;
	}
	if (rem != 0) {
		if (rb_get(rb, &rbdata) != RB_SUCCESS) {
			PR_DEBUG("ring buffer error or empty\n");
			if (send_cnt == 0) {
				stuffs->nw = 0;
				return ERROR;
			} else {
				stuffs->nw = send_cnt;
				return SUCCESS;
			}
		}
		pkt_p->hdr.un.echo.sequence = rbdata.icmp_sequence;
		pkt_p->len = htons(rem);
		pkt_p->hdr.checksum = 0;
		memcpy((void *)pkt_p->data,
				(const void *)(buf + send_cnt), rem);
		pkt_p->hdr.checksum = htons(in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt)
					- (PAYLOAD_SIZE - rem)));

		rem += PKT_STUFF_SIZE;
		if (send_icmp(net_fd, pkt_p, &addr, &rem) == ERROR) {
			if (send_cnt == 0) {
				stuffs->nw = 0;
				return ERROR;
			} else {
				stuffs->nw = send_cnt;
				return SUCCESS;
			}
		}
		send_cnt += (rem - PKT_STUFF_SIZE);
	}
	stuffs->nw = send_cnt;
	return SUCCESS;
}

RC_t recieve_from_client(int net_fd, int tun_fd, IcmpStuff_t * stuffs)
{
	uint16_t cksum, pkt_id = stuffs->pkt_id;
	int nw, nr, tot, i, cwnd = stuffs->cwnd;
	socklen_t addr_len = sizeof(struct sockaddr);
	struct sockaddr_in *client_addr = stuffs->client_addr, addr;
	struct pkt *pkt_p = stuffs->recv_pkt;
	RBData_t rbdata;
	RingBuf_t *rb = stuffs->rb;
	for (i = 0, tot = 0; i < cwnd; i++) {
		nr = recvfrom(net_fd, pkt_p, sizeof(struct pkt), 0,
				(struct sockaddr *)&addr, &addr_len);
		if (nr == -1) {
			perror("recvfrom");
			continue;
		}
		if (addr.sin_addr.s_addr != client_addr->sin_addr.s_addr) {
			PR_DEBUG("packet was received from wrong address: %s\n",
					inet_ntoa(addr.sin_addr));
			PR_DEBUG("valid address is: %s\n",
					inet_ntoa(client_addr->sin_addr));
			continue;
		}
		cksum = ntohs(pkt_p->hdr.checksum);
		pkt_p->hdr.checksum = 0;
		if (cksum != in_cksum((uint16_t *)pkt_p, nr)) {
			PR_DEBUG("wrong checksum in incoming packet\n");
			continue;
		}
		if (ntohs(pkt_p->hdr.un.echo.id) != pkt_id) {
			PR_DEBUG("wrong packet id: %hu, correct id: %hu\n",
					ntohs(pkt_p->hdr.un.echo.id), pkt_id);
			continue;
		}
		rbdata.icmp_sequence = pkt_p->hdr.un.echo.sequence;
		rb_put(rb, rbdata);
		if (write_all(tun_fd, pkt_p->data, nr - PKT_STUFF_SIZE,
					&nw) == ERROR) {
			PR_DEBUG("error writing to tun\n");
			;
		}
		tot += (nr - PKT_STUFF_SIZE);
	}
	return SUCCESS;
}
	
RC_t recieve_from_server(int net_fd, IcmpStuff_t * stuffs)
{
	/* I need to check the old sequence number and the last received,
	 * if the numbers match, then there is nothing more to read
	 */
	socklen_t addr_len = sizeof(struct sockaddr);
	uint16_t old_seq = stuffs->old_seq;
	uint16_t pkt_id = stuffs->pkt_id, cksum;
	bool need_icmp;
	int nr, tot, i, cwnd = (int)stuffs->cwnd;
	uint8_t *buf_p = stuffs->buffer;
	struct pkt *pkt_p = calloc(1, sizeof(struct pkt));
	struct sockaddr_in * s_addr = stuffs->server_addr, curr_addr;
	if (pkt_p == NULL)
		return ERROR;
	for (nr = 0, tot = 0, i = 0; i < cwnd; i++) {
		nr = recvfrom(net_fd, pkt_p, sizeof(struct pkt), 0,
				(struct sockaddr *)&curr_addr, &addr_len);
		if (nr == -1) {
			if (tot > 0) {
				stuffs->nr = tot;
				return SUCCESS;
			} else {
				return ERROR;
			}
		}
		if (curr_addr.sin_addr.s_addr != s_addr->sin_addr.s_addr) {
			PR_DEBUG("packet was received from wrong address: %s\n",
					inet_ntoa(curr_addr.sin_addr));
			PR_DEBUG("valid address is: %s\n",
					inet_ntoa(s_addr->sin_addr));
			continue;
		}
		cksum = ntohs(pkt_p->hdr.checksum);
		pkt_p->hdr.checksum = 0;
		if (cksum != in_cksum((uint16_t *)pkt_p, nr)) {
			PR_DEBUG("wrong checksum in incoming packet\n");
			continue;
		}
		if (pkt_p->need_icmp_fl == true) {
			need_icmp = true;
		} else {
			need_icmp = false;
		}
		if (ntohs(pkt_p->hdr.un.echo.id) != pkt_id) {
			PR_DEBUG("wrong packet id: %hu, correct id: %hu\n",
					ntohs(pkt_p->hdr.un.echo.id), pkt_id);
			continue;
		}
		if (ntohs(pkt_p->hdr.un.echo.sequence) != old_seq++) {
			PR_DEBUG("old sequence: %hu != incoming seq: %hu\n",
					old_seq - 1,
					ntohs(pkt_p->hdr.un.echo.sequence));
			PR_DEBUG("may be a paqcket loss\n");
			;
		}
		memcpy(buf_p + tot, pkt_p->data, nr - PKT_STUFF_SIZE);
		tot += (nr - PKT_STUFF_SIZE);
	}
	stuffs->need_icmp = need_icmp;
	stuffs->nr = tot;
	return SUCCESS;
}

RC_t send_to_server(int net_fd, IcmpStuff_t * stuffs)
{
	/* i is the number of integral "PAYLOAD_SIZE" units */
	int buf_len = stuffs->nr;
	uint32_t i = (buf_len / PAYLOAD_SIZE), tot = sizeof(struct pkt), n;
	int send_cnt;
	uint32_t rem = buf_len % PAYLOAD_SIZE;
	uint16_t seq = stuffs->seq;
	uint8_t *buf = stuffs->buffer;
	struct pkt *pkt_p = stuffs->send_pkt;
	struct sockaddr_in *addr = stuffs->server_addr;
	pkt_p->len = htons(PAYLOAD_SIZE);
	pkt_p->cwnd = htons(stuffs->cwnd);
	PR_DEBUG("remainder is %d\n", rem);
	PR_DEBUG("count of PAYLOAD_SIZE units is %d\n", i);
	for (n = 0, send_cnt = 0; n < i; n++) {
		pkt_p->hdr.un.echo.sequence = htons(seq++);
		memcpy((void *)pkt_p->data,
				(const void *)(buf + send_cnt), PAYLOAD_SIZE);
		pkt_p->hdr.checksum = 0;
		pkt_p->hdr.checksum = htons(in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt)));

		if (send_icmp(net_fd, pkt_p, addr, &tot) == ERROR)
			return ERROR;
		send_cnt += (tot - PKT_STUFF_SIZE);
	}
	if (rem != 0) {
		pkt_p->hdr.un.echo.sequence = htons(seq++);
		pkt_p->len = htons(rem);
		pkt_p->hdr.checksum = 0;
		memcpy((void *)pkt_p->data, (const void *)(buf + send_cnt),
				rem);
		pkt_p->hdr.checksum = htons(in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt)
					- (PAYLOAD_SIZE - rem)));

		rem += PKT_STUFF_SIZE;
		if (send_icmp(net_fd, pkt_p, addr, &rem) == ERROR) {
			return ERROR;
		}
		send_cnt += (rem - PKT_STUFF_SIZE);
	}
	stuffs->seq = seq;
	stuffs->nw = send_cnt;
	return SUCCESS;
}

RC_t send_icmp(int net_fd, struct pkt * send_pkt, struct sockaddr_in * addr,
		uint32_t * pkt_size)
	/* pkt_size is payload size (include icmphdr and PKT_STUFF_SIZE) */
{
	int send_cnt, attempt;
	for (attempt = ATTEMPT_CNT;;) {
		if ((send_cnt = sendto(net_fd, send_pkt, *pkt_size,
						0, (struct sockaddr *)addr,
						sizeof(struct sockaddr_in)))
				== -1) {
			if (--attempt >= 0) {
				continue;
			} else {
				return ERROR;
			}
		}
		*pkt_size = send_cnt;
		return SUCCESS;
	}
}

uint16_t in_cksum(uint16_t * addr, size_t len)
{
	int nleft = len;
	int sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&answer) += *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

void free_icmp_stuffs(IcmpStuff_t * stuffs)
{
	if (stuffs) {
		if (stuffs->buffer)
			free(stuffs->buffer);
		if (stuffs->rb)
			rb_del(stuffs->rb);
		if (stuffs->buffer)
			free(stuffs->buffer);
		if (stuffs->client_addr)
			free(stuffs->client_addr);
		if (stuffs->server_addr)
			free(stuffs->server_addr);
		if (stuffs->send_pkt)
			free(stuffs->send_pkt);
		if (stuffs->recv_pkt)
			free(stuffs->recv_pkt);
		free(stuffs);
	}
}
