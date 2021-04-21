#include <string.h>
#include <math.h>

#include <arpa/inet.h>

#include <errno.h>
#include <sys/select.h>

#include <communication_routines.h>
#include <ring_buffer.h>
/*
RC_t send_to_server(int net_fd, IcmpStuff_t * stuffs)
{
	// i is the number of integral "PAYLOAD_SIZE" units
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
		pkt_p->hdr.checksum = in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt));

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
		pkt_p->hdr.checksum = in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt)
					- (PAYLOAD_SIZE - rem));

		rem += PKT_STUFF_SIZE;
		if (send_icmp(net_fd, pkt_p, addr, &rem) == ERROR) {
			return ERROR;
		}
		send_cnt += (rem - PKT_STUFF_SIZE);
	}
	stuffs->seq = seq;
	stuffs->nw = send_cnt;
	return SUCCESS;
}*/
/*
RC_t recieve_from_server(int net_fd, IcmpStuff_t * stuffs)
{
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
		cksum = pkt_p->hdr.checksum;
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
*/
RC_t send_first_packet(int net_fd, IcmpStuff_t * stuffs)
{
	struct sockaddr_in addr;
	struct timeval tv, optval;
	socklen_t sock_len = sizeof(struct sockaddr),
		  setsockopt_len = sizeof(optval);
	double integer;
	uint32_t i, pkt_size = (sizeof(struct pkt) - PAYLOAD_SIZE),
		 iphdrlen, icmplen;
	ssize_t nr;
	uint16_t cksum, seq;
	PR_DEBUG("size of packet: %iu\n", pkt_size);
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
		stuffs->send_pkt->hdr.checksum = in_cksum((uint16_t *)
					stuffs->send_pkt, pkt_size);
		if (send_icmp(net_fd, stuffs->send_pkt, stuffs->server_addr,
					&pkt_size) == ERROR) {
			fprintf(stderr, "send first packet error\n");
			continue;
		}
		if (setsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO,
					(const void *)&tv,
					sizeof(tv)) == -1) {
			perror("setsockopt");
			return ERROR;
		}
		if ((nr = recvfrom(net_fd, stuffs->recv_pkt,
					IP_MAXPACKET, MSG_WAITALL,
					(struct sockaddr *)&addr,
					&sock_len)) == -1) {
			perror("recvfrom firts packet from server");
			continue;
		}
		if (setsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO, &optval,
					setsockopt_len) == -1) {
			perror("setsockopt");
			return ERROR;
		}
		if (stuffs->server_addr->sin_addr.s_addr !=
				addr.sin_addr.s_addr) {
			PR_DEBUG("packet was received from wrong address: %s\n",
					inet_ntoa(stuffs->
						server_addr->sin_addr));
			PR_DEBUG("valid address is: %s\n",
					inet_ntoa(addr.sin_addr));
			continue;
		}
		iphdrlen = ((struct iphdr *)stuffs->recv_pkt)->ihl *
			sizeof(int);
		icmplen = ntohs(((struct iphdr *)stuffs->recv_pkt)->tot_len) -
			iphdrlen;
		/* get check sum of ip header */
		cksum = ((struct iphdr *)stuffs->recv_pkt)->check;
		((struct iphdr *)stuffs->recv_pkt)->check = 0;
		if (cksum != in_cksum((uint16_t *)stuffs->recv_pkt,
				iphdrlen)) {
			fprintf(stderr, "wrong checksum in ip header 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum((uint16_t *)stuffs->recv_pkt,
					iphdrlen), cksum);
			continue;
		}
		/* get check sum of icmp header */
		cksum = ((struct icmphdr *)stuffs->recv_pkt +
				iphdrlen)->checksum;
		((struct icmphdr *)stuffs->recv_pkt + iphdrlen)->checksum = 0;
		if (cksum != in_cksum(((uint16_t *)stuffs->
						recv_pkt + iphdrlen),
						icmplen)) {
			fprintf(stderr, "check sum of icmp packet 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum(((uint16_t *)stuffs->
							recv_pkt + iphdrlen),
						icmplen), cksum);
			continue;
		}
		PR_DEBUG("first packet size is %zu should be %zu\n",
				nr,
				(sizeof(struct pkt) - PAYLOAD_SIZE +
				 sizeof(struct iphdr)));
		if (((struct pkt *)stuffs->recv_pkt + iphdrlen)->
				first_packet != true) {
			PR_DEBUG("first packet is not \"first packet\"\n");
			PR_DEBUG("\"first_packet\" field value is: 0X%X\n",
					((struct pkt *)stuffs->recv_pkt +
					 iphdrlen)->first_packet);
			continue;
		}
		if (seq != ntohs(((struct pkt *)stuffs->recv_pkt + iphdrlen)->
					hdr.un.echo.sequence)) {
			PR_DEBUG("sequence %hu is not a valid sequence %hu\n",
					ntohs(((struct pkt *)stuffs->
						recv_pkt + iphdrlen)->
						hdr.un.echo.sequence),
					seq);
		}

	}
	return SUCCESS;
}

RC_t do_client_communication(NetFD_t * fds, CMD_t * args)
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
	stuffs->client_addr = calloc(1, sizeof(struct sockaddr_in));
	if (stuffs->client_addr == NULL) {
		perror("calloc client_addr");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	stuffs->buffer = calloc(1, BUF_SIZE);
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
	stuffs->recv_pkt = malloc(IP_MAXPACKET);
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

	stuffs->pkt_id = args->session_id;
	stuffs->send_pkt->hdr.un.echo.id = htons(stuffs->pkt_id);
	PR_DEBUG("ICMP_ECHO is: %d\n", ICMP_ECHO);
	stuffs->send_pkt->hdr.type = ICMP_ECHO;
	stuffs->send_pkt->hdr.code = ICMP_ECHOREPLY;

	stuffs->server_addr->sin_family = AF_INET;
	stuffs->server_addr->sin_port = 0;
	stuffs->server_addr->sin_addr = args->ip_addr.remote_ip;

	PR_DEBUG("len of pkt: %zu, len of pkt - PAYLOAD_SIZE: %zu\n",
			sizeof(struct pkt),
			(sizeof(struct pkt) - PAYLOAD_SIZE));

	if (send_first_packet(net_fd, stuffs) == ERROR) {
		fprintf(stderr, "sending the first packet to client "
				"returned an error\n");

		free_icmp_stuffs(stuffs);
		return ERROR;
	}

	PR_DEBUG("handshake is happened\n");
	free_icmp_stuffs(stuffs);
	return SUCCESS;
/*
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
			if (read_all(tun_fd, &stuffs->buffer, BUF_SIZE,
						&stuffs->nr) == ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
			stuffs->old_seq = stuffs->seq;
			if (send_to_server(net_fd, stuffs) == ERROR) {
				if (stuffs->nw == 0) {
					err_fl = true;
					break;
				}
			}
		} else if (FD_ISSET(net_fd, &rfds) == true) {
			if (recieve_from_server(net_fd, stuffs) == ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
			if (write_all(tun_fd, stuffs->buffer, stuffs->nr,
						&stuffs->nw) == ERROR) {
				if (stuffs->nw == 0) {
					err_fl = true;
					break;
				}
			}
		} else {
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
				= in_cksum((uint16_t *)send_pkt,
							pkt_size);
			send_icmp(net_fd, send_pkt, stuffs->server_addr,
					&pkt_size);
		}
	}
*/
	free_icmp_stuffs(stuffs);
	if (err_fl == true)
		return ERROR;
	else
		return SUCCESS;
}

