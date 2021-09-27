#include <string.h>
#include <math.h>

#include <arpa/inet.h>

#include <errno.h>
#include <sys/select.h>

#include <communication_routines.h>
#include <ring_buffer.h>

RC_t receive_from_server(int net_fd, int tun_fd, IcmpStuff_t * stuffs)
{
	socklen_t addr_len = sizeof(struct sockaddr);
	uint16_t pkt_id = stuffs->pkt_id, cksum;
	uint16_t old_seq = stuffs->old_seq;
	int32_t nr, nw;
	uint32_t tot, i, cwnd = (int)stuffs->cwnd;
	uint32_t iphdrlen, icmplen;
	void *pkt_p = stuffs->recv_pkt;
	struct sockaddr_in *s_addr = stuffs->server_addr, addr;
	bool need_icmp;
	for (nr = 0, tot = 0, i = 0; i < cwnd; i++) {
		nr = recvfrom(net_fd, pkt_p, IP_MAXPACKET, 0,
				(struct sockaddr *)&addr, &addr_len);
		if (nr == -1) {
			perror("recvfrom()");
			if (tot > 0) {
				stuffs->nr = tot;
				return SUCCESS;
			} else {
				return ERROR;
			}
		}
		PR_DEBUG("read from net %i bytes\n", nr);
		if (addr.sin_addr.s_addr != s_addr->sin_addr.s_addr) {
			PR_DEBUG("packet was received from wrong address: %s\n",
					inet_ntoa(addr.sin_addr));
			PR_DEBUG("valid address is: %s\n",
					inet_ntoa(s_addr->sin_addr));
			continue;
		}
		//get iphdr len and icmp len
		iphdrlen = GET_IP_HDR_LEN(pkt_p);
		PR_DEBUG("size of iphdr: %u\n", iphdrlen);
		icmplen = GET_ICMP_LEN(pkt_p);
		PR_DEBUG("size of icmp: %u\n", icmplen);

		//get check sum of ip header
		cksum = GET_IP_CKSUM(pkt_p);
		SET_IPHDR_CKSUM_0(pkt_p);
		if (CHECK_IP_CKSUM(pkt_p, cksum)) {
			fprintf(stderr, "wrong checksum in ip header 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum((uint16_t *)pkt_p, iphdrlen),
					cksum);
			continue;
		}
		//get check sum of icmp header
		cksum = GET_ICMP_CKSUM(pkt_p);
		SET_ICMPHDR_CKSUM_0(pkt_p);
		if (!CHECK_ICMP_CKSUM(pkt_p, cksum)) {
			fprintf(stderr, "check sum of icmp packet 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum(((uint16_t *)
							((uint8_t *)pkt_p +
							 iphdrlen)), icmplen),
					cksum);
			continue;
		}
		//check hdr.un.echo.id
		if (!CHECK_ECHO_ID(pkt_p, pkt_id)) {
			fprintf(stderr, "hdr.un.echo.id has wrong id: %hu, "
					"walid id: %hu\n",
					ntohs(((struct pkt *)
					 ((uint8_t *)pkt_p + iphdrlen))->
						hdr.un.echo.id), pkt_id);
			continue;
		}
		//check pkt_p->session_id
		if (!CHECK_SESSION_ID(pkt_p, pkt_id)) {
			fprintf(stderr, "received packet has wrong session id: "
					"%hu, walid session id: %hu\n",
					ntohs(((struct pkt *)
					((uint8_t *)pkt_p + iphdrlen))->
						session_id), pkt_id);
			continue;
		}

		//check hdr.un.echo.sequence
		if (!CHECK_OLD_SEQ(pkt_p, old_seq)) {
			PR_DEBUG("sequence %hu is not a valid sequence %hu\n",
					ntohs(((struct pkt *)((uint8_t *)pkt_p +
								iphdrlen))->
						hdr.un.echo.sequence), old_seq);
		}
		++old_seq;

		//store need_icmp_fl flag
		need_icmp = GET_NEED_ICMP(pkt_p);;
		//write data to tun_fd
		PR_DEBUG("write_all()\n");
		if (write_all(tun_fd, ((struct pkt *)((uint8_t *)pkt_p +
							iphdrlen))->data, nr -
					(PKT_STUFF_SIZE + iphdrlen), &nw) ==
				ERROR) {
			fprintf(stderr, "write to tun_fd failed. byte count: "
					"%lu\n", nr - (PKT_STUFF_SIZE +
						iphdrlen));
			continue;
		}
		if (nr > (int32_t)(PKT_STUFF_SIZE + iphdrlen))
			tot += (nr - (PKT_STUFF_SIZE + iphdrlen));
	}
	stuffs->need_icmp = need_icmp;
	stuffs->nw = nw;
	stuffs->nr = tot;
	return SUCCESS;
}

RC_t send_to_server(int net_fd, IcmpStuff_t * stuffs)
{
	// i is the number of integral "PAYLOAD_SIZE" units
	int32_t buf_len = stuffs->nr; //number of bytes read from tun_fd
	uint32_t i = (buf_len / PAYLOAD_SIZE), tot = sizeof(struct pkt), n;
	uint32_t send_cnt, rem = buf_len % PAYLOAD_SIZE; //rem is remainder
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

		if (send_icmp(net_fd, pkt_p, addr, &tot) == ERROR) {
			if (send_cnt == 0) {
				stuffs->nw = 0;
				return ERROR;
			} else {
				stuffs->nw = send_cnt;
				return SUCCESS;
			}
		}
		if (tot > PKT_STUFF_SIZE)
			send_cnt += tot - PKT_STUFF_SIZE;
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
			if (send_cnt == 0) {
				stuffs->nw = 0;
				return ERROR;
			} else {
				stuffs->nw = send_cnt;
				return SUCCESS;
			}
		}
		if (rem > PKT_STUFF_SIZE)
			send_cnt += (rem - PKT_STUFF_SIZE);
	}
	stuffs->seq = seq;
	stuffs->nw = send_cnt;
	return SUCCESS;
}

RC_t send_first_packet(int net_fd, IcmpStuff_t * stuffs)
{
	bool complete = false;
	struct sockaddr_in addr;
	struct timeval tv, optval;
	socklen_t sock_len = sizeof(struct sockaddr),
		  setsockopt_len = sizeof(optval);
	double integer;
	uint32_t i, pkt_size = (sizeof(struct pkt) - PAYLOAD_SIZE),
		 iphdrlen, icmplen;
	ssize_t nr;
	uint16_t cksum, seq;
	tv.tv_usec = modf(stuffs->rto, &integer) * 1000000;
	tv.tv_sec = integer;
	if (getsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO, &optval,
				&setsockopt_len) == -1) {
		perror("getsockopt");
		return ERROR;
	}
	for (i = 0; i < ATTEMPT_CNT && !complete; i++) {
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
		PR_DEBUG("recvfrom success, size: %zu\n", nr);
		if (setsockopt(net_fd, SOL_SOCKET, SO_RCVTIMEO, &optval,
					setsockopt_len) == -1) {
			perror("setsockopt");
			return ERROR;
		}
		if (stuffs->server_addr->sin_addr.s_addr !=
				addr.sin_addr.s_addr) {
			PR_DEBUG("packet was received from wrong address: %s\n",
					inet_ntoa(addr.sin_addr));
			PR_DEBUG("valid address is: %s\n",
					inet_ntoa(stuffs->
						server_addr->sin_addr));
			continue;
		}
		iphdrlen = GET_IP_HDR_LEN(stuffs->recv_pkt);
		icmplen = GET_ICMP_LEN(stuffs->recv_pkt);
		/* get check sum of ip header */
		cksum = GET_IP_CKSUM(stuffs->recv_pkt);
		SET_IPHDR_CKSUM_0(stuffs->recv_pkt);
		if (!CHECK_IP_CKSUM(stuffs->recv_pkt, cksum)) {
			fprintf(stderr, "wrong checksum in ip header 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum((uint16_t *)stuffs->recv_pkt,
					iphdrlen), cksum);
			continue;
		}
		/* get check sum of icmp header */
		cksum = GET_ICMP_CKSUM(stuffs->recv_pkt);
		SET_ICMPHDR_CKSUM_0(stuffs->recv_pkt);
		if (CHECK_ICMP_CKSUM(stuffs->recv_pkt, cksum)) {
			fprintf(stderr, "check sum of icmp packet 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum(((uint16_t *)
							((uint8_t *)stuffs->
							recv_pkt + iphdrlen)),
						icmplen), cksum);
			continue;
		}
		PR_DEBUG("first packet size is %zu should be %zu\n",
				nr,
				(sizeof(struct pkt) - PAYLOAD_SIZE +
				 sizeof(struct iphdr)));
		if (!CHECK_FIRST_PACKET(stuffs->recv_pkt)) {
			PR_DEBUG("first packet is not \"first packet\"\n");
			PR_DEBUG("\"first_packet\" field value is: 0X%X\n",
					((struct pkt *)
					 ((uint8_t *)stuffs->recv_pkt +
					 iphdrlen))->first_packet);
			continue;
		}
		if (!CHECK_ECHO_ID(stuffs->recv_pkt, stuffs->pkt_id)) {
			fprintf(stderr, "hdr.un.echo.id has wrong id: %hu, "
					"walid id: %hu\n",
					ntohs(((struct pkt *)
					 ((uint8_t *)stuffs->recv_pkt +
					  iphdrlen))->hdr.un.echo.id),
					stuffs->pkt_id);
			continue;
		}

		if (!CHECK_SESSION_ID(stuffs->recv_pkt, stuffs->pkt_id)) {
			fprintf(stderr, "received packet has wrong session id: "
					"%hu, walid session id: %hu\n",
					ntohs(((struct pkt *)
					((uint8_t *)stuffs->recv_pkt +
					iphdrlen))->session_id),
					stuffs->pkt_id);
			continue;
		}
		if (!CHECK_OLD_SEQ(stuffs->recv_pkt, seq)) {
			PR_DEBUG("sequence %hu is not a valid sequence %hu\n",
					ntohs(((struct pkt *)
							((uint8_t *)stuffs->
						recv_pkt + iphdrlen))->
						hdr.un.echo.sequence),
					seq);
		}
		complete = true;
	}
	if (i < ATTEMPT_CNT)
		return SUCCESS;
	else
		return ERROR;
}

RC_t do_client_communication(NetFD_t * fds, CMD_t * args)
{
	int net_fd = fds->net_fd, tun_fd = fds->tun_fd, ret;
	int maxfd = net_fd > tun_fd ? net_fd : tun_fd;
	fd_set rfds;
	uint32_t pkt_size = PKT_STUFF_SIZE;
	bool err_fl = false;
	struct timeval sel_to; /* select() timeout */
	struct pkt *send_pkt_local;
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
	send_pkt_local = calloc(1, sizeof(struct pkt));
	stuffs->send_pkt = send_pkt_local;
	if (stuffs->send_pkt == NULL) {
		perror("calloc send_pkt");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
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

	stuffs->cwnd = INITIAL_CWND_SIZE;
	stuffs->rto = INITIAL_RTO;
	stuffs->pkt_id = args->session_id;
	stuffs->send_pkt->hdr.un.echo.id = htons(stuffs->pkt_id);
	stuffs->send_pkt->session_id = htons(stuffs->pkt_id);
	stuffs->send_pkt->hdr.type = ICMP_ECHO;
	stuffs->send_pkt->hdr.code = ICMP_ECHOREPLY;

	stuffs->server_addr->sin_family = AF_INET;
	stuffs->server_addr->sin_port = 0;
	stuffs->server_addr->sin_addr = args->ip_addr.remote_ip;

	if (send_first_packet(net_fd, stuffs) == ERROR) {
		fprintf(stderr, "sending the first packet to server "
				"returned an error\n");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}

	PR_DEBUG("handshake is happened\n");

	sel_to.tv_sec = 1;
	sel_to.tv_usec = 0;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(net_fd, &rfds);
		FD_SET(tun_fd, &rfds);
		//ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
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
			PR_DEBUG("read_all()\n");
			if (read_all(tun_fd, stuffs->buffer, BUF_SIZE,
						&stuffs->nr) == ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
			stuffs->old_seq = stuffs->seq;
			PR_DEBUG("send_to_server()\n");
			if (send_to_server(net_fd, stuffs) == ERROR) {
				if (stuffs->nw == 0) {
					err_fl = true;
					break;
				}
			}
		} else if (FD_ISSET(net_fd, &rfds) == true) {
			PR_DEBUG("receive_from_server()\n");
			if (receive_from_server(net_fd, tun_fd, stuffs) ==
					ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
		} else {
			sel_to.tv_sec = 1;
			sel_to.tv_usec = 0;
			PR_DEBUG("Idle, no data\n");
			send_pkt_local->hdr.un.echo.sequence =
				htons(stuffs->seq++);
			send_pkt_local->len = 0;
			send_pkt_local->cwnd = htons(stuffs->cwnd);
			send_pkt_local->hdr.checksum = 0;
			send_pkt_local->hdr.checksum
				= in_cksum((uint16_t *)send_pkt_local,
							pkt_size);
			send_icmp(net_fd, send_pkt_local, stuffs->server_addr,
					&pkt_size);
		}
	}
	free_icmp_stuffs(stuffs);
	if (err_fl == true)
		return ERROR;
	else
		return SUCCESS;
}
