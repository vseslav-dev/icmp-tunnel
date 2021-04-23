#include <string.h>

#include <arpa/inet.h>

#include <errno.h>
#include <sys/select.h>

#include <communication_routines.h>
#include <ring_buffer.h>

RC_t receive_from_client(int net_fd, int tun_fd, IcmpStuff_t * stuffs)
{
	socklen_t addr_len = sizeof(struct sockaddr);
	uint16_t cksum;
	int32_t nr, nw;
        uint32_t tot, i, cwnd = (int)stuffs->cwnd;
	uint32_t iphdrlen, icmplen;
	void *pkt_p = stuffs->recv_pkt;
	struct sockaddr_in *c_addr = stuffs->client_addr, addr;
	RBData_t rbdata;
	RingBuf_t *rb = stuffs->rb;
	for (nr = 0, tot = 0, i = 0; i < cwnd; i++) {
		nr = recvfrom(net_fd, pkt_p, IP_MAXPACKET, 0,
				(struct sockaddr *)&addr, &addr_len);
		if (nr == -1) {
			if (tot > 0) {
				stuffs->nr = tot;
				return SUCCESS;
			} else {
				return ERROR;
			}
		}
		if (addr.sin_addr.s_addr != c_addr->sin_addr.s_addr) {
			PR_DEBUG("packet was received from wrong address: %s\n",
					inet_ntoa(addr.sin_addr));
			PR_DEBUG("valid address is: %s\n",
					inet_ntoa(c_addr->sin_addr));
			continue;
		}
		//get iphdr len and icmp len
		iphdrlen = ((struct iphdr *)pkt_p)->ihl * sizeof(int);
		PR_DEBUG("size of iphdr: %u\n", iphdrlen);
		icmplen = ntohs(((struct iphdr *)pkt_p)->tot_len) - iphdrlen;
		PR_DEBUG("size of icmp: %u\n", icmplen);

		//get check sum of ip header
		cksum = ((struct iphdr *)pkt_p)->check;
		((struct iphdr *)pkt_p)->check = 0;
		if (cksum != in_cksum((uint16_t *)pkt_p, iphdrlen)) {
			fprintf(stderr, "wrong checksum in ip header 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum((uint16_t *)pkt_p, iphdrlen),
					cksum);
			continue;
		}

		//get check sum of icmp header
		cksum = ((struct icmphdr *)((uint8_t *)pkt_p + iphdrlen))->
			checksum;
		((struct icmphdr *)((uint8_t *)pkt_p + iphdrlen))->checksum = 0;
		if (cksum != in_cksum(((uint16_t *)((uint8_t *)pkt_p +
							iphdrlen)), icmplen)) {
			fprintf(stderr, "check sum of icmp packet 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum(((uint16_t *)
							((uint8_t *)pkt_p +
							 iphdrlen)), icmplen),
					cksum);
			continue;
		}

		//check pkt_p->session_id
		if (ntohs(((struct pkt *)((uint8_t *)pkt_p + iphdrlen))->
					session_id) != stuffs->pkt_id) {
			fprintf(stderr, "received packet has wrong session id: "
					"%hu, walid session id: %hu\n",
					ntohs(((struct pkt *)
					((uint8_t *)pkt_p + iphdrlen))->
						session_id), stuffs->pkt_id);
			continue;
		}

		//check hdr.un.echo.sequence
		rbdata.icmp_sequence = ((struct pkt *)((uint8_t *)pkt_p +
							iphdrlen))->
					hdr.un.echo.sequence;

		//check hdr.un.echo.id
		rbdata.id = ((struct pkt *)((uint8_t *)pkt_p + iphdrlen))->
				hdr.un.echo.id;

		rb_put(rb, rbdata);
		
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
	stuffs->nw = nw;
	stuffs->nr = tot;
	return SUCCESS;
}

RC_t send_to_client(int net_fd, IcmpStuff_t * stuffs)
{
	int32_t buf_len = stuffs->nr;
	uint32_t i = (buf_len / PAYLOAD_SIZE), tot = sizeof(struct pkt), n;
	uint32_t send_cnt, rem = buf_len % PAYLOAD_SIZE;
	uint8_t *buf = stuffs->buffer;
	RingBuf_t *rb = stuffs->rb;
	RBData_t rbdata;
	struct pkt *pkt_p = stuffs->send_pkt;
	struct sockaddr_in *addr = stuffs->client_addr;
	pkt_p->len = htons(PAYLOAD_SIZE);
	pkt_p->cwnd = htons(stuffs->cwnd);
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
		pkt_p->hdr.un.echo.id = rbdata.id;
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
		pkt_p->hdr.un.echo.id = rbdata.id;
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
	stuffs->nw = send_cnt;
	return SUCCESS;
}

RC_t get_first_packet(int net_fd, IcmpStuff_t * stuffs)
{
	bool complete = false;
	socklen_t sock_len = sizeof(struct sockaddr);
	uint32_t i, pkt_size = sizeof(struct pkt) - PAYLOAD_SIZE,
		 iphdrlen, icmplen;
	ssize_t nr;
	uint16_t cksum, changed_id;
	for (i = 0; i < ATTEMPT_CNT && !complete; i++) {
		PR_DEBUG("recvfrom starts\n");
		if ((nr = recvfrom(net_fd, stuffs->recv_pkt,
					IP_MAXPACKET, MSG_WAITALL,
					(struct sockaddr *)stuffs->client_addr,
					&sock_len)) == -1) {
			perror("recvfrom firts packet from client");
			continue;
		}
		PR_DEBUG("recvfrom finished\n");
		PR_DEBUG("client addr: %s\n", inet_ntoa(stuffs->client_addr->
					sin_addr));
		iphdrlen = ((struct iphdr *)stuffs->recv_pkt)->ihl *
			sizeof(int);
		PR_DEBUG("size of iphdr is %i\n", iphdrlen);
		icmplen = ntohs(((struct iphdr *)stuffs->recv_pkt)->tot_len) -
			iphdrlen;
		PR_DEBUG("size of icmp packet is %i\n", icmplen);
		// get check sum of ip header
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
		PR_DEBUG("ip check sum is: %hu, computed check sum is:%hu\n",
				cksum, in_cksum((uint16_t *)stuffs->recv_pkt,
					iphdrlen));
		/* get check sum of icmp header */
		cksum = ((struct icmphdr *)((uint8_t *)stuffs->recv_pkt +
				iphdrlen))->checksum;
		((struct icmphdr *)((uint8_t *)stuffs->recv_pkt +
		 iphdrlen))->checksum = 0;
		if (cksum != in_cksum(((uint16_t *)((uint8_t *)stuffs->
						recv_pkt + iphdrlen)),
						icmplen)) {
			fprintf(stderr, "check sum of icmp packet 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum(((uint16_t *)
							((uint8_t *)stuffs->
							recv_pkt + iphdrlen)),
						icmplen), cksum);
			continue;
		}
		PR_DEBUG("cksum is: 0X%X\n", cksum);
		PR_DEBUG("first packet size is %zu should be %zu\n",
				nr,
				(sizeof(struct pkt) - PAYLOAD_SIZE +
				 sizeof(struct iphdr)));
		if (((struct pkt *)((uint8_t *)stuffs->recv_pkt + iphdrlen))->
				first_packet != true) {
			PR_DEBUG("first packet is not \"first packet\"\n");
			PR_DEBUG("\"first_packet\" field value is: 0X%X\n",
					((struct pkt *)
					 ((uint8_t *)stuffs->recv_pkt +
					 iphdrlen))->first_packet);
			continue;
		}
		if (ntohs(((struct pkt *)((uint8_t *)stuffs->recv_pkt +
							iphdrlen))->
					session_id) != stuffs->pkt_id) {
			fprintf(stderr, "received packet has wrong session id: "
					"%hu, walid session id: %hu\n",
					ntohs(((struct pkt *)
							((uint8_t *)stuffs->
							 recv_pkt + iphdrlen))->
						session_id), stuffs->pkt_id);
			continue;
		}
		changed_id = ntohs(((struct pkt *)((uint8_t *)stuffs->recv_pkt +
						iphdrlen))->hdr.un.echo.id);
		PR_DEBUG("changed id: %hu\n", changed_id);

		stuffs->seq
			= ntohs(((struct pkt *)((uint8_t *)stuffs->recv_pkt +
						iphdrlen))->
					hdr.un.echo.sequence);
		PR_DEBUG("sequence is: %hu\n", stuffs->seq);
		PR_DEBUG("session-id is: %hu\n", stuffs->pkt_id);
		stuffs->send_pkt->hdr.un.echo.id = htons(changed_id);
		stuffs->send_pkt->hdr.un.echo.sequence = htons(stuffs->seq);
		stuffs->send_pkt->first_packet = true;
		stuffs->send_pkt->len = 0;
		stuffs->send_pkt->hdr.checksum = 0;
		stuffs->send_pkt->hdr.checksum =
			in_cksum((uint16_t *)stuffs->send_pkt,
						sizeof(struct pkt) -
						PAYLOAD_SIZE);
		if (send_icmp(net_fd, stuffs->send_pkt,
					stuffs->client_addr,
					&pkt_size) == ERROR) {
			fprintf(stderr, "cannot send answer to first packet\n");
			return ERROR;
		}
		complete = true;
	}
	if (i < ATTEMPT_CNT)
		return SUCCESS;
	else
		return ERROR;
}

RC_t do_server_communication(NetFD_t * fds, CMD_t * args)
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
	if ((stuffs->recv_pkt = malloc(IP_MAXPACKET)) == NULL) {
		perror("malloc recv_pkt");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}
	stuffs->rto = INITIAL_RTO;
	stuffs->pkt_id = args->session_id;
	stuffs->send_pkt->hdr.type = ICMP_ECHOREPLY;
	stuffs->send_pkt->hdr.code = 0;
	stuffs->send_pkt->session_id = htons(stuffs->pkt_id);

	stuffs->client_addr->sin_family = AF_INET;
	stuffs->client_addr->sin_port = 0;
	stuffs->client_addr->sin_addr = args->ip_addr.local_ip;

	if (get_first_packet(net_fd, stuffs) == ERROR) {
		fprintf(stderr, "reading the first packet from client "
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
			if (read_all(tun_fd, stuffs->buffer,
						BUF_SIZE, &stuffs->tun_nr)
					== ERROR) {
				err_fl = true;
				break;
			}
			stuffs->need_icmp = true;
			PR_DEBUG("send_to_client()\n");
			if (send_to_client(net_fd, stuffs) == ERROR) {
				if (stuffs->nw == 0) {
					err_fl = true;
					break;
				}
			}
			if (stuffs->tun_nr <= stuffs->nw) {
				stuffs->need_icmp = false;
				stuffs->send_pkt->need_icmp_fl = false;
			} else {
				stuffs->need_icmp = true;
				stuffs->send_pkt->need_icmp_fl = true;
			}
		} else if (FD_ISSET(net_fd, &rfds) == true) {
			PR_DEBUG("receive_from_client()\n");
			if (receive_from_client(net_fd, tun_fd, stuffs)
					== ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
		} else {
			PR_DEBUG("Idle, no data\n");
			// idle, if no data 
			continue;
		}
	}			// for (;;)

	free_icmp_stuffs(stuffs);
	//free(cwnd_buf);
	if (err_fl == true)
		return ERROR;
	else
		return SUCCESS;
}
