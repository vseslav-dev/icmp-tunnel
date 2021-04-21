#include <string.h>

#include <arpa/inet.h>

#include <errno.h>
#include <sys/select.h>

#include <communication_routines.h>
#include <ring_buffer.h>
/*
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
		cksum = pkt_p->hdr.checksum;
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
}*/
/*
RC_t send_to_client(int net_fd, IcmpStuff_t * stuffs)
{
	struct sockaddr_in addr = *(stuffs->client_addr);
	struct pkt *pkt_p = stuffs->send_pkt;
	RingBuf_t *rb = stuffs->rb;
	RBData_t rbdata;
	uint8_t *buf = stuffs->buffer;
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
		pkt_p->hdr.checksum = in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt));

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
		pkt_p->hdr.checksum = in_cksum((uint16_t *)pkt_p,
					sizeof(struct pkt)
					- (PAYLOAD_SIZE - rem));

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
}*/

RC_t get_first_packet(int net_fd, IcmpStuff_t * stuffs)
{
	socklen_t sock_len = sizeof(struct sockaddr);
	uint32_t i, pkt_size = sizeof(struct pkt) - PKT_STUFF_SIZE,
		 iphdrlen, icmplen;
	ssize_t nr;
	uint16_t cksum;
	for (i = 0; i < ATTEMPT_CNT; i++) {
		PR_DEBUG("recvfrom starts\n");
		if ((nr = recvfrom(net_fd, stuffs->recv_pkt,
					IP_MAXPACKET, MSG_WAITALL,
					(struct sockaddr *)stuffs->client_addr,
					&sock_len)) == -1) {
			perror("recvfrom firts packet from client");
			continue;
		}
		PR_DEBUG("recvfrom finished\n");
		iphdrlen = ((struct iphdr *)stuffs->recv_pkt)->ihl *
			sizeof(int);
		icmplen = ntohs(((struct iphdr *)stuffs->recv_pkt)->tot_len) -
			iphdrlen;
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
		/* get check sum of icmp header */
		cksum = ((struct icmphdr *)stuffs->recv_pkt +
				iphdrlen)->checksum;
		((struct icmphdr *)stuffs->recv_pkt + iphdrlen)->checksum = 0;
		if (cksum != in_cksum((uint16_t *)stuffs->
						recv_pkt + iphdrlen,
						icmplen)) {
			fprintf(stderr, "check sum of icmp packet 0X%X, "
					"check sum is: 0X%X\n",
					in_cksum(((uint16_t *)stuffs->
							recv_pkt + iphdrlen),
						icmplen), cksum);
			continue;
		}
		PR_DEBUG("cksum is: 0X%X\n", cksum);
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
		stuffs->seq
			= ntohs(((struct pkt *)stuffs->recv_pkt + iphdrlen)->
					hdr.un.echo.sequence);
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
	}
	return SUCCESS;
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
	stuffs->send_pkt->hdr.type = ICMP_ECHOREPLY;
	stuffs->send_pkt->hdr.code = 0;
	stuffs->pkt_id = args->session_id;

	stuffs->client_addr->sin_family = AF_INET;
	stuffs->client_addr->sin_port = 0;
	stuffs->client_addr->sin_addr = args->ip_addr.local_ip;

	stuffs->rto = INITIAL_RTO;

	sel_to.tv_sec = 1;
	sel_to.tv_usec = 0;

	if (get_first_packet(net_fd, stuffs) == ERROR) {
		fprintf(stderr, "reading the first packet from client "
				"returned an error\n");
		free_icmp_stuffs(stuffs);
		return ERROR;
	}

	PR_DEBUG("handshake is happened\n");
	free_icmp_stuffs(stuffs);
	return SUCCESS;

	/*
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
			if (recieve_from_client(net_fd, tun_fd, stuffs)
					== ERROR) {
				if (stuffs->nr == 0) {
					err_fl = true;
					break;
				}
			}
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
			// idle, if no data 
			continue;
		}
	}			// for (;;)
	*/

	free_icmp_stuffs(stuffs);
	//free(cwnd_buf);
	if (err_fl == true)
		return ERROR;
	else
		return SUCCESS;

	return SUCCESS;
}
