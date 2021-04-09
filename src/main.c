#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include <getopt.h>

#include <limits.h>

#include <arpa/inet.h>

#include <string.h>

#include <errno.h>

#include <main.h>

RC_t parsing_cmd(int argc, char **argv, CMD_t ** args);
RC_t get_ipaddr(char *ip_str, struct in_addr *ip_addr);
void free_stuff(CMD_t ** args, NetFD_t ** fds);
void usage(FILE * stream);

#ifdef DEBUG
int EF_ALIGNMENT = 0;
int EF_PROTECT_FREE = 1;
#endif

int main(int argc, char **argv)
{
	CMD_t *args = NULL;
	NetFD_t *fds = NULL;

	PR_DEBUG(PROGRAM_NAME);
	PR_DEBUG("\n");
	PR_DEBUG("start...\n");
	PR_DEBUG("parsing command line...\n");

	RC_t ret = parsing_cmd(argc, argv, &args);
	if (ret < SUCCESS)
		exit(EXIT_FAILURE);
	else if (ret == HELP_RET)
		exit(EXIT_SUCCESS);

	PR_DEBUG("take_tun_fd...\n");

	if (get_tun_fd(&fds, args) < SUCCESS) {
		free_stuff(&args, NULL);
		exit(EXIT_FAILURE);
	}

	PR_DEBUG("establish_connect...\n");

	if (establish_connect(fds) < SUCCESS) {
		free_stuff(&args, &fds);
		exit(EXIT_FAILURE);
	}

	PR_DEBUG("do_communication...\n");
	PR_DEBUG
	    ("Now you can setup ip address for tun"
	     "interface and tune routing tables\n");

	if (do_communication(fds, args) < SUCCESS) {
		free_stuff(&args, &fds);
		exit(EXIT_FAILURE);
	}

	close(fds->tun_fd);
	free_stuff(&args, &fds);
	fprintf(stderr, "good luck\n");
	exit(EXIT_SUCCESS);
}

RC_t parsing_cmd(int argc, char **argv, CMD_t ** args)
{
	bool client_fl = false, server_fl = false, tun_name_fl = false;
	bool session_id_fl = false;
	int c;
	unsigned int session_id;
	CMD_t *tmp_args = NULL;
	static struct option long_opts[] = {
		{"server", optional_argument, NULL, 's'},
		{"client", required_argument, NULL, 'c'},
		{"tun-name", required_argument, NULL, 'n'},
		{"help", no_argument, NULL, 'h'},
		{"session-id", required_argument, NULL, 'i'},
		{NULL, 0, NULL, 0}
	};
	tmp_args = calloc(1, sizeof(CMD_t));
	if (tmp_args == NULL) {
		perror("calloc tmp_args");
		return ERROR;
	}
	while ((c = getopt_long(argc, argv, "s::c:n:i::h", long_opts, NULL))
	       != -1) {
		switch (c) {
		case 'h':
			usage(stdout), free_stuff(&tmp_args, NULL);
			return HELP_RET;
			break;
		case 'c':
			if (server_fl == true) {
				fprintf(stderr,
					"can't both options \"server\""
					" and \"client\"\n");
				usage(stderr), free_stuff(&tmp_args, NULL);
				return PARSING_ERR;
			}
			if (get_ipaddr(optarg, &tmp_args->ip_addr.remote_ip) ==
			    ERROR) {
				fprintf(stderr,
					"bad ip address or hostname \"%s\"\n",
					optarg);
				usage(stderr), free_stuff(&tmp_args, NULL);
				return PARSING_ERR;
			}
			tmp_args->role = CLIENT;
			client_fl = true;
			break;
		case 's':
			if (client_fl == true) {
				fprintf(stderr,
					"can't both options \"server\""
					" and \"client\"\n");
				usage(stderr), free_stuff(&tmp_args, NULL);
				return PARSING_ERR;
			}
			if (optarg != NULL) {
				if (get_ipaddr
				    (optarg,
				     &tmp_args->ip_addr.local_ip) == ERROR) {
					fprintf(stderr,
						"bad ip address or"
						" hostname \"%s\"\n",
						optarg);
					usage(stderr), free_stuff(&tmp_args,
								  NULL);
					return PARSING_ERR;
				}
			} else {
				/*set local_ip as 0x0, INADDR_ANY define
				 * as 0x00000000
				 */
				memset(&tmp_args->ip_addr.local_ip, 0,
				       sizeof(struct in_addr));
			}
			tmp_args->role = SERVER;
			server_fl = true;
			break;
		case 'n':
			if (strlen(optarg) > IFNAMSIZ) {
				fprintf(stderr, "dev name too large\n");
				usage(stderr), free_stuff(&tmp_args, NULL);
				return PARSING_ERR;
			}
			strcpy(tmp_args->tun_name, optarg);
			tun_name_fl = true;
			break;
		case 'i':
			if (sscanf(optarg, "%u", &session_id)
					== 0) {
				perror("sscanf");
				usage(stderr), free_stuff(&tmp_args, NULL);
				return PARSING_ERR;
			}
			if (session_id > USHRT_MAX) {
				fprintf(stderr, "session_id cannot greater "
						"than %d\n", USHRT_MAX);
				usage(stderr), free_stuff(&tmp_args, NULL);
				return PARSING_ERR;
			}
			tmp_args->session_id = (uint16_t)session_id;
			session_id_fl = true;
			break;
		case '?':
			fprintf(stderr, "bad option\n");
			usage(stderr), free_stuff(&tmp_args, NULL);
			return PARSING_ERR;
			break;
		case ':':
			fprintf(stderr, "missing argument\n");
			usage(stderr), free_stuff(&tmp_args, NULL);
			return PARSING_ERR;
		default:
			fprintf(stderr, "getopt bad code \"0X%x\"\n", c);
			usage(stderr), free_stuff(&tmp_args, NULL);
			return PARSING_ERR;
			break;
		}
	}

	if (server_fl == false && client_fl == false) {
		fprintf(stderr,
			"there should be one"
			" option \"client\" or \"server\"\n");
		usage(stderr), free_stuff(&tmp_args, NULL);
		return PARSING_ERR;
	}
	if (tun_name_fl == false) {
		strcpy(tmp_args->tun_name, DEFAULT_TUN_NAME);
	}
	if (session_id_fl == false) {
		fprintf(stderr, "session_id should be set\n");
		usage(stderr), free_stuff(&tmp_args, NULL);
		return PARSING_ERR;
	}
#ifdef DEBUG
	if (tmp_args->role == SERVER) {
		PR_DEBUG("role is \"server\"\n");
		PR_DEBUG("listen ip address: %s\n",
			 inet_ntoa(tmp_args->ip_addr.local_ip));
	} else {
		PR_DEBUG("role is \"client\"\n");
		PR_DEBUG("connect to ip address: \"%s\"\n",
			 inet_ntoa(tmp_args->ip_addr.remote_ip));
	}
	PR_DEBUG("tun name is: %s\n", tmp_args->tun_name);
	PR_DEBUG("session_id was set by %u\n", tmp_args->session_id);
#endif
	*args = tmp_args;
	return SUCCESS;
}

RC_t get_ipaddr(char *ip_str, struct in_addr *ip_addr)
{
	struct addrinfo hints, *result;
	int err;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(ip_str, NULL, &hints, &result)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		return ERROR;
	}
	*ip_addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
	freeaddrinfo(result);
	return SUCCESS;
}

void free_stuff(CMD_t ** args, NetFD_t ** fds)
{
	if (args) {
		if (*args) {
			free(*args);
			*args = NULL;
		}
	}
	if (fds) {
		if (*fds) {
			free(*fds);
			*fds = NULL;
		}
	}
}

void usage(FILE * stream)
{
	fprintf(stream, PROGRAM_NAME
		": --server | --client=ip_addr --session-id=icmp_id"
		"(icmp_id must be the same on both server and client)"
		"[--tun-name=\"tun-name\"] [--help]\n");
}
