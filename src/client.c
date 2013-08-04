#include <sys/sendfile.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <libgen.h>
#include <sys/param.h>
#include <pthread.h>

#define __USE_GNU
#include <fcntl.h>

#include "send_file.h"

static int local_sockfd;
static int running = 0;
static int checksum_flag = 1;

pthread_t progress_thread;
static progress_struct p;

#define ACCUM_WRITE(var, buffer) do {\
	memcpy((buffer)+accum, &(var), sizeof(var));\
	accum += sizeof(var);\
} while (0)

#define ACCUM_WRITE_SIZE(var, buffer, size) do {\
	memcpy((buffer)+accum, &(var), (size));\
	accum += size;\
} while (0)

#define ACCUM_WRITE_ARRAY(arr_ptr, buffer, num_elements) do {\
	memcpy((buffer)+accum, (arr_ptr), num_elements*sizeof(*(arr_ptr)));\
	accum += num_elements*sizeof(*(arr_ptr));\
} while(0)


static int send_file(char* filename) {

	int fd = open(filename, O_RDONLY);
	if (fd < 0) { fprintf(stderr, "send_handshake: opening file failed.\n"); return -1; }

	struct stat st;
	fstat(fd, &st);

	unsigned long filesize = st.st_size;
	unsigned char *sha1 = NULL;

	
	if (!checksum_flag) {
		printf("(skipping checksum calculation)\n");
	}
	else {
		unsigned char* block = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (block == MAP_FAILED) { fprintf(stderr, "mmap() failed.\n"); return -1; }
		printf("Calculating sha1 sum of input file...\n");
		sha1 = get_sha1(block, filesize);
		munmap(block, filesize);

		printf("Done! (got ");
		print_sha1(sha1);
		printf(").\n\n");
	}

	char *filename_base = basename(filename);
	int filename_base_len = strlen(filename_base);

	printf("Input file \"%s\":\n basename: %s,\n filesize: %lu\n", filename, filename_base, filesize);

	char handshake_buffer[128];
	
	int accum = 0;
	ACCUM_WRITE(protocol_id, handshake_buffer);
	ACCUM_WRITE(filesize, handshake_buffer);
	ACCUM_WRITE(checksum_flag, handshake_buffer);
	ACCUM_WRITE_ARRAY(filename_base, handshake_buffer, filename_base_len+1); // to include the \0 char
	if (checksum_flag) {
		ACCUM_WRITE_ARRAY(sha1, handshake_buffer, SHA_DIGEST_LENGTH);
	}

	ssize_t sent_bytes;	
	sent_bytes = send(local_sockfd, handshake_buffer, accum, 0);

	if (sent_bytes < 0) {
		fprintf(stderr, "sending handshake failed\n");
	}

	int received_bytes;

	UNBUFFERED_PRINTF("\nWaiting for remote consent...");
	received_bytes = recv(local_sockfd, handshake_buffer, 8, 0); 
	if (received_bytes <= 0) { fprintf(stderr, "recv: blessing length <= 0\n"); return -1; }

	int prid;
	memcpy(&prid, handshake_buffer, sizeof(protocol_id));

	int handshake_status;
	memcpy(&handshake_status, handshake_buffer + sizeof(protocol_id), sizeof(handshake_status));

	if (prid != protocol_id) { 
		fprintf(stderr, "protocol id mismatch!\n"); 
		return -1; 
	}
	switch (handshake_status) {
		case HANDSHAKE_OK:
			printf("handshake ok.\n");
			break;
		case HANDSHAKE_FAIL:
			fprintf(stderr, "received HANDSHAKE_FAIL (%x) from remote. exiting.\n", handshake_status); 
			return -1;
			break;
		case HANDSHAKE_DENIED:
			fprintf(stderr, "received HANDSHAKE_DENIED (%x) from remote.\n", handshake_status);
			return -1;
			break;
		case HANDSHAKE_CHECKSUM_REQUIRED:
			fprintf(stderr, "received HANDSHAKE_CHECKSUM_REQUIRED (%x) from remote (the -c option can't be used). Aborting.\n", handshake_status);
			return -1;
		default:
			break;
	}
	
	// else we're free to start blasting ze file data
	printf("Starting sendfile().\n");
	off_t total_bytes_sent = 0;

	struct timeval tv_beg;
	memset(&tv_beg, 0, sizeof(tv_beg));

	gettimeofday(&tv_beg, NULL);

	p = construct_pstruct(&total_bytes_sent, filesize, &tv_beg, &running);
	pthread_create(&progress_thread, NULL, progress_callback, (void*)&p);
	static const long chunk_size = 16384;

	while (total_bytes_sent < filesize && running == 1) {
		long would_send = filesize-total_bytes_sent;
		long gonna_send = MIN(would_send, chunk_size);
		if ((sent_bytes = sendfile(local_sockfd, fd, &total_bytes_sent, gonna_send)) < gonna_send) {
			if (sent_bytes < 0) {
				fprintf(stderr, "sendfile() failed: %s\n", strerror(errno)); 
			}
			else {
				fprintf(stderr, "sent_bytes < filesize (!), transfer cancelled by remote.\n");
			}
			return -1;
		}
	}

	pthread_join(progress_thread, NULL);
	print_progress(total_bytes_sent, filesize, &tv_beg);
	printf("\n transfer successful! XD\n");

	return 0;

	free(sha1);
}

void usage() {
	printf("send_file_client: usage: send_file_client [[ options ]] <IPv4 addr> <filename>.\n Options:\n -c:\t\tskip checksum (sha1) verification (requires server-side support)\n -p PORT\tspecify remote port\n -h\t\tdisplay this help and exit.\n\n");
}

void cleanup() {
	running = 0;
	close(local_sockfd);	
}

void signal_handler(int sig) {
	if (sig == SIGINT) {
		fprintf(stderr, "\nReceived SIGINT. Aborting.\n");
		cleanup();
		exit(1);
	}
}


int main(int argc, char* argv[]) {

	struct sigaction new_action, old_action;
	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		sigaction(SIGINT, &new_action, NULL);
	}

	if (argc < 3) {
		usage();
		return 1;
	}

	int c;
	char *strtol_endptr;
	while ((c = getopt(argc, argv, "chp:")) != -1) {
		switch(c) {
			case 'c':
				printf("-c provided -> Skipping checksum computation.\n");
				checksum_flag = 0;
				break;
			case 'h':
				usage();
				return 0;
			case 'p': 
				port = strtol(optarg, &strtol_endptr, 0);	// base-10 
				if (strtol_endptr == optarg || *strtol_endptr != '\0') {
					// endptr != '\0' indicates only a part of the string was used in the conversion
					fprintf(stderr, "Invalid port specification \"%s\", attempting to use default port %d instead.\n", optarg, DEFAULT_PORT);
					port = DEFAULT_PORT;
				}
				break;

			case '?':
				fprintf(stderr, "warning: unknown option \'-%c\n\'", optopt);
				break;
			default:
				abort();
		}
	}
	
	// send_file RECIPIENT_IP FILENAME

	int rval = 1;

	if (argc - optind > 2) {
		fprintf(stderr, "send_file client: multiple filenames specified as argument. Sending only one file is supported, so just \033[1mtar\033[m them up kk? ;)\n");
		usage();
		return 1;
	}

	char* remote_ipstr = strdup(argv[optind]);
	char* filename = strdup(argv[optind+1]);

	struct sockaddr_in local_saddr, remote_saddr;
	memset(&local_saddr, 0, sizeof(local_saddr));
	memset(&remote_saddr, 0, sizeof(local_saddr));

	local_saddr.sin_family = AF_INET;
	local_saddr.sin_addr.s_addr = INADDR_ANY;
	local_saddr.sin_port = htons(port);

	local_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (local_sockfd < 0) { 
		fprintf(stderr, "socket() failed\n"); 
		rval = 1; 
		goto cleanup_and_exit;
	}

	remote_saddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, remote_ipstr, &remote_saddr.sin_addr) <= 0) { 
		fprintf(stderr, "inet_pton failed. invalid ip_string? (\"%s\")\n", remote_ipstr);
		usage();
		rval = 1;
		goto cleanup_and_exit;
	}
	remote_saddr.sin_port = htons(port);

	socklen_t remote_saddr_len = sizeof(remote_saddr);

	if (connect(local_sockfd, (struct sockaddr*) &remote_saddr, remote_saddr_len) < 0) {
		fprintf(stderr, "connect failed: %s\n", strerror(errno));
		rval = 1;
		goto cleanup_and_exit;
	}

	running = 1;
	if (send_file(filename) < 0) {
		fprintf(stderr, "send_file failure.\n");
		rval = 1;
		goto cleanup_and_exit;
	}
	rval = 0;

cleanup_and_exit:
	free(remote_ipstr);
	free(filename);

	cleanup();


	return rval;

}
