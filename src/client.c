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

#include "send_file.h"

static int local_sockfd;
static int running = 0;
static int32_t checksum_flag = 1;

static int progress_bar_flag = 1;
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
	if (fd < 0) { fprintf(stderr, "send_handshake: opening file failed: %s\n", strerror(errno)); return -1; }

	struct stat st;
	fstat(fd, &st);

	HEADERINFO h;
	h.protocol_id = protocol_id;
	h.filesize = st.st_size;
	h.sha1_included = checksum_flag;

	if (!checksum_flag) {
		printf("(skipping checksum calculation)\n");
	}
	else {
		//unsigned char* block = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		//if (block == MAP_FAILED) { fprintf(stderr, "mmap() failed %s\n", strerror(errno)); return -1; }
		printf("Calculating sha1 sum of input file...\n");
		unsigned char *sha1 = get_sha1(filename, h.filesize);
		memcpy(h.sha1, sha1, SHA_DIGEST_LENGTH);
//		munmap(block, h.filesize);

		printf("Done! (got ");
		print_sha1(sha1);
		printf(").\n\n");

		free(sha1);
	}

	h.filename = basename(filename);
	int filename_base_len = strlen(h.filename);

	printf("Input file \"%s\":\n basename: %s,\n filesize: %" PRId64"\n", filename, h.filename, h.filesize);

	char handshake_buffer[128];
	
	int64_t accum = 0;
	ACCUM_WRITE(h.protocol_id, handshake_buffer);
	ACCUM_WRITE(h.filesize, handshake_buffer);
	ACCUM_WRITE(h.sha1_included, handshake_buffer);
	ACCUM_WRITE_ARRAY(h.filename, handshake_buffer, filename_base_len+1); // to include the \0 char
	if (h.sha1_included) {
		ACCUM_WRITE_ARRAY(h.sha1, handshake_buffer, SHA_DIGEST_LENGTH);
	}

	int64_t sent_bytes;	
	sent_bytes = send(local_sockfd, handshake_buffer, accum, 0);

	if (sent_bytes < 0) {
		fprintf(stderr, "sending handshake failed, %s\n", strerror(errno));
		return -1;
	}

	int received_bytes;

	UNBUFFERED_PRINTF("\nWaiting for remote consent...");
	received_bytes = recv(local_sockfd, handshake_buffer, 8, 0); 
	if (received_bytes <= 0) { fprintf(stderr, "recv: blessing length <= 0 (%s)\n", strerror(errno)); return -1; }

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
	

#define JOIN_PROGRESS_THREAD_RETURN(retval) do {\
       	running = 0;\
	if (progress_bar_flag == 1) pthread_join(progress_thread, NULL);\
       	return (retval); } while(0)

	// else we're free to start blasting ze file data

	printf("Starting sendfile().\n");
	int64_t total_bytes_sent = 0;

	struct _timer timer = timer_construct();
	
	if (progress_bar_flag == 1) {
		p = construct_pstruct(&total_bytes_sent, h.filesize, &timer, &running);
		pthread_create(&progress_thread, NULL, progress_callback, (void*)&p);
	}

	while (total_bytes_sent < h.filesize && running == 1) {
		int64_t would_send = h.filesize-total_bytes_sent;
		int64_t gonna_send = MIN(would_send, CHUNK_SIZE);
		// sendfile should automatically increment the file offset pointer for fd
		if ((sent_bytes = sendfile(local_sockfd, fd, NULL, gonna_send)) < gonna_send) {
			if (sent_bytes < 0) {
				fprintf(stderr, "\nsendfile() failed: %s\n", strerror(errno)); 
			}
			else {
				fprintf(stderr, "\nwarning: sent_bytes < gonna_send! (transfer cancelled by remote?)");
			}
			JOIN_PROGRESS_THREAD_RETURN(-1);
		}
		total_bytes_sent += gonna_send;
	}

	if (progress_bar_flag == 1) {
		pthread_join(progress_thread, NULL);
	}

	printf("\nFile transfer successful.\n");

	double seconds = timer.get_us(&timer)/1000000.0;
	double MBs = get_megabytes(total_bytes_sent)/seconds;
	double percent = 100.0*(double)total_bytes_sent/(double)h.filesize;

	fprintf(stderr, "\nSent %.2f MB of %.2f MB (%.2f%%) in %.3f seconds (%.2f MB/s).\n\n", 
	get_megabytes(total_bytes_sent), 
	get_megabytes(h.filesize),
	percent, seconds, MBs);

	return 0;

}

void usage() {
	printf("\nsend_file_client: usage: send_file_client [[ options ]] <IPv4 addr> <filename>."\
	       "\n Options:\n"\
	       " -b:\t\tdisable progress monitoring (default: on)\n"\
	       " -c:\t\tskip checksum (sha1) verification (requires server-side support)\n"\
	       " -p PORT\tspecify remote port\n"\
	       " -h\t\tdisplay this help and exit.\n\n");
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

	int c;
	char *strtol_endptr;
	while ((c = getopt(argc, argv, "bchp:")) != -1) {
		switch(c) {
			case 'b':
				printf("-b provided -> progress monitoring disabled.\n");
				progress_bar_flag = 0;
				break;

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
				if (optopt != 'p') {
					fprintf(stderr, "warning: unknown option \'-%c\'\n", optopt);
				}
				break;

			default:
				abort();
		}
	}
	
	// send_file RECIPIENT_IP FILENAME

	int rval = 1;

	int num_nonoption_args = argc - optind;

	if (num_nonoption_args > 2) {
		fprintf(stderr, "send_file client: multiple filenames specified as argument. Sending only one file is supported.\n");
		usage();
		return 1;
	} else if (num_nonoption_args < 2) {
		fprintf(stderr, "send_file_client: error: missing either recipient ip or input file.\n");
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

	/*int sndbuf_size = 64*1024 - 1;
	if (setsockopt(local_sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size)) < 0) {
		fprintf(stderr, "Warning: setsockopt SO_SNDBUF->%d failed: %s\n", sndbuf_size, strerror(errno));
	}*/

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
