#include <sys/sendfile.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <stdio.h>
#include <time.h>
#include <sys/mman.h>
#include <pthread.h>

#include "send_file.h"

static int local_sockfd = -1;
static int remote_sockfd = -1;

static int allow_checksum_skip_flag = 0;
static int always_accept_flag = 0;

static int running = 0;

static int progress_bar_flag = 1;
static progress_struct p;
static pthread_t progress_thread;

static void cleanup() {
	running = 0;
	close(local_sockfd);
	if (remote_sockfd != -1) {
		close(remote_sockfd);
	}
	exit(1);
}

static int validate_protocol_welcome_header(const char* buf, size_t buf_size) {
	int id;
	memcpy(&id, buf, sizeof(id));

	if (id != protocol_id) { return -1; }
	return 0;
}

static char *get_available_filename(const char* orig_filename) {
	char name_buf[128];
	strcpy(name_buf, orig_filename);
	name_buf[strlen(orig_filename)] = '\0';
	int num = 1;
	while (access(name_buf, F_OK) != -1) {
		// file exists, rename using the (#) scheme
		int bytes = sprintf(name_buf, "%s(%d)", orig_filename, num);
		name_buf[bytes] = '\0';
		++num;
	}
	return strdup(name_buf);
}


static int get_headerinfo(const char* buf, size_t buf_size, HEADERINFO *h) {
	memset(h, 0, sizeof(HEADERINFO));
	long accum = 0;
	memcpy(&h->protocol_id, buf, sizeof(h->protocol_id));
	accum += sizeof(h->protocol_id);

	memcpy(&h->filesize, buf + accum, sizeof(h->filesize));
	accum += sizeof(h->filesize);

	memcpy(&h->sha1_included, buf+accum, sizeof(h->sha1_included));
	accum += sizeof(h->sha1_included);

	h->filename = strdup(buf + accum);
	if (!h->filename) { 
		fprintf(stderr, "Error: extracting file name from header info failed. Bad header?\n");
		return -1;
	}
	int name_len = strlen(h->filename);
	accum += name_len + 1;
	memcpy(&h->sha1[0], buf + accum, SHA_DIGEST_LENGTH);

	return 0;


}	

static int consolidate(int out_sockfd, int flag) {
	char hacknowledge_buffer[8];
	memcpy(hacknowledge_buffer, &protocol_id, sizeof(protocol_id));
	memcpy(hacknowledge_buffer+sizeof(protocol_id), &flag, sizeof(flag));	
	int sent_bytes = send(out_sockfd, hacknowledge_buffer, 8, 0);
	if (sent_bytes <= 0) { 
		fprintf(stderr, "consolidate failed (send()): %s\n", strerror(errno));
	}
	return 0;
}



static long recv_file(int sockfd, int *pipefd, int outfile_fd, ssize_t filesize) {
	struct timeval tv_beg;
	memset(&tv_beg, 0, sizeof(tv_beg));
	gettimeofday(&tv_beg, NULL);

	off_t total_bytes_processed = 0;	

	if (progress_bar_flag == 1) {
		p = construct_pstruct(&total_bytes_processed, filesize, &tv_beg, &running);
		pthread_create(&progress_thread, NULL, progress_callback, (void*)&p);
	}

	while (total_bytes_processed < filesize && running == 1) {
		static const int max_chunksize = 16384;
		static const int spl_flag = SPLICE_F_MORE | SPLICE_F_MOVE;

		long bytes_recv = 0;
		long bytes = 0;

		off_t would_process = filesize - total_bytes_processed;
	       	off_t gonna_process = MIN(would_process, max_chunksize);

		// splice to pipe write head
		if ((bytes = 
		splice(sockfd, NULL, pipefd[1], NULL, gonna_process, spl_flag)) <= 0) {
			fprintf(stderr, "\nsocket->pipe_write splice returned %ld: %s. (connection aborted by client?)\n", bytes_recv, strerror(errno));
			cleanup();
		}
		// splice from pipe read head to file fd
		bytes_recv += bytes;

		int bytes_in_pipe = bytes_recv;
		int bytes_written = 0;

		__off64_t k = total_bytes_processed;

		while (bytes_in_pipe > 0) {
			if ((bytes_written = 
			splice(pipefd[0], NULL, outfile_fd, &k, bytes_in_pipe, spl_flag)) <= 0) {
				fprintf(stderr, "\npipe_read->file_fd splice returned %d: %s\n", bytes_written, strerror(errno));
				cleanup();
			}

			bytes_in_pipe -= bytes_written;

		}
		total_bytes_processed = k;
	}
	if (total_bytes_processed != filesize) {
		fprintf(stderr, "warning: total_bytes_processed != filesize!\n");
	}
	
	if (progress_bar_flag == 1) {
		pthread_join(progress_thread, NULL);
	}


	double seconds = get_us(&tv_beg)/1000000.0;
	double MBs = get_megabytes(total_bytes_processed)/seconds;

	fprintf(stderr, "\nReceived %.2f MB in %.3f seconds (%.2f MB/s).\n\n", get_megabytes(total_bytes_processed), seconds, MBs);

	return total_bytes_processed;

}

static void make_lowercase(char *arr, int length) {
	int i = 0;
	for (; i < length; ++i) {
		arr[i] = tolower(arr[i]);
	}
}

static int ask_user_consent() {
	UNBUFFERED_PRINTF("Is this ok? [y/N] ");
	char buffer[128];
	buffer[127] = '\0';
	int index;
	char c;
get_answer:
	index = 0;
	while ((c = getchar()) != '\n') {
		buffer[index] = c;
		if (index < 127) {
			++index;
		}
	}
	
	buffer[index] = '\0';
	make_lowercase(buffer, index);

	if (strcmp(buffer, "y") == 0) {
		return 1;
	}
	else if (strcmp(buffer, "n") == 0) {
		return 0;
	}
	else { 
		UNBUFFERED_PRINTF("Unknown answer \"%s\". [y/N]?", buffer);
		goto get_answer; // ;)
	} 

}



void signal_handler(int sig) {
	if (sig == SIGINT) {
		fprintf(stderr, "\nReceived SIGINT. Aborting.\n");
		cleanup();

	}
}

void usage() {
	fprintf(stderr, "send_file_server usage:  send_file_server [[ OPTIONS ]]\n"\
			"Options:\n"\
		        " -a\t\talways accept transfers\n"\
			" -b\t\tdisable progress monitoring (default: enabled)\n"\
		        " -c\t\tallow program to skip checksum verification\n"\
		        " -p PORTNUM\tspecify port (default 51337)\n"\
		        " -h\t\tdisplay this help and exit.\n");
}

int main(int argc, char* argv[]) {

	int c;
	char *strtol_endptr;
	while ((c = getopt(argc, argv, "abchp:")) != -1) {
		switch(c) {
			case 'a':
				printf("-a provided -> always accepting file transfers without asking for consent.\n");
				always_accept_flag = 1;
				break;
			case 'b':
				printf("-b provided -> progress monitoring disabled.\n");	
				progress_bar_flag = 0;
				break;

			case 'c':
				printf("-c provided -> allowing program to skip checksum verification.\n");
				allow_checksum_skip_flag = 1;
				break;
			case 'h':
				usage();
				return 0;
				break;
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
	
	struct sigaction new_action, old_action;
	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		sigaction(SIGINT, &new_action, NULL);
	}

	struct sockaddr_in local_saddr, remote_saddr;

	local_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (local_sockfd < 0) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return 1;
	}

	memset(&local_saddr, 0, sizeof(local_saddr));
	memset(&remote_saddr, 0, sizeof(remote_saddr));

	local_saddr.sin_family = AF_INET;
	local_saddr.sin_addr.s_addr = INADDR_ANY;
	local_saddr.sin_port = htons(port);

	if (bind(local_sockfd, (struct sockaddr*) &local_saddr, sizeof(local_saddr)) < 0) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		return 1;
	}

	printf("send_file_server (recipient)\n\n");
	print_ip_addresses();
	printf("bind() on port \033[1m%d\033[m.\n", port);
	listen(local_sockfd, 5);

	char handshake_buffer[128];

	running = 1;

	while (running == 1) {
		fprintf(stderr, "\nListening for incoming connections.\n");

		remote_sockfd = -1;
		int outfile_fd = -1;

		socklen_t remote_saddr_size = sizeof(remote_saddr);
		remote_sockfd = accept(local_sockfd, (struct sockaddr *) &remote_saddr, &remote_saddr_size);
		if (remote_sockfd < 0) {
			fprintf(stderr, "warning: accept() failed: %s\n", strerror(errno));
		}

		char ip_buf[32];
		inet_ntop(AF_INET, &(remote_saddr.sin_addr), ip_buf, sizeof(ip_buf));
		printf("Client connected from %s.\n", ip_buf);

		int received_bytes = 0;	
		int handshake_len = recv(remote_sockfd, handshake_buffer, sizeof(handshake_buffer), 0);
		if (handshake_len <= 0) {
			fprintf(stderr, "error: handshake_len <= 0: %s\n", strerror(errno));
			close(remote_sockfd); 
			continue;
		}
		received_bytes += handshake_len;

		if (validate_protocol_welcome_header(handshake_buffer, handshake_len) < 0) {
			fprintf(stderr, "warning: validate_protocol_welcome_header failed!\n");
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			goto cleanup;
		}

		HEADERINFO h;

		if (get_headerinfo(handshake_buffer, handshake_len, &h) < 0) {
			fprintf(stderr, "error: headerinfo error!\n");
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			goto cleanup;
		}

		if (h.sha1_included == 0 && allow_checksum_skip_flag == 0) {
			fprintf(stderr, "error: client didn't provide a sha1 hash for the input file (-c was used; use -c on the server to allow this). Rejecting.\n");
			consolidate(remote_sockfd, HANDSHAKE_CHECKSUM_REQUIRED);
			goto cleanup;
		}

		int pipefd[2];

		if (pipe(pipefd) < 0) {
			fprintf(stderr, "pipe() error: %s\n", strerror(errno));
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			goto cleanup;
		}

		char *name = get_available_filename(h.filename);

		fprintf(stderr, "The client wants to send the file %s (size %.2f MB).\n", h.filename, get_megabytes(h.filesize)); 

		if (always_accept_flag == 0) {
			if (!ask_user_consent()) { 
				consolidate(remote_sockfd, HANDSHAKE_DENIED); 
				goto cleanup; 
			}
		}

		fprintf(stderr, "Writing to output file %s.\n\n", name);
		outfile_fd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		free(name);

		if (outfile_fd < 0) {
			fprintf(stderr, "open() failed (errno: %s).\n", strerror(errno));
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			goto cleanup;
		}

		// inform the client program that they can start blasting dat file data
		consolidate(remote_sockfd, HANDSHAKE_OK);

		long ret;
		if ((ret = recv_file(remote_sockfd, pipefd, outfile_fd, h.filesize)) < h.filesize) {
			if (ret < 0) {
				fprintf(stderr, "recv_file failure.\n");
			}
			else {
				fprintf(stderr, "recv_file: warning: received data size (%ld) is less than expected (%lu)!\n", ret, h.filesize);
			}
			goto cleanup;
		}
		
		unsigned char* block = mmap(NULL, h.filesize, PROT_READ, MAP_SHARED, outfile_fd, 0);
		if (block == MAP_FAILED) {
			fprintf(stderr, "mmap on outfile_fd failed: %s.\n", strerror(errno));
			return 1;
		}

		if (h.sha1_included && allow_checksum_skip_flag == 0) {
			fprintf(stderr, "Calculating sha1 sum...\n\n");
			unsigned char* sha1_received = get_sha1(block, h.filesize);
			munmap(block, h.filesize);
			
			if (compare_sha1(h.sha1, sha1_received) < 0) {
				return 1;
			}

			free(sha1_received);
		}
		else {
			fprintf(stderr, "(skipping checksum verification)\n\n");
		}
		printf("Success.\n");

		free(h.filename);

	cleanup:
		close(remote_sockfd);
		close(outfile_fd);

	}

	cleanup();

	return 0;
}
