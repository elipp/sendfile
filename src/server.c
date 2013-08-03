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

#define __USE_GNU
#include <fcntl.h>
#include "send_file.h"

int local_sockfd;

static int validate_protocol_welcome_header(const char* buf, size_t buf_size) {
	int id;
	memcpy(&id, buf, sizeof(id));

	if (id != protocol_id) { return -1; }
	return 0;
}

static char *get_available_filename(const char* orig_filename) {
	int name_len = strlen(orig_filename);
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

	memcpy(&h->output_filesize, buf + accum, sizeof(h->output_filesize));
	accum += sizeof(h->output_filesize);

	h->output_filename = strdup(buf + accum);
	if (!h->output_filename) { 
		fprintf(stderr, "Error: extracting file name from header info failed. Bad header?\n");
		return -1;
	}
	int name_len = strlen(h->output_filename);
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

static int recv_file(int remote_sockfd, int *pipefd, int outfile_fd, long file_size) {
	long bytes_recv = 0;
	long total_bytes_processed = 0;	
	struct timeval tv_beg, tv_end;
	memset(&tv_beg, 0, sizeof(tv_beg));
	memset(&tv_end, 0, sizeof(tv_end));
	gettimeofday(&tv_beg, NULL);

	while (total_bytes_processed < file_size) {
		static const int max_chunksize = 16384;
		long would_process = file_size - total_bytes_processed;
		long gonna_process = MIN(would_process, max_chunksize);
		int spl_flag = SPLICE_F_MORE | SPLICE_F_MOVE;

		// splice to pipe write head
		if ((bytes_recv = 
		splice(remote_sockfd, NULL, pipefd[1], NULL, gonna_process, spl_flag)) <= 0) {
			fprintf(stderr, "socket->pipe_write splice returned %d: %s\n", bytes_recv, strerror(errno));
			return -1;
		}
		// splice from pipe read head to file fd

		int bytes_in_pipe = bytes_recv;
		int bytes_written = 0;
		while (bytes_in_pipe > 0) {
			if ((bytes_written = 
			splice(pipefd[0], NULL, outfile_fd, &total_bytes_processed, bytes_in_pipe, spl_flag)) <= 0) {
				fprintf(stderr, "pipe_read->file_fd splice returned %d: %sn", bytes_written, strerror(errno));
				return -1;
			}

			bytes_in_pipe -= bytes_written;

		}
	}			
	
	gettimeofday(&tv_end, NULL);
	double microseconds = (tv_end.tv_sec*1000000 + tv_end.tv_usec) - (tv_beg.tv_sec*1000000 + tv_beg.tv_usec);
	double seconds = microseconds/1000000;
	double MBs = get_megabytes(file_size)/seconds;

	fprintf(stderr, "Received %ld bytes in %f seconds (%f MB/s).\n\n", file_size, seconds, MBs);

	return 1;

}

static void make_lowercase(char *arr, int length) {
	int i = 0;
	for (; i < length; ++i) {
		arr[i] = tolower(arr[i]);
	}
}

static int ask_user_consent() {
	fprintf(stderr, "Is this ok? [y/N] ");
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
		fprintf(stderr, "Unknown answer \"%s\". [y/N]?", buffer);
		goto get_answer; 
	} 

}

int main(int argc, char* argv[]) {

	struct sockaddr_in local_saddr, remote_saddr;

	local_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (local_sockfd < 0) {
		fprintf(stderr, "socket() failed.\n");
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

	fprintf(stdout, "sendfile_server: bind() on port %d.\n", port);

	listen(local_sockfd, 5);

	char handshake_buffer[128];

	while (1) {
		fprintf(stderr, "\nListening for incoming connections.\n");
		int remote_sockfd;
		socklen_t remote_saddr_size = sizeof(remote_saddr);
		remote_sockfd = accept(local_sockfd, (struct sockaddr *) &remote_saddr, &remote_saddr_size);
		if (remote_sockfd < 0) {
			fprintf(stderr, "warning: accept() failed.\n");
		}

		char ip_buf[32];
		char *ipstr = inet_ntop(AF_INET, &(remote_saddr.sin_addr), ip_buf, sizeof(ip_buf));
		printf("Client connected from %s.\n", ip_buf);

		int received_bytes = 0;	
		int handshake_len = recv(remote_sockfd, handshake_buffer, sizeof(handshake_buffer), 0);
		if (handshake_len <= 0) {
			fprintf(stderr, "error: handshake_len <= 0\n");
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

		int outfile_fd;
		int pipefd[2];

		if (pipe(pipefd) < 0) {
			fprintf(stderr, "pipe() error.\n");
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			goto cleanup;
		}

		char *name = get_available_filename(h.output_filename);
		fprintf(stderr, "The client wants to send the file %s (size %.2f MB).\n", h.output_filename, get_megabytes(h.output_filesize)); 
		if (!ask_user_consent()) { consolidate(remote_sockfd, HANDSHAKE_DENIED); goto cleanup; }

		fprintf(stderr, "Writing to output file %s\n", name);
		outfile_fd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		free(name);

		if (outfile_fd < 0) {
			fprintf(stderr, "open() failed (errno: %s).\n", strerror(errno));
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			goto cleanup;
		}

		// inform the client program that they can start blasting dat file data
		consolidate(remote_sockfd, HANDSHAKE_OK);

		if (recv_file(remote_sockfd, pipefd, outfile_fd, h.output_filesize) < 0) {
			fprintf(stderr, "recv_file failure.\n");
			goto cleanup;
		}
		
		unsigned char* block = mmap(NULL, h.output_filesize, PROT_READ, MAP_SHARED, outfile_fd, 0);
		if (block == MAP_FAILED) {
			fprintf(stderr, "mmap on outfile_fd failed: %s.\n", strerror(errno));
			return 1;
		}

		fprintf(stderr, "Calculating sha1 sum...\n\n");
		unsigned char* sha1_received = get_sha1(block, h.output_filesize);
		munmap(block, h.output_filesize);
		
		if (compare_sha1(h.sha1, sha1_received) < 0) {
			return 1;
		}

		free(sha1_received);
		free(h.output_filename);

	cleanup:
		close(remote_sockfd);
		close(outfile_fd);

	}

	return 0;
}
