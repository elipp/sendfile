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

typedef struct _HEADERINFO {
	int protocol_id;
	unsigned long output_filesize;
	char *output_filename;
	unsigned char sha1[SHA_DIGEST_LENGTH];
} HEADERINFO;

static char *get_available_filename(const char* orig_filename) {
	int name_len = strlen(orig_filename);
	char name_buf[128];
	strcpy(name_buf, orig_filename);
	int num = 1;
	while (access(name_buf, F_OK) != -1) {
		// file exists, rename using the (#) scheme
		int bytes = sprintf(name_buf, "%s(%d)", orig_filename, num);
		name_buf[bytes] = '\0';
		++num;
	}
	return strdup(name_buf);
}

#define DUMP_BUFFER(ptr, size) do {\
	int i = 0;\
	printf("buffer contents at %p:\n", ptr);\
	for (; i < size; ++i) {\
		printf("%02X ", (unsigned char)ptr[i]);\
		if (i % 8 == 7) {\
			printf("\n");\
		}\
	}\
	printf("\n");\
}while(0)

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

static int send_blessing(int out_sockfd, int flag) {
	char hacknowledge_buffer[8];
	memcpy(hacknowledge_buffer, &protocol_id, sizeof(protocol_id));
	memcpy(hacknowledge_buffer+sizeof(protocol_id), &flag, sizeof(flag));	
	int sent_bytes = send(out_sockfd, hacknowledge_buffer, 8, 0);
	if (sent_bytes <= 0) { 
		fprintf(stderr, "send_blessing failed (send())\n");
	}
	fprintf(stdout, "sent blessing %d to remote.\n", flag);
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
//		static const int max_chunksize = 16384;
		static const int max_chunksize = 65536;
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
	double MBs = (file_size/1048576.0)/seconds;

	fprintf(stderr, "Received %ld bytes in %f seconds (%f MB/s).\n\n", file_size, seconds, MBs);

	return 1;

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
		int remote_sockfd;
		socklen_t remote_saddr_size = sizeof(remote_saddr);
		remote_sockfd = accept(local_sockfd, (struct sockaddr *) &remote_saddr, &remote_saddr_size);
		if (remote_sockfd < 0) {
			fprintf(stderr, "warning: accept() failed.\n");
		}

		char ip_buf[32];
		char *ipstr = inet_ntop(AF_INET, &remote_saddr.sin_addr, ip_buf, 32);
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
			send_blessing(remote_sockfd, BLESSING_NO);
			goto cleanup;
		}

		HEADERINFO h;

		if (get_headerinfo(handshake_buffer, handshake_len, &h) < 0) {
			fprintf(stderr, "error: headerinfo error!\n");
			send_blessing(remote_sockfd, BLESSING_NO);
			goto cleanup;
		}

		int outfile_fd;
		int pipefd[2];

		if (pipe(pipefd) < 0) {
			fprintf(stderr, "pipe() error.\n");
			send_blessing(remote_sockfd, BLESSING_NO);
			goto cleanup;
		}

		char *name = get_available_filename(h.output_filename);
		printf("Writing to output file %s\n", name);
		outfile_fd = open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		free(name);

		if (outfile_fd < 0) {
			fprintf(stderr, "open() failed (errno: %s).\n", strerror(errno));
			send_blessing(remote_sockfd, BLESSING_NO);
			goto cleanup;
		}

		// inform the client program that they can start blasting dat file data
		send_blessing(remote_sockfd, BLESSING_YES);

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
