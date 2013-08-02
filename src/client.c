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

#define __USE_GNU
#include <fcntl.h>

#include "send_file.h"

int local_sockfd;

static int send_file(const char* filename) {

	int fd = open(filename, O_RDONLY);
	if (fd < 0) { fprintf(stderr, "send_handshake: opening file failed.\n"); return -1; }

	struct stat st;
	fstat(fd, &st);

	unsigned long filesize = st.st_size;

	printf("input file %s filesize: %lu\n", filename, filesize);
	unsigned char* block = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (block == MAP_FAILED) { fprintf(stderr, "mmap() failed.\n"); return -1; }
	
	fprintf(stderr, "Calculating sha1 sum of input file...\n");
	unsigned char* sha1 = get_sha1(block, filesize);
	munmap(block, filesize);
	fprintf(stderr, "Done (got ");
	print_sha1(sha1);
	fprintf(stderr, ").\n");

	char *filename_base = basename(filename);
	int filename_base_len = strlen(filename_base);
	char handshake_buffer[128];
	
	int accum = 0;
	memcpy(handshake_buffer, &protocol_id, sizeof(protocol_id));
	accum += sizeof(protocol_id);
	memcpy(handshake_buffer + accum, &filesize, sizeof(filesize));
	accum += sizeof(filesize);

	memcpy(handshake_buffer + accum, filename_base, filename_base_len);
	accum += filename_base_len + 1;

	memcpy(handshake_buffer + accum, sha1, SHA_DIGEST_LENGTH);
	accum += SHA_DIGEST_LENGTH;
	int sent_bytes;	
	sent_bytes = send(local_sockfd, handshake_buffer, accum, 0);

	if (sent_bytes < 0) {
		fprintf(stderr, "sending handshake failed\n");
	}

	int received_bytes;

	char blessing_buffer[8];
	
	received_bytes = recv(local_sockfd, blessing_buffer, 8, 0); 
	if (received_bytes <= 0) { fprintf(stderr, "recv: blessing length <= 0\n"); return -1; }
	int prid;
	int blessing;
	memcpy(&prid, blessing_buffer, sizeof(protocol_id));
	memcpy(&blessing, blessing_buffer + sizeof(protocol_id), sizeof(blessing));
	if (prid != protocol_id) { fprintf(stderr, "protocol id mismatch!\n"); return -1; }
	if (blessing != BLESSING_YES) { fprintf(stderr, "received NAK (BLESSING_NO) (%d) from remote. exiting.\n", blessing); }
	
	// else we're free to start blasting dat file data
	fprintf(stderr, "Handshake ok. Starting sendfile().\n");
	if ((sent_bytes = sendfile(local_sockfd, fd, 0, filesize)) <= 0) {
		fprintf(stderr, "sendfile() failed: %s\n", strerror(errno)); 
		return -1;
	}
	fprintf(stderr, "sendfile() successful.\n");

	return 0;


	free(sha1);
}



int main(int argc, char* argv[]) {

	if (argc < 3) {
		fprintf(stderr, "send_file usage: send_file RECIPIENT_IP FILENAME\n");
		return 1;
	}
	
	// send_file RECIPIENT_IP FILENAME

	char* remote_ipstr = strdup(argv[1]);
	char* filename = strdup(argv[2]);

	struct sockaddr_in local_saddr, remote_saddr;
	memset(&local_saddr, 0, sizeof(local_saddr));
	memset(&remote_saddr, 0, sizeof(local_saddr));

	local_saddr.sin_family = AF_INET;
	local_saddr.sin_addr.s_addr = INADDR_ANY;
	local_saddr.sin_port = htons(port);

	local_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (local_sockfd < 0) { fprintf(stderr, "socket() failed\n"); return 1; }

	remote_saddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, remote_ipstr, &remote_saddr.sin_addr) <= 0) { 
		fprintf(stderr, "inet_pton failed. invalid ip_string? (\"%s\")\n", remote_ipstr);
		return 1;
	}
	remote_saddr.sin_port = htons(port);

	socklen_t remote_saddr_len = sizeof(remote_saddr);

	if (connect(local_sockfd, (struct sockaddr*) &remote_saddr, remote_saddr_len) < 0) {
		fprintf(stderr, "connect() failed.\n");
		return 1;
	}

	if (send_file(filename) < 0) {
		fprintf(stderr, "send_file failure.\n");
		return 1;
	}

	free(remote_ipstr);
	free(filename);
	
	close(local_sockfd);

	return 0;

}
