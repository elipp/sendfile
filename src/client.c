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

static int local_sockfd;
static int checksum_flag = 1;

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
		fprintf(stderr, "(skipping checksum calculation)\n");
	}
	else {
		unsigned char* block = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (block == MAP_FAILED) { fprintf(stderr, "mmap() failed.\n"); return -1; }
		fprintf(stderr, "Calculating sha1 sum of input file...\n");
		sha1 = get_sha1(block, filesize);
		munmap(block, filesize);

		fprintf(stderr, "Done! (got ");
		print_sha1(sha1);
		fprintf(stderr, ").\n");
	}

	char *filename_base = basename(filename);
	int filename_base_len = strlen(filename_base);

	printf("input file %s (basename %s). filesize: %lu\n", filename, filename_base, filesize);

	char handshake_buffer[128];
	
	int accum = 0;
	ACCUM_WRITE(protocol_id, handshake_buffer);
	ACCUM_WRITE(filesize, handshake_buffer);
	ACCUM_WRITE(checksum_flag, handshake_buffer);
	ACCUM_WRITE_ARRAY(filename_base, handshake_buffer, filename_base_len+1); // to include the \0 char
	if (checksum_flag) {
		ACCUM_WRITE_ARRAY(sha1, handshake_buffer, SHA_DIGEST_LENGTH);
	}

//	DUMP_BUFFER(handshake_buffer, accum);

	int sent_bytes;	
	sent_bytes = send(local_sockfd, handshake_buffer, accum, 0);


	if (sent_bytes < 0) {
		fprintf(stderr, "sending handshake failed\n");
	}

	int received_bytes;

	fprintf(stderr, "Waiting for remote consent...");
	received_bytes = recv(local_sockfd, handshake_buffer, 8, 0); 
	if (received_bytes <= 0) { fprintf(stderr, "recv: blessing length <= 0\n"); return -1; }
	int prid;
	int handshake_status;
	memcpy(&prid, handshake_buffer, sizeof(protocol_id));
	memcpy(&handshake_status, handshake_buffer + sizeof(protocol_id), sizeof(handshake_status));
	if (prid != protocol_id) { 
		fprintf(stderr, "protocol id mismatch!\n"); 
		return -1; 
	}
	switch (handshake_status) {
		case HANDSHAKE_OK:
			fprintf(stderr, "ok.\n");
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
			fprintf(stderr, "received HANDSHAKE_CHECKSUM_REQUIRED (%x) from remote (the -c option can't be used).\n", handshake_status);
			return -1;
		default:
			break;
	}
	
	// else we're free to start blasting ze file data
	fprintf(stderr, "Handshake ok. Starting sendfile().\nProgress data unavailable - use an external program, such as NetHogs.\n");
	if ((sent_bytes = sendfile(local_sockfd, fd, 0, filesize)) < filesize) {
		if (sent_bytes < 0) {
			fprintf(stderr, "sendfile() failed: %s\n", strerror(errno)); 
		}
		else {
			fprintf(stderr, "sent_bytes < filesize (!), transfer cancelled by remote.\n");
		}
		return -1;
	}
	fprintf(stderr, "sendfile() successful.\n");

	return 0;


	free(sha1);
}

void usage(char* argv[]) {
	fprintf(stderr, "%s: usage: %s <IPv4 addr> <filename>.\n Options: \t-c:\tskip checksum (sha1) calculation (requires server-side support)\n\n", argv[0], argv[0]);
}

int main(int argc, char* argv[]) {

	if (argc < 3) {
		usage(argv);
		return 1;
	}

	int c;
	while ((c = getopt(argc, argv, "c")) != -1) {
		switch(c) {
			case 'c':
				fprintf(stderr, "-c provided -> Skipping checksum computation.\n");
				checksum_flag = 0;
				break;
			case '?':
				fprintf(stderr, "warning: unknown option \'-%c\n\'", optopt);
				break;
			default:
				abort();
		}
	}
	
	// send_file RECIPIENT_IP FILENAME

	char* remote_ipstr = strdup(argv[optind]);
	char* filename = strdup(argv[optind+1]);

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
		fprintf(stderr, "connect failed: %s\n", strerror(errno));
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
