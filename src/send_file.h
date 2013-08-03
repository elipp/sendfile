#ifndef SEND_FILE_H
#define SEND_FILE_H

#include <openssl/sha.h>
#include <ctype.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

const int protocol_id = 0x0d355480;

#define DEFAULT_PORT 51337
int port = DEFAULT_PORT;

#define HANDSHAKE_FAIL 0
#define HANDSHAKE_OK 1
#define HANDSHAKE_DENIED 2
#define HANDSHAKE_CHECKSUM_REQUIRED 3

#define SHA1_NOT_INCLUDED 0
#define SHA1_INCLUDED 1

typedef struct _HEADERINFO {
	int protocol_id;
	unsigned long filesize;
	char *filename;
	int sha1_included;
	unsigned char sha1[SHA_DIGEST_LENGTH];
} HEADERINFO;

void print_ip_addresses() {

	struct ifaddrs *addrs = NULL;
	struct ifaddrs *addrs_iter = NULL;

	getifaddrs(&addrs);

	fprintf(stderr, "IP addresses for local interfaces via getifaddrs (local loopback lo excluded):\n\n");
	char ip_buf[INET_ADDRSTRLEN];	
	for (addrs_iter = addrs; addrs_iter != NULL; addrs_iter = addrs_iter->ifa_next) {
		if (addrs_iter->ifa_addr->sa_family == AF_INET) {	// the other option would be AF_INET6, but never mind 
			if (strcmp(addrs_iter->ifa_name, "lo") == 0) { continue; } // we don't really care about local loopback here
			inet_ntop(AF_INET, &((struct sockaddr_in *)addrs_iter->ifa_addr)->sin_addr, ip_buf, INET_ADDRSTRLEN);
			fprintf(stderr, "interface %s ip: %s\n", addrs_iter->ifa_name, ip_buf);
		} 
	}
	if (addrs != NULL) { 
		freeifaddrs(addrs);
       	}

}

#define IS_PRINTABLE_CHAR(c) ((unsigned char)(c) >= 0x20 && (unsigned char)(c) <= 0x7E)

#define DUMP_BUFFER(ptr, size) do {\
	int i = 0;\
	printf("buffer contents at %p:\n", ptr);\
	for (; i < size; ++i) {\
		if (IS_PRINTABLE_CHAR(ptr[i])) {\
			printf("%c  ", (char)(ptr[i]));\
		}\
		else {\
			printf("%02x ", (unsigned char)ptr[i]);\
		}\
		if (i % 8 == 7) {\
			printf("\n");\
		}\
	}\
	printf("\n");\
} while(0)

double get_megabytes(unsigned long bytes) {
	return (bytes)/(1048576.0);
}

unsigned char *get_sha1(unsigned char* buffer, unsigned long bufsize) {
	unsigned char *outbuf = malloc(SHA_DIGEST_LENGTH);
	SHA1(buffer, bufsize, outbuf);
	return outbuf;
}

void print_sha1(const unsigned char *sha1) {
	char tmpbuf[64];
	int i = 0;
	int offset = 0;
	for (; i < SHA_DIGEST_LENGTH; ++i) {
		sprintf(tmpbuf + offset, "%02x", sha1[i]);
		offset += 2;
	}
	tmpbuf[offset+1] = '\0';
	fprintf(stderr, "%s", tmpbuf);
}

int compare_sha1(const unsigned char* sha1_a, const unsigned char* sha1_b) {
	int i = 0;
	for (; i < SHA_DIGEST_LENGTH; ++i) {
		if (sha1_a[i] != sha1_b[i]) {
			fprintf(stderr, "WARNING! sha1 mismatch!\n");
			return -1;
		}
	}
	fprintf(stderr, "sha1 sums match! =)\n");
	fprintf(stderr, "expected \t");
	print_sha1(sha1_a);
	fprintf(stderr, ",\ngot \t\t");
	print_sha1(sha1_b);
	fprintf(stderr, ".\n\n");
	return 1;
}

#endif
