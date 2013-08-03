#ifndef SEND_FILE_H
#define SEND_FILE_H

#include <openssl/sha.h>

const int protocol_id = 0x0d355480;

const int port = 51337;

#define HANDSHAKE_FAIL 0
#define HANDSHAKE_OK 1
#define HANDSHAKE_DENIED 2

typedef struct _HEADERINFO {
	int protocol_id;
	unsigned long output_filesize;
	char *output_filename;
	unsigned char sha1[SHA_DIGEST_LENGTH];
} HEADERINFO;

#define IS_PRINTABLE_CHAR(c) ((unsigned char)(c) >= 0x20 && (unsigned char)(c) <= 0x7E)

#define DUMP_BUFFER(ptr, size) do {\
	int i = 0;\
	printf("buffer contents at %p:\n", ptr);\
	for (; i < size; ++i) {\
		if (IS_PRINTABLE_CHAR(ptr[i])) {\
			printf("%c  ", (char)(ptr[i]));\
		}\
		else {\
			printf("%02X ", (unsigned char)ptr[i]);\
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
	fprintf(stderr, ".\n");
	return 1;
}

#endif
