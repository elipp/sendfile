#ifndef SEND_FILE_H
#define SEND_FILE_H

#include <openssl/sha.h>

const int protocol_id = 0x0d355480;

const int port = 51337;

#define BLESSING_NO 0
#define BLESSING_YES 1

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
} while(0)

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
	fprintf(stderr, "sha1 sums match! =)\n\n");
	fprintf(stderr, "expected \t");
	print_sha1(sha1_a);
	fprintf(stderr, ",\ngot \t\t");
	print_sha1(sha1_b);
	fprintf(stderr, ".\n");
	return 1;
}

#endif
