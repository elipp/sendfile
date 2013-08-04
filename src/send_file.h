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

#define CLIENT_ABORT 0xF

#define SHA1_NOT_INCLUDED 0
#define SHA1_INCLUDED 1

#define UNBUFFERED_PRINTF(fmt, ...) do { fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

typedef struct _HEADERINFO {
	int protocol_id;
	ssize_t filesize;
	char *filename;
	int sha1_included;
	unsigned char sha1[SHA_DIGEST_LENGTH];
} HEADERINFO;

double get_us(const struct timeval *beg) {
	struct timeval end;
	memset(&end, 0, sizeof(end));
	gettimeofday(&end, NULL);
	double microseconds = (end.tv_sec*1000000 + end.tv_usec) - (beg->tv_sec*1000000 + beg->tv_usec);
	return microseconds;
}

void print_ip_addresses() {

	struct ifaddrs *addrs = NULL;
	struct ifaddrs *addrs_iter = NULL;

	getifaddrs(&addrs);

	printf("IP addresses for local interfaces via getifaddrs (local loopback lo excluded):\n\n");
	char ip_buf[INET_ADDRSTRLEN];	
	for (addrs_iter = addrs; addrs_iter != NULL; addrs_iter = addrs_iter->ifa_next) {
		if (addrs_iter->ifa_addr->sa_family == AF_INET) {	// the other option would be AF_INET6, but never mind 
			if (strcmp(addrs_iter->ifa_name, "lo") == 0) { continue; } // we don't really care about local loopback here
			inet_ntop(AF_INET, &((struct sockaddr_in *)addrs_iter->ifa_addr)->sin_addr, ip_buf, INET_ADDRSTRLEN);
			printf("interface %s ip: \033[1m%s\033[m\n", addrs_iter->ifa_name, ip_buf);
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
	printf("%s", tmpbuf);
}

int compare_sha1(const unsigned char* sha1_a, const unsigned char* sha1_b) {
	int i = 0;
	for (; i < SHA_DIGEST_LENGTH; ++i) {
		if (sha1_a[i] != sha1_b[i]) {
			fprintf(stderr, "WARNING! sha1 mismatch!\n");
			return -1;
		}
	}
	printf("sha1 sums match! =)\n");
	printf("expected \t");
	print_sha1(sha1_a);
	printf(",\ngot \t\t");
	print_sha1(sha1_b);
	printf(".\n\n");
	return 1;
}

typedef struct _progress_struct {
	const off_t *cur_bytes;
	ssize_t total_bytes;
	const struct timeval *beg;
	const int *running_flag;
} progress_struct;

progress_struct construct_pstruct(const off_t *cur_bytes_addr, ssize_t total_bytes, const struct timeval *beg_addr, const int *running_flag_addr) {
	progress_struct p;

	p.cur_bytes = cur_bytes_addr;
	p.total_bytes = total_bytes;
	p.beg = beg_addr;
	p.running_flag = running_flag_addr;

	return p;
}

void print_progress(long cur_bytes, long total_bytes, const struct timeval *beg) {
	
	static const char* esc_composite_clear_line_reset_left = "\r\033[0K";	// ANSI X3.64 magic
	UNBUFFERED_PRINTF("%s", esc_composite_clear_line_reset_left);

	float progress = 100*(float)(cur_bytes)/(float)(total_bytes);

	// MB/s = (bytes/2^20) : (microseconds/1000000)
	// == (bytes/1048576) * (1000000/microseconds)
	// == (1000000/1048576) * (bytes/microseconds)
	static const float MB_us_coeff = 1000000.0/1048576.0;

	float rate = MB_us_coeff*((float)cur_bytes)/get_us(beg);	
	printf("%lu/%lu bytes transferred (%.2f %%, %.2f MB/s)", cur_bytes, total_bytes, progress, rate);
	fflush(stdout);

}

void *progress_callback(void *progress) {

	progress_struct *p = (progress_struct*)progress;

	while (*p->cur_bytes < p->total_bytes) {
		long cur_bytes = *p->cur_bytes;
		long total_bytes = p->total_bytes;
	
		if (*p->running_flag == 0) {
			fprintf(stderr, "\nTransfer aborted!\n");
			print_progress(cur_bytes, total_bytes, p->beg);
			return NULL;
		}

		print_progress(cur_bytes, total_bytes, p->beg);
		sleep(1);
	}
	
	return NULL;
}


#endif
