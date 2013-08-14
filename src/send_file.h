#ifndef SEND_FILE_H
#define SEND_FILE_H

#include <openssl/sha.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>
#include <Windows.h>
#include <process.h>
#define SLEEP_S(seconds) Sleep((1000*(seconds)))
#elif __linux__

#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <inttypes.h>
#include <libgen.h>
#define SLEEP_S(seconds) sleep((seconds))

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU // for splice constants, SPLICE_F_MOVE, SPLICE_F_MORE
#endif
#include <fcntl.h>

#endif

#include "timer.h"

#ifndef MAX_HOSTNAME_LEN
#define MAX_HOSTNAME_LEN 255 // arbitrary
#endif

const int32_t protocol_id = 0x0d355480;

#define DEFAULT_PORT 51337
unsigned short port = DEFAULT_PORT;

#define HANDSHAKE_FAIL 0
#define HANDSHAKE_OK 1
#define HANDSHAKE_DENIED 2
#define HANDSHAKE_CHECKSUM_REQUIRED 3

#define CLIENT_ABORT 0xF

#define SHA1_NOT_INCLUDED 0
#define SHA1_INCLUDED 1

#ifndef MIN
#define MIN(a,b)\
	((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b)\
	((a) > (b) ? (a) : (b))
#endif

#define UNBUFFERED_PRINTF(fmt, ...) do { fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
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

double get_megabytes(int64_t bytes) {
	return (bytes)/(1048576.0);
}

typedef struct _HEADERINFO {
	int64_t filesize;
	int32_t protocol_id;
	int32_t sha1_included;
	char *filename;
	unsigned char sha1[SHA_DIGEST_LENGTH];
} HEADERINFO;


#ifdef __linux__
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

#elif _WIN32

void print_ip_addresses() {
	char hostname[MAX_HOSTNAME_LEN];
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		fprintf(stderr, "error retrieving host name! (error %x)\n", GetLastError());
		return;
	}
	printf("hostname: %s\n", hostname);
	struct hostent *phe = (struct hostent*)gethostbyname(hostname);

	if (!phe) {
		fprintf(stderr, "gethostbyname failed!\n (error %x)\n", GetLastError());
		return;
	}

	printf("IP addresses for local interfaces via gethostbyname:\n\n");
	for (int i = 0; phe->h_addr_list[i] != NULL; ++i) {
			struct in_addr addr;
			memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
			printf("%d - ip: %s\n", i, inet_ntoa(addr));
	}
}
#endif

#ifdef __linux__
#define HANDLE int64_t*
void *my_mmap_readonly_shared(int opened_fd, int64_t filesize, HANDLE *fm) {
		unsigned char* block = (unsigned char*)mmap(NULL, filesize, PROT_READ, MAP_SHARED, opened_fd, 0);
		if (block == MAP_FAILED) { 
			fprintf(stderr, "mmap() failed: %s\n", strerror(errno)); 
			return NULL;
		}
		else { 
			return block; 
		}
}

void my_munmap(void *block, int64_t size, HANDLE fm) {
	munmap(block, size);
}
#elif _WIN32
void *my_mmap_readonly_shared(HANDLE opened_filehandle, int64_t filesize, HANDLE *fm) {
		*fm = CreateFileMapping(opened_filehandle, NULL, PAGE_READONLY, 0, 0, NULL);
		if (*fm == INVALID_HANDLE_VALUE) { 
			fprintf(stderr, "CreateFileMapping failed (error %x).\n", GetLastError());
			return NULL;
		}
		void *block = MapViewOfFile(*fm, FILE_MAP_READ, 0, 0, 0);
		if (!block) { 
			fprintf(stderr, "MapViewOfFile failed (error %x).\n", GetLastError());
			return NULL;
		}
		return block;
}

void my_munmap(void *block, int64_t size, HANDLE fm) {
	UnmapViewOfFile(block);
	CloseHandle(fm);
}

#endif

#ifdef __linux__
char *get_basename(char* full_filename) {
	return basename(full_filename);
}
#elif _WIN32
char *get_basename(char* full_filename) {
	char filename_base[_MAX_FNAME];
	char file_ext[_MAX_EXT];
	_splitpath(NULL, NULL, NULL, filename_base, file_ext);
	char basename[_MAX_FNAME+_MAX_EXT+1];
	sprintf(basename, "%s.%s\0", filename_base, file_ext);

	int filename_base_len = strlen(basename);
	return _strdup(basename);
}
#endif

unsigned char *get_sha1(unsigned char* buffer, unsigned long bufsize) {
	unsigned char *outbuf = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
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
	int64_t total_bytes;
	const struct _timer *timer;
	const int *running_flag;
} progress_struct;

progress_struct construct_pstruct(const off_t *cur_bytes_addr, int64_t total_bytes, const struct _timer *timer, const int *running_flag_addr) {
	progress_struct p;

	p.cur_bytes = cur_bytes_addr;
	p.total_bytes = total_bytes;
	p.timer = timer;
	p.running_flag = running_flag_addr;

	return p;
}

void print_progress(off_t cur_bytes, int64_t total_bytes, const struct _timer *timer) {
	
	#ifdef __linux__
	static const char* esc_composite_clear_line_reset_left = "\r\033[0K";	// ANSI X3.64 magic
	#elif _WIN32
	static const char *esc_composite_clear_line_reset_left = "\r";	// will have to do :(
	#endif	
	
	UNBUFFERED_PRINTF("%s", esc_composite_clear_line_reset_left);
	
	float progress = 100*(float)(cur_bytes)/(float)(total_bytes);

	// MB/s = (bytes/2^20) : (microseconds/1000000)
	// == (bytes/1048576) * (1000000/microseconds)
	// == (1000000/1048576) * (bytes/microseconds)
	static const float MB_us_coeff = 1000000.0/1048576.0;

	float rate = MB_us_coeff*((float)cur_bytes)/timer->get_us(timer);	
	printf("%lu/%" PRId64 " bytes transferred (%.2f %%, %.2f MB/s)", cur_bytes, total_bytes, progress, rate);
	fflush(stdout);

}

#ifdef __linux__	// for pthreads, the signature is void(*)(void*)
void *progress_callback(void *progress) {
#elif _WIN32
unsigned __stdcall progress_callback(void *progress) {
#endif
	progress_struct *p = (progress_struct*)progress;

	while (*p->cur_bytes < p->total_bytes) {
		off_t cur_bytes = *p->cur_bytes;
		int64_t total_bytes = p->total_bytes;
	
		if (*p->running_flag == 0) {
			fprintf(stderr, "\nTransfer aborted!\n");
			print_progress(cur_bytes, total_bytes, p->timer);
			return NULL;
		}

		print_progress(cur_bytes, total_bytes, p->timer);
		SLEEP_S(1);
	}
	
	print_progress(*p->cur_bytes, p->total_bytes, p->timer);
	fprintf(stderr, "\n");
	
	return NULL;
}


#endif
