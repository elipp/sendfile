#ifndef SEND_FILE_H
#define SEND_FILE_H

#include "non_portable_stuff.h"
#include "timer.h"

#include <openssl/sha.h>

#ifndef MAX_HOSTNAME_LEN
#define MAX_HOSTNAME_LEN 255 // arbitrary
#endif

const int32_t protocol_id = 0x0d355480;
#ifdef _WIN32
#define CHUNK_SIZE (1024*1024)	// TransmitFile performs a LOT better this way ^_^
#elif __linux__
#define CHUNK_SIZE (8*1024)		// splice() on the other hand has a limit at 16384 for chunk size O_o
#endif

#define DEFAULT_PORT 51337

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



typedef struct _HEADERINFO {
	int64_t filesize;
	int32_t protocol_id;
	int32_t sha1_included;
	char *filename;
	unsigned char sha1[SHA_DIGEST_LENGTH];
} HEADERINFO;

#define SHA_HASH_CHUNKSIZE (16*1024*1024)
typedef struct {
	FILE *fp;
	long long num_runs;
	unsigned char *alternating_buffers[2];
	int *read_done;
} fread_ahead_arg_struct;

typedef struct _progress_struct {
	const int64_t *cur_bytes;
	int64_t total_bytes;
	const struct _timer *timer;
	const int *running_flag;
} progress_struct;

void print_ip_addresses();

#ifdef __linux__
void *fread_ahead(void *args);
#elif _WIN32
unsigned __stdcall fread_ahead(void *args);
#endif

double get_megabytes(int64_t bytes);
unsigned char *get_sha1(const char* filename, uint64_t bufsize);
void print_sha1(const unsigned char *sha1);
int compare_sha1(const unsigned char* sha1_a, const unsigned char* sha1_b);

progress_struct construct_pstruct(const int64_t *cur_bytes_addr, int64_t total_bytes, const struct _timer *timer, const int *running_flag_addr);

void print_progress(int64_t cur_bytes, int64_t total_bytes, const struct _timer *timer);

#ifdef __linux__	// for pthreads, the signature is void(*)(void*)
void *progress_callback(void *progress);
#elif _WIN32
unsigned __stdcall progress_callback(void *progress);
#endif

#endif
