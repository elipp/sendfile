#ifndef NON_PORTABLE_STUFF_H
#define NON_PORTABLE_STUFF_H



#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Winsock2.h>
#include <ws2tcpip.h>	
#include <Mswsock.h>
#include <Windows.h>
#include <process.h>
#include <sys\types.h>

#include "XGetopt.h"

#define strdup _strdup

int init_WSOCK();

#define NATIVE_FILEHANDLE HANDLE
#define INVALIDATE_FILEHANDLE(fh) do { fh = INVALID_HANDLE_VALUE; } while(0)
#define NATIVE_FILEHANDLE_INVALID(fh) ((fh == INVALID_HANDLE_VALUE))
#define CLOSE_SOCKET(sockfd) do { closesocket((sockfd)); } while(0)

struct thread_struct {
	HANDLE handle;
};

typedef unsigned (__stdcall *CALLBACK_FUNC)(void*);
#define SIGHANDLER_CALLBACK PHANDLER_ROUTINE

struct splice_struct {
	char *buffer;
	int64_t buffer_size;
};

#define SLEEP_S(seconds) do { Sleep((1000*(seconds))); } while(0)
#define SLEEP_MS(ms) do { Sleep((ms)); } while(0)

char *get_error_message(DWORD errcode);

#define PRINT_ERROR(funcname) do {\
	fprintf(stderr, funcname ": error: %s\n", get_error_message(GetLastError()));\
	} while (0)

#define PRINT_SOCKET_ERROR(funcname) do {\
	fprintf(stderr, funcname ": error: %s\n", get_error_message(WSAGetLastError()));\
	} while(0)

#elif __linux__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <inttypes.h>
#include <libgen.h>

#include <pthread.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU // for splice constants, SPLICE_F_MOVE, SPLICE_F_MORE
#endif
#include <fcntl.h>

#define NATIVE_FILEHANDLE int
#define INVALIDATE_FILEHANDLE(fd) do { (fd = -1); } while(0)
#define NATIVE_FILEHANDLE_INVALID(fd) ((fd < 0))
#define CLOSE_SOCKET(sockfd) do { close((sockfd)); } while(0)

typedef struct {
	pthread_t handle;
} thread_struct;

typedef struct {
	int pipefd[2];
} splice_struct;

typedef void* (*CALLBACK_FUNC)(void*);
typedef void (*SIGHANDLER_CALLBACK)(int);

#define SLEEP_S(seconds) do { sleep((seconds)); } while(0)
#define SLEEP_MS(ms) do { usleep((ms)*1000); } while(0)

#define PRINT_ERROR(funcname) do {\
	fprintf(stderr, funcname ": error: %s\n", strerror(errno));\
	} while (0)
#define PRINT_SOCKET_ERROR(funcname) PRINT_ERROR(funcname)


#endif

void setup_signal_handler(SIGHANDLER_CALLBACK cb);

int splice_struct_construct(splice_struct *sp);
void splice_struct_cleanup(splice_struct *sp);

void thread_start(thread_struct *t, CALLBACK_FUNC cb, void *args);
void thread_join(thread_struct *t);

int64_t splice_from_socket_to_file(int sockfd, NATIVE_FILEHANDLE fh, splice_struct *sp, int64_t filesize, int64_t total_bytes_processed);
int64_t send_chunk(int sockfd, NATIVE_FILEHANDLE fh, int64_t gonna_send, int64_t total_bytes_sent);

void *native_mmap_readonly_shared(NATIVE_FILEHANDLE opened_filehandle, int64_t filesize, NATIVE_FILEHANDLE *fm);
void native_munmap(void *block, int64_t size, NATIVE_FILEHANDLE fm);

NATIVE_FILEHANDLE open_file_object_wb_native(char *filename);
NATIVE_FILEHANDLE open_file_object_rb_native(char *filename);
void close_file_object_native(NATIVE_FILEHANDLE fh);

char *get_basename(char* full_filename);
char *get_available_filename(const char* orig_filename);

uint64_t get_filesize(char *filename);

extern SIGHANDLER_CALLBACK signal_handler;

#endif
