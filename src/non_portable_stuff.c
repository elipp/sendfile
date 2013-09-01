#include "non_portable_stuff.h"
#include "send_file.h"

extern void cleanup();

#ifdef _WIN32

BOOL __stdcall sighandler(DWORD param) {
		switch(param) {
		 case CTRL_CLOSE_EVENT:
			 return TRUE;			
			 cleanup();
			 exit(1);
			 break;
		 case CTRL_C_EVENT:
			 cleanup();
			 exit(1);
			 break;
		 default:
			 return FALSE;
			 break;
	}
}

int init_WSOCK() {

	int ret;
	WSAData wsaData;
	ret = WSAStartup(MAKEWORD(2,2), &wsaData);

	if (ret != 0) {
		PRINT_SOCKET_ERROR("WSAStartup");
		return 0;
	}
	return 1;
}

#elif __linux__

void sighandler(int sig) {
	if (sig == SIGINT) {
		fprintf(stderr, "\nReceived SIGINT. Aborting.\n");
		cleanup();
		exit(2);
	}
}

#endif

SIGHANDLER_CALLBACK signal_handler = sighandler;

#ifdef _WIN32
void thread_start(thread_struct *t, CALLBACK_FUNC cb, void *args) {
	t->handle = (HANDLE)_beginthreadex(NULL, NULL, cb, args, 0, 0);
}
 void thread_join(thread_struct *t) {
	WaitForSingleObject(t->handle, NULL);
	CloseHandle(t->handle);
}

char *get_error_message(DWORD errcode) {
	static char lpBuffer[256];
	if (errcode != 0) {
		FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode, MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT), 
		lpBuffer, sizeof(lpBuffer)-1, NULL);
	}
	return lpBuffer;

}

#elif __linux__
void thread_start(thread_struct *t, CALLBACK_FUNC cb, void* args) {
	pthread_create(&t->handle, NULL, cb, args);
}

void thread_join(thread_struct *t) {
	pthread_join(t->handle, NULL);
}
#endif

#ifdef _WIN32

int splice_struct_construct(splice_struct *sp) {
	sp->buffer = (char*)malloc(CHUNK_SIZE);
	if (!sp->buffer) {
		PRINT_ERROR("malloc()");
		return -1;
	}
	sp->buffer_size = CHUNK_SIZE;
	return 1;
}
void splice_struct_cleanup(splice_struct *sp) {
	free(sp->buffer);
}
#elif __linux__

int splice_struct_construct(splice_struct *sp) {

	if (pipe(sp->pipefd) < 0) {
		PRINT_ERROR("pipe()");
		return -1;
	}

	return 1;
}
void splice_struct_cleanup(splice_struct *sp) {
	close(sp->pipefd[1]);
	close(sp->pipefd[0]);
}

#endif



#ifdef _WIN32
int64_t splice_from_socket_to_file(int sockfd, NATIVE_FILEHANDLE fh, splice_struct *sp, int64_t filesize, int64_t total_bytes_processed) {

	int64_t bytes_recv = 0;
	int64_t bytes = 0;
	
	if ((bytes = recv(sockfd, sp->buffer, sp->buffer_size, 0)) < 0) {
			PRINT_SOCKET_ERROR("recv()");
			return bytes;
	}	
	DWORD bytes_written;
	if (!WriteFile(fh, sp->buffer, bytes, &bytes_written, NULL)) {
		PRINT_ERROR("WriteFile()");
		return -1;
	}
	return bytes_written;
}

#elif __linux__
int64_t splice_from_socket_to_file(int sockfd, NATIVE_FILEHANDLE fh, splice_struct *sp, int64_t filesize, int64_t total_bytes_processed) {
	
	static const int spl_flag = SPLICE_F_MORE | SPLICE_F_MOVE;
	
	int64_t bytes_recv = 0;
	int64_t bytes = 0;

	int64_t would_process = filesize - total_bytes_processed;
	int64_t gonna_process = MIN(would_process, CHUNK_SIZE);

	// splice to pipe write head
	if ((bytes = 
	splice(sockfd, NULL, sp->pipefd[1], NULL, gonna_process, spl_flag)) <= 0) {
		if (bytes < 0) {
			PRINT_SOCKET_ERROR("splice");
			return bytes;
		}
		else fprintf(stderr, "warning: a 0-byte socket->pipe_write splice has occurred!\n"); 
	}
	// splice from pipe read head to file fh
	bytes_recv += bytes;

	int64_t bytes_in_pipe = bytes_recv;
	int64_t bytes_written = 0;

	while (bytes_in_pipe > 0) {
		if ((bytes_written = 
		splice(sp->pipefd[0], NULL, fh, &total_bytes_processed, bytes_in_pipe, spl_flag)) <= 0) {
			PRINT_SOCKET_ERROR("splice()");
			return -1;
		}
		bytes_in_pipe -= bytes_written;
	}
	
	return bytes;

}
#endif

#ifdef _WIN32
int64_t send_chunk(int sockfd, NATIVE_FILEHANDLE fh, int64_t gonna_send, int64_t total_bytes_sent) {
	
	static const DWORD TF_FLAGS = TF_USE_KERNEL_APC;

	if (!TransmitFile(sockfd, fh, gonna_send, 0, NULL, NULL, TF_FLAGS)) {
		PRINT_SOCKET_ERROR("TransmitFile");
		return -1;
	}	
	// the fh has to be manually fseek()d :(
	LARGE_INTEGER tb;
	tb.QuadPart = (LONGLONG)(total_bytes_sent + gonna_send);
	SetFilePointerEx(fh, tb, NULL, FILE_BEGIN);
	
	return gonna_send;
}
#elif __linux__
int64_t send_chunk(int sockfd, NATIVE_FILEHANDLE fh, int64_t gonna_send, int64_t total_bytes_sent) {
	int64_t sent_bytes;

	// sendfile should automatically increment the file offset pointer for fh
	if ((sent_bytes = sendfile(sockfd, fh, NULL, gonna_send)) < gonna_send) {
		if (sent_bytes < 0) {
			PRINT_SOCKET_ERROR("sendfile()");
			return sent_bytes;
		}
		else {
			fprintf(stderr, "sent_bytes < filesize (!), transfer cancelled by remote.\n");
		}
		return -1;
	}
	return sent_bytes;
}
#endif

#ifdef __linux__
#define HANDLE int64_t*
void *my_mmap_readonly_shared(int opened_fd, int64_t filesize, HANDLE *fm) {
		unsigned char* block = (unsigned char*)mmap(NULL, filesize, PROT_READ, MAP_SHARED, opened_fd, 0);
		if (block == MAP_FAILED) { 
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
void *native_mmap_readonly_shared(HANDLE opened_filehandle, int64_t filesize, HANDLE *fm) {
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

void native_munmap(void *block, int64_t size, HANDLE fm) {
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
	_splitpath(full_filename, NULL, NULL, filename_base, file_ext);
	char basename[_MAX_FNAME+_MAX_EXT+1];
	sprintf(basename, "%s%s", filename_base, file_ext);

	return _strdup(basename);

}
#endif

#ifdef __linux__
char *get_available_filename(const char* orig_filename) {
	char name_buf[128];
	strcpy(name_buf, orig_filename);
	name_buf[strlen(orig_filename)] = '\0';
	int num = 1;
	while (access(name_buf, F_OK) != -1) {
		// file exists, rename using the (#) scheme
		int bytes = sprintf(name_buf, "%s(%d)", orig_filename, num);
		name_buf[bytes] = '\0';
		++num;
	}
	return strdup(name_buf);
}

#elif _WIN32

static BOOL file_exists(LPCTSTR szPath) {
  DWORD dwAttrib = GetFileAttributes(szPath);
  return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

char *get_available_filename(const char* orig_filename) {
	char filename[FILENAME_MAX];
	strcpy(filename, orig_filename);

	int num = 1;
	while (file_exists(filename)) {
		sprintf(filename, "%s(%d)\0", orig_filename, num);
		++num;
	}
	return strdup(filename);
}
#endif

#ifdef __linux__

NATIVE_FILEHANDLE open_file_object_wb_native(char *filename) {
	NATIVE_FILEHANDLE fh = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

	if (fh < 0) {
		PRINT_ERROR("open()");
	}
	return fh;
}

NATIVE_FILEHANDLE open_file_object_rb_native(char *filename) {
	NATIVE_FILEHANDLE fh = open(filename, O_RDONLY);
	if (fh < 0) {
		PRINT_ERROR("open()");
	}
	return fh;
}

void close_file_object_native(NATIVE_FILEHANDLE fh) {
	close(fh);
}

#elif _WIN32
NATIVE_FILEHANDLE open_file_object_wb_native(char *filename) {

	NATIVE_FILEHANDLE fh = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (fh == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "open_file_object_wb_native(%s) failed.\n", filename);
		PRINT_ERROR("CreateFile()");
	}
	return fh;
}

NATIVE_FILEHANDLE open_file_object_rb_native(char *filename) {
	NATIVE_FILEHANDLE fh = CreateFile(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);		
	if (fh == INVALID_HANDLE_VALUE) {		
		fprintf(stderr, "open_file_object_rb_native(%s) failed.\n", filename);
		PRINT_ERROR("CreateFile()");
	}
	return fh;
}

void close_file_object_native(NATIVE_FILEHANDLE fh) {
	CloseHandle(fh);
}

#endif

#ifdef __linux__
void setup_signal_handler(SIGHANDLER_CALLBACK cb) {
	
	struct sigaction new_action, old_action;
	new_action.sa_handler = cb;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		sigaction(SIGINT, &new_action, NULL);
	}

}

#elif _WIN32
void setup_signal_handler(PHANDLER_ROUTINE cb) {
	SetConsoleCtrlHandler(cb, TRUE);	
}
#endif

#ifdef __linux__
uint64_t get_filesize(char *filename) {
	NATIVE_FILEHANDLE fh = open_file_object_rb_native(filename);	
	if (NATIVE_FILEHANDLE_INVALID(fh)) {
		return -1;
	}
	struct stat st;
	fstat(fh, &st);
	close_file_object_native(fh);
	return (uint64_t)(st.st_size);
}

#elif _WIN32
uint64_t get_filesize(char* filename) {
	LARGE_INTEGER filesize;
	NATIVE_FILEHANDLE fh = open_file_object_rb_native(filename);
	if (NATIVE_FILEHANDLE_INVALID(fh)) {
		return -1;
	}
	if (!GetFileSizeEx(fh, &filesize)) {
		fprintf(stderr, "GetFileSizeEx failed: %s.\n", get_error_message(GetLastError()));
		close_file_object_native(fh);
		return -1;
	}
	close_file_object_native(fh);
	return (uint64_t)filesize.QuadPart;
}
#endif


