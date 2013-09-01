#include "send_file.h"

const int32_t protocol_id = 0x0d355480;

double get_megabytes(int64_t bytes) {
	return(bytes)/(1048576.0);
}

#ifdef __linux__
void print_ip_addresses() {

	struct ifaddrs *addrs = NULL;
	struct ifaddrs *addrs_iter = NULL;

	getifaddrs(&addrs);
	if (!addrs) { fprintf(stderr, "getifaddrs failed (no interfaces -> not connected)!\n"); return; }

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

void *fread_ahead(void *args) {
	fread_ahead_arg_struct s = *(fread_ahead_arg_struct*)args;
	long long i = 0;
	while (i < s.num_runs) {
		fread(s.alternating_buffers[i%2], sizeof(unsigned char), SHA_HASH_CHUNKSIZE, s.fp);
		s.read_done[i%2] = 1;
		++i;
		while (s.read_done[i%2] == 1) {
			SLEEP_MS(40);
		}

	}
	return NULL;
}

#elif _WIN32
unsigned __stdcall fread_ahead(void *args) {

	fread_ahead_arg_struct s = *(fread_ahead_arg_struct*)args;
	long long i = 0;
	while (i < s.num_runs) {
		fread(s.alternating_buffers[i%2], sizeof(unsigned char), SHA_HASH_CHUNKSIZE, s.fp);
		s.read_done[i%2] = 1;
		++i;
		while (s.read_done[i%2] == 1) {
			SLEEP_MS(25);
		}

	}
	return 0;
}
#endif

unsigned char *get_sha1(const char* filename, uint64_t bufsize) {
	FILE *fp = fopen(filename, "rb");
	if (!fp) { 
		fprintf(stderr, "fopen(%s, \"rb\") failed!: %s\n:", filename, strerror(errno)); 
		return NULL; 
	}
	// mmap() has a ~2.8GB limitation on 32-bit linux, so a chunk-based approach must be taken
	SHA_CTX ctx;
	SHA1_Init(&ctx);

	long long num_full_chunks = bufsize/SHA_HASH_CHUNKSIZE;
	long long excess = bufsize%SHA_HASH_CHUNKSIZE;
	int read_done[2] = {0, 0};

	
	thread_struct fread_thread;
	fread_ahead_arg_struct s;
	memset(&s, 0, sizeof(s));
	s.fp = fp;
	s.num_runs = num_full_chunks;
	s.alternating_buffers[0] = (unsigned char*)malloc(SHA_HASH_CHUNKSIZE);
	s.alternating_buffers[1] = (unsigned char*)malloc(SHA_HASH_CHUNKSIZE);
	s.read_done = read_done;

	if (!(s.alternating_buffers[0] && s.alternating_buffers[1])) {
		PRINT_ERROR("malloc()");
		return NULL;
	}

	long long i = 0;
	thread_start(&fread_thread, fread_ahead, &s);
	while (i < num_full_chunks) {
		while (read_done[i%2] == 0) {
			SLEEP_MS(25);
		}
		SHA1_Update(&ctx, s.alternating_buffers[i%2], SHA_HASH_CHUNKSIZE);
		read_done[i%2] = 0;
		++i;
	}

	thread_join(&fread_thread);

	fread(s.alternating_buffers[0], sizeof(unsigned char), excess, fp);
	SHA1_Update(&ctx, s.alternating_buffers[0], excess);

	free(s.alternating_buffers[0]);
	free(s.alternating_buffers[1]);

	fclose(fp);

	unsigned char *outbuf = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
	SHA1_Final(outbuf, &ctx);
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
	fputs(tmpbuf, stderr);
}

int compare_sha1(const unsigned char* sha1_a, const unsigned char* sha1_b) {
	int i = 0;
	for (; i < SHA_DIGEST_LENGTH; ++i) {
		if (sha1_a[i] != sha1_b[i]) {
			return -1;
		}
	}
	return 1;
}


progress_struct construct_pstruct(const int64_t *cur_bytes_addr, int64_t total_bytes, const struct _timer *timer, const int *running_flag_addr) {
	progress_struct p;

	p.cur_bytes = cur_bytes_addr;
	p.total_bytes = total_bytes;
	p.timer = timer;
	p.running_flag = running_flag_addr;

	return p;
}

void print_progress(int64_t cur_bytes, int64_t total_bytes, const struct _timer *timer) {

#ifdef __linux__
	static const char* esc_composite_clear_line_reset_left = "\r\033[0K";	// ANSI X3.64 magic
#elif _WIN32
	static const char *esc_composite_clear_line_reset_left = "\r";	// will have to do :(
#endif	

	fputs(esc_composite_clear_line_reset_left, stderr);

	float progress = 100*(float)(cur_bytes)/(float)(total_bytes);

	// MB/s = (bytes/2^20) : (microseconds/1000000)
	// == (bytes/1048576) * (1000000/microseconds)
	// == (1000000/1048576) * (bytes/microseconds)
	static const float MB_us_coeff = 1000000.0/1048576.0;

	float rate = MB_us_coeff*((float)cur_bytes)/timer_get_us(timer);	
	printf("%lld/%lld bytes transferred (%.2f %%, %.2f MB/s)", (long long)cur_bytes, (long long)total_bytes, progress, rate);
	fflush(stdout);

}

#ifdef __linux__	// for pthreads, the signature is void(*)(void*)
void *progress_callback(void *progress) {
#elif _WIN32
unsigned __stdcall progress_callback(void *progress) {
#endif
	progress_struct *p = (progress_struct*)progress;

	while (*p->cur_bytes < p->total_bytes) {
		int64_t cur_bytes = *p->cur_bytes;
		int64_t total_bytes = p->total_bytes;

		if (*p->running_flag == 0) {
			fprintf(stderr, "\nTransfer aborted!\n");
			print_progress(cur_bytes, total_bytes, p->timer);
			return NULL;
		}

		print_progress(cur_bytes, total_bytes, p->timer);
		SLEEP_S(1);
	}

	return NULL;
}
