#include "send_file.h"

static int local_sockfd = -1;
static int remote_sockfd = -1;
static NATIVE_FILEHANDLE outfile_fd;

static int allow_checksum_skip_flag = 0;
static int always_accept_flag = 0;

static int running = 0;
static unsigned short port = DEFAULT_PORT;

static int progress_bar_flag = 1;
static progress_struct p;
static thread_struct progress_thread;

#define CLOSE_VALID_FILEHANDLE(fd) do {\
	if (!(NATIVE_FILEHANDLE_INVALID(fd))) { close_file_object_native(fd); }\
	INVALIDATE_FILEHANDLE(fd);\
	} while(0)

static void reset_state() {
	CLOSE_SOCKET(remote_sockfd);
	CLOSE_VALID_FILEHANDLE(outfile_fd);
}

void cleanup() {
	reset_state();
	CLOSE_SOCKET(local_sockfd);
}

static int validate_protocol_welcome_header(const char* buf, size_t buf_size) {
	int id;
	memcpy(&id, buf, sizeof(id));

	if (id != protocol_id) { return -1; }
	return 0;
}

static int get_headerinfo(const char* buf, size_t buf_size, HEADERINFO *h) {
	memset(h, 0, sizeof(HEADERINFO));
	int64_t accum = 0;
	memcpy(&h->protocol_id, buf, sizeof(h->protocol_id));
	accum += sizeof(h->protocol_id);

	memcpy(&h->filesize, buf + accum, sizeof(h->filesize));
	accum += sizeof(h->filesize);

	memcpy(&h->sha1_included, buf+accum, sizeof(h->sha1_included));
	accum += sizeof(h->sha1_included);

	h->filename = strdup(buf + accum);
	if (!h->filename) { 
		fputs("\nError: extracting file name from header info failed. Bad header?\n", stderr);
		return -1;
	}
	int name_len = strlen(h->filename);
	accum += name_len + 1;
	memcpy(&h->sha1[0], buf + accum, SHA_DIGEST_LENGTH);

	return 0;


}	

static int consolidate(int out_sockfd, int flag) {
	char hacknowledge_buffer[8];
	memcpy(hacknowledge_buffer, &protocol_id, sizeof(protocol_id));
	memcpy(hacknowledge_buffer+sizeof(protocol_id), &flag, sizeof(flag));	
	int sent_bytes = send(out_sockfd, hacknowledge_buffer, 8, 0);
	if (sent_bytes <= 0) { 
		PRINT_SOCKET_ERROR("send()");
	}
	return sent_bytes;
}


static int64_t recv_file(int sockfd, NATIVE_FILEHANDLE outfile_fd, int64_t filesize) {

	int64_t total_bytes_processed = 0;	

	struct _timer timer = timer_construct();

	if (progress_bar_flag == 1) {
		p = construct_pstruct(&total_bytes_processed, filesize, &timer, &running);
		thread_start(&progress_thread, progress_callback, (void*)&p);
	}

#define JOIN_PROGRESS_THREAD_RETURN(retval) do {\
       	running = 0;\
		if (progress_bar_flag == 1) thread_join(&progress_thread);\
       	return (retval); } while(0)

	splice_struct sp;
	if (splice_struct_construct(&sp) < 0) {
		return -1;
	}

	while (total_bytes_processed < filesize && running == 1) {
		int64_t bytes;
		if ((bytes = splice_from_socket_to_file(sockfd, outfile_fd, &sp, filesize, total_bytes_processed)) < 0) {
			JOIN_PROGRESS_THREAD_RETURN(-1);
		}
		total_bytes_processed += bytes;
	}
	if (total_bytes_processed != filesize) {
		fputs("\nwarning: total_bytes_processed != filesize!\n", stderr);
	}

	splice_struct_cleanup(&sp);
	
	if (progress_bar_flag == 1) {
		running = 0;
		thread_join(&progress_thread);
	}

	double seconds = timer_get_us(&timer)/1000000.0;
	double MBs = get_megabytes(total_bytes_processed)/seconds;
	double percent = 100.0*(double)total_bytes_processed/(double)filesize;

	fprintf(stderr, "\nReceived %.2f MB of %.2f MB (%.2f%%) in %.3f seconds (%.2f MB/s).\n\n", 
	get_megabytes(total_bytes_processed), 
	get_megabytes(filesize), percent, seconds, MBs);

	return total_bytes_processed;

}

static void make_lowercase(char *arr, int length) {
	int i = 0;
	for (; i < length; ++i) {
		arr[i] = tolower(arr[i]);
	}
}

static int ask_user_consent() {
	UNBUFFERED_PRINTF("Is this ok? [y/N] ");
	char buffer[128];
	buffer[127] = '\0';
	int index;
	char c;
get_answer:
	index = 0;
	while ((c = getchar()) != '\n') {
		buffer[index] = c;
		if (index < 127) {
			++index;
		}
	}
	
	buffer[index] = '\0';
	make_lowercase(buffer, index);

	if (strcmp(buffer, "y") == 0) {
		return 1;
	}
	else if (strcmp(buffer, "n") == 0) {
		return 0;
	}
	else { 
		UNBUFFERED_PRINTF("Unknown answer \"%s\". [y/N]?", buffer);
		goto get_answer; // ;)
	} 

}


void usage() {
	fputs("send_file_server usage:  send_file_server [[ OPTIONS ]]\n"\
			"Options:\n"\
		        " -a\t\talways accept transfers\n"\
			" -b\t\tdisable progress monitoring (default: enabled)\n"\
		        " -c\t\tallow program to skip checksum verification\n"\
		        " -p PORTNUM\tspecify port (default 51337)\n"\
		        " -h\t\tdisplay this help and exit.\n", stderr);
}

int main(int argc, char* argv[]) {

	int c;
	char *strtol_endptr;
	while ((c = getopt(argc, argv, "abchp:")) != -1) {
		switch(c) {
			case 'a':
				puts("-a provided -> always accepting file transfers without asking for consent.");
				always_accept_flag = 1;
				break;
			case 'b':
				puts("-b provided -> progress monitoring disabled.");	
				progress_bar_flag = 0;
				break;

			case 'c':
				puts("-c provided -> allowing program to skip checksum verification.");
				allow_checksum_skip_flag = 1;
				break;
			case 'h':
				usage();
				return 0;
				break;
			case 'p':
				port = strtol(optarg, &strtol_endptr, 0);	// base-10 
				if (strtol_endptr == optarg || *strtol_endptr != '\0') {
					// endptr != '\0' indicates only a part of the string was used in the conversion
					fprintf(stderr, "Invalid port specification \"%s\", attempting to use default port %d instead.\n", optarg, DEFAULT_PORT);
					port = DEFAULT_PORT;
				}
				break;
			case '?':
				fprintf(stderr, "warning: unknown option \'-%c\n\'", optopt);
				break;
			default:
				abort();
		}
	}
	
	setup_signal_handler(signal_handler);
	struct sockaddr_in local_saddr, remote_saddr;

#ifdef _WIN32
	if (!init_WSOCK()) {
		return -1;
	}
#endif

	local_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (local_sockfd < 0) {
		PRINT_SOCKET_ERROR("socket()");
		return 1;
	}

	memset(&local_saddr, 0, sizeof(local_saddr));
	memset(&remote_saddr, 0, sizeof(remote_saddr));

	local_saddr.sin_family = AF_INET;
	local_saddr.sin_addr.s_addr = INADDR_ANY;
	local_saddr.sin_port = htons(port);

	if (bind(local_sockfd, (struct sockaddr*) &local_saddr, sizeof(local_saddr)) < 0) {
		PRINT_SOCKET_ERROR("bind()");
		return 1;
	}

	printf("send_file_server (recipient)\n\n");
	print_ip_addresses();
	printf("bind() on port %d.\n", (int)port);
	listen(local_sockfd, 5);

	char handshake_buffer[128];

	running = 1;

	while (running == 1) {
		fputs("\nListening for incoming connections.\n", stderr);

		socklen_t remote_saddr_size = sizeof(remote_saddr);
		remote_sockfd = accept(local_sockfd, (struct sockaddr *) &remote_saddr, &remote_saddr_size);
		if (remote_sockfd < 0) {
			PRINT_SOCKET_ERROR("accept()");
			reset_state();
			continue;
		}

		char ip_buf[32];
		inet_ntop(AF_INET, &(remote_saddr.sin_addr), ip_buf, sizeof(ip_buf));
		printf("Client connected from %s.\n", ip_buf);

		int received_bytes = 0;	
		int handshake_len = recv(remote_sockfd, handshake_buffer, sizeof(handshake_buffer), 0);

		if (handshake_len <= 0) {
			if (handshake_len < 0) fprintf(stderr, "error: recv: %s\n", strerror(errno));
			else fprintf(stderr, "recv: remote has performed an orderly shutdown.\n"); 
			reset_state();
			continue;
		}
		received_bytes += handshake_len;

		if (validate_protocol_welcome_header(handshake_buffer, handshake_len) < 0) {
			fputs("\nwarning: validate_protocol_welcome_header failed!\n", stderr);
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			reset_state();
			continue;
		}

		HEADERINFO h;

		if (get_headerinfo(handshake_buffer, handshake_len, &h) < 0) {
			fputs("\nerror: headerinfo error!\n", stderr);
			consolidate(remote_sockfd, HANDSHAKE_FAIL);
			reset_state();
			continue;
		}

		if (h.sha1_included == 0 && allow_checksum_skip_flag == 0) {
			fputs("\nerror: client didn't provide a sha1 hash for the input file (-c was used; use -c on the server to allow this). Rejecting.\n", stderr);
			consolidate(remote_sockfd, HANDSHAKE_CHECKSUM_REQUIRED);
			reset_state();
			continue;
		}

		char *out_name = get_available_filename(h.filename);

		fprintf(stderr, "The client wants to send the file %s (size %.2f MB).\n", h.filename, get_megabytes(h.filesize)); 

		if (always_accept_flag == 0) {
			if (!ask_user_consent()) { 
				consolidate(remote_sockfd, HANDSHAKE_DENIED); 
				free(out_name);
				reset_state();
				continue;
			}
		}

		fprintf(stderr, "Writing to output file %s.\n\n", out_name);
		outfile_fd = open_file_object_wb_native(out_name);

		if (NATIVE_FILEHANDLE_INVALID(outfile_fd)) {
			free(out_name);
			reset_state();
			return -1;
		}

		free(out_name);


		// inform the client program that they can start blasting dat file data

		/*
		int rcvbuf_size = 64*1024 - 1;
		if (setsockopt(remote_sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
			fprintf(stderr, "Warning: setsockopt SO_RCVBUF->%d failed: %s\n", rcvbuf_size, strerror(errno));
		}
		*/

		consolidate(remote_sockfd, HANDSHAKE_OK);

		int64_t ret;
		if ((ret = recv_file(remote_sockfd, outfile_fd, h.filesize)) != h.filesize) {
			if (ret < 0) {
				fputs("\nrecv_file failure.\n", stderr);
			}
			else {
				fprintf(stderr, "recv_file: warning: received data size (%lld) is less than expected (%lld)!\n", (long long)ret, (long long)h.filesize);
			}
			reset_state();
			continue;
		}
		
		CLOSE_VALID_FILEHANDLE(outfile_fd);

		if (h.sha1_included && allow_checksum_skip_flag == 0) {
			fputs("Calculating sha1 sum...\n", stderr);
			unsigned char* sha1_received = get_sha1(h.filename, h.filesize);
			
			if (compare_sha1(h.sha1, sha1_received) < 0) {
				fputs("WARNING! sha1 mismatch!\n", stderr);
				return 1;
			}

			fputs("sha1 sums match! =)\nexpected \t",stderr);
			print_sha1(h.sha1);
			fputs(",\ngot \t\t",stderr);
			print_sha1(sha1_received);
			fputs(".\n\n", stderr);

			free(sha1_received);
		}
		else {
			fputs("(skipping checksum verification)\n", stderr);
		}
		printf("Success.\n");

		free(h.filename);
		reset_state();

	}

	cleanup();
	return 0;

}
