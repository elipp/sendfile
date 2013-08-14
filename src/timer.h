#ifndef TIMER_H
#define TIMER_H

#include <sys/time.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

struct _timer {
	double cpu_freq;	// in kHz
	__int64 counter_start;

	__int64 get() const {
		LARGE_INTEGER li;
		QueryPerformanceCounter(&li);
		return li.QuadPart;
	}
	bool init() {
		LARGE_INTEGER li;
		QueryPerformanceFrequency(&li);
		cpu_freq = double(li.QuadPart);	// in Hz. this is subject to dynamic frequency scaling, though
		begin();
		return true;
	}
	void begin() {
		LARGE_INTEGER li;
		QueryPerformanceFrequency(&li);
		cpu_freq = double(li.QuadPart);
		QueryPerformanceCounter(&li);
		counter_start = li.QuadPart;
	}


	inline double get_s() const {	
		return double(_timer::get()-_timer::counter_start)/_timer::cpu_freq;
	}
	inline double get_ms() const {
		return double(1000*(_timer::get_s()));
	}
	inline double get_us() const {
		return double(1000000*(_timer::get_s()));
	}
	_timer() {
		if (!init()) { fprintf(stderr, "_timer error.\n"); }
	}
};


#elif __linux__

struct _timer {
	struct timeval beg;
	
	void (*begin)(struct _timer*);
	double (*get_us)(const struct _timer*);
	double (*get_ms)(const struct _timer*);
	double (*get_s)(const struct _timer*);
};

void timer_begin(struct _timer* timer);
double timer_get_us(const struct _timer* timer);
double timer_get_ms(const struct _timer* timer);
double timer_get_s(const struct _timer* timer);

struct _timer timer_construct();

#endif

#endif
