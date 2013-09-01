#ifndef TIMER_H
#define TIMER_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>

struct _timer {
	double cpu_freq;	// in kHz
	__int64 counter_start;
};

#elif __linux__
#include <sys/time.h>

struct _timer {
	struct timeval beg;
};

#endif

struct _timer timer_construct();

void timer_begin(struct _timer* timer);
double timer_get_us(const struct _timer* timer);
double timer_get_ms(const struct _timer* timer);
double timer_get_s(const struct _timer* timer);

#endif

