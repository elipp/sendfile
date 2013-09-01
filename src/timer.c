#include "timer.h"

#ifdef _WIN32

struct _timer timer_construct() {
	struct _timer timer;
	timer_begin(&timer);
	return timer;
}

static __int64 timer_get(const struct _timer *timer) {
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	return li.QuadPart;
}
void timer_begin(struct _timer *timer) {
	LARGE_INTEGER li;
	QueryPerformanceFrequency(&li);
	timer->cpu_freq = double(li.QuadPart);
	QueryPerformanceCounter(&li);
	timer->counter_start = li.QuadPart;
}

double timer_get_s(const struct _timer *timer) {	
	return double(timer_get(timer) - timer->counter_start)/timer->cpu_freq;
}
double timer_get_ms(const struct _timer *timer) {
	return double(1000*(timer_get_s(timer)));
}
double timer_get_us(const struct _timer *timer) {
	return double(1000000*(timer_get_s(timer)));
}

#elif __linux__

struct _timer timer_construct() {
	struct _timer r;
	memset(&r, 0, sizeof(r));
	gettimeofday(&r.beg, NULL);	
	return r;
}

void timer_begin(struct _timer* timer) {
	gettimeofday(&timer->beg, NULL);
}
	
double timer_get_us(const struct _timer* timer) {
	struct timeval end;
	memset(&end, 0, sizeof(end));
	gettimeofday(&end, NULL);
	return (end.tv_usec + end.tv_sec*1000000) - (timer->beg.tv_usec + timer->beg.tv_sec*1000000);
}

double timer_get_s(const struct _timer* timer) {
	return timer_get_us(timer)/1000000.0;
}
	
double timer_get_ms(const struct _timer* timer) {
	return timer_get_us(timer)/1000.0;
}
	
#endif


