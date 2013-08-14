#include "timer.h"

#ifdef __linux__

struct _timer timer_construct() {
	
	struct _timer r;
	memset(&r, 0, sizeof(r));
	r.begin = timer_begin;
	r.get_us = timer_get_us;
	r.get_ms = timer_get_ms;
	r.get_s = timer_get_s;
		
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
	return timer->get_us(timer)/1000000.0;
}
	
double timer_get_ms(const struct _timer* timer) {
	return timer->get_us(timer)/1000.0;
}
	
#endif


