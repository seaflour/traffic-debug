#ifndef TIME_ANALYSIS_H
#define TIME_ANALYSIS_H

// The start should be the time of the first packet's arrival.
#define START_TIME time(NULL)

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

int totalPktCount;
int caplenCount;

double avgBps;
double pps;
double totalTime;
double updateTime;

struct timeval end;
struct timeval diff;

time_t absStartTime;

void time_analysis(time_t t, long sec, long usec, int len, int caplen);
void print_alert(time_t at, int flag);

#endif