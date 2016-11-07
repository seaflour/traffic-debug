#ifndef TIME_ANALYSIS_H
#define TIME_ANALYSIS_H

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

long avgBps;
long ts;
int totalPktCount;
int pps;

#define START_TIME time(NULL)
time_t totalTime;

void time_analysis(time_t t, long sec, long usec, int len, int caplen);
void print_analysis(int len);
void print_alert(time_t at, int flag);

#endif