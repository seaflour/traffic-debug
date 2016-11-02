#ifndef TIME_ANALYSIS_H
#define TIME_ANALYSIS_H

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

long currBps;
long avgBps;
long ts;
int totalPktCount;
int pps;

extern const time_t startTime;

void time_analysis(long sec, long usec, int len, int caplen);
void print_analysis(int tpc);

#endif
