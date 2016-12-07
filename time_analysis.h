#ifndef TIME_ANALYSIS_H
#define TIME_ANALYSIS_H

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

int stFlag;
int firstUsecFlag;
int tempPktCount;
int totalPktCount;
int totalCaplen;
int tempCaplen;

double avgBps;
double pps;
double updateTime;
double firstUsec;
double lastUsec;

time_t absStartTime;   // This is the start time that will be updated as we advance the window.
time_t localStartTime; // This is the start time of the first packet that came in.
time_t endTime;        // Hold the final time when the last packet comes in.

void init(long sec);
void time_analysis(time_t t, long sec, long usec, int caplen);
void print_alert(time_t at, long usec, int flag);
double getTotalTime(time_t t1, time_t t2);
void printStats();

#endif
