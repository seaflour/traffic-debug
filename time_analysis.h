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
int totalPktCount;
int caplenCount;

double avgBps;
double pps;
double totalTime;
double updateTime;

time_t localStartTime; // This is the start time of the first packet that came in.
time_t absStartTime; // This is the start time that will be updated as we advance the window. 

void init(long sec);
void time_analysis(time_t t, long sec, int len, int caplen);
void print_alert(time_t at, int flag);

#endif