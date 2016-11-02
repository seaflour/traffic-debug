#include "time_analysis.h"

/**
 * calculates bytes/second, packets/second,
 * average bytes/second
 * @param sec
 * @param usec
 * @param len
 * @param caplen
 */
const startTime = time(NULL); //sets global constant to the current system time

void time_analysis(long sec, long usec, int len, int caplen) {

    //get total seconds since epoch that packet came in
    //this should be subtracted from the global starting localtime
    ts += sec + (usec / 1000000);

    //this should get elapsed time since start and when received this packet
    ts = ts - startTime;

    //calculate the current bytes/second for this individual packet
    currBps += (caplen / ts);

    //keep running count of the average bps for output later
    avgBps = ((avgBps + currBps) / totalPktCount);

    //count number of packets we have so far, for use in average
    totalPktCount++;
}

/**
 * outputs calculated data from time_analysis function
 */
void print_analysis(int tpc) {
    printf("Average Bytes/sec: %ld\n", avgBps);
    printf("Total time(seconds): %ld\n", ts);
    printf("Total Packets: %d\n", tpc);
}