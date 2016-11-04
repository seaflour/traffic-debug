#include "time_analysis.h"

/**
 * calculates packets/second, average bytes/second,
 * keeps count of total packets, total receiving time
 * @param st
 * @param sec
 * @param usec
 * @param len
 * @param caplen
 */

void time_analysis(time_t st, long sec, long usec, int len, int caplen)
{
    // Get total seconds since epoch that packet came in.
    // This should be subtracted from the global starting localtime.
    ts += sec + (usec / 1000000);

    // This gets the elapsed time since start and receiving this packet.
    ts = ts - st;

    totalTime += ts;

    // Count number of packets we have so far, for use in average.
    totalPktCount++;
}

/**
 * outputs calculated data from time_analysis function
 */
void print_analysis(int len)
{
    pps = (totalPktCount / totalTime);
    avgBps = (len / totalPktCount);
    printf("Average bytes/sec: %ld\n", avgBps);
    printf("Total time(seconds): %ld\n", totalTime);
    printf("Total Packets: %d\n", totalPktCount);
    printf("PacketsPerSecond: %d\n", pps);
}