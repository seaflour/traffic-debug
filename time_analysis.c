#include "time_analysis.h"

/**
 * calculates packets/second, average bytes/second,
 * keeps count of total packets, total receiving time
 * @param st
 * @param sec
 * @param len
 * @param caplen
 */

void time_analysis(time_t st, long sec, int len, int caplen)
{
    //print_alert(st, 1);

    struct tm *ts;
    char buf[80];
    ts = localtime(&st);

    strftime(buf, 80, "%H:%M:%S", ts);
    //printf("%s\n", buf);
    
    // Record captured packet length.
    caplenCount += caplen;

    // Time in seconds when packet came in.
    updateTime = sec;
    
    // This gets the elapsed time since absStartTime and receiving this packet.
    updateTime -= st;

    // Track the totalTime elapsed since start.
    totalTime += updateTime;

    // Count number of packets we have so far, for use in average.
    totalPktCount++;

    //printf("updateTime2: %f\n", updateTime);

    // Check if we are within the desired window of time to check for disruptions.
    // TODO: tune these metrics for best result.
    if (updateTime >= 7)
    {
        // Check for low pps.
        if ((totalPktCount / updateTime) < 50)
        {
            print_alert(updateTime, 0);
        }

        // Check for low bytes/sec.
        if ((caplenCount / updateTime) < 10000)
        {
            print_alert(updateTime, 1);
        }

        // Set starting time to be the current updateTime and continue
        // measuring from here until we hit the window again.
        absStartTime = updateTime;
    }
    // pps = (totalPktCount / totalTime);
    // avgBps = (len / totalPktCount);
}

/**
 * Print alert message notifying user of 
 * network interruption.
 */
void print_alert(time_t alertTime, int flag)
{
    struct tm *ts;
    char buffer[80];            //buffer to hold formatted time string
    ts = localtime(&alertTime); //fill time struct

    strftime(buffer, 80, "%H:%M:%S", ts);
    if (flag == 0)
    {
        printf("Low pps expereinced at %s\n", buffer);
    }
    else if (flag == 1)
    {
        printf("Low bytes/sec experienced at %s\n", buffer);
    }
}

void init(long sec){
    stFlag = 1;
    totalPktCount = 0;
    caplenCount = 0;
    totalTime = 0;
    updateTime = 0;
    localStartTime = sec;
    absStartTime = localStartTime;
}