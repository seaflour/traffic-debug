#include "time_analysis.h"

// Tracks total packet count, final packet's endTime,
// checks within a window of time for low bps and/or pps.
// st - time of last checked packet.
// sec - current packet's arrival time to second precision.
// usec - current packet's arrival time to microsecond precision.
// caplen - current packet's byte count.
void time_analysis(time_t st, long sec, long usec, int caplen)
{
    // Store the usec part of the first packet's time.
    if (firstUsecFlag == 0)
    {
        firstUsec = (usec / 1000000.00);
        firstUsecFlag = 1;
    }

    // Record captured packet length.
    totalCaplen += caplen;
    tempCaplen += caplen;
    // Time(seconds) when packet came in and gets the elapsed time
    // since absStartTime and receiving this packet.
    updateTime = (sec - st);

    // Count number of packets we have so far, for use in average.
    totalPktCount++;
    tempPktCount++;
    // Check if we are within the desired window of time to check for disruptions.
    if (updateTime >= 3)
    {
        //printf("Irregular packet arrival time!\n");
        // Check for low pps.
        if ((tempPktCount / updateTime) < 50)
        {
            print_alert(sec, usec, 0);
        }

        // Check for low bytes/sec.
        if ((tempCaplen / updateTime) < 10000)
        {
            print_alert(sec, usec, 1);
        }

        // Set starting time to be the current updateTime and continue
        // measuring from here until we hit the window again.
        absStartTime = sec;
        tempPktCount = 0;
        tempCaplen = 0;
    }

    // Track the final time of a packet arrival.
    endTime = sec;
    // Store the usec part of the final packet's time.
    lastUsec = (usec / 1000000.00);
}

// Print alert message notifying user of
// network interruption.
// alertTime - time within window that set off the check.
// usec - microsecond part of time.
// flag - indicates whether it is a bps or pps check.
void print_alert(time_t alertTime, long usec, int flag)
{
    struct tm *ts;
    char buffer[80];            //buffer to hold formatted time string
    ts = localtime(&alertTime); //fill time struct

    // I print usec on a separate line because there is no usec part
    // in strftime so we print and concatenate the output to strftime's
    // formatted output.
    strftime(buffer, 80, "%H:%M:%S", ts);
    if (flag == 0)
    {
        printf("[%d] Low pps expereinced at %s", totalPktCount, buffer);
        printf(".%.6ld\n", usec);
    }
    else if (flag == 1)
    {
        printf("[%d] Low bytes/sec experienced at %s", totalPktCount, buffer);
        printf(".%.6ld\n", usec);
    }
}

// Calculates the total time since start and endTime.
// t1 - starting time.
// t2 - end time.
double getTotalTime(time_t t1, time_t t2)
{
    return (t2 - t1);
}

// Print calculated information.
void printStats()
{
    printf("\nTotal Packets: %d\n", totalPktCount);
    printf("Time span (seconds): %.3f\n", (getTotalTime(localStartTime, endTime) + (lastUsec - firstUsec)));
    printf("Average packets/sec: %.2lf\n", (totalPktCount / (getTotalTime(localStartTime, endTime) + (lastUsec - firstUsec))));
    printf("Total Bytes: %d\n", totalCaplen);
    printf("Average bytes/sec: %.2lf\n", (totalCaplen / (getTotalTime(localStartTime, endTime) + (lastUsec - firstUsec))));
}

// Initialize global variables.
void init(long sec)
{
    avgBps = 0;
    pps = 0;
    stFlag = 1;
    totalPktCount = 0;
    tempPktCount = 0;
    totalCaplen = 0;
    updateTime = 0;
    firstUsec = 0;
    firstUsecFlag = 0;
    lastUsec = 0;
    localStartTime = sec;
    absStartTime = localStartTime;
}