#include "detect_stream.h"

int dns_lookup(char *addr, char *hostname) {
    FILE *fp;
    char command[1024];
    char buffer[1024];

    /* from nslookup i.ytimg.com */
    /* these addresses resolve to cache.google.com but are not youtube streams */
    char *iplist[15] = {"68.65.124.53",
        "68.65.124.42",
        "68.65.124.34",
        "68.65.124.27",
        "68.65.124.23",
        "68.65.124.29",
        "68.65.124.59",
        "68.65.124.19",
        "68.65.124.38",
        "68.65.124.49",
        "68.65.124.15",
        "68.65.124.44",
        "68.65.124.57",
        "68.65.124.30",
        "68.65.124.45"};

    /* check against known false positives from i.ytimg.com */
    for (int i = 0; i < 15; i++) {
        if (strcmp(addr, iplist[i]) == 0)
            return -1;
    }

    /* create command string */
    sprintf(command, "host %s | cut -d' ' -f5 | head -c -1", addr);

    /* execute command and open fp for reading result */
    fp = popen(command, "r");

    if (fp == NULL) {
        return 0;
    }

    /* read the output of the command */
    fgets(buffer, sizeof (buffer) - 1, fp);

    pclose(fp);

    return strcmp(buffer, hostname);
}
