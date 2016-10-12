/*
 * trd217
 * from http://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
 * test program for captureing tcp packets
 *
 */

#include <arpa/inet.h>
#include "detect-stream.h"
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 1;
    printf("Packet number [%d]\ttime: %ld %ldl\n", count++, (long int) (pkthdr->ts.tv_sec), (long int) (pkthdr->ts.tv_usec));
}

void usage(int code) {
    fprintf(stderr, "traffic-debug - detect interruptions in video streams\n");
    fprintf(stderr, "Usage: traffic-debug [OPTIONS] [device]\n");
    fprintf(stderr, "\nOPTIONS\n\t-h\tprint this text\n");
    exit(code);
}

/**
 * mjc714
 * logs packets to file
 * TODO: format and implement proper filter for YT stream traffic
 * move this into callback so that pcap_loop will act on this too-
 * to write the packets as it prints it out?
 * Or maybe have 2 loop/dispatch listening on the device-
 * one to log the packets?
 * @param cp - 'savefile' handle
 * @param fname - file name
 */
void packetLog(pcap_t *cp, const char *fname) {
    pcap_dumper_t pdt;

    //try to open the file to save packets to else
    //could not open the file or some other reason, return NULL
    if ((pdt = pcap_dump_fopen(cp, fname)) == NULL) {
        fprintf(stderr, "%s\n", pcap_geterr(cp));
        exit(EXIT_FAILURE);
    }

    //close the file handle
    pcap_dump_close();
}

int main(int argc, char **argv) {
    int opt;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program fp; /* to hold compiled program */
    bpf_u_int32 pMask; /* subnet mask */
    bpf_u_int32 pNet; /* ip address */
    char *device;

    // Check if sufficient arguments were supplied
    if (argc < 2) {
        usage(1);
    }


    // Parse command line options
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h':
                usage(0);
                break;
            default:
                usage(1);
        }
    }

    // The last option must be the device name
    device = argv[argc - 1];

    printf("\nStarting capture on device [%s]...\n", argv[1]);

    // fetch the network address and network mask
    pcap_lookupnet(device, &pNet, &pMask, errbuf);

    // open device for sniffing
    descr = pcap_open_live(device, BUFSIZ, 0, -1, Ferrbuf);
    if (descr == NULL) {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // compile the filter expression
    if (pcap_compile(descr, &fp, "tcp", 0, pNet) == -1) {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    // set the filter
    if (pcap_setfilter(descr, &fp) == -1) {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    // for every packet received, call the callback function
    // no limit on number of packets
    pcap_loop(descr, -1, callback, NULL);

    //log packets to file
    packetLog(descr);

    printf("\nFinished.\n");
    return 0;
}
