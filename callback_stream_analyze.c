#include "callback_stream_analyze.h"

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 1;
    printf("Packet number [%d]\ttime: %ld %ld\n", count++, (long int) (pkthdr->ts.tv_sec), (long int) (pkthdr->ts.tv_usec));

    //output packet
    for (int i = 0; i < (pkthdr->caplen + 1); i++) {
        printf("Packet: %.2x\n", packet[i - 1]);
    }
}
