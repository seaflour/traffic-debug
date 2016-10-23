<<<<<<< HEAD
#include "callback_stream_analyze.h"

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
}
=======
#include "callback_stream_analyze.h"

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 1;
    printf("Packet number [%d]\ttime: %ld %ld\n", count++, (long int) (pkthdr->ts.tv_sec), (long int) (pkthdr->ts.tv_usec));
}
>>>>>>> origin
