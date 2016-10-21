#ifndef CALLBACK_STREAM_LOG
#define CALLBACK_STREAM_LOG

#include <pcap.h>
#include <sys/types.h>

void callback_stream_log(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet); 

#endif
