#include <pcap.h>
#include <sys/types.h>

#ifndef CALLBACK_STREAM_ANALYZE_H
#define CALLBACK_STREAM_ANALYZE_H

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet); 

#endif
