#include "callback_stream_log.h"

void callback_stream_log(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
  pcap_dump(arg, pkthdr, packet);
}
