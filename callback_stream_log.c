#include "callback_stream_log.h"

<<<<<<< HEAD
/**
 * creates a dump handle so that we can write packet data to the
 * specified file
 * @param file
 * @param pkthdr
 * @param packet
 */
void callback_stream_log(u_char *file, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pcap_dump(file, pkthdr, packet);
=======
void callback_stream_log(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
  pcap_dump(arg, pkthdr, packet);
>>>>>>> analyze-stream
}
