#ifndef DETECT_INIT_H
#define DETECT_INIT_H
#include <pcap.h>
#include <sys/types.h>

pcap_t *detect_init(char *device, u_char *link, char *errbuf);

#endif
