#ifndef HANDLE_INIT_H
#define HANDLE_INIT_H
#include <pcap.h>
#include <sys/types.h>

pcap_t *handle_init(char *device, char *filter, u_char *link, char *errbuf);

#endif
