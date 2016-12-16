#ifndef GLOBAL_H
#define GLOBAL_H

#include <pcap.h>

extern char streamip[];
extern int precision;
pcap_t *handle;
extern struct stamp *ts_list_head;
extern struct stamp *user_list_head;

#endif
