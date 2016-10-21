#ifndef TRAFFIC_DEBUG_H
#define TRAFFIC DEBUG_H

#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include "detect_stream.h"
#include "detect_init.h"
#include "callback_detect_stream.h"
#include "callback_stream_analyze.h"
#include "callback_stream_log.h"

pcap_t *handle;
char *streamip;

void usage(char *name, int code);
void print_devices();
int main(int argc, char **argv);

#endif
