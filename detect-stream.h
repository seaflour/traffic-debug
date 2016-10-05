#ifndef DETECT_STREAM_H
#define DETECT_STREAM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// returns 0 if addr resolves to cache.google.com 
int dns_lookup_youtube(char *addr);

#endif
