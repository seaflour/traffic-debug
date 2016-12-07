#include <pcap.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "global.h"
#include "time_analysis.h"

#ifndef CALLBACK_STREAM_ANALYZE_H
#define CALLBACK_STREAM_ANALYZE_H

struct tcp_header {
	u_short src_port; 	/* source port */
	u_short dst_port; 	/* destination port */
	u_int seq;			/* tcp sequence number */
	u_int ack;			/* tcp acknowledgement number */
	u_char tcp_off;		/* data offset */
	u_char tcp_flags;	/* control bits */
#define TCP_CWR 0x80	/* congestion window reduced */
#define TCP_ECE 0x40	/* ECN echo */
#define TCP_URG 0x20	/* urgent */
#define TCP_ACK 0x10	/* acknowledgement */
#define TCP_PSH 0x08	/* push */
#define TCP_RST 0x04	/* reset */
#define TCP_SYN 0x02	/* synchronize seq */
#define TCP_FIN 0x01	/* finished */

	u_short win_size;	/* window size */
	u_short tcp_check;	/* checksum */
	u_short tcp_urg;	/* urgent pointer */
	/* options if offset > 5 */
};

#define SIZE_ETHERNET 14
#define SIZE_WLAN 30
#define SIZE_IP 20

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet); 

#endif
