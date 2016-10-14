#ifndef CALLBACK_DETECT_STREAM_H
#define CALLBACK_DETECT_STREAM_H

/* help from http://www.tcpdump.org/pcap.html */
/* IP header */
struct sniff_ip {
	u_char ip_vhl;			/* version << 4 | header length >> 2 */
	u_char ip_tos;			/* type of service */
	u_short ip_len;			/* total length */
	u_short ip_id;			/* identification */
	u_short ip_off;			/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flags */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmented bits */
	u_char ip_ttl;			/* time to live */
	u_char ip_p;			/* protocol */
	u_short ip_sum;			/* checksum */
	struct in_addr ip_src, ip_dst; 	/* source and dest addresses */
};

#define SIZE_ETHERNET 14
#define SIZE_WLAN 30

void callback_detect_stream(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet); 

#endif
