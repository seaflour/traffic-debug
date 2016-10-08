
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
#include "detect-stream.h"

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
/* not sure that we need these two macros ... */
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)
#define SIZE_ETHERNET 14
#define SIZE_WLAN 30

struct sniff_ip *ip; /* The IP header */
pcap_t *handle;

void callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	int hdr_size;
	char srcname[100]; 
	printf("Packet number [%d]\ttime: %ld %ldl\n", count++, (long int)(pkthdr->ts.tv_sec), (long int)(pkthdr->ts.tv_usec));
	

	/* use length of link layer header to get to the IP header */
	if (strcmp((char *)arg, "e") == 0) {
		hdr_size = SIZE_ETHERNET;
	} else if (strcmp((char *)arg, "w") == 0) {
		hdr_size = SIZE_WLAN;
	} else {
		/* unsupported device */
		exit(1);
	}

	// casting magic
	ip = (struct sniff_ip*)(packet + hdr_size);
	strcpy(srcname, inet_ntoa(ip->ip_src));

	// dns lookup the source IP address
	if (dns_lookup_youtube(srcname) == 0) {
		fprintf(stderr,"YouTube stream detected, from address %s\n", srcname);
		pcap_breakloop(handle);
	}
}

void usage(char *name, int code) {
	fprintf(stderr, "%s - detect interruptions in video streams\n", name);
	fprintf(stderr, "Usage: %s [OPTIONS] [device]\n", name);
	fprintf(stderr, "\nOPTIONS\n\t-h\tprint this text\n");
	exit(code);
}

int main(int argc, char **argv) {
	char *ip1 = "68.65.124.13"; /* IP of a youtube stream */
	char *ip2 = "173.194.68.91"; /* IP of a youtube webpage */
	fprintf(stderr, "lookup %s: %d\n", ip1, dns_lookup_youtube(ip1)); /* should print 0 */
	fprintf(stderr, "lookup %s: %d\n", ip2, dns_lookup_youtube(ip2)); /* should not print 0 */

	int opt;

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp; 	/* to hold compiled program */
	bpf_u_int32 pMask; 		/* subnet mask */
	bpf_u_int32 pNet;		/* ip address */
	char *device;
	u_char *link; 			/* type of link layer header */


	// Check if sufficient arguments were supplied
	if (argc < 2) {
		usage(argv[0],1);
	}


	// Parse command line options
	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0],0);
				break; 
			default: 
				usage(argv[0],1);
		}
	}
	
	// The last option must be the device name
	device = argv[argc-1];

	printf("\nStarting TCP capture on device [%s]...\n",argv[1]);

	// fetch the network address and network mask
	pcap_lookupnet(device, &pNet, &pMask, errbuf);

	// open device for sniffing
	handle = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
	if (handle == NULL) {
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		return -1;
	}
	
	// determine link-layer header type
	switch (pcap_datalink(handle)) {
		case DLT_EN10MB: 
			/* Ethernet */ 
			link = (u_char *)"e";
			break;
		case DLT_IEEE802_11:
			/* WLAN */
			link = (u_char *)"w";
			break;
		default:
			/* something else */
			fprintf(stderr, "Device %s is not supported. Please use an ethernet or WLAN device.\n", device);
			exit(2);
	}


	// compile the filter expression
	if (pcap_compile(handle, &fp, "tcp", 0, pNet) == -1) {
		printf("\npcap_compile() failed\n");
		return -1;
	}

	// set the filter
	if (pcap_setfilter(handle, &fp) == -1) {
		printf("\npcap_setfilter() failed\n");
		exit(1);
	}

	// compiled filter no longer needed
	pcap_freecode(&fp);

	// for every packet received, call the callback function
	// no limit on number of packets
	// pass the type of link header, ethernet or WLAN supported
	pcap_loop(handle, -1, callback, link);
	
	/* trd TODO
	 * compile a new pcap filter and then begin analyzing traffic
	 */

	// cleanup
	pcap_close(handle);
	printf("\nFinished.\n");
	return 0;
}
