/*
 * trd217
 * from http://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
 * test program for captureing tcp packets
 *
 */

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

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	printf("\nPacket number [%d], length: %d\n", count++, pkthdr->len);
}

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	struct bpf_program fp; 	/* to hold compiled program */
	bpf_u_int32 pMask; 		/* subnet mask */
	bpf_u_int32 pNet;		/* ip address */
	pcap_if_t *alldevs;

	// Check if sufficient arguments were supplied
	if (argc != 4) {
		printf("\nUsage %s [device] [protocol] [number-of-packets]\n", argv[0]);
		return 0;
	}

	// Prepare a list of all the devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	printf("\ndevice [%s] capturing [%d] packets\n\n Starting capture...\n",argv[1], (atoi)(argv[3]));

	// fetch the network address and network mask
	pcap_lookupnet(argv[1], &pNet, &pMask, errbuf);

	// open device for sniffing
	descr = pcap_open_live(argv[1], BUFSIZ, 0, -1, errbuf);
	if (descr == NULL) {
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		return -1;
	}

	// compile the filter expression
	if (pcap_compile(descr, &fp, argv[2], 0, pNet) == -1) {
		printf("\npcap_compile() failed\n");
		return -1;
	}

	// set the filter
	if (pcap_setfilter(descr, &fp) == -1) {
		printf("\npcap_setfilter() failed\n");
		exit(1);
	}

	// for every packet received, call the callback function
	// for now, maximum limit on packets is specified by the user
	pcap_loop(descr, atoi(argv[3]), callback, NULL);
	
	printf("\nFinished.\n");
	return 0;
}
