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

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	printf("Packet number [%d]\ttime: %ld %ldl\n", count++, (long int)(pkthdr->ts.tv_sec), (long int)(pkthdr->ts.tv_usec));
}

void usage(char *name, int code) {
	fprintf(stderr, "%s - detect interruptions in video streams\n", name);
	fprintf(stderr, "Usage: %s [OPTIONS] [device]\n", name);
	fprintf(stderr, "\nOPTIONS\n\t-h\tprint this text\n");
	exit(code);
}

int main(int argc, char **argv) {
	char *ip1 = "68.65.124.13";
	char *ip2 = "31.13.80.36";

	fprintf(stderr, "lookup %s: %d\n", ip1, dns_lookup_youtube(ip1));
	fprintf(stderr, "lookup %s: %d\n", ip2, dns_lookup_youtube(ip2));

	int opt;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	struct bpf_program fp; 	/* to hold compiled program */
	bpf_u_int32 pMask; 		/* subnet mask */
	bpf_u_int32 pNet;		/* ip address */
	char *device;

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
	descr = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
	if (descr == NULL) {
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		return -1;
	}

	// compile the filter expression
	if (pcap_compile(descr, &fp, "tcp", 0, pNet) == -1) {
		printf("\npcap_compile() failed\n");
		return -1;
	}

	// set the filter
	if (pcap_setfilter(descr, &fp) == -1) {
		printf("\npcap_setfilter() failed\n");
		exit(1);
	}

	// for every packet received, call the callback function
	// no limit on number of packets
	pcap_loop(descr, -1, callback, NULL);
	
	printf("\nFinished.\n");
	return 0;
}
