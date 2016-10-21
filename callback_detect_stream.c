#include "callback_detect_stream.h"

void callback_detect_stream(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	int hdr_size;
	char srcname[100]; 
	struct sniff_ip *ip;
	printf("Packet number [%d]\ttime: %ld %ld\n", count++, (long int)(pkthdr->ts.tv_sec), (long int)(pkthdr->ts.tv_usec));
	

	/* use length of link layer header to get to the IP header */
	if (*arg == (u_char)'e') {
		hdr_size = SIZE_ETHERNET;
	} else if (*arg == (u_char)'w') {
		hdr_size = SIZE_WLAN;
	} else {
		/* not ethernet or WLAN */
		fprintf(stderr, "Device not supported\n");
		exit(EXIT_FAILURE);
	}

	/* find IP header info with sneaky cast */
	ip = (struct sniff_ip*)(packet + hdr_size);
	strcpy(srcname, inet_ntoa(ip->ip_src));

	fprintf(stderr,"ip: %s\n", srcname);
	/* dns lookup the source IP address */
	if (dns_lookup(srcname, "cache.google.com.") == 0) {
		fprintf(stderr,"YouTube stream detected, from address %s\n", srcname);
		if (strcmp(streamip,"") == 0)
			streamip = srcname;
		pcap_breakloop(handle);
	}
}
