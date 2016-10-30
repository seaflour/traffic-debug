#include "callback_stream_analyze.h"

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

	static int count = 1;
	/*	static int prevlen = 0;*/
	/*	static u_char *prev = NULL;*/
	struct tcp_header *tcp_pack;
	static struct tcp_header *tcp_prev = NULL;
	int hdr_size = SIZE_IP;

	if (*arg == (u_char) 'f' && tcp_prev != NULL) {
		free(tcp_prev);
		tcp_prev = NULL;
	} else {
		printf("Packet number [%d]\n", count++);

		time_analysis((long int) (pkthdr->ts.tv_sec), (long int) (pkthdr->ts.tv_usec), (int) (pkthdr->len));

		/* add length of link layer header to the IP header */
		if (*arg == (u_char) 'e') {
			hdr_size += SIZE_ETHERNET;
		} else if (*arg == (u_char) 'w') {
			hdr_size += SIZE_WLAN;
		}
		tcp_pack = (struct tcp_header*)(packet + hdr_size);

		printf("seq: %u\tack: %u\n", ntohl(tcp_pack->seq), ntohl(tcp_pack->ack));

		if (tcp_prev == NULL)
			tcp_prev = malloc(sizeof(struct tcp_header));
		else
			printf("Prev\nseq: %u\tack %u\n\n", ntohl(tcp_prev->seq), ntohl(tcp_prev->ack));

		memcpy(tcp_prev, tcp_pack, sizeof(struct tcp_header));
	}
}
