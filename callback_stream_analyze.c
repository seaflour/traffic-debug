#include "callback_stream_analyze.h"

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

	static int count = 1;
	static int retrans_min = 0, retrans_max = 0;
	struct tcp_header *tcp_pack;
	static struct tcp_header *tcp_prev = NULL;
	int hdr_size = SIZE_IP;
	unsigned int sequence, prevseq;

	if (*arg == (u_char) 'f' && tcp_prev != NULL) {
		free(tcp_prev);
		tcp_prev = NULL;
	} else {
		printf("Packet number [%d]\n", count++);

		time_analysis((long int) (pkthdr->ts.tv_sec), (long int) (pkthdr->ts.tv_usec), (int) (pkthdr->len));

		if (tcp_prev == NULL) {
			tcp_prev = malloc(sizeof(struct tcp_header));
		} else {
			/* add length of link layer header to the IP header */
			if (*arg == (u_char) 'e') {
				hdr_size += SIZE_ETHERNET;
			} else if (*arg == (u_char) 'w') {
				hdr_size += SIZE_WLAN;
			}
			tcp_pack = (struct tcp_header*)(packet + hdr_size);

			sequence = ntohl(tcp_pack->seq);
			prevseq = ntohl(tcp_prev->seq);

			if (sequence < prevseq) {
				retrans_min++;
				retrans_max++;
				printf("* * * suspect error * * *\n");
			}
			if (sequence == prevseq) {
				retrans_max++;
				printf("* possible error *\n");
			}

			printf("seq: %u\tack: %u\n", sequence, prevseq);
			printf("seq: %u\tack: %u (prev)\n", ntohl(tcp_prev->seq), ntohl(tcp_prev->ack));
			printf("errors: %d - %d\n\n", retrans_min, retrans_max);
		}

		memcpy(tcp_prev, tcp_pack, sizeof(struct tcp_header));
	}
}
