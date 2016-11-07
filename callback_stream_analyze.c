#include "callback_stream_analyze.h"

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	static int bad_count = 0, good_count = 0;
	static int err_min = 0, err_max = 0;
	struct tcp_header *tcp_pack;
	static struct tcp_header *tcp_prev = NULL;
	static unsigned int prev_len = 0;
	int hdr_size = SIZE_IP;
	unsigned int sequence, prevseq;

	int snapshot[((int)(pkthdr->len) / ((int)(pkthdr)->caplen))];
	struct timeval snapTime;
	static int caplenCount = 0;

	if (*arg == (u_char) 'f' && tcp_prev != NULL) {
		free(tcp_prev);
		tcp_prev = NULL;
	} else {
		time_analysis((long int) (pkthdr->ts.tv_sec), (long int) (pkthdr->ts.tv_usec), (int) (pkthdr->len), (int) (pkthdr->caplen));
		printf("Packet number [%d]", count++);
		gettimeofday(&snapTime, NULL);
		
		time_t tempTime = snapTime.tv_sec + (snapTime.tv_usec/1000000);
		caplenCount += (int)(pkthdr->caplen);

		if((tempTime - START_TIME) == 5){
			if((count/tempTime) < 10){ // This indicates low pps.
				print_alert(tempTime, 0);
			} else if(caplenCount/tempTime){ // This indiciates low bytes/sec.
				print_alert(tempTime, 1);
			}
		}
		time_analysis(START_TIME, (long int) (pkthdr->ts.tv_sec), (long int) (pkthdr->ts.tv_usec), (int) (pkthdr->len), (int) (pkthdr->caplen));

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
				/* SEQ is lower... retransmission likely */	
				good_count = 0;
				bad_count++;
			} else if (sequence == prevseq) {
				/* SEQ is unchanged... retransmission possible*/
				good_count = 0;
				bad_count++;
			} else {
				/* normal SEQ */
				good_count++;
				/* reset bad counter if we've seen 3 good packets in a row */
				if (good_count > 3)
					bad_count = 0;
			}

			if (bad_count > 3) {
				printf("Packet number [%d] stream error likely!\n", count++);
			}

/*			printf("seq: %u\tack: %u (prev)\n", ntohl(tcp_prev->seq), ntohl(tcp_prev->ack));*/
/*			printf("\nseq: %u\tack: %u\n", sequence,  ntohl(tcp_pack->ack));*/
/*			printf("errors: %d - %d\n\n", err_min, err_max);*/
		}

		memcpy(tcp_prev, tcp_pack, sizeof(struct tcp_header));
		prev_len = pkthdr->len;
	}
}
