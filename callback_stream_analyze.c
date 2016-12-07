#include "callback_stream_analyze.h"

#define ANSI_RED	"\x1b[91m"
#define ANSI_GRAY	"\x1b[37m"
#define ANSI_RESET	"\x1b[0m"

void callback_stream_analyze(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	/* how many consecutive good/bad packets needed to trigger a reset */
	const int THRESHOLD = precision;


	static int count = 1;
	static int bad_count = 0, good_count = 0;
	static struct tcp_header *tcp_prev = NULL;
/*	static unsigned int prev_len = 0;  */
	static struct timeval start_error_ts;
	static struct tm *start_error_timeofday;
	struct tm *end_error_timeofday;
	char buff_start[80];
	char buff_end[80];

	struct tcp_header *tcp_pack;
	int hdr_size = SIZE_IP;
	unsigned int sequence, prevseq;

	if (*arg == (u_char) 'f' && tcp_prev != NULL) {
		free(tcp_prev);
		tcp_prev = NULL;
	} else if (pkthdr != NULL) {

		// This will get the first incoming packet's time and stFlag is then set
		// so this will not run again.
		if(stFlag != 1){
			init((long int)(pkthdr->ts.tv_sec));
		}
		time_analysis(absStartTime, (long int)(pkthdr->ts.tv_sec), (long int)(pkthdr->ts.tv_usec), (int)(pkthdr->caplen));
		
		if (*arg == (u_char) 'e') {
			hdr_size += SIZE_ETHERNET;
		} else if (*arg == (u_char) 'w') {
			hdr_size += SIZE_WLAN;
		}

		tcp_pack = (struct tcp_header*)(packet + hdr_size);

		if (tcp_prev == NULL) {
			tcp_prev = malloc(sizeof(struct tcp_header));
		} else {
			/* add length of link layer header to the IP header */

			sequence = ntohl(tcp_pack->seq);
			prevseq = ntohl(tcp_prev->seq);

			if (sequence < prevseq) {
				if (good_count != 0) {
					start_error_ts = pkthdr->ts;
					start_error_timeofday = localtime(&(pkthdr->ts.tv_sec));
				}
				good_count = 0;
				bad_count++;
			} else if (sequence == prevseq) {
				if (good_count != 0) {
					start_error_ts = pkthdr->ts;
					start_error_timeofday = localtime(&(pkthdr->ts.tv_sec));
				}
				good_count = 0;
				bad_count++;
			} else {
				good_count++;
				/* reset bad counter if we've seen enough good packets in a row */
				if (good_count > THRESHOLD) {
					/* if there are many errors in a row, that's a bad sign */
					if (bad_count > THRESHOLD) {
/*						printf("Packet number [%d] stream error likely!\tRun of %d errors.\n", count-THRESHOLD, bad_count); */
						end_error_timeofday = localtime(&(pkthdr->ts.tv_sec));
						strftime(buff_start, 80, "%H:%M:%S", start_error_timeofday);
						strftime(buff_end, 80, "%H:%M:%S", end_error_timeofday);
						printf(
							ANSI_RED "Error" ANSI_RESET " from %s.%.2ld to %s.%.2ld: " ANSI_GRAY "TCP retransmission\n" ANSI_RESET,
							buff_start,
							(long) start_error_ts.tv_usec/10000,
							buff_end,
							(long) pkthdr->ts.tv_usec/10000
						);
					}
					bad_count = 0;
				}
			}
			/* Check for TCP reset */
/*			if ((tcp_pack->tcp_flags & TCP_RST) == TCP_RST) {*/
/*				printf("Packet number[%d] TCP reset, possibly bad\n", count+1);*/
/*			}*/
			count++;
		}

		memcpy(tcp_prev, tcp_pack, sizeof(struct tcp_header));
/*		prev_len = pkthdr->len; */
	}

}
