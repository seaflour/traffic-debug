#include "traffic_debug.h"

void usage(char *name, int code){
}

void print_devices(){
}

void cleanup(){
	pcap_close(handle);
	printf("\nFinished.\n");
}

extern pcap_t *handle;
extern char *streamip;

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	int opt;
	char *device;	/* network device */
	u_char *link;
	int log;
	char *fname = NULL;

	// Check if sufficient arguments were supplied
	if (argc < 2) {
		usage(argv[0],1);
	}

	// Parse command line options
	while ((opt = getopt(argc, argv, "hl")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0],0);
				break; 
			case 'l':
				print_devices();
				break;
			default: 
				usage(argv[0],EXIT_FAILURE);
		}
	}

	if (fname != NULL) {
		handle = pcap_open_offline(fname,errbuf);
		if (handle == NULL) {
			fprintf(stderr, "%s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	} else {
		// The last option is the device name;
		device = argv[argc-1];

		handle = detect_init(device, &link, errbuf);

		pcap_loop(handle, -1, callback_detect_stream, link); 

		/* tentatively */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "\npcap_setfilter() failed!\n");
			return EXIT_FAILURE;
		}
	}
	if (log) { 
		pcap_loop(handle, -1, callback_stream_log, NULL);
	} else {
		pcap_loop(handle, -1, callback_stream_analyze, NULL);
	}

	cleanup();
	return 0;
}
