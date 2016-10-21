#include "traffic_debug.h"

void usage(char *name, int code){
	fprintf(stderr, "%s - detect interruptions in video streams\n", name);
	fprintf(stderr, "Usage: %s [OPTIONS] [device]\n", name);
	fprintf(stderr, "\nOPTIONS\n\t-h\tprint this text\n");
	fprintf(stderr, "\t-l\tlist available network devices\n");
	exit(code);
}

void print_devices(){
	pcap_if_t *devlist;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_findalldevs(&devlist,errbuf);
	while (devlist != NULL) {
		printf("%s\n",devlist->name);
		devlist = devlist->next;
	}

	pcap_freealldevs(devlist);
	exit(0);
}

void cleanup(){
	pcap_close(handle);
	printf("\nFinished.\n");
}

/*extern pcap_t *handle;*/
/*extern char streamip[16];*/

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	int opt;
	char *device;	/* network device */
	u_char link;
	char *ifname = NULL;	/* file name for reading in */
	char *ofname = NULL;	/* file name for writing out */
	char filter[24];

	// Check if sufficient arguments were supplied
	if (argc < 2) {
		usage(argv[0],1);
	}

	// Parse command line options
	while ((opt = getopt(argc, argv, "hlo:i:")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0],0);
				break; 
			case 'l':
				print_devices();
				break;
			case 'o':
				if (optarg == NULL) {
					fprintf(stderr,"No filename provided.\n");
					usage(argv[0], EXIT_FAILURE);
				}
				ofname = optarg;
				break;
			case 'i':
				if (optarg == NULL) {
					fprintf(stderr,"No filename provided.\n");
					usage(argv[0], EXIT_FAILURE);
				}
				ifname = optarg;
				break;
			default: 
				usage(argv[0],EXIT_FAILURE);
		}
	}

	if (ifname != NULL) {
		handle = pcap_open_offline(ifname,errbuf);
		if (handle == NULL) {
			fprintf(stderr, "%s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	} else {
		// The last option is the device name;
		device = argv[argc-1];

		handle = handle_init(device,"tcp and not src host localhost", &link, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Error: %s\n.", errbuf);
			exit(EXIT_FAILURE);
		}

		printf("Starting capture on device [%s]...\n", device);

		strcpy(streamip,"");
		pcap_loop(handle, -1, callback_detect_stream, &link); 
		sprintf(filter, "src net %s", streamip);

		fprintf(stderr,"Filtering on '%s'...\n", filter);

		/* create new filter */
		handle = handle_init(device, filter, &link, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Error: %s\n.", errbuf);
			exit(EXIT_FAILURE);
		}
		/*if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "\npcap_setfilter() failed!\n");
			return EXIT_FAILURE;
		}*/
	}
	if (ofname != NULL) { 
		pcap_loop(handle, -1, callback_stream_log, NULL);
	} else {
		pcap_loop(handle, -1, callback_stream_analyze, NULL);
	}

	cleanup();
	return 0;
}
