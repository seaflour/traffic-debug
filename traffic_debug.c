#include "traffic_debug.h"

void usage(char *name, int code) {
    fprintf(stderr, "%s - detect interruptions in video streams\n", name);
    fprintf(stderr, "Usage: %s [OPTIONS] [device]\n", name);
    fprintf(stderr, "\nOPTIONS\n\t-h\tprint this text\n");
    fprintf(stderr, "\t-l\tlist available network devices\n");
    fprintf(stderr, "\t-p\tprecision of error detection, default 3\n");
    fprintf(stderr, "\t-o\ttake file name to save log to\n");
    fprintf(stderr, "\t-i\ttake file name to analyze\n");
    fprintf(stderr, "\t-x\tdrop a percentage of traffic after stream detection\n");
    exit(code);
}

void print_devices() {
    pcap_if_t *devlist;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&devlist, errbuf);
    while (devlist != NULL) {
        printf("%s\n", devlist->name);
        devlist = devlist->next;
    }

    pcap_freealldevs(devlist);
    exit(0);
}

void cleanup() {
	u_char c = 'f';
    pcap_close(handle);
	callback_stream_analyze(&c, NULL, NULL);
	printf("\nFinished.\n");
}

void signal_handler(int signo){
	if (signo == SIGINT) {
		pcap_breakloop(handle);
	} 
} 

int precision;

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int opt;
    char *device = NULL; /* network device */
    u_char link;
    char *ifname = NULL; /* file name for reading in */
    char *ofname = NULL; /* file name for writing out */
    char filter[24];
 	precision = 3;

	char dropstr[128];
	int droprate = 0;

    struct pcap_stat stat; //struct to store capture stats

    // Check if sufficient arguments were supplied
    if (argc < 2) {
        usage(argv[0], 1);
    }

    // Parse command line options
	while (optind < argc) {
		if ((opt = getopt(argc, argv, "hlo:i:x:p:")) != -1) {
			switch (opt) {
				case 'h':
					usage(argv[0], 0);
					break;
				case 'l':
					print_devices();
					break;
				case 'p':
					precision = atoi(optarg);
					break;
				case 'o':
					if (optarg == NULL) {
						fprintf(stderr, "No filename provided.\n");
						usage(argv[0], EXIT_FAILURE);
					}
					ofname = optarg;
					break;
				case 'i':
					if (optarg == NULL) {
						fprintf(stderr, "No filename provided.\n");
						usage(argv[0], EXIT_FAILURE);
					}
					ifname = optarg;
					break;
				case 'x':
					droprate = atoi(optarg);
					if ((optarg == NULL) || (droprate > 100) || (droprate < 0)) {
						fprintf(stderr, "No percentage provided.\n");
						usage(argv[0], EXIT_FAILURE);
					}
					break;
				default:
					usage(argv[0], EXIT_FAILURE);
			}
		}
		else {
			device = argv[optind];
			optind++;
		}
	}

	/* register signal handler */
	if (signal(SIGINT, signal_handler) == SIG_ERR)
		fprintf(stderr,"Cannot handle SIGINT\n");

	if (ifname != NULL) {
		printf("Analyzing file %s...\n", ifname);
		handle = pcap_open_offline(ifname, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "%s\n", errbuf);
			exit(EXIT_FAILURE);
		}
		// determine link-layer header type
		switch (pcap_datalink(handle)) {
			case DLT_EN10MB:
				/* Ethernet */
				link = (u_char) 'e';
				break;
			case DLT_IEEE802_11:
				/* WLAN */
				link = (u_char) 'w';
				break;
			default:
				/* something else */
				fprintf(stderr, "Device is not supported. Please use an ethernet or WLAN device.\n");
				exit(EXIT_FAILURE);
		}
	} else {
		// The last option is the device name;
		if (device == NULL) {
			fprintf(stderr, "Missing device name.\n");
			usage(argv[0],EXIT_FAILURE);
		}

		handle = handle_init(device, "tcp and not src host localhost", &link, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Error: %s\n.", errbuf);
			exit(EXIT_FAILURE);
		}

		printf("Starting capture on device [%s]...\n", device);

		strcpy(streamip, "");
		pcap_loop(handle, -1, callback_detect_stream, &link);
		sprintf(filter, "src net %s", streamip);

		/*		fprintf(stderr, "Filtering on '%s'...\n", filter); */

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

		/*		fprintf(stderr,"drop rate %d\n",droprate); */
		if (droprate != 0) {
			sprintf(dropstr,"trafficshape %s drop %d", device, droprate);
			system(dropstr);
		}

	}
	if (ofname != NULL) {
		pcap_dumper_t *dump;

		if ((dump = pcap_dump_open(handle, ofname)) != NULL) {
			pcap_loop(handle, -1, callback_stream_log, (unsigned char *) dump);
		} else {
			fprintf(stderr, "%s\n", errbuf);
			pcap_close(handle);
			exit(EXIT_FAILURE);
		}
	} else {
		pcap_loop(handle, -1, callback_stream_analyze, &link);
	}
	//set capture to statistics mode and fill in stat struct
	if (pcap_stats(handle, &stat) < 0) {
		fprintf(stderr, "%s\n", errbuf);
		//pcap_close(handle);
		//exit(EXIT_FAILURE);
	}
	//output capture statistics
	/*	printf("\nReceived Packets: %u\n", stat.ps_recv); */
	/*	printf("Dropped Driver Packets: %u\n", stat.ps_drop); */
	/*	printf("Dropped Interface Packets: %u\n", stat.ps_ifdrop); */

	if (ifname == NULL && ofname == NULL)
		printStats();

	cleanup();
	if (droprate != 0 && device != NULL) {
		sprintf(dropstr,"trafficshape %s drop", device);
		system(dropstr);
	}
	return 0;
}
