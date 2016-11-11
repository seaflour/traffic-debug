#include "traffic_debug.h"

void usage(char *name, int code) {
    fprintf(stderr, "%s - detect interruptions in video streams\n", name);
    fprintf(stderr, "Usage: %s [OPTIONS] [device]\n", name);
    fprintf(stderr, "\nOPTIONS\n\t-h\tprint this text\n");
    fprintf(stderr, "\t-l\tlist available network devices\n");
    fprintf(stderr, "\t-o\ttake file name to save log to\n");
    fprintf(stderr, "\t-i\ttake file name to analyze\n");
    fprintf(stderr, "\t-d\tspecify device capture direction(in, out, inout)\n");
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

void cleanup(int i) {
	u_char c = 'f';
    pcap_close(handle);
	callback_stream_analyze(&c, NULL, NULL);
	if (i != 0) {
		printf("Stopping packet drop...\n");
		system("trafficshape stop");
	}
	printf("\nFinished.\n");
}

void signal_handler(int signo){
	if (signo == SIGINT) {
		pcap_breakloop(handle);
	} 
} 

/*extern pcap_t *handle;*/

/*extern char streamip[16];*/

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int opt;
    char *device; /* network device */
    u_char link;
    char *ifname = NULL; /* file name for reading in */
    char *ofname = NULL; /* file name for writing out */
    char filter[24];
    char *capDir; //capture direction

	char dropstr[24];
	int droprate = 0;

    struct pcap_stat stat; //struct to store capture stats

    // Check if sufficient arguments were supplied
    if (argc < 2) {
        usage(argv[0], 1);
    }

    // Parse command line options
    while ((opt = getopt(argc, argv, "hlo:i:d:x:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0], 0);
                break;
            case 'l':
                print_devices();
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
            case 'd':
				if (optarg == NULL) {
                    fprintf(stderr, "No direction specified.\n");
                    usage(argv[0], EXIT_FAILURE);
                }
                capDir = optarg;
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

	/* register signal handler */
	if (signal(SIGINT, signal_handler) == SIG_ERR)
		fprintf(stderr,"Cannot handle SIGINT\n");

    if (ifname != NULL) {
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
		device = argv[argc - 1];

		handle = handle_init(device, "tcp and not src host localhost", &link, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Error: %s\n.", errbuf);
			exit(EXIT_FAILURE);
		}

		//set the capture direction to only those received by device
		//other options, PCAP_D_OUT, PCAP_D_INOUT
		if ((strcmp(capDir, "in")) == 0) {
			pcap_setdirection(handle, PCAP_D_IN);
		} else if ((strcmp(capDir, "out")) == 0) {
			pcap_setdirection(handle, PCAP_D_OUT);
		} else if ((strcmp(capDir, "inout")) == 0) {
			pcap_setdirection(handle, PCAP_D_INOUT);
		} else {
			//printf("Error processing option, setting to default: 'INOUT'\n");
			pcap_setdirection(handle, PCAP_D_INOUT);
		}

		printf("Starting capture on device [%s]...\n", device);

		strcpy(streamip, "");
		pcap_loop(handle, -1, callback_detect_stream, &link);
		sprintf(filter, "src net %s", streamip);

		fprintf(stderr, "Filtering on '%s'...\n", filter);

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

		fprintf(stderr,"drop rate %d\n",droprate);
		if (droprate != 0) {
			sprintf(dropstr,"trafficshape drop %d", droprate);
			printf("Beginning packet drop at %d%%\n", droprate);
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
	printf("\nReceived Packets: %u\n", stat.ps_recv);
	printf("Dropped Driver Packets: %u\n", stat.ps_drop);
	printf("Dropped Interface Packets: %u\n", stat.ps_ifdrop);
<<<<<<< HEAD
=======

    // printf("Average bytes/sec: %.2f\n", avgBps);
    // printf("Total time(seconds): %.2f\n", totalTime);
    // printf("Total Packets: %d\n", totalPktCount);
    // printf("Packets/sec: %.2f\n", pps);

>>>>>>> 61e5d76fd8aa3c8e230e72f61d000aefa37be6ff
	cleanup(droprate);
	return 0;
}
