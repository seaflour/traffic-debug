#include "traffic_debug.h"

void usage(char *name, int code) {
}

void print_devices() {
}

void cleanup() {
    pcap_close(handle);
    printf("\nFinished.\n");
}

extern pcap_t *handle;
extern char *streamip;

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int opt;
    char *device; /* network device */
    u_char link;
    char *ifname = NULL; /* file name for reading in */
    char *ofname = NULL; /* file name for writing out */

    // Check if sufficient arguments were supplied
    if (argc < 2) {
        usage(argv[0], 1);
    }

    // Parse command line options
    while ((opt = getopt(argc, argv, "hlo:i:")) != -1) {
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
            default:
                usage(argv[0], EXIT_FAILURE);
        }
    }

    if (ifname != NULL) {
        handle = pcap_open_offline(ifname, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "%s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        // The last option is the device name;
        device = argv[argc - 1];

        handle = detect_init(device, &link, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error: %s\n.", errbuf);
            exit(EXIT_FAILURE);
        }

        pcap_loop(handle, -1, callback_detect_stream, &link);

        /* create new filter */
        /*		if (pcap_setfilter(handle, &fp) == -1) {
                                fprintf(stderr, "\npcap_setfilter() failed!\n");
                                return EXIT_FAILURE;
                        }*/
    }
    if (ofname != NULL) {
        pcap_dumper_t *dump;
        //try to open the dump handle to pass packets to 'ofname'
        if ((dump = pcap_dump_open(handle, ofname)) != NULL) {
            pcap_loop(handle, -1, callback_stream_log, (unsigned char *) dump);
        } else {
            fprintf(stderr, "%s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        pcap_loop(handle, -1, callback_stream_analyze, NULL);
    }

    cleanup();
    return 0;
}
