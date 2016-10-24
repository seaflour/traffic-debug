#include "handle_init.h"

pcap_t *handle_init(char *device, u_char *link, char *errbuf) {
    pcap_t *handle;
    bpf_u_int32 pNet; /* ip address */
    bpf_u_int32 pMask; /* Subnet mask */
    struct bpf_program fp; /* compiled filter */

    pcap_lookupnet(device, &pNet, &pMask, errbuf);
    handle = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);

    // determine link-layer header type
    switch (pcap_datalink(handle)) {
        case DLT_EN10MB:
            /* Ethernet */
            *link = (u_char) 'e';
            break;
        case DLT_IEEE802_11:
            /* WLAN */
            *link = (u_char) 'w';
            break;
        default:
            /* something else */
            sprintf(errbuf, "Device %s is not supported. Please use an ethernet or WLAN device.\n", device);
            return NULL;
    }


    // compile the filter expression
    if (pcap_compile(handle, &fp, "tcp and not src host localhost", 0, pNet) == -1) {
        sprintf(errbuf, "pcap_compile() failed\n");
        return NULL;
    }

    // set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        sprintf(errbuf, "pcap_setfilter() failed\n");
        return NULL;
    }

    return handle;
}
