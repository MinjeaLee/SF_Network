
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
// #include <libnet.h>
#include "_libnet.h"

void usage() {
    printf("syntax: sudo pcap-test <interface>\n");
    printf("sample: sudo pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* interface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet); // pcap dump info.

        if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("%u bytes captured\n", header->caplen);

        // Ethernet Header
        struct libnet_ethernet_hdr* ethernet_header = (struct libnet_ethernet_hdr*)packet;
        printf("Ethernet Header\n");
        printf("\tsrcmac: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2], ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
        printf("\tdstmac: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1], ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);

        // IP Header
        struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        printf("IP Header\n");
        printf("\tsrcip: %d.%d.%d.%d\n", ip_header->ip_src.s_addr & 0xff, (ip_header->ip_src.s_addr >> 8) & 0xff, (ip_header->ip_src.s_addr >> 16) & 0xff, (ip_header->ip_src.s_addr >> 24) & 0xff);
        printf("\tdstip: %d.%d.%d.%d\n", ip_header->ip_dst.s_addr & 0xff, (ip_header->ip_dst.s_addr >> 8) & 0xff, (ip_header->ip_dst.s_addr >> 16) & 0xff, (ip_header->ip_dst.s_addr >> 24) & 0xff);

        // TCP Header
        struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
        printf("TCP Header\n");
        printf("\tsrcport: %d\n", ntohs(tcp_header->th_sport));
        printf("\tdstport: %d\n", ntohs(tcp_header->th_dport));

        // Payload
        const u_char* payload = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
        printf("Payload\n");
        printf("\t%02x %02x %02x %02x %02x %02x %02x %02x\n", payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7]);
        printf("\n");
    }
    
    pcap_close(pcap);

    return 0;
}