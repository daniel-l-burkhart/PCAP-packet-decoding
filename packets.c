#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "packets.h"
#include "pcap.h"

#define IP_HDR_LENGTH (20)
#define TCP_HDR_LENGTH (20)

pcap_hdr_t read_global_pcap_header(FILE* pcap_file) {
	pcap_hdr_t header;
	fseek(pcap_file, 0, SEEK_SET);
	fread(&header, sizeof(pcap_hdr_t), 1, pcap_file);
	return header;
}

ETH_INFO decode_eth_frame(FILE* pcap_file) {
	
	ETH_INFO info;
	
	pcaprec_hdr_t recordHeader;
	fread(&recordHeader, sizeof(pcaprec_hdr_t), 1, pcap_file);
	
	fread(&info.mac_dest[0], 1, 6, pcap_file);
	
	fread(&info.mac_src[0], 1, 6, pcap_file);

	unsigned short fluff;
	fread(&fluff, 2, 1, pcap_file);
	
	return info;
}


IP_INFO decode_ipv4_packet(FILE* pcap_file) {
	
	IP_INFO info;
	
	unsigned short fluff;
	fread(&fluff, 2, 1, pcap_file);
	
	unsigned short ipLength;
	unsigned char swapped[2];
	unsigned char tmp;
	
	fread(&swapped[0], 1, 2, pcap_file);
	tmp = swapped[0];
	swapped[0] = swapped[1];
	swapped[1] = tmp;
	
	ipLength = *(unsigned short*) swapped;
	
	
	info.tcp_length = (ipLength-20);
	
	unsigned char eightFluff;
	fread(&eightFluff, 1, 8, pcap_file);
	
	fread(&info.src[0], 1, 4, pcap_file);
	
	fread(&info.dest[0], 1, 4, pcap_file);
	
	return info;
}

TCP_INFO decode_tcp_segment(FILE* pcap_file, IP_INFO ip_info) {
	
	TCP_INFO info;
	
	unsigned char swapped[2];
	unsigned char tmp;
	
	fread(&swapped[0], 1, 2, pcap_file);
	tmp = swapped[0];
	swapped[0] = swapped[1];
	swapped[1] = tmp;
	
	info.src_port = *(unsigned short *)swapped;
	
	unsigned char swapped2[2];
	fread(&swapped2[0], 1, 2, pcap_file);
	tmp = swapped2[0];
	swapped2[0] = swapped2[1];
	swapped2[1] = tmp;
	
	info.dest_port = *(unsigned short *)swapped2;
	
	int numberOfElements = (ip_info.tcp_length-4);
	
	unsigned char* tcp_fluff;
	tcp_fluff = (unsigned char*)malloc(numberOfElements);
	fread(tcp_fluff, numberOfElements, 1, pcap_file);
	
	return info;
}

struct sockaddr* create_socket(unsigned char ip_addr[], unsigned short port) {
	
	struct sockaddr_in* sock;

	sock = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));

	sock->sin_family = AF_INET;
	sock->sin_port = htons(port);
	memcpy(&(sock->sin_addr.s_addr), ip_addr, 4);
	memset(sock->sin_zero, 0, 8);
	return (struct sockaddr*)sock;
}

void print_reverse_lookup(unsigned char ip_addr[], unsigned short port) {
	
	struct sockaddr* sock = NULL;
	char namebuf[50];
	char servbuf[25];
	int outcome = 0;

	sock = create_socket(ip_addr, port);
	
	outcome = getnameinfo(sock, sizeof(struct sockaddr_storage), namebuf, 50, servbuf, 25, 0);
	
	if (!outcome) {
		printf("%s: %s\n", namebuf, servbuf);
	} else {
		printf("%u.%u.%u.%u:%u\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], port); 
	}
	
	free(sock);
	sock = NULL;
}
