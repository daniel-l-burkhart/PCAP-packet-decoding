#include <stdlib.h>
#include "CuTest.h"
#include "packets.h"

/**
* Test the source TCP address.
**/
void Test_src_tcp_port(CuTest* ct) {
	
	FILE* infile;
	
	IP_INFO ip_info;
	TCP_INFO tcp_info;

	infile = fopen("testdata/single_packet.pcap", "rb");

	read_global_pcap_header(infile);
	
	decode_eth_frame(infile);
	ip_info = decode_ipv4_packet(infile);
	tcp_info = decode_tcp_segment(infile, ip_info);

	CuAssertIntEquals(ct, 443, tcp_info.src_port);

}

/**
* Test the destination TCP address.
**/
void Test_dest_tcp_port(CuTest* ct) {
	
	FILE* infile;
	IP_INFO ip_info;
	TCP_INFO tcp_info;

	
	infile = fopen("testdata/single_packet.pcap", "rb");

	read_global_pcap_header(infile);
	decode_eth_frame(infile);
	ip_info = decode_ipv4_packet(infile);
	tcp_info = decode_tcp_segment(infile, ip_info);
	
	CuAssertIntEquals(ct, 65533, tcp_info.dest_port);
}

/**
* Tests source IP address
**/
void Test_src_ip_address(CuTest* ct) {
	
	unsigned char* ipAddress;
	ipAddress = (unsigned char*) malloc(sizeof(char)*7);
	
	FILE* infile;
	IP_INFO ip_info;
	
	infile = fopen("testdata/single_packet.pcap", "rb");

	read_global_pcap_header(infile);
	decode_eth_frame(infile);
	ip_info = decode_ipv4_packet(infile);
	decode_tcp_segment(infile, ip_info);
	
	sprintf(ipAddress, "%u.%u.%u.%u", ip_info.src[0], ip_info.src[1], ip_info.src[2], ip_info.src[3]);
	CuAssertStrEquals(ct, "31.13.65.1", ipAddress);
}

/**
* Tests destination IP address
**/
void Test_dest_ip_address(CuTest* ct) {
	
	unsigned char* ipAddress;
	ipAddress = (unsigned char*) malloc(sizeof(char)*7);
	
	FILE* infile;
	IP_INFO ip_info;

	
	infile = fopen("testdata/single_packet.pcap", "rb");

	read_global_pcap_header(infile);
	decode_eth_frame(infile);
	ip_info = decode_ipv4_packet(infile);
	decode_tcp_segment(infile, ip_info);
	
	sprintf(ipAddress, "%u.%u.%u.%u", ip_info.dest[0], ip_info.dest[1], ip_info.dest[2], ip_info.dest[3]);
	CuAssertStrEquals(ct, "160.10.25.97", ipAddress);
}

/**
* Test source mac address in comparison to wireshark.
**/
void Test_src_mac_address(CuTest* ct) {
	
	unsigned char* macAddress;
	macAddress = (unsigned char*) malloc(sizeof(char)*11);
	
	FILE* infile;
	ETH_INFO eth_info;
	IP_INFO ip_info;
	
	infile = fopen("testdata/single_packet.pcap", "rb");

	read_global_pcap_header(infile);
	eth_info = decode_eth_frame(infile);
	ip_info= decode_ipv4_packet(infile);
	decode_tcp_segment(infile, ip_info);
	
	sprintf(macAddress, "%X:%X:%X:%X:%X:%X", eth_info.mac_src[0], eth_info.mac_src[1], eth_info.mac_src[2], eth_info.mac_src[3], eth_info.mac_src[4], eth_info.mac_src[5]);
	CuAssertStrEquals(ct, "0:4:96:8B:E6:19", macAddress);
	
}

/**
* Test destination mac address in comparison to wireshark output.
**/ 
void Test_dest_mac_address(CuTest* ct) {
	
	unsigned char* macAddress;
	macAddress = (unsigned char*) malloc(sizeof(char)*11);
	
	FILE* infile;
	ETH_INFO eth_info;
	IP_INFO ip_info;
	
	infile = fopen("testdata/single_packet.pcap", "rb");

	read_global_pcap_header(infile);
	eth_info = decode_eth_frame(infile);
	ip_info= decode_ipv4_packet(infile);
	decode_tcp_segment(infile, ip_info);
	
	sprintf(macAddress, "%X:%X:%X:%X:%X:%X", eth_info.mac_dest[0], eth_info.mac_dest[1], eth_info.mac_dest[2], eth_info.mac_dest[3], eth_info.mac_dest[4], eth_info.mac_dest[5]);
	CuAssertStrEquals(ct, "B8:CA:3A:D5:C3:F6", macAddress);

}