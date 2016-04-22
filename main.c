#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packets.h"

/**
 * Main method for our wfm program ("Who's Following Me?")
 *
 * Usage: wfm packets.pcap, where packets.pcap if a pcap file containing only
 * ethernet frames (with no VLAN tag) containing IP packets with 20-byte headers, 
 * containing TCP segments.
 * 
 * @param argc should be exactly 2
 * @param argv argv[1] should be the name of a .pcap file to open
 */
int main(int argc, char* argv[]) {
	char* pcap_filename;
	FILE* infile;
	IP_INFO ip_info;
	TCP_INFO tcp_info;

	// simple check of command-line args
	if (argc != 2) {
		printf("Usage: wfm <capturefile>.pcap");
		return EXIT_FAILURE;
	}

	// open pcap file for reading
	pcap_filename = argv[1];
	infile = fopen(pcap_filename, "rb");
	if (!infile) {
		return EXIT_FAILURE;
	}

	read_global_pcap_header(infile);
	
	while (1) {
		
		decode_eth_frame(infile);
		ip_info = decode_ipv4_packet(infile);
		tcp_info = decode_tcp_segment(infile, ip_info);

		if (feof(infile)) {
			break;
		}
		
		// lookup and print source address:port information
		print_reverse_lookup(ip_info.src, tcp_info.src_port);
		print_reverse_lookup(ip_info.dest, tcp_info.dest_port);
	
	}

	
	// tidy up
	fclose(infile);
	infile = NULL;
	return EXIT_SUCCESS;
}
