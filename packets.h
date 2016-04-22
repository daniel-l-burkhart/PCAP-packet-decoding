#ifndef PACKETS_H
#define PACKETS_H

#include <sys/socket.h>
#include "pcap.h"
#include <stdio.h>

#define TPID_802_1Q (0x8100)

/**
 * Reads in the global PCAP file header and returns it.  After this operation,
 * the file pointer will be at the beginning of the first packet in the file.
 *
 * @param pcap_file a PCAP file
 * @return the global PCAP file header
 */
pcap_hdr_t read_global_pcap_header(FILE* pcap_file);

/**
 * A structure recording information about an ethernet frame.  
 */
typedef struct {
	/** destination MAC address */
	unsigned char mac_dest[6];

	/** source MAC address */
	unsigned char mac_src[6];
} ETH_INFO;

/**
 * Decodes pcap packet into a single ethernet frame from the current file position.  
 * Assumes the file pointer is at the beginning of the PCAP packet, i.e., that the
 * current packet's pcaprec_hdr_t has not yet been read.  This function assumes that
 * an ethernet frame is exactly 14 bytes long (no VLAN tag) and that its ethertype
 * is "IP" (i.e., it contains an IPv4 packet).
 *
 * Once complete, the file pointer is at the beginning of the IP header for the packet.
 *
 * @param pcap_file a PCAP file
 * @return the ETH_INFO struct with information about the packet
 */
ETH_INFO decode_eth_frame(FILE* pcap_file);


/**
 * A structure recording information about an IPv4 packet.
 */
typedef struct {
	/** the source IP address for the packet */
	unsigned char src[4];

	/** the destination IP address for the packet */
	unsigned char dest[4];

	/** the length of the TCP segment contained in this IP packet */
	unsigned short tcp_length;
} IP_INFO;

/**
 * Decodes an IPv4 packet starting at the current file position.  Assumes a packet
 * header length of 20 bytes and that the packet contains a TCP segment as its payload.
 *
 * Once complete, the file pointer is at the beginning of the TCP header for the packet.
 *
 * @param pcap_file a PCAP file
 * @return the IP_INFO for the packet at the current file position
 */
IP_INFO decode_ipv4_packet(FILE* pcap_file);

/**
 * A structure recording information about a TCP segment.
 */
typedef struct {
	/** the source port for the segment */
	unsigned short src_port;

	/** the destination port for the segment */
	unsigned short dest_port;
} TCP_INFO;

/**
 * Decodes a TCP segment starting at the current file position.
 *
 * Once complete, the file pointer is at either end-of-file or the beginning of the next
 * PCAP packet.
 *
 * @param pcap_file a PCAP file
 * @return the TCP_INFO stuct with information about the current TCP segment
 */
TCP_INFO decode_tcp_segment(FILE* pcap_file, IP_INFO parent);

/**
 * Builds a TCP/IP socket address from a TCP port and an IP_INFO-style char array.
 *
 * @param ip_addr an IP address with one octet per array element.
 * @param port a TCP port.
 */
struct sockaddr* create_socket(unsigned char ip_addr[], unsigned short port);

/**
 * Prints to stdout the hostname and service (obtained by reverse dns lookup)
 * associated with the given IP address and TCP port, e.g.,
 * 
 * www.example.com:http
 *
 * If the reverse information cannot be obtained, simply prints the IP address
 * and port, e.g.,
 *
 * 123.100.8.34:443
 *
 * @param ip_addr the IP address as an array of octets
 * @param port the TCP port
 */
void print_reverse_lookup(unsigned char ip_addr[], unsigned short port);

#endif
