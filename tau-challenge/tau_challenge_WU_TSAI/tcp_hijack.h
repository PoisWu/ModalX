/*
 * pcap_example.h
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */

#ifndef PCAP_EXAMPLE_H_
#define PCAP_EXAMPLE_H_

#define BUF_SIZE 65536

int header_type;
#define LINKTYPE_NULL 0
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

char *address_array = "192.168.1.102"; //the answer to put...
int max(int num1, int num2);
int min(int num1, int num2);
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void send_rst_back();
void *send_thread();
#endif /* PCAP_EXAMPLE_H_ */
