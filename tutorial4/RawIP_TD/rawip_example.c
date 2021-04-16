/*
 * rawip_example.c
 *
 *  Created on: May 4, 2016
 *      Author: jiaziyi
 */
// ref https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
// ref https://www.binarytides.com/raw-sockets-c-code-linux/
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include "header.h"

#define SRC_IP  "192.168.1.111" //set your source ip here. It can be a fake one
#define SRC_PORT 54321 //set the source port here. It can be a fake one

#define DEST_IP "127.0.0.1"
//#define DEST_IP "129.104.89.108" //set your destination ip here
#define DEST_PORT 40000 //set the destination port here
#define TEST_STRING "test data" //a test string as packet payload

int main(int argc, char *argv[])
{
	char source_ip[] = SRC_IP;
	char dest_ip[] = DEST_IP;


	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	
    int hincl = 0;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}



	char packet[65536], *data;
	char data_string[] = TEST_STRING;
	memset(packet, 0, 65536);

	//IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//UDP header pointer
	struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_udp_header psh; //pseudo header

	//data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

	//fill the data section
	strncpy(data, data_string, strlen(data_string));

	//fill the IP header here
	iph->version=4;
	iph->ihl=5;
	iph->tos= 0; 
	iph->tot_len=htons(sizeof(struct iphdr)+sizeof(struct udphdr)+strlen(data_string));     
	iph->id=0;
	iph->frag_off=0;
	iph->ttl=255;
	iph->protocol=17; // udp service https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	iph->check=0;
	iph->saddr=inet_addr(source_ip);
	iph->daddr=inet_addr(dest_ip);
	iph->check=checksum((unsigned short *) packet, iph->tot_len);

	
	
	//fill the UDP header
	
	udph->source=htons(SRC_PORT);
	udph->dest=htons(DEST_PORT);
	udph->len=htons(sizeof(struct udphdr)+strlen(data_string));
	udph->check=0;
	
	//fill the UDP pseudo header
	psh.source_address=iph->saddr;
	psh.dest_address=iph->daddr;
	psh.protocol=IPPROTO_UDP;
	psh.udp_length=udph->len;
	psh.placeholder=0;

	int psize=sizeof(struct pseudo_udp_header) + sizeof(struct udphdr)+strlen(data_string);
	char *pseudogram=malloc(psize);
	memcpy(pseudogram, (char *)&psh,sizeof(struct pseudo_udp_header));
	memcpy(pseudogram+sizeof(struct pseudo_udp_header),udph,sizeof(struct udphdr)+strlen(data_string));



	udph->check=checksum((unsigned short *) pseudogram,psize);

	
	
	//-----------------------
	fprintf(stdout , "\n");
    fprintf(stdout , "IP Header\n");
    fprintf(stdout , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(stdout , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(stdout , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(stdout , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(stdout , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(stdout , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(stdout , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(stdout , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(stdout , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(stdout , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(stdout , "   |-Checksum : %d\n",ntohs(iph->check));
	
	struct in_addr s;
	s.s_addr= iph->saddr;
    fprintf(stdout , "   |-Source IP        : %s\n" , inet_ntoa(s) );
	struct in_addr d;
	d.s_addr= iph->daddr;
    fprintf(stdout , "   |-Destination IP   : %s\n" , inet_ntoa(d) );

    fprintf(stdout , "\nUDP Header\n");
    fprintf(stdout , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(stdout , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(stdout , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(stdout , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	

	//----------------------------

	//send the packet
	

    struct sockaddr_in *to=malloc(sizeof(struct sockaddr_in));
    memset(to,0,sizeof(struct sockaddr_in));
    to->sin_family=AF_INET;
    to->sin_port=udph->dest;
	to->sin_addr.s_addr=iph->daddr;
   
    int nb_byte_sent = sendto(fd,packet,iph->tot_len,0,(const struct sockaddr *)to,sizeof(struct sockaddr_in));
    if(nb_byte_sent<0){
		fprintf(stderr,"fail send\n");
	}


	return 0;

}
