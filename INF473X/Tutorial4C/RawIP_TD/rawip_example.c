/*
 * rawip_example.c
 *
 *  Created on: May 4, 2016
 *      Author: jiaziyi
 */


#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include "header.h"

#define SRC_IP  "192.168.1.111" //set your source ip here. It can be a fake one
#define SRC_PORT 54321 //set the source port here. It can be a fake one

#define DEST_IP "127.0.0.1" //set your destination ip here
#define DEST_PORT 40000 //set the destination port here
#define TEST_STRING "test data" //a test string as packet payload

int main(int argc, char *argv[])
{
	char source_ip[] = SRC_IP;
	char dest_ip[] = DEST_IP;


	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    int hincl = 1;                  /* 1 = on, 0 = off */
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
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data));//?
	iph->id = 0;//? - how do Iknow which one to put in here??
	//iph->flags not used
	iph->frag_off = 0;
	iph->ttl = 255;//Time to live
	iph->protocol = 17;//udp protocol
	iph->check = 0;//Check to zero b4 calculating the checksum
	iph->saddr = inet_addr(source_ip);
	iph->daddr = inet_addr(dest_ip);

	//Calculating the IP check sum
	iph->check = checksum((unsigned short *) packet, iph->tot_len);
	
	//fill the UDP header
	udph->source= htons(SRC_PORT);//If we do not fill it starts with zero
	udph->dest= htons(DEST_PORT);
	udph->len= htons(8 + strlen(data));
	udph->check = 0;//Check to zero b4 calculating the checksum

	//fill the UDP pseudo header
	psh.dest_address = iph->daddr;
	psh.source_address= iph->saddr;
	psh.protocol = 17;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));
	psh.placeholder = 0;

	//Calculating UDP check sum - WHY DO WE HAVE TO CONSIDER THE PSEUDO HEADER TO CALCULATE THE CHECKSUM?
	int psize = sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + strlen(data);
	char *pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_udp_header));
	memcpy(pseudogram + sizeof(struct pseudo_udp_header) , udph , sizeof(struct udphdr) + strlen(data));
	
	udph->check = checksum( (unsigned short*) pseudogram , psize);

	//CreatING destination socket address
    struct sockaddr_in t;
    t.sin_addr.s_addr=iph->daddr;
    t.sin_family=AF_INET;
    t.sin_port=udph->dest;

	//-------------------------------------------------------------------------------
	printf("\n");
    printf( "IP Header\n");
    printf( "   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf( "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf( "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf( "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf( "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph->check));
    printf("   |-Source IP        : %s\n" , source_ip );
    printf("   |-Destination IP   : %s\n" , dest_ip);

	printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));


	//------------------------------------------------------------------------------

	//SENDING THE PACKET
	if(sendto(fd, packet, iph->tot_len, 0, (const struct  sockaddr *)&t, sizeof(t))==-1){
		puts("Not able to send package\n");
	}//I dont know if the correct size should be 65536 or the total length in the IP package or another thing


	return 0;

}
