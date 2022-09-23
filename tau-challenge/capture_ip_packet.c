
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <unistd.h>

#include "header.h"

void treat_ip_packet(const u_char *buff){
    struct iphdr *in_iphr=buff;
    struct tcphdr *in_tcphdr = (struct tcphdr*)(in_iphr + 1);
    
}