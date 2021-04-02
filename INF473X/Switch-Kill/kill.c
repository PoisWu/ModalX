/*
We have to generate a big volume of packets with different source addresses (layer-2 source addresses, aka 'Mac')
[Maybe it would be a good idea to set some threads to do it simuntaneously]
After flooding we take a look at how our switch is behaving to see if it crashed or entered in broadcast-mode

Can we use the TCP-Syn-Flooding code to do this? Cause technically we are sending a bunch of different packets (yes and no, because we have to change the Mac and not the IP)

- To keep it continous: We have to mesure/guess the timeout of the hash-table in the switch, because it's going to refresh from time to time

To do:
. Create a random layer-2 source address
. Send them all

*/


#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<time.h>
#include <unistd.h>//For close()

#include "header.h"

#define TEST_STRING "Hijacking Switch" //a test string as packet payload
#define DEFAULT_INTERFACE "eth0" //change to your own eth interface
#define BUF_SIZE   1024     // packet maximum size

int main(int argc, char *argv[]) {
    //Generate aleatory seed based on time
    srand(time(NULL));
    
    int mysocket;
    char buf[BUF_SIZE];//Buffer for our package

    struct sockaddr_ll socket_address;//a device-independent physical-layer address
    
    struct ethh *eh = (struc ethh*) buf;
    struct iphdr *iph = (struct iph*) (buf +sizeof(struct ethh));
    struct tcphdr * tcph = (struct tcphdr*) (buf + sizeof(struct ethh) + sizeof(struct tcphdr));







    return 0;
}   