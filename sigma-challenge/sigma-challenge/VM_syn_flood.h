#ifndef VM_syn_flood_H
#define VM_syn_flood_H

#define VM_IP "192.168.56.101"
#define VM_PORT 2000
#define MAX 128
#define TEST_STRING "test" //a test string as packet payload



void send_message(int sockfd,char *send_packet);
void fil_up_syn_flood_rawheader(char * packet);
void random_IP_header(struct iphdr *iph);
void random_TCP_header(struct tcphdr *tcph,unsigned int source_address,unsigned int dest_address);


#endif //VM_syn_flood_H