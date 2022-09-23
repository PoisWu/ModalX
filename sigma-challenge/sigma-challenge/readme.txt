Collab with Tsai Bing-shun
ref1 https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
ref2 for syn flood attack https://www.binarytides.com/raw-sockets-c-code-linux/ 
ref3 for TCP rawIP espacially checksum https://www.binarytides.com/raw-sockets-c-code-linux/ 

I wrote some fuction auxiliere to make the function more stucture(declared in VM_syn_flood.h):
=============
void fil_up_syn_flood_rawheader(char * packet);
    It will fil up the header with random IP header and TCP header. It calls two suivant fuction "random_IP_header" and "ramdom_TCP_header"
============
void random_IP_header(struct iphdr *iph);
    fil up the IP header. it will choose randomly the source IP address.
===========
void random_TCP_header(struct tcphdr *tcph,unsigned int source_address,unsigned int dest_address);
    fil up the TCP header. it will choose randomly the port number. It need also the Source IP address and dest IP address so i pass them to it.
===========
void send_message(int sockfd,char *send_packet);
    Send the send_packet whitch the IP header and TCP header have been filed up via the socket sockfd. Because the TCP/IP header is well-prepared, so i can find all I need for the fuction "sendto". (like server_addr or server_port) 
===========

So to do syn-flood attack it juste need to create a raw socket and then call fil_up_syn_flood_rawheader and send_message

Remark: 
- For the TCP checksum I did the same thing in ref3. I created the pseudo-header. Then i calculate.

- The variable flood in main() (use to setting the flood attack) is setted to 0 for l'instant.

