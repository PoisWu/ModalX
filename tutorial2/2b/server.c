#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

#define UNIT_LENGTH 1024

int main(int arg,char* argv[]){
    // Ref https://www.geeksforgeeks.org/udp-server-client-implementation-c/
    //setup input 
    if(arg<2){
        fprintf(stderr,"Missing argument, please make sure that you enter PORT_NUMBER");
        return 1;
    }
    
    int PORT_NUMBER=atoi(argv[1]);
    

    
    /**
     * How about the IP_ADDRESS
     * 
    **/
    // Setup the Connextion
    int sockfd=socket(AF_INET,SOCK_DGRAM,0);

    struct sockaddr_in *from=malloc(sizeof(struct sockaddr_in));
    memset(from,0,sizeof(struct sockaddr_in));
    
    struct sockaddr_in *serv_addr=malloc(sizeof(struct sockaddr_in));
    memset(serv_addr,0,sizeof(struct sockaddr_in));
    serv_addr->sin_family=AF_INET;
    serv_addr->sin_addr.s_addr = INADDR_ANY;
    serv_addr->sin_port=htons(PORT_NUMBER);

    bind(sockfd,(const struct sockaddr *) serv_addr,sizeof(struct sockaddr_in));

    // Recv the msg 
    
    char* buf=malloc(UNIT_LENGTH);
    int *lenfrom=malloc(sizeof(int));
    *lenfrom = sizeof(struct sockaddr_in);
    int nb_byte_recv = recvfrom(sockfd, buf, UNIT_LENGTH ,MSG_DONTROUTE,( struct sockaddr *) from,(socklen_t *) lenfrom);
    printf("%s\n",buf); 
    printf("nb_bytes_recv:\t%d\n",nb_byte_recv);
    buf[nb_byte_recv]='\0';

    sendto(sockfd,buf,nb_byte_recv,MSG_DONTROUTE,(const struct sockaddr *)from,sizeof(*from));
    free(from);
    close(sockfd);

    return 0;

}