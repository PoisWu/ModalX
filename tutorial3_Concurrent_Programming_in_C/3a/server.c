#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <pthread.h> 

#include "server.h"


int main(int arg,char* argv[]){
    // Ref https://www.geeksforgeeks.org/udp-server-client-implementation-c/
    //setup input 
    // Ref https://gist.github.com/oleksiiBobko/43d33b3c25c03bcc9b2b
    if(arg<2){
        fprintf(stderr,"Missing argument, please make sure that you enter PORT_NUMBER");
        return 1;
    }
    
    int PORT_NUMBER=atoi(argv[1]);
    int server_sockfd=socket(AF_INET,SOCK_DGRAM,0);

    struct sockaddr_in *client_addr=malloc(sizeof(struct sockaddr_in));
    memset(client_addr,0,sizeof(struct sockaddr_in));
    
    struct sockaddr_in *serv_addr=malloc(sizeof(struct sockaddr_in));
    memset(serv_addr,0,sizeof(struct sockaddr_in));
    serv_addr->sin_family=AF_INET;
    serv_addr->sin_addr.s_addr = INADDR_ANY;
    serv_addr->sin_port=htons(PORT_NUMBER);

    bind(server_sockfd,(const struct sockaddr *) serv_addr,sizeof(struct sockaddr_in));

    info_ser_cli *ser_cli=malloc(sizeof(info_ser_cli));
    ser_cli->server_sockfd=server_sockfd;
    ser_cli->client_addr=client_addr;

    pthread_t pid[NB_SERVER_MAX];
    for(int i=0;i<NB_SERVER_MAX;i++){
        if(pthread_create(&pid[i],NULL,server_thread,(void*) ser_cli)){
            fprintf(stderr,"Error creating server thread\n");
            return 1;
        }
    }    
    while(1);
    return 0;

}
void* server_thread(void* arg){

    info_ser_cli* ser_cli = (info_ser_cli *) arg;
    while(1){

        char* buf=malloc(UNIT_LENGTH);
        int *lenfrom=malloc(sizeof(int));
        *lenfrom = sizeof(struct sockaddr_in);
        int nb_byte_recv = recvfrom(ser_cli->server_sockfd, buf, UNIT_LENGTH ,MSG_DONTROUTE,( struct sockaddr *) ser_cli->client_addr,(socklen_t *) lenfrom);
        
        printf("Thread %d recieve message :\n",pthread_self());
        printf("%s\n",buf); 
        printf("nb_bytes_recv:\t%d\n",nb_byte_recv);
        buf[nb_byte_recv]='\0';
        
        sendto(ser_cli->server_sockfd,buf,nb_byte_recv,MSG_DONTROUTE,(const struct sockaddr *)ser_cli->client_addr,sizeof(*ser_cli->client_addr));
        sleep(1);
        printf("Thread %d is ready!\n",pthread_self());
    }
}
