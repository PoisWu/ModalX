#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "client.h"

pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t changement =PTHREAD_COND_INITIALIZER;
int time_to_send = 1;

int main(int arg, char* argv[]){
    // Setup input IP_ADDRESS and PORT_NUMBER
    if(arg<2){
        fprintf(stderr, "Missing argument, please make sure that you enter IP_ADDRESS and PORT_NUMBER ");
        return 1;
    }
    char *IP_ADDRESS = argv[1];
    int PORT_NUMBER=atoi(argv[2]);
    
    if(PORT_NUMBER==0){
        fprintf(stderr,"No available PORT_NUMBER");
        return 1;
    }
    //Preparaton 

    int sockfd=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in *to=malloc(sizeof(struct sockaddr_in));
    memset(to,0,sizeof(struct sockaddr_in));
    to->sin_family=AF_INET;
    to->sin_port=htons(PORT_NUMBER);
    int ok_convert_IP = inet_pton(AF_INET,IP_ADDRESS,&(to->sin_addr.s_addr));
    if(ok_convert_IP !=1){
        fprintf(stderr,"Fail to convert the IP_ADDRESS");
    }
    addr_port *addr_port = malloc(sizeof(struct addr_port));

    addr_port->sockfd=sockfd;
    addr_port->to=to;

    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        return 1;
    }
    
    // Exacute send_thread
    pthread_t send_thread;
    if(pthread_create(&send_thread,NULL,thread_send,(void*) addr_port)){
        fprintf(stderr,"Error creating send_thread\n");
        return 1;
    }

    pthread_t recv_thread;
    if(pthread_create(&recv_thread,NULL,thread_recv,(void*) addr_port)){
        fprintf(stderr,"Error creat recv_thread\n");
        return 1;
    }
    while(1);
    
    close(sockfd);
    free(addr_port);
    return 0;
}

void* thread_send(void* arg){
    addr_port* AP=(addr_port*)arg;
    
    while(1){
        
        printf("Enter text. Press enter on blank line to exit.\n");
        unsigned ConsecutiveEnterCount = 0;
        char* msg=malloc(UNIT_LENGTH);
        int rest=UNIT_LENGTH;
        int msglen=0;
        
        for (;;) {
            char buffer[1024];
            if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                break;  // handle error or EOF
            }
            if (buffer[0] == '\n') {
                ConsecutiveEnterCount++;
                if (ConsecutiveEnterCount >= 1 /* or 1, not clear on OP intent */) {
                    break;
                }
            }else{
                ConsecutiveEnterCount = 0;           
            }
            msglen+=strlen(buffer);

            if(strlen(buffer)<rest){
                    strcat(msg,buffer);
                    rest-=strlen(buffer);
            }else{
                    rest+=UNIT_LENGTH;
                    msg=realloc(msg,strlen(msg)+UNIT_LENGTH);
                    strcat(msg,buffer);
            }
        }
        
        // pthread_mutex_lock(&lock);
        // while(!time_to_send){
        //     pthread_cond_wait(&changement,&lock);
        // }
        int nb_byte_sent = sendto((AP->sockfd),msg,msglen,MSG_DONTROUTE,(const struct sockaddr *)AP->to,sizeof(struct sockaddr_in));
        // time_to_send=0;
        // pthread_cond_signal(&changement);
        // pthread_mutex_unlock(&lock);

        if(nb_byte_sent<0){
            perror("Send failed");
        }
        pthread_mutex_unlock(&lock);

        printf("number of byte sent is %d\n",nb_byte_sent);
        puts("========");
        puts("");
    
        free(msg);
    }
   
}


void* thread_recv(void *arg){
    addr_port* AP=(addr_port*)arg;

    // Recv the msg 
  
    while(1){
        
        char* buf=malloc(UNIT_LENGTH);
        int *lenfrom=malloc(sizeof(int));
        *lenfrom = sizeof(struct sockaddr_in);
        
        // pthread_mutex_lock(&lock);
        // while(time_to_send){
        //     pthread_cond_wait(&changement,&lock);
        // }
        // time_to_send=1;
        int nb_byte_recv = recvfrom((AP->sockfd), buf, UNIT_LENGTH ,MSG_DONTROUTE,(struct sockaddr *) AP->to,(socklen_t *) lenfrom);
        // pthread_cond_signal(&changement);
        // pthread_mutex_unlock(&lock);

        if(nb_byte_recv<0){
            perror("recv failed");
            exit(EXIT_FAILURE);
        }

        printf("nb_bytes_recv:\t%d\n",nb_byte_recv);
        printf("the message recived is:\n%s",buf);
        free(buf);
        free(lenfrom);
    }
}
