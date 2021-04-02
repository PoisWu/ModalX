#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#define TAM_MSG 5000
#define MAX_THREAD 2

void* receiving(void*);
void* sending(void*);
enum {RECEIVE, SEND};
pthread_t threads[MAX_THREAD];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


typedef struct arg_receiving{
    int mysocket;
    char msg[TAM_MSG];
    struct sockaddr_in remaddr;
    socklen_t addrlen;
}arg_receiving;

typedef struct  arg_sending
{   
    int mysocket;
    char msg[TAM_MSG];
    struct sockaddr_in remaddr;
    socklen_t addrlen;
}arg_sending;



//ABLE TO RECEIVE MSGs WHILE Sending - Je vais creer une Thread Receive et une Thread Send


int main(int argc, char* argv[]){

    int mysocket, check;
    struct sockaddr_in remaddr;
    socklen_t addrlen = sizeof(remaddr);
    char msg[TAM_MSG];

    if (argc < 2) {
	    fprintf(stderr, "Missing argument. Please enter IP_ADDRESS.\n");
	    return 1;
    }
    char* IP_ADDRESS = argv[1];
    if (argc < 3) {
	    fprintf(stderr, "Missing argument. Please enter PORT_NUMBER.\n");
	    return 2;
    }
    int PORT_NUMBER = atoi(argv[2]);

    //Create socket UDP
    mysocket = socket(AF_INET, SOCK_DGRAM,0);

    //Character of our destination
    remaddr.sin_family = AF_INET;
    remaddr.sin_port = htons(PORT_NUMBER);
    inet_pton(AF_INET, IP_ADDRESS, &(remaddr.sin_addr));
    //------------------------------------------------------------------
    //Creating thread sending
    arg_sending *args = malloc(sizeof(arg_sending));
    arg_receiving *argr = malloc(sizeof(arg_receiving));
    args->mysocket = mysocket;
    args->remaddr = remaddr;
    argr->mysocket = mysocket;
    argr->remaddr = remaddr;
    //We can receive msg from servers with whom we have not sent
    pthread_create(&(threads[SEND]), NULL, sending, args);
    pthread_create(&(threads[RECEIVE]), NULL, receiving, argr);

    for(int i=0;i<MAX_THREAD;i++){
        pthread_join(threads[i],NULL);
    }


}
void* sending(void* args){
    int hwmny_tsmt = 0;
    arg_receiving *actual_args = args;
    while(strcmp(actual_args->msg, "END\n")!=0){
        fgets(actual_args->msg, TAM_MSG, stdin);
        hwmny_tsmt = sendto(actual_args->mysocket, actual_args->msg, strlen(actual_args->msg), MSG_CONFIRM, (struct sockaddr*)&(actual_args->remaddr), sizeof(struct sockaddr));
        if(hwmny_tsmt<0) {
            puts("erreur sending");
            return -1;
        }
        if(strcmp(actual_args->msg, "END\n")==0){ puts("Sent END from client, server shut down"); return 0;}
        printf("SENDING: Thread %ld : %d bytes sent as: ", (long)pthread_self(), hwmny_tsmt); //the number is not the ID of the packet, it`s just to give us an idea of how many we have gotten till now
        puts(actual_args->msg);
        memset(actual_args->msg,0,sizeof(TAM_MSG));
    }

}

void* receiving(void *args){
    int hwmny_tsmt = 0;
    arg_receiving *actual_args = args;
    while(strcmp(actual_args->msg, "END\n")!=0){
        hwmny_tsmt = recvfrom(actual_args->mysocket,actual_args->msg, TAM_MSG, 0, (struct sockaddr *) &(actual_args->remaddr), &(actual_args->addrlen));
        if(hwmny_tsmt<0) {
            puts("erreur receiving");
            return -1;
        }
        if(strcmp(actual_args->msg, "END\n")==0){ puts("Reveiced END from client"); return 0;}
        printf("RECEIVING: Thread %ld : %d bytes received as: ", (long)pthread_self(), hwmny_tsmt); //the number is not the ID of the packet, it`s just to give us an idea of how many we have gotten till now
        puts(actual_args->msg);
    }
}