#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#define TAM 5000
#define MAX_THREAD 3

void* receiving(void*);
pthread_t threads[MAX_THREAD];
pthread_mutex_t lock;

typedef struct arg_receiving{
    int mysocket;
    char msg[TAM];
    struct sockaddr_in remaddr;
    socklen_t addrlen;
}arg_receiving;


int main(int argc, char* argv[]){
    
    //Treatment of entries
    if (argc < 2) {
	    fprintf(stderr, "Missing argument. Please enter Port Number.\n");
	    return 1;
    }
    int PORT_NUMBER = atoi(argv[1]);
    //Declaration
    int mysocket;
    struct sockaddr_in addr;
    struct sockaddr_in remaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    char msg[TAM];
    int contador = 0;
    //-------------
    //Filling our addr
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_NUMBER);
    inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr));

    mysocket = socket(AF_INET,SOCK_DGRAM, 0);
    
    if(bind(mysocket, (struct sockaddr*) &addr,sizeof(struct sockaddr_in))==-1) puts("Not possible to bind\n");
    printf("You are binded to %d and IP 127.0.0.1\n", PORT_NUMBER);//n`affiche pas et apres que je envoye un truc il ferme
    //--------------
    //Locking creation
    if(pthread_mutex_init(&lock, NULL)) {
		puts("Impossible to create Mutex\n"); 
		return -1;
	}
    //-------------
    while(contador<MAX_THREAD){//working till we type END or we reach the max of threads
        //Creating Threads
        arg_receiving *args = malloc(sizeof(arg_receiving));
        args->mysocket = mysocket;
        args->remaddr = remaddr;
        args->addrlen = addrlen;
        pthread_create(&(threads[contador]), NULL, receiving, args);        
        memset(args->msg,0,sizeof(args->msg));
        pthread_join(threads[contador],NULL);
        contador++;
        if(contador==3) contador=0;
    }

    /*for(int i=0;i<MAX_THREAD;i++){
        pthread_join(threads[i],NULL);
    }*/
    return 0;
}




void* receiving(void *args){
    int hwmny_tsmt = 0;
    arg_receiving *actual_args = args;
    if(pthread_mutex_lock(&lock)) puts("Incapable of locking");
    memset(actual_args->msg,0,TAM);
    hwmny_tsmt = recvfrom(actual_args->mysocket,actual_args->msg, TAM, 0, (struct sockaddr *) &(actual_args->remaddr), &(actual_args->addrlen));
    if(pthread_mutex_unlock(&lock)) puts("Incapable of locking");
   
    if(strcmp(actual_args->msg, "END\n")==0){ puts("Reveiced END from client"); return 0;}
    printf("Thread %ld : %d bytes received as: ", (long)pthread_self(), hwmny_tsmt); //the number is not the ID of the packet, it`s just to give us an idea of how many we have gotten till now
    puts(actual_args->msg);

    usleep(3000000);

    //Sending confirmation as the same msg
    hwmny_tsmt = sendto(actual_args->mysocket, actual_args->msg, strlen(actual_args->msg), MSG_CONFIRM, (struct sockaddr*)&(actual_args->remaddr), sizeof(struct sockaddr));
     printf("%d Bytes sent back as: %s", hwmny_tsmt, actual_args->msg); 
     if(hwmny_tsmt<0) {
         puts("Couldn`t respond to msg with the same content\n");
         return -1;
         //ctrl+c to exit
     }
}