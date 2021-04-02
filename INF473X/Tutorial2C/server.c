#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define TAM 5000


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
    int hwmny_tsmt = -1;
    int contador = 0;
    //-------------
    //Filling our addr
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_NUMBER);
    inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr));

    mysocket = socket(AF_INET,SOCK_DGRAM, 0);
    
    if(bind(mysocket, (struct sockaddr*) &addr,sizeof(struct sockaddr_in))==-1) puts("Not possible to bind\n");
    printf("You are binded to %d and IP 127.0.0.1\n", PORT_NUMBER);//n`affiche pas et apres que je envoye un truc il ferme
    
    while(hwmny_tsmt =! 0){//working till we receive 0 bytes in a transmission or if we type END\n
        contador++;
        //Receiving
        hwmny_tsmt = recvfrom(mysocket,msg, TAM, 0, (struct sockaddr *) &remaddr, &addrlen);
        printf("Transmission number %d : %d bytes received as: ", contador, hwmny_tsmt); //the number is not the ID of the packet, it`s just to give us an idea of how many we have gotten till now
        puts(msg);
        //Sending Back - How do I know if it`s arriving to the client
        //strcpy(msg, "Hello... it`s me, I was wondering if after all this years you`d like to meet...");
    
        hwmny_tsmt = sendto(mysocket, msg, strlen(msg), MSG_CONFIRM, (struct sockaddr*)&remaddr, sizeof(remaddr));
        printf("%d Bytes sent back as: %s", hwmny_tsmt, msg); //the number is not the ID of the packet, it`s just to give us an idea of how many we have gotten till now
        
        if(hwmny_tsmt<0) {
            puts("Couldn`t respond to msg with the same content\n");
            return -1;
            //ctrl+c to exit
        }
        puts("-----------------------------------------------------------");
        if(strcmp(msg, "END\n")==0){ puts("Reveiced END from client"); break;}
        memset(msg,0,sizeof(msg));
    }

    return 0;
}