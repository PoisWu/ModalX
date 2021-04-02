#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#define TAM_MSG 5000

int main(int argc, char* argv[]){

    int mysocket, check;
    struct sockaddr_in destination4;
    socklen_t addrlen = sizeof(destination4);
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
    destination4.sin_family = AF_INET;
    destination4.sin_port = htons(PORT_NUMBER);
    inet_pton(AF_INET, IP_ADDRESS, &(destination4.sin_addr));
    //------------------------------------------------------------------
    fgets(msg, TAM_MSG, stdin);
    check = sendto(mysocket, msg, strlen(msg), MSG_CONFIRM, (struct sockaddr*)&destination4, sizeof(destination4) );
    if(check<0) {
        puts("DEU MERDA");
        return -1;
    }
    //Another way of doing it -> strcpy(msg, "Hello... it`s me, I was wondering if after all this years you`d like to meet...");
    //Waiting an answer from the server
    check = recvfrom(mysocket, msg, TAM_MSG, 0, (struct sockaddr*)&destination4, &addrlen);
    
    if(check<=0) {
        puts("No answer from the server");
        return -1;
    }
    //-----------------------
    //Print msg received from server
    puts("Msg received from server:\n");
    puts(msg);
    puts("--------------------------------");

}