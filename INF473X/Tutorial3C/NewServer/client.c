#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


int main(int argc, char* argv[]){

    int mysocket, check;
    struct sockaddr_in destination4;
    char msg[5000];
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

    //Creation socket UDP
    mysocket = socket(AF_INET, SOCK_DGRAM,0);

    //Character of our destination
    destination4.sin_family = AF_INET;
    destination4.sin_port = htons(PORT_NUMBER);
    inet_pton(AF_INET, IP_ADDRESS, &(destination4.sin_addr));
    //------------------------------------------------------------------
    while(1){
        fgets(msg, 1000, stdin);
        check = sendto(mysocket, msg, strlen(msg), MSG_CONFIRM, (struct sockaddr*)&destination4, sizeof(destination4));
        if(check<0) {
            puts("DEU MERDA");
            return -1;
            //ctrl+c to exit
        }
    }
    
    //strcpy(msg, "Hello... it`s me, I was wondering if after all this years you`d like to meet...");
    
    puts(msg);
    puts("--------------------------------");

}