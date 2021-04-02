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


#define UNIT_LENGTH 2


int main(int arg, char* argv[]){
    // Setup input IP_ADDRESS and PORT_NUMBER
    if(arg<2){
        fprintf(stderr, "Missing argument, please make sure that you enter IP_ADDRESS and PORT_NUMBER ");
        return 1;
    }
    char *IP_ADDRESS = argv[1];
    char *strPORT_NUMBER= argv[2];
    int PORT_NUMBER=atoi(strPORT_NUMBER);
    if(PORT_NUMBER==0){
        fprintf(stderr,"No available PORT_NUMBER");
        return 1;
    }
    

    /*
    *  https://stackoverflow.com/questions/13592875/reading-multiple-lines-of-input-with-scanf
    *  cf : read many lines 
    */

    // Setup input msg sended. 
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
            if (ConsecutiveEnterCount >= 2 /* or 1, not clear on OP intent */) {
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
    //Setup the connection and send the msg.
    int sockfd=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in *to=malloc(sizeof(struct sockaddr_in));
    memset(to,0,sizeof(struct sockaddr_in));
    to->sin_family=AF_INET;
    to->sin_port=htons(PORT_NUMBER);
    int ok_convert_IP = inet_pton(AF_INET,IP_ADDRESS,&(to->sin_addr.s_addr));
    if(ok_convert_IP !=1){
        fprintf(stderr,"Fail to convert the IP_ADDRESS");
        return 1;
    }
    int nb_byte_sent = sendto(sockfd,msg,msglen,MSG_DONTROUTE,(const struct sockaddr *)to,sizeof(struct sockaddr_in));
     printf("%d",nb_byte_sent);
    close(sockfd);

    return 0;


}