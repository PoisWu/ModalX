#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include <stdbool.h>

#define VM_IP "192.168.56.101"
#define VM_PORT 2000
#define MAX 128

void commicate(int sock_fd){
    for(;;){
        char buff[MAX];
        bzero(buff,sizeof(buff));
        int n = 0;    
        while((buff[n++]=getchar())!= '\n')
            ;
        write(sock_fd,buff,sizeof(buff));
        printf("write down\n");
        bzero(buff,sizeof(buff));
        n = read(sock_fd,buff,sizeof(buff));
        printf("n=%d\n",n);
        if(n==0){
            break;
        }
        printf("%s\n",buff);
        fflush(stdout);
    }
}

int main(){
    int sock_fd;
    struct sockaddr_in servaddr;
    sock_fd=socket(AF_INET,SOCK_STREAM,0);
    if(sock_fd==-1){
        printf("socket creation failded..\n");
        exit(0);
    }else{
        printf("socket successfully created...\n");
    }
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family=AF_INET;
    servaddr.sin_addr.s_addr=inet_addr(VM_IP);
    servaddr.sin_port=htons(VM_PORT);
    if(connect(sock_fd,(const struct sockaddr *)&servaddr,sizeof(servaddr))!=0){
        printf("connction with the server failed...\n");
        exit(0);
    }else{
        printf("connected to the server...\n");
    }
    commicate(sock_fd);

    return 0;

}