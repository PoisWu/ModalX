#ifndef SERVER_H
#define SERVER_H
#define UNIT_LENGTH 1024
#define NB_SERVER_MAX 1

typedef struct info_server_and_client
{
    int server_sockfd;
    struct sockaddr_in* serv_addr;
    struct sockaddr_in* client_addr;

} info_ser_cli;


void* server_thread(void* arg);

#endif //SERVER_H