#ifndef CLIENT_H
#define CLIENT_H

#define UNIT_LENGTH 1024
typedef struct addr_port{
    int sockfd;
    struct sockaddr_in *to;
    
}addr_port;

/**
 *  This function is a sub fuction which continue to send the msg to the server.
 * 
 * @param arg type :addr_port who connain sock and PORT_NUMBEER
 * @return Normally there is no return 
*/
void* thread_send(void* arg);

/**
 * This function is a sub funtion which continue to recieve the msg from the server.
 * @param arg type :addr_port* which point to the POINT_NUMBER
 * @return Normally there is no return
*/
void* thread_recv(void *arg);

#endif //CLIENT_H