/**
 *  Jiazi Yi
 *
 * LIX, Ecole Polytechnique
 * jiazi.yi@polytechnique.edu
 *
 * Updated by Pierre Pfister
 *
 * Cisco Systems
 * ppfister@cisco.com
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>


#include "url.h"
#include "wgetX.h"
#define BUFFER_SIZE 1024

int main(int argc, char* argv[]) {
    url_info info;
    const char * file_name = "received_page";
    struct http_reply reply;
    char* response=NULL;
    bool need_redirect=false;
    if (argc < 2) {
	    fprintf(stderr, "Missing argument. Please enter URL.\n");
	    return 1;
    }

    char *url = argv[1];

    // Get optional file name
    if (argc > 2) {
	    file_name = argv[2];
    }

    // First parse the URL
    do{
        int ret = parse_url(url, &info);
        if (ret) {
            fprintf(stderr, "Could not parse URL '%s': %s\n", url, parse_url_errstr[ret]);
            return 2;
        }
        

        //If needed for debug
        //print_url_info(&info);


        ret = download_page(&info, &reply);
        if (ret) {
            return 3;
        }

        // Now parse the responses
        response = read_http_reply(&reply,&need_redirect);
        if (response == NULL) {
            fprintf(stderr, "Could not parse http reply\n");
            return 4;
        }
        
        url=response;
        
    }while(need_redirect);
    

    // Write response to a file
    write_data(file_name, response, reply.reply_buffer + reply.reply_buffer_length - response);
    

    // Free allocated memory
    free(reply.reply_buffer);

    // Just tell the user where is the file
    fprintf(stderr, "the file is saved in %s.\n", file_name);
    return 0;
}

int download_page(url_info *info, http_reply *reply) {


    // cf example in man getaddrinfo
    struct addrinfo hints,*result;
    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype= SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;
    if(getaddrinfo(info->host,info->protocol,&hints,&result)!=0){
        perror("Fail to translate client socket");
        exit(EXIT_FAILURE);
    }
    
    
    //Find avaialbe socket and open the socket cf example in man getaddrinfo
    int sockfd=0;
    bool sockfd_founded=false;
    for(struct addrinfo *res = result ; res ; res = result->ai_next){
        if((sockfd=socket(res->ai_family,res->ai_socktype,res->ai_protocol))>=0){
            if(connect(sockfd,res->ai_addr,res->ai_addrlen)==0){
                sockfd_founded=true;
                break;
            }
        }
        close(sockfd); 
    }

    if(!sockfd_founded){
        perror("No socket available");
        exit(EXIT_FAILURE);
    }


    /*
     * https://gist.github.com/nolim1t/126991/ae3a7d36470d2a81190339fbc78821076a4059f7
     * the reference i use to finish the request write
     */     
    // request
    char *request_buffer=http_get_request(info);
    char buffer[BUFFER_SIZE];
    bzero(buffer,BUFFER_SIZE);
    write(sockfd,request_buffer,strlen(request_buffer));
    shutdown(sockfd,SHUT_WR);

    // Recevie the data.
    int UNIT_LENGTH=1024;
    int rest=UNIT_LENGTH;
    reply->reply_buffer = (char *) malloc(UNIT_LENGTH);
    reply->reply_buffer_length=0;
    ssize_t numByte_recv=0;
    char* debut=reply->reply_buffer;
    do{
        numByte_recv = recv(sockfd,reply->reply_buffer+(reply->reply_buffer_length),rest,0);

        if(numByte_recv<0){
            perror("recieve error!");
            exit(EXIT_FAILURE);
        }else{
            reply->reply_buffer_length+=numByte_recv;
            rest-=numByte_recv;
            if(rest==0){
                reply->reply_buffer = realloc(reply->reply_buffer, (reply->reply_buffer_length)+UNIT_LENGTH);
                rest=UNIT_LENGTH;
            }
        }
    }while(numByte_recv!=0);
    
    return 0;
}

void write_data(const char *path, const char * data, int len) {
    FILE *fp;
    fp = fopen(path,"w");
    if(fp==NULL){
        perror("Open file error");
        exit(EXIT_FAILURE);
    }else{
        fwrite (data , sizeof(char),len, fp);
    }
    fclose(fp);
}

char* http_get_request(url_info *info) {
    char * request_buffer = (char *) malloc(100 + strlen(info->path) + strlen(info->host));
    snprintf(request_buffer, 1024, "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
	    info->path, info->host);
    return request_buffer;
}

char *next_line(char *buff, int len) {
    if (len == 0) {
	    return NULL;
    }
    char *last = buff + len - 1;
    while (buff != last) {
	    if (*buff == '\r' && *(buff+1) == '\n') {
	        return buff;
	    }
	        buff++;
    }
    return NULL;
}

char *read_http_reply(struct http_reply *reply,bool *add_need_redirect) {    

    char *status_line = next_line(reply->reply_buffer, reply->reply_buffer_length);
    if (status_line == NULL) {
	    fprintf(stderr, "Could not find status\n");
	    return NULL;
    }

    *status_line = '\0'; // Make the first line is a null-terminated string

    // Now let's read the status (parsing the first line)
    int status;
    double http_version;
    int rv = sscanf(reply->reply_buffer, "HTTP/%lf %d", &http_version, &status);
    if (rv != 2) {
	    fprintf(stderr, "Could not parse http response first line (rv=%d, %s)\n", rv, reply->reply_buffer);
	    return NULL;
    }

    

    if (status != 200) {
	    if(status/100==3){
            char *buf = status_line + 2;
            char *new_derection = strstr(buf,"http://");
            char *end_derection = strstr(new_derection,"\r\n");
            *end_derection='\0';
            *add_need_redirect=true;
            return new_derection;

        }else{
            fprintf(stderr, "Server returned status %d (should be 200)\n", status);
	        return NULL;
        }      
    
    }else{
        char *buf = status_line + 2;
        int len=(reply->reply_buffer_length)-((reply->reply_buffer)-buf-1);
        char *next_buf=next_line(buf,len);
        while(next_buf!=buf){
            next_buf+=2;
            len=len-(next_buf-buf-1);
            buf=next_buf;
            next_buf=next_line(buf,len);
        }
        *add_need_redirect=false;
        buf+=2;
        
        return buf;
    }    
}
