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

#include "url.h"
#include "wgetX.h"

#define MAXRCVLEN 4000

int main(int argc, char* argv[]) {
    url_info info;
    const char * file_name = "received_page";
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
    int ret = parse_url(url, &info);
    if (ret) {
	    fprintf(stderr, "Could not parse URL '%s': %s\n", url, parse_url_errstr[ret]);
	    return 2;
    }

    //If needed for debug
    //print_url_info(&info);

    // Download the page
    struct http_reply reply;

    ret = download_page(&info, &reply);
    if (ret) {
	    return 3;
    }

    // Now parse the responses
    char *response = read_http_reply(&reply);
    if (response == NULL) {
	    fprintf(stderr, "Could not parse http reply\n");
	    return 4;
    }

    // Write response to a file
    response[strlen(response)-1] = '\0';
    puts("====");
    puts(response);
    //printf("strlen=%d, last char %c%c%c%c\n", strlen(response), response[1258-5], response[1258-4], response[1258-3], response[1258-2]);
    // write_data(file_name, response, reply.reply_buffer + reply.reply_buffer_length - response);
    write_data(file_name, response, strlen(response));

    // Free allocated memory
    free(reply.reply_buffer);

    // Just tell the user where is the file
    fprintf(stderr, "the file is saved in %s.", file_name);
    return 0;
}

int download_page(url_info *info, http_reply *reply) {

    struct hostent* host;
    //char* host_ip;
    char* http_request;
    char* buffer_reply;
    int recebimento;
    //------------------------------------------------------
    //CREATING SOCKET
    int mysocket;
    struct sockaddr_in dest;//Destination

    mysocket = socket(AF_INET, SOCK_STREAM, 0);
    //-----------------------------------------------------
    /*
     * To be completed:
     *   You will first need to resolve the hostname into an IP address.
     *
     *   Option 1: Simplistic
     *     Use gethostbyname function.
     *
     *   Option 2: Challenge
     *     Use getaddrinfo and implement a function that works for both IPv4 and IPv6.
     *
     */

    host = gethostbyname(info->host);//obsolete but we`re sticking with it right now
    if(host->h_addr_list == NULL){ puts("IP ADDRESSES NOT FOUND\n"); return -1;}
    // host_ip = strncpy(host_ip, *(host->h_addr_list), host->h_length);

    //Dest caracterization
    memset(&dest, 0, sizeof(dest));//Initialization with 0 of the memory space
    dest.sin_family = AF_INET;
    memcpy(&dest.sin_addr, host->h_addr_list[0], host->h_length);
    // printf("h_length=%d, %s\n", host->h_length, *(host->h_addr_list));
    dest.sin_port = htons(info->port);
    
    if (connect(mysocket, (struct sockaddr *)&dest, sizeof(struct sockaddr))) {
	    fprintf(stderr, "Could not connect: %s\n", strerror(errno));
        puts("NOT CONNECTED");
        return -1;
    }

    puts("SUCCESSFULY CONNECTED");

    /*
     * To be completed:
     *   Next, you will need to send the HTTP request.
     *   Use the http_get_request function given to you below.
     *   It uses malloc to allocate memory, and snprintf to format the request as a string.
     *
     *   Use 'write' function to send the request into the socket.
     *
     * write_data  Note: You do not need to send the end-of-string \0 character.
     *   Note2: It is good practice to test if the function returned an error or not.
     *   Note3: Call the shutdown function with SHUT_WR flag after sending the request
     *          to inform the server you have nothing left to send.
     *   Note4: Free the request buffer returned by http_get_request by calling the 'free' function.
     *
     */

    http_request = http_get_request(info);
    if(send(mysocket, http_request, strlen(http_request),0) == -1){//equivalent a write
        puts("\nPROBLEM SENDING REQUEST");
        return -1;
    }
        puts("SUCCESSFULY SENT REQUEST");
    if(shutdown(mysocket,SHUT_WR)==-1) puts("\nPROBLEM SHUTTING DOWN");
    free(http_request);

    /*
     * To be completed:
     *   Now you will need to read the response from the server.
     *   The response must be stored in a buffer allocated with malloc, and its address must be save in reply->reply_buffer.
     *   The length of the reply (not the length of the buffer), must be saved in reply->reply_buffer_length.
     *
     *   Important: calling recv only once might only give you a fragment of the response.
     *              in order to support large file transfers, you have to keep calling 'recv' until it returns 0.
     *
     *   Option 1: Simplistic
     *     Only call recv once and give up on receiving large files.
     *     BUT: Your program must still be able to store the beginning of the file and
     *          display an error message stating the response was truncated, if it was.
     *
     *   Option 2: Challenge
     *     Do it the proper way by calling recv multiple times.
     *     Whenever the allocated reply->reply_buffer is not large enough, use realloc to increase its size:
     *        reply->reply_buffer = realloc(reply->reply_buffer, new_size);
     *
     *
     */

    buffer_reply = malloc(MAXRCVLEN*sizeof(char));
    int len = 0;
    recebimento = recv(mysocket,buffer_reply,5000,0);
    if(recebimento<0){
        puts("DEU ERRO NO RECV");
		return -1;
    }

    puts("SUCCESSFULY GOT REPPLY");
    /*if(recebimento > 4000){
        puts("TRUNCATED ANSWER");
    }
    if(recebimento < 0){
        puts("RECEPTION NOT MADE");
        return -1;
    }*/

    reply->reply_buffer = buffer_reply;
    puts(reply->reply_buffer);
    reply->reply_buffer_length = recebimento;
    //Got this while from: https://stackoverflow.com/questions/2413189/c-malloc-increase-buffer-size
    //NE MARCHE PAS BIEN!!!!!
    while (recebimento > 0){
        memcpy(reply->reply_buffer + len, buffer_reply, recebimento);
        len+=recebimento;
        char *tmp_alloc = (char*) malloc(len + MAXRCVLEN);
        if(!tmp_alloc)
        {
            printf("failed to alocate memory!\n");
            return 1;
        }
        memcpy(tmp_alloc, reply->reply_buffer, len);
        free(reply->reply_buffer);
        reply->reply_buffer = tmp_alloc;
        reply->reply_buffer_length = len + MAXRCVLEN;
        recebimento = recv(mysocket, buffer_reply, MAXRCVLEN, 0);
    }



    close(mysocket);
    return 0;
}

void write_data(const char *path, const char * data, int len) {
    FILE *p = fopen(path,"w+");
    fwrite(data, sizeof(char), len,p);
    fclose(p);
    /*TO BE TESTED*/
}

char* http_get_request(url_info *info) {
    char * request_buffer = (char *) malloc(100 + strlen(info->path) + strlen(info->host));
    snprintf(request_buffer, 1024, "GET /%s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
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
            return buff; // 'blah\r\nblah'
        }
        buff++;
    }
    return NULL;
}

// 1 - input: 'status \r\n blah \r\n blah \r\n' -> output: 'status [\r]\n blah \r\n blah \r\n'
// 2 - input: ' blah \r\n blah \r\n' -> output: ' blah [\r]\n blah \r\n'

char *read_http_reply(struct http_reply *reply) {
    
    // Let's first isolate the first line of the reply
    char *status_line = next_line(reply->reply_buffer, reply->reply_buffer_length);
    if (status_line == NULL) {
	fprintf(stderr, "Could not find status\n");
	return NULL;
    }
    *status_line = '\0'; // Make the first line is a null-terminated string

    // 'status 200 \0\n blahblah \r\n blahblah'

    // Now let's read the status (parsing the first line)
    int status;
    double http_version;
    int rv = sscanf(reply->reply_buffer, "HTTP/%lf %d", &http_version, &status);
    if (rv != 2) {
	fprintf(stderr, "Could not parse http response first line (rv=%d, %s)\n", rv, reply->reply_buffer);
	return NULL;
    }

    if (status != 200) {
	fprintf(stderr, "Server returned status %d (should be 200)\n", status);
	return NULL;
    }

    char *buf = status_line + 2, *buff_aux; // 'status 200 \r\n[b]lahblah \r\nblahblahblah'
    // char *buff_aux= malloc(reply->reply_buffer_length);
    // char *buf2 = malloc(reply->reply_buffer_length);
    // memset(buff_aux, ' ', reply->reply_buffer_length);

    /*
     * To be completed:
     *   The previous code only detects and parses the first line of the reply.
     *   But servers typically send additional header lines:
     *     Date: Mon, 05 Aug 2019 12:54:36 GMT<CR><LF>
     *     Content-type: text/css<CR><LF>
     *     Content-Length: 684<CR><LF>
     *     Last-Modified: Mon, 03 Jun 2019 22:46:31 GMT<CR><LF>
     *     <CR><LF>
     *
     *   Keep calling next_line until you read an empty line, and return only what remains (without the empty line).
     *
     *   Difficul challenge:
     *     If you feel like having a real challenge, go on and implement HTTP redirect support for your client.
     *
     */
    buf = next_line(buf,reply->reply_buffer_length); // input buf = '[b]lahblah \r\nblahblahblah' -> output buf = '[\r]\nblahblahblah'
    buf += 2;

    while(buf!=NULL){
        buff_aux = buf;
        buf = next_line(buf,reply->reply_buffer_length); // input buf = '[\r]\nblahblahblah\r\n' ->
        if(abs(buf-buff_aux)<=2) break;
        buf += 2;
        if(buf==NULL) break;
    }

    buf += 2;
    return buf;
}
