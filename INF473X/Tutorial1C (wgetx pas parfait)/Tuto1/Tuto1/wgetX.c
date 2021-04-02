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

#include <arpa/inet.h>
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

#define MAXRCVLEN 1000

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
    write_data(file_name, response, reply.reply_buffer + reply.reply_buffer_length - response);

    // Free allocated memory
    free(reply.reply_buffer);

    // Just tell the user where is the file
    fprintf(stderr, "the file is saved in %s.", file_name);
    return 0;
}

int download_page(url_info *info, http_reply *reply) {

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
	struct hostent *h;
	h = gethostbyname(info->host);

    /*
     * To be completed:
     *   Next, you will need to send the HTTP request.
     *   Use the http_get_request function given to you below.
     *   It uses malloc to allocate memory, and snprintf to format the request as a string.
     *
     *   Use 'write' function to send the request into the socket.
     *
     *   Note: You do not need to send the end-of-string \0 character.
     *   Note2: It is good practice to test if the function returned an error or not.
     *   Note3: Call the shutdown function with SHUT_WR flag after sending the request
     *          to inform the server you have nothing left to send.
     *   Note4: Free the request buffer returned by http_get_request by calling the 'free' function.
     *
     */
	
	char *request_buffer = http_get_request(info);

//le fameux socket 
	int sockfd;
	char *ip;
	struct sockaddr_in dest;	
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	
	memset(&dest, 0, sizeof(dest));	

	dest.sin_family = AF_INET;

	/*ip = malloc(100);
	struct in_addr addr;
	memcpy(&addr, h->h_addr_list[0], sizeof(struct in_addr));
	strcpy(ip,inet_ntoa(addr)); 

	printf("IP:\t%s\n", ip);

	inet_pton(AF_INET, ip, &dest.sin_addr);*/
    
    memcpy(&dest.sin_addr, h->h_addr_list[0], sizeof(struct in_addr));

	dest.sin_port = htons(info->port);

	if (connect(sockfd, (struct sockaddr *)&dest, sizeof(struct sockaddr))) {
		fprintf(stderr, "Could not connect: %s\n", strerror(errno));
		return -1;
    	}
//fin du socket

	write(sockfd, request_buffer, strlen(request_buffer));
	shutdown(sockfd, SHUT_WR);
	free(request_buffer);


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
	char *buffer;
    int len = 0;
    int k;
    reply->reply_buffer = (char*) malloc(10000);
    reply->reply_buffer_length = 10000;
    
	buffer = malloc(MAXRCVLEN);
	k = recv(sockfd, buffer, MAXRCVLEN, 0);
    	if (k < 0) {
		fprintf(stderr, "recv returned error: %s\n", strerror(errno));
		return -1;
    	}

//La boucle while est issue du code trouvé ici: https://stackoverflow.com/questions/2413189/c-malloc-increase-buffer-size
    while (k > 0){
        memcpy(reply->reply_buffer + len, buffer, k);
        len+=k;
        //printf("k = %d \n", k);
        if (1){
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
        }
        k = recv(sockfd, buffer, MAXRCVLEN, 0);
    }
    return 0;
}

void write_data(const char *path, const char * data, int len) {
    /*
     * To be completed:
     *   Use fopen, fwrite and fclose functions.
     */
	FILE *stream;
	stream = fopen(path, "w");
	fwrite(data, 1, len, stream);

	fclose(stream);
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

char *read_http_reply(struct http_reply *reply) {

    // Let's first isolate the first line of the reply
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
	fprintf(stderr, "Server returned status %d (should be 200)\n", status);
	return NULL;
    }

    char *buf = status_line + 2;

    /*
     * To be completed:what is sock_stream in socket programming
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
     *   Difficult challenge:
     *     If you feel like having a real challenge, go on and implement HTTP redirect support for your client.
     *
     */

	while((*buf != '\r' || *(buf+1) != '\n')){
		buf = next_line(buf, reply->reply_buffer_length);
		buf+=2;
	}
	printf("site :%s\n", buf);
	

    return buf;
}
