I have completed the wgetX.c
in which the function `download_page` can be decomposed in three parties:
 1. getaddrinfo 
 2. Declare socket and connect to the server.
 3. write and revc. 

I change the input of `read_http_reply` by adding a new parameter `bool *addr_need_redirect` which pass the need to redirect so I also modified  `main` to treat the case which needs a redirection. 

The rest is seens not too complicate. 
