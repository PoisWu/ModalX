Idea: trying to do the same thing in this video https://www.youtube.com/watch?v=1S0aBV-Waeo&t=613s&ab_channel=Computerphile

Shell code reference : http://shell-storm.org/shellcode/files/shellcode-603.php

low addr                                                                                                                            high addr 

| -------------256(buf)------|hello dear ----------128(greeting_txt)--------| -----some registers store(like rbp)------|------6(return addr)-----|

The detail about the offset. 
|Hello dear | shell code(30) |...........| register(>8)| return 6 bytes| 
            |  -> messgae payload start from here.    ..........          
            |     <-    offset             ->          |
| <-           128 byte               ->|           
So the possible offset is at least 128-strlen("hello dear ")+8= 128-12+8=124.

I dont really know how many byte taken by registers(I am sure there are at least 1 register whitch is rbp), so i make a for loop to try all the possible offset(Begin with 124). and i found the return_addr is at the 12+140=152 after the head greeting_txt,whitch means that there are 3(24/3) registers stored in the stack.

First, i seed a msg whitch contain the shell code, if the server executes the shell code, then the connection will not be closed by server, so i can the command that i want and receieve the messgae from the server.
If the server doesn't execute the shell code, then the connection will be imediately closed by server(cf sorcecode of server), whitch can be used to test if we have good offset.

I found that I need at least 2 thread to deal with input and output, beacause i wrote it in the same function, and if there is not return messgae from the server, then the function will be stuck and wait the not-existing message. 
For reason of symetry. i wrote 2 sub_threads "fd_write" and "fd_read" whitch write and read the file discriptor sockfd seperiately.

Once the server executes shell code, i can reuse the bash command to write my name in the index.html
