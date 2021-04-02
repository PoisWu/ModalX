/*
    Done in collab with Joaquin Castanon
*/



Instructions:

1- Don't forget to change the IP_SERVER define to the IP of the virtual machine that suits you

2- type 'make' in your terminal in the good folder to compile and construct our exploit application

3- To change the "Winners Page":
AFTER CONNECTING type: 'cd var/www/html;sed -i 's/<\/body>/<div> "Hugo Serrao" <\/div><\/body>/' index.html;'
(Same reason for using this as the last vulnerable application challenge)







Justifing the exploit: (references and credits in the code)
. We start by seeing that we have another strcat(greeting_text, buffer) as in the last challenge, but this time without our call for system(command), so let's take a look at the stack organisation using GDB
                            Memoire Stack for parse() (using GDB)
|--------------------------------------|----------------|--------|-----|           |-------------|
    Buffer                             Greeting_text    RBP      return_address  prameters/variable   Function
|                  256                 |     128        |     8  |  6  |           |
. We see that we can flood ower greeting_text and reach the return_address for parse(), pointing to a space in memory that suits us. In this case buffer
. So in buffer we are going to need something similar to system(), which is goig to be a shellcode for opening a terminal (similar to the one here https://www.youtube.com/watch?v=1S0aBV-Waeo&t=498s)
. Then we are going to fill with some "garbage" (we've chosen NOOP) and at the good location we put our return_address (which is given at the begining of the code)
. At this moment you are probably aware that the good calculation we made for our return_address address was not correct, that's because we have some local variables that were added in the virtual_machine application code and are not avaiable for us. But this shouldn't be a big deal, just play around with the close numbers from what you have calculated and you should be good to go 


