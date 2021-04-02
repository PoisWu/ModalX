Step3:
The fonction pass the content of pointer, so in the first `modify`, it pass a copy of server, and change the value locally. 

For the modify-by-pointer, the fonction takes address of server as variable, so it modify the value of server.

Step4.
I think the reason why `cmok` wasn’t modified for the same reason, it assigne one copy of `cmok` to `albi` .
The reason why `albi` and `s2` change the value at the same time is that `s2`point to `albi`. Thus they represent the same thing.  

Step5.
Server s in `create_idserver` is created locally, it will be erase after the function finish. So s3 point to noting.
As a result, we have to declare the idserver before  and then modify it. we can juste use the same idea of fuction `modify-by-pointer`. 
