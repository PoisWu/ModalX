#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>




int main(int arg, char *argv[]){
    printf("%d\n",arg);
    for(int i=0;i<arg;i++){
        printf("%s\n",argv[i]);
    }
    return 0;
}