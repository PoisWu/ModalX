#include "fancy-hello-world.h"


void hello_string(char* name, char* output){
    strcpy(output, "Hello World, hello ");
    output = strcat(output, name);
}

int  main(void){
    
    char name[50] ;
    char output[100];

    printf("What`s your name?\n");
    fgets(name,50,stdin);

    hello_string(name,output);
    
    printf("%s", output);

    return 0;
}