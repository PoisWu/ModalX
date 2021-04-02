#include <stdio.h>
#include <string.h>
#include "fancy-hello-world.h"

int main(void) {
    char name[11];
    char output[30];
    hello_string(name,output); 
    return 0;
}
void hello_string(char* name, char* output) {
    strcat(output,"Hello world, hello ");
    printf("Please enter your name: (limit to 10 caracters)\n");
    fgets(name,11,stdin);
    name[strcspn(name, "\n")] = '\0'; // remove the last '\n' cf. https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input
    strcat(output,name);
    strcat(output, "!\n");
    printf("%s", output);
}