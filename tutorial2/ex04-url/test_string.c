#include<stdio.h>
#include<string.h>

int main(){
    char *str1="abcd";
    char *str2=strstr(str1,"b");
    printf("%s\n",str1);
    printf("%s\n",str2);
    strcpy(str2,"0");
    printf("%s\n",str1);
    printf("%s\n",str2);

}