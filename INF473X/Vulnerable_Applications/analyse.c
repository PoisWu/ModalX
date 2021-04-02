#include <stdio.h>
#include <string.h>


/*Memoire Stack (comme la video computerphile)
|--------------------------------------|------|-----------------------------------------------------|
    greeting_text                      command     buffer
|                  128                 |  48  |         256                                         |
*/


int parse()
{
  char buf[256] = {0};
  char command[] = "uptime | sed 's/.*up \\([^,]*\\), .*/\\1/'";
  char greeting_text[128];

  strcpy(greeting_text, "abcdefghijklmno");
  printf("%lld\n",buf-command);//La difference est touj la même (-176)
  printf("%d\n", command);//L'adresse il change touj
  return 0;
}

int main() {
    parse();
}