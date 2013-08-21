#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BUF_SIZE 1024

void get_msg(unsigned char **msg) {
  char buffer[BUF_SIZE];
  size_t contentSize = 1; // includes NULL
  *msg = malloc(sizeof(char) * BUF_SIZE);
  (*msg)[0] = '\0'; // make null-terminated
  while(fgets(buffer, BUF_SIZE, stdin))
  {
    char *old = *msg;
    contentSize += strlen(buffer);
    *msg = realloc(*msg, contentSize);
    strcat(*msg, buffer);
  }
  (*msg)[strlen(*msg)-1] = '\0';
}
