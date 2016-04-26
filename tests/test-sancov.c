#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  char buf[100];

//  while (__AFL_LOOP(1000)) {
     /* Reset state. */
     memset(buf, 0, 100);

     /* Read input data. */
     read(0, buf, 100);

     /* Parse it in some vulnerable way. You'd normally call a library here. */
     if (buf[0] != 'p') 
	puts("error 1");
     else if (buf[1] != 'w')
	puts("error 2");
     else if (buf[2] != 'n')
	puts("error 3");
     else
	abort();	// Bug
//  } // End-while-loop

  return 0;
}
