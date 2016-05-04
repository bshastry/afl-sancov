#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void bug() {
	abort();
}

int main(int argc, char* argv[]) {
	char buf[10];
	int bytes_read = 0;

	/* Reset state. */
	memset(buf, 0, 10);

	/* Read input data. */
	bytes_read = read(0, buf, 10);

	if (!bytes_read)
		return 1;

	/* Parse it in some vulnerable way. You'd normally call a library here. */
	if (!strcmp(buf, "pwn"))
		bug();
	else
		puts("works!");

	return 0;
}
