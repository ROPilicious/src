#include <stdio.h>

int main(int argc, char const *argv[])
{
	printf("Hello World\n");

	asm("int $0x80");
	return 0;
}
