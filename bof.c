#include<stdio.h>

void func() {

	char buffer[100];
	read(0, buffer, sizeof(buffer));
}

int main() {

	printf("Before function call\n");
	func();
	printf("After function call\n");
	return 0;
}


