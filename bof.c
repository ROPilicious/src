#include<stdio.h>

void func() {

	char buffer[100];
	gets(buffer);
}

int main() {

	printf("Before function call\n");
	func();
	printf("After function call\n");
	return 0;
}


