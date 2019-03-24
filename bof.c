#include<stdio.h>

void func() {

	char buffer[100];
	gets(buffer);
	printf("%s\n", buffer);
}

int main() {

	unsigned int gid, uid;
        gid = geteuid();
        uid = geteuid();

        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);	

	printf("Before function call\n");
	func();
	printf("After function call\n");
	return 0;
}


