#include<stdio.h>

void func() {

	char buffer[100];
	gets(buffer);
	fflush(stdin);

	printf("%s\n", buffer);
	fflush(stdout);
}

int main() {

	unsigned int gid, uid;
        gid = geteuid();
        uid = geteuid();

        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);	

	printf("Before function call\n");
	fflush(stdout);

	func();
	
	printf("After function call\n");
	fflush(stdout);
	return 0;
}


