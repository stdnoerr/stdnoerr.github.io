#include<stdio.h>

// gcc ret2shellcode.c -o ret2shellcode -z execstack -no-pie -fno-stack-protector 

__attribute__((constructor))
void ignore_me(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void win(int arg1, int arg2){
	if (arg1 == 0xdeadbeef && arg2 == 0xcafebabe){
		puts("You're awesome");

		execve("/bin/sh", NULL, NULL);
	}
}

int main(int argc, char **argv, char **environ){
	char buf[0x60];

	puts("Show me your creativity :P");
	printf("For now, Imma tell you a secret: %p\n", buf);

	gets(buf);
}