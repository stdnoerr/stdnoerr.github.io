#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>

// gcc flagleak.c -o flagleak -no-pie -fno-stack-protector

__attribute__((constructor))
void ignore_me(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void print_flag(){
	char input[0x30];
	int fd = open("flag.txt", O_RDONLY);
	char * addr = malloc(0x30);

	if (fd < 0){
		perror("Error");
		_exit(-1);
	}
	read(fd, addr, 0x30);

	puts("Not that easy. There is a part 2 haha");
	fgets(input, sizeof(input), stdin);

	printf(input);

	_exit(0);
}


int main(int argc, char **argv, char **environ){
	char buf[0x60];

	puts("Time to step up you game.");
	read(0, buf, 0x60 + 8 + 16);
}