#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(){
	char * a = malloc(0x40-8);
	char * b = malloc(0x170-8);
	char * c = malloc(0x100-8);

	free(b);
	*((long *)b-1) = 0x100;
	char * b1 = malloc(0x30);
	char * d = malloc(0x40);
	free(b1);
	*((long *)b1-1) = 0x271;
	char str1[260] = {"A"};
	char str2[10] = {"B"};
	char * b2 = malloc(0x260);
	printf("原来\n");
	printf("b-> %s\n", b);
	printf("d-> %s\n", d);
	strncpy(b, str1, 260);
	printf("After strcpy1 :\n");
	printf("b-> %s\n", b);
	printf("d-> %s\n", d);
	printf("After strcpy2 :\n");
	printf("b-> %s\n", b);
	printf("d-> %s\n", d);
	return 0;
}
