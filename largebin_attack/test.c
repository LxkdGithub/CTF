#include<stdio.h>
#include<stdlib.h>

int main(){
	char * a = malloc(0x210);
	char * bound1 = malloc(0x30);
	char * b = malloc(0x220);
	char * bound = malloc(0x300);
	free(a);
	free(b);
	char * c = malloc(0x210);
	char * d = malloc(0x230);
	return 0;
}
