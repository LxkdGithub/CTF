#include<stdio.h>
#include<stdlib.h>

int main(){
	char * a[10];
	for(int i=0;i<10;i++){
		a[i] = malloc(0x30+i);
	}
	for(int i=0;i<10;i++){
		free(a[i]);
	}
	
	char * b[10];
	for(int i=0;i<10;i++){
		char * b = malloc(0x30+i);
	}
	
	return 0;
	
}

