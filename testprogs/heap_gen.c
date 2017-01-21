#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void testing_func(void){
    int *test2 = malloc(sizeof(int) * 32);
    printf("second malloc done\n");
    test2[0] = 0x10;
    test2[20] = 0xffccffee;
    printf("About to free\n");
    free(test2);
}

int main(int argc,char* argv[]){
    char *test = malloc(sizeof(char) * 32); 
    char *src = "herpderp";
    strncpy(test,src,32);  
    printf("Here's the str: %s\n",test);
    testing_func();
    free(test);
}

