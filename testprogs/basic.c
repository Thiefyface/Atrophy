#include <stdio.h>
#include <stdlib.h>

int main(int argc,char * argv[]){
    char * asdf;
    
    FILE * a;
    printf("asdf!\n"); 
    a = fopen("/tmp/asdf","w"); 
    fwrite(0,1,2,a); 
    fclose(a);
    puts("asdf");
    exit(-1);
}
