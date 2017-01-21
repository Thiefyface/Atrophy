#include <unistd.h>
#include <stdio.h>

int asdf = 2;

int main(int argc,char * argv[]){
    int i = 1;
    while (i++ > 0){
        printf("Executing loop: %d\n",i);
        sleep(4);
    }
}
