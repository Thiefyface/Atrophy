#include <stdio.h>
void function_a(){

    printf("asdf!\n");
}

void function_1(){
    function_a();
}


int main(int argc, char* argv[]){
    printf("main...\n");
    function_1(); 

}




