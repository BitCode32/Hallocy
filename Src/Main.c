#include <Hallocy/Allocator.h>
#include <stdio.h>

int main() {
    printf("starting program...\n");

    char hello[6] = { 'h', 'e', 'l', 'l', 'o', '\0' };
    char hello_copy[6];
    hallocy_copy_memory(hello_copy, hello, 6 * sizeof(char));

    printf("output copy: %s\n", hello_copy);
    printf("finished program!\n");
    return 0;
}