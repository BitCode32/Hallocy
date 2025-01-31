#include <Hallocy/Allocator.h>
#include <stdio.h>

int main() {
    printf("starting program...\n");

    char hello[6] = { 'h', 'e', 'l', 'l', 'o', '\0' };
    char hello_copy[6];
    hallocy_copy_memory(hello_copy, hello, 6 * sizeof(char));
    hallocy_set_memory(hello, '?', 5);

    char random_message[100] = "random";
    hallocy_move_memory(random_message + 4, random_message, 7);

    char *medium_memory = hallocy_malloc(HALLOCY_SMALL_ALLOCATION + 10);
    hallocy_set_memory(medium_memory, 'H', HALLOCY_SMALL_ALLOCATION + 10);

    printf("output copy: %s\n", hello_copy);
    printf("output set: %s\n", hello);
    printf("output move: %s\n", random_message);
    printf("output medium allocation: %s\n", medium_memory);
    
    hallocy_free(medium_memory);
    printf("finished program!\n");
    return 0;
}