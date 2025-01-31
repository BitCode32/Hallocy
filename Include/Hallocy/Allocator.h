#ifndef HALLOCY_ALLOCATOR
#define HALLOCY_ALLOCATOR

#include <stdint.h>

#define HALLOCY_LARGE_ALLOCATION 1048576
#define HALLOCY_SMALL_ALLOCATION 1024

void *hallocy_malloc(size_t size);
void hallocy_free(void *pointer);

void *hallocy_set_memory(void *pointer, const int value, const size_t count);
void *hallocy_copy_memory(void *destination, const void *source, const size_t size);
void *hallocy_move_memory(void *destination, const void *source, size_t size);

#endif