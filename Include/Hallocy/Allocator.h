#ifndef HALLOCY_ALLOCATOR
#define HALLOCY_ALLOCATOR

#include <stdint.h>

void *hallocy_copy_memory(void *destination, const void *source, const size_t size);

#endif