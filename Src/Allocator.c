#include "../Include/Hallocy/Allocator.h"

void *hallocy_copy_memory(void *destination, const void *source, const size_t size) {
    unsigned char *destination_bytes = (unsigned char*)destination;
    const unsigned char *source_bytes = (const unsigned char*)source;

    for (size_t i = 0; i < size; i++) {
        destination_bytes[i] = source_bytes[i];
    }

    return destination;
}