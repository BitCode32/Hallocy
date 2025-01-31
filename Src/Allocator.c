#include "../Include/Hallocy/Allocator.h"

void *hallocy_set_memory(void *pointer, const int value, const size_t count) {
    unsigned char *pointer_bytes = (unsigned char*)pointer;
    const unsigned char value_bytes = (const unsigned char)value;

    for (size_t i = 0; i < count; i++) {
        pointer_bytes[i] = value_bytes;
    }

    return pointer;
}

void *hallocy_copy_memory(void *destination, const void *source, const size_t size) {
    unsigned char *destination_bytes = (unsigned char*)destination;
    const unsigned char *source_bytes = (const unsigned char*)source;

    for (size_t i = 0; i < size; i++) {
        destination_bytes[i] = source_bytes[i];
    }

    return destination;
}

void *hallocy_move_memory(void *destination, const void *source, const size_t size) {
    unsigned char *destination_bytes = (unsigned char*)destination;
    const unsigned char *source_bytes = (const unsigned char*)source;

    if (destination_bytes > source_bytes) {
        for (size_t i = size - 1; i > 0; i--) {
            destination_bytes[i] = source_bytes[i];
        }
    } else {
        for (size_t i = 0; i < size; i++) {
            destination_bytes[i] = source_bytes[i];
        }
    }

    return destination;
}