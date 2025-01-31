#include "../Include/Hallocy/Allocator.h"

#if defined(_WIN32)
#include <windows.h>

static HANDLE hallocy_heap = NULL;
#elif defined(__linux__)
#include <unistd.h>
#include <sys/mman.h>
#endif

typedef struct hallocy_memory_header {
    size_t size;
    struct hallocy_memory_header *next;
} hallocy_memory_header;

static size_t page_size = 0;

void *hallocy_malloc(size_t size) {
    if (page_size == 0) {
        #if defined(_WIN32)
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);

        page_size = system_info.dwPageSize;
        #elif defined(__linux__)
        page_size = sysconf(_SC_PAGE_SIZE);
        #endif
    }

    size_t total_size = size + sizeof(hallocy_memory_header);
    hallocy_memory_header *new_header = NULL;
    if (total_size >= HALLOCY_LARGE_ALLOCATION) {
        total_size = page_size * (size_t)(((float)total_size / (float)page_size) + 1.0f);
        #if defined(_WIN32)
        new_header = VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        #elif defined(__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        #endif
    }

    if (new_header == NULL) {
        return NULL;
    }

    new_header->size = total_size;
    new_header->next = NULL;

    return new_header + 1;
}

void hallocy_free(void *pointer) {
    hallocy_memory_header *header = (hallocy_memory_header*)(pointer) - 1;
    if (header->size >= HALLOCY_LARGE_ALLOCATION) {
        #if defined(_WIN32)
        VirtualFree(header, 0, MEM_RELEASE);
        #elif defined(__linux__)
        munmap(header, header->size);
        #endif
    }
}

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