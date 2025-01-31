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

static size_t medium_memory_allocated_freed = 0;
static size_t medium_memory_allocated_size = 0;
static hallocy_memory_header *medium_memory_bin = NULL;

static _Thread_local size_t small_memory_allocated_freed = 0;
static _Thread_local size_t small_memory_allocated_size = 0;
static _Thread_local hallocy_memory_header *small_memory_bin = NULL;

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
    } else if (total_size > HALLOCY_SMALL_ALLOCATION) {
        hallocy_memory_header *previous_header = NULL;
        new_header = medium_memory_bin;
        while (new_header != NULL) {
            if (new_header->size >= total_size) {
                if (previous_header != NULL) {
                    previous_header->next = new_header->next;
                } else {
                    medium_memory_bin = medium_memory_bin->next;
                }

                new_header->next = NULL;
                return new_header + 1;
            }

            previous_header = new_header;
            new_header = new_header->next;
        }
        
        #if defined(_WIN32)
        if (hallocy_heap == NULL) {
            hallocy_heap = GetProcessHeap();
        }

        new_header = HeapAlloc(hallocy_heap, 0, total_size);
        #elif defined (__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        #endif

        medium_memory_allocated_size += (new_header) ? total_size : 0;
    } else {
        hallocy_memory_header *previous_header = NULL;
        new_header = small_memory_bin;
        while (new_header != NULL) {
            if (new_header->size >= total_size) {
                if (previous_header != NULL) {
                    previous_header->next = new_header->next;
                } else {
                    small_memory_bin = small_memory_bin->next;
                }

                new_header->next = NULL;
                return new_header + 1;
            }

            previous_header = new_header;
            new_header = new_header->next;
        }
        
        #if defined(_WIN32)
        if (hallocy_heap == NULL) {
            hallocy_heap = GetProcessHeap();
        }

        new_header = HeapAlloc(hallocy_heap, 0, total_size);
        #elif defined (__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        #endif

        small_memory_allocated_size += (new_header) ? total_size : 0;
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
    } else if (header->size > HALLOCY_SMALL_ALLOCATION) {
        header->next = medium_memory_bin;
        medium_memory_bin = header;

        medium_memory_allocated_freed += header->size;
        if (medium_memory_allocated_size > HALLOCY_LARGE_ALLOCATION && medium_memory_allocated_size == medium_memory_allocated_freed) {
            hallocy_memory_header *previous_header = NULL;
            hallocy_memory_header *current_header = medium_memory_bin;
            while (current_header != NULL) {
                previous_header = current_header;
                current_header = current_header->next;

                #if defined(_WIN32)
                HeapFree(hallocy_heap, 0, previous_header);
                #elif defined(__linux__)
                munmap(previous_header, previous_header->size);
                #endif
            }

            medium_memory_bin = NULL;
            medium_memory_allocated_freed = 0;
            medium_memory_allocated_size = 0;
        }
    } else {
        header->next = small_memory_bin;
        small_memory_bin = header;

        small_memory_allocated_freed += header->size;
        if (small_memory_allocated_size > HALLOCY_LARGE_ALLOCATION && small_memory_allocated_size == small_memory_allocated_freed) {
            hallocy_memory_header *previous_header = NULL;
            hallocy_memory_header *current_header = small_memory_bin;
            while (current_header != NULL) {
                previous_header = current_header;
                current_header = current_header->next;

                #if defined(_WIN32)
                HeapFree(hallocy_heap, 0, previous_header);
                #elif defined(__linux__)
                munmap(previous_header, previous_header->size);
                #endif
            }

            small_memory_bin = NULL;
            small_memory_allocated_freed = 0;
            small_memory_allocated_size = 0;
        }
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