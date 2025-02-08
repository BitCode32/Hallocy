/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * -----------------------------------------------------------------------------
 * File: Allocator.c
 * Description:
 *  This file contains the functions for allocating, freeing and managing memory.
 *  It includes functions to allocate, reallocate, free, copy, move and set memory.
 *  The file also defines the structure used as header for the allocated memory.
 * 
 * Author: BitCode32
 * -----------------------------------------------------------------------------
 */
#include "../Include/Hallocy/Allocator.h"
#include "../Include/Hallocy/Simd.h"

#if defined(_WIN32)
#include <windows.h>

static HANDLE hallocy_heap = NULL;
#elif defined(__linux__)
#include <unistd.h>
#include <sys/mman.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <immintrin.h>
#include <arm_neon.h>
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

    size_t total_size = page_size * (size_t)(((float)(size + sizeof(hallocy_memory_header)) / (float)page_size) + 1.0f);
    hallocy_memory_header *new_header = NULL;
    if (total_size >= HALLOCY_LARGE_ALLOCATION) {
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

void *hallocy_calloc(size_t count, size_t size) {
    if (page_size == 0) {
        #if defined(_WIN32)
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);

        page_size = system_info.dwPageSize;
        #elif defined(__linux__)
        page_size = sysconf(_SC_PAGE_SIZE);
        #endif
    }

    size_t total_size = page_size * (size_t)(((float)((size * count) + sizeof(hallocy_memory_header)) / (float)page_size) + 1.0f);
    hallocy_memory_header *new_header = NULL;
    if (total_size >= HALLOCY_LARGE_ALLOCATION) {
        #if defined(_WIN32)
        new_header = VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        hallocy_set_memory(new_header + 1, 0, total_size - sizeof(hallocy_memory_header));
        #elif defined(__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ZERO, -1, 0);
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
                hallocy_set_memory(new_header + 1, 0, total_size - sizeof(hallocy_memory_header));
                return new_header + 1;
            }

            previous_header = new_header;
            new_header = new_header->next;
        }
        
        #if defined(_WIN32)
        if (hallocy_heap == NULL) {
            hallocy_heap = GetProcessHeap();
        }

        new_header = HeapAlloc(hallocy_heap, HEAP_ZERO_MEMORY, total_size);
        #elif defined (__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ZERO, -1, 0);
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
            hallocy_set_memory(new_header + 1, 0, total_size - sizeof(hallocy_memory_header));
            new_header = new_header->next;
        }
        
        #if defined(_WIN32)
        if (hallocy_heap == NULL) {
            hallocy_heap = GetProcessHeap();
        }

        new_header = HeapAlloc(hallocy_heap, HEAP_ZERO_MEMORY, total_size);
        #elif defined (__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_ZERO, -1, 0);
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

void *hallocy_set_memory(void *pointer, int value, size_t count) {
    unsigned char *pointer_bytes = (unsigned char*)pointer;
    unsigned char value_bytes = (unsigned char)value;

    switch (hallocy_supports_simd()) {
        case HALLOCY_SIMD_AVX512: {
            __m512i simd_value = _mm512_set1_epi8(value_bytes);
            while (count >= 64) {
                _mm512_storeu_si512((__m512i*)pointer_bytes, simd_value);
                pointer_bytes += 64;
                count -= 64;
            }
        }

        case HALLOCY_SIMD_AVX2:
        case HALLOCY_SIMD_AVX: {
            __m256i simd_value = _mm256_set1_epi8(value_bytes);
            while (count >= 32) {
                _mm256_storeu_si256((__m256i*)pointer_bytes, simd_value);
                pointer_bytes += 32;
                count -= 32;
            }
        }

        case HALLOCY_SIMD_SSE2:
        case HALLOCY_SIMD_SSE: {
            __m128i simd_value = _mm_set1_epi8(value_bytes);
            while (count >= 16) {
                _mm_storeu_si128((__m128i*)pointer_bytes, simd_value);
                pointer_bytes += 16;
                count -= 16;
            }
            break;
        }

        default: {
            size_t *pointer_word = (size_t*)pointer_bytes;

            size_t word_size = sizeof(size_t);
            size_t value_word = 0;
            for (size_t i = 0; i < word_size; i++) {
                value_word |= (size_t)value_bytes << (i * 8);
            }

            while (count >= word_size) {
                *pointer_word++ = value_word;
                count -= word_size;
            }

            pointer_bytes = (unsigned char*)pointer_word;
            break;
        }
    }

    while (count-- > 0) {
        *pointer_bytes++ = value_bytes;
    }

    return pointer;
}

void *hallocy_copy_memory(void *destination, const void *source, size_t size) {
    unsigned char *destination_bytes = (unsigned char*)destination;
    unsigned char *source_bytes = (unsigned char*)source;

    switch (hallocy_supports_simd()) {
        case HALLOCY_SIMD_AVX512: {
            __m512i simd_value;
            while (size >= 64) {
                simd_value = _mm512_loadu_si512((__m512i*)source_bytes);
                _mm512_storeu_si512((__m512i*)destination_bytes, simd_value);

                destination_bytes += 64;
                source_bytes += 64;
                size -= 64;
            }
        }

        case HALLOCY_SIMD_AVX2:
        case HALLOCY_SIMD_AVX: {
            __m256i simd_value;
            while (size >= 32) {
                simd_value = _mm256_loadu_si256((__m256i*)source_bytes);
                _mm256_storeu_si256((__m256i*)destination_bytes, simd_value);

                destination_bytes += 32;
                source_bytes += 32;
                size -= 32;
            }
        }

        case HALLOCY_SIMD_SSE2:
        case HALLOCY_SIMD_SSE: {
            __m128i simd_value;
            while (size >= 16) {
                simd_value = _mm_loadu_si128((__m128i*)source_bytes);
                _mm_storeu_si128((__m128i*)destination_bytes, simd_value);

                destination_bytes += 16;
                source_bytes += 16;
                size -= 16;
            }
            break;
        }

        default: {
            size_t *destination_word = (size_t*)destination_bytes;
            size_t *source_word = (size_t*)source_bytes;

            size_t word_size = sizeof(size_t);
            while (size >= word_size) {
                *destination_word++ = *source_word++;
                size -= word_size;
            }

            destination_bytes = (unsigned char*)destination_word;
            source_bytes = (unsigned char*)source_word;
            break;
        }
    }

    while (size-- > 0) {
        *destination_bytes++ = *source_bytes++;
    }

    return destination;
}

void *hallocy_move_memory(void *destination, const void *source, size_t size) {
    unsigned char *destination_bytes = (unsigned char*)destination;
    const unsigned char *source_bytes = (const unsigned char*)source;

    if (destination_bytes > source_bytes) {
        destination_bytes += size;
        source_bytes += size;

        switch (hallocy_supports_simd()) {
            case HALLOCY_SIMD_AVX512: {
                __m512i simd_value;
                while (size >= 64) {
                    simd_value = _mm512_loadu_si512((__m512i*)source_bytes);
                    _mm512_storeu_si512((__m512i*)destination_bytes, simd_value);

                    destination_bytes -= 64;
                    source_bytes -= 64;
                    size -= 64;
                }
            }

            case HALLOCY_SIMD_AVX2:
            case HALLOCY_SIMD_AVX: {
                __m256i simd_value;
                while (size >= 32) {
                    simd_value = _mm256_loadu_si256((__m256i*)source_bytes);
                    _mm256_storeu_si256((__m256i*)destination_bytes, simd_value);

                    destination_bytes -= 32;
                    source_bytes -= 32;
                    size -= 32;
                }
            }

            case HALLOCY_SIMD_SSE2:
            case HALLOCY_SIMD_SSE: {
                __m128i simd_value;
                while (size >= 16) {
                    simd_value = _mm_loadu_si128((__m128i*)source_bytes);
                    _mm_storeu_si128((__m128i*)destination_bytes, simd_value);

                    destination_bytes -= 16;
                    source_bytes -= 16;
                    size -= 16;
                }
                break;
            }

            default: {
                size_t *destination_word = (size_t*)destination_bytes;
                size_t *source_word = (size_t*)source_bytes;

                size_t word_size = sizeof(size_t);
                while (size >= word_size) {
                    *destination_word-- = *source_word--;
                    size -= word_size;
                }

                destination_bytes = (unsigned char*)destination_word;
                source_bytes = (unsigned char*)source_word;
                break;
            }
        }

        while (size-- > 0) {
            *destination_bytes-- = *source_bytes--;
        }

        return destination;
    } else {
        return hallocy_copy_memory(destination, source, size);
    }
}