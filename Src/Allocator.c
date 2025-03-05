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

static INIT_ONCE hallocy_init_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION hallocy_critical_section;
#elif defined(__linux__)
#include <unistd.h>
#include <sys/mman.h>
#include <syscall.h>

#define FUTEX_WAKE 0
#define FUTEX_WAIT 1

static int futex_address = 0;
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

#if defined(_WIN32)
static BOOL CALLBACK hallocy_initialize_mutex(PINIT_ONCE init_once, PVOID parameter, PVOID *context) {
    (void)init_once;
    (void)parameter;
    (void)context;

    return InitializeCriticalSectionEx(&hallocy_critical_section, 0x00000400, 0);
}
#endif

static void *hallocy_allocate(size_t size, bool zero_memory) {
    if (page_size == 0) {
        #if defined(_WIN32)
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);

        page_size = system_info.dwPageSize;
        #elif defined(__linux__)
        page_size = sysconf(_SC_PAGE_SIZE);
        #endif
    }

    size_t total_size = page_size * (size_t)((size + sizeof(hallocy_memory_header) + page_size - 1) / page_size);
    hallocy_memory_header *new_header = NULL;
    if (total_size >= HALLOCY_LARGE_ALLOCATION) {
        #if defined(_WIN32)
        new_header = VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (new_header == NULL) {
            return NULL;
        }

        if (zero_memory) {
            hallocy_set_memory(new_header + 1, 0, total_size - sizeof(hallocy_memory_header));
        }
        #elif defined(__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_header == MAP_FAILED) {
            return NULL;
        }
        #endif
    } else if (total_size > HALLOCY_SMALL_ALLOCATION) {
        #if defined(_WIN32)
        InitOnceExecuteOnce(&hallocy_init_once, hallocy_initialize_mutex, NULL, NULL);
        EnterCriticalSection(&hallocy_critical_section);
        #elif defined(__linux__)
        bool locked = false;
        while (!locked) {
            if (__sync_bool_compare_and_swap(&futex_address, 0, 1)) {
                locked = true;
            } else {
                syscall(SYS_futex, &futex_address, FUTEX_WAIT, 1, NULL, NULL, 0);
            }
        }
        #endif

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
                if (zero_memory) {
                    hallocy_set_memory(new_header + 1, 0, total_size - sizeof(hallocy_memory_header));
                }

                #if defined(_WIN32)
                LeaveCriticalSection(&hallocy_critical_section);
                #elif defined(__linux__)
                futex_address = 0;
                syscall(SYS_futex, &futex_address, FUTEX_WAKE, 1, NULL, NULL, 0);
                #endif

                return new_header + 1;
            }

            previous_header = new_header;
            new_header = new_header->next;
        }
        
        #if defined(_WIN32)
        if (hallocy_heap == NULL) {
            hallocy_heap = GetProcessHeap();
        }

        if (zero_memory) {
            new_header = HeapAlloc(hallocy_heap, HEAP_ZERO_MEMORY, total_size);
        } else {
            new_header = HeapAlloc(hallocy_heap, 0, total_size);
        }

        medium_memory_allocated_size += (new_header) ? total_size : 0;

        LeaveCriticalSection(&hallocy_critical_section);
        #elif defined (__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_header == MAP_FAILED) {
            return NULL;
        }

        medium_memory_allocated_size += (new_header) ? total_size : 0;

        futex_address = 0;
        syscall(SYS_futex, &futex_address, FUTEX_WAKE, 1, NULL, NULL, 0);
        #endif
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
                if (zero_memory) {
                    hallocy_set_memory(new_header + 1, 0, total_size - sizeof(hallocy_memory_header));
                }

                return new_header + 1;
            }

            previous_header = new_header;
            new_header = new_header->next;
        }

        #if defined(_WIN32)
        if (hallocy_heap == NULL) {
            hallocy_heap = GetProcessHeap();
        }

        if (zero_memory) {
            new_header = HeapAlloc(hallocy_heap, HEAP_ZERO_MEMORY, total_size);
        } else {
            new_header = HeapAlloc(hallocy_heap, 0, total_size);
        }
        #elif defined (__linux__)
        new_header = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_header == MAP_FAILED) {
            return NULL;
        }
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

void *hallocy_malloc(size_t size) { return hallocy_allocate(size, false); }
void *hallocy_calloc(size_t count, size_t size) { return hallocy_allocate(count * size, true); }

void *hallocy_realloc(void *pointer, size_t size) {
    if (pointer == NULL) {
        return hallocy_malloc(size);
    }

    if (size == 0) {
        hallocy_free(pointer);
        return NULL;
    }

    hallocy_memory_header *header = (hallocy_memory_header*)(pointer) - 1;
    if (size <= header->size && size >= header->size - HALLOCY_SMALL_ALLOCATION) {
        return pointer;
    }

    void *reallocated_memory = hallocy_malloc(size);
    hallocy_copy_memory(reallocated_memory, pointer, (size < header->size) ? size : header->size);
    hallocy_free(pointer);

    return reallocated_memory;
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
        #if defined(_M_ARM64) || defined(__aarch64__) || defined(__arm__)
        case HALLOCY_SIMD_NEON: {
            uint8x16_t simd_value = vdupq_n_u8(value_bytes);
            while (count >= 16) {
                vst1q_u8(pointer_bytes, simd_value);
                pointer_bytes += 16;
                count -= 16;
            }
            break;
        }
        #else
        case HALLOCY_SIMD_AVX512: {
            __m512i simd_value = _mm512_set1_epi8(value_bytes);
            while (count >= 64) {
                _mm512_storeu_si512((__m512i*)pointer_bytes, simd_value);
                pointer_bytes += 64;
                count -= 64;
            }
        }

        case HALLOCY_SIMD_AVX2: {
            __m256i simd_value = _mm256_set1_epi8(value_bytes);
            while (count >= 32) {
                _mm256_storeu_si256((__m256i*)pointer_bytes, simd_value);
                pointer_bytes += 32;
                count -= 32;
            }
        }

        case HALLOCY_SIMD_AVX:
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
        #endif

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
        #if defined(_M_ARM64) || defined(__aarch64__) || defined(__arm__)
        case HALLOCY_SIMD_NEON: {
            uint8x16_t simd_value;
            while (count >= 16) {
                simd_value = vdupq_n_u8(source_bytes);
                vst1q_u8(destination_bytes, simd_value);
                destination_bytes += 16;
                source_bytes += 16;
                size -= 16;
            }
            break;
        }
        #else
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
        #endif

        default: {
            size_t *destination_word = (size_t*)destination_bytes;
            size_t *source_word = (size_t*)source_bytes;

            size_t word_size = sizeof(size_t);
            while (size >= word_size) {
                *destination_word = *source_word;

                destination_word++;
                source_word++;
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
            #if defined(_M_ARM64) || defined(__aarch64__) || defined(__arm__)
            case HALLOCY_SIMD_NEON: {
                uint8x16_t simd_value;
                while (count >= 16) {
                    simd_value = vdupq_n_u8(source_bytes);
                    vst1q_u8(destination_bytes, simd_value);
                    destination_bytes -= 16;
                    source_bytes -= 16;
                    size -= 16;
                }
                break;
            }
            #else
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
            #endif

            default: {
                size_t *destination_word = (size_t*)destination_bytes;
                size_t *source_word = (size_t*)source_bytes;

                size_t word_size = sizeof(size_t);
                while (size >= word_size) {
                    *destination_word = *source_word;

                    destination_word--;
                    source_word--;
                    size -= word_size;
                }

                destination_bytes = (unsigned char*)destination_word;
                source_bytes = (unsigned char*)source_word;
                break;
            }
        }

        while (size-- > 0) {
            *destination_bytes = *source_bytes;

            destination_bytes--;
            source_bytes--;
        }

        return destination;
    } else {
        return hallocy_copy_memory(destination, source, size);
    }
}

bool hallocy_compare_memory(const void *pointer1, const void *pointer2, size_t size) {
    unsigned char *pointer_bytes1 = (unsigned char*)pointer1;
    unsigned char *pointer_bytes2 = (unsigned char*)pointer2;

    switch (hallocy_supports_simd()) {
        #if defined(_M_ARM64) || defined(__aarch64__) || defined(__arm__)
        case HALLOCY_SIMD_NEON: {
            while (size >= 16) {
                uint8x16_t simd_value1 = vdupq_n_u8(pointer_bytes1);
                uint8x16_t simd_value2 = vdupq_n_u8(pointer_bytes2);

                uint8x16_t result = vceqq_u8(simd_value1, simd_value2);
                if (vmaxvq_u8(result) != 0xFF) {
                    return false;
                }

                pointer_bytes1 += 16;
                pointer_bytes2 += 16;
                size -= 16;
            }
            break;
        }
        #else
        case HALLOCY_SIMD_AVX512: {
            while (size >= 64) {
                __m512i simd_value1 = _mm512_loadu_si512((__m512i*)pointer_bytes1);
                __m512i simd_value2 = _mm512_loadu_si512((__m512i*)pointer_bytes2);

                __m512i result = _mm512_xor_si512(simd_value1, simd_value2);
                if (_mm512_test_epi64_mask(result, result) != 0) {
                    return false;
                }

                pointer_bytes1 += 64;
                pointer_bytes2 += 64;
                size -= 64;
            }
        }

        case HALLOCY_SIMD_AVX2:
        case HALLOCY_SIMD_AVX: {
            while (size >= 32) {
                __m256i simd_value1 = _mm256_loadu_si256((__m256i*)pointer_bytes1);
                __m256i simd_value2 = _mm256_loadu_si256((__m256i*)pointer_bytes2);

                __m256i result = _mm256_xor_si256(simd_value1, simd_value2);
                if (!_mm256_testz_si256(result, result)) {
                    return false;
                }

                pointer_bytes1 += 32;
                pointer_bytes2 += 32;
                size -= 32;
            }            
        }

        case HALLOCY_SIMD_SSE2:
        case HALLOCY_SIMD_SSE: {
            while (size >= 16) {
                __m128i simd_value1 = _mm_loadu_si128((__m128i*)pointer_bytes1);
                __m128i simd_value2 = _mm_loadu_si128((__m128i*)pointer_bytes2);

                __m128i result = _mm_xor_si128(simd_value1, simd_value2);
                if (!_mm_testz_si128(result, result)) {
                    return false;
                }

                pointer_bytes1 += 16;
                pointer_bytes2 += 16;                
                size -= 16;
            }
            break;
        }
        #endif

        default: {
            size_t *pointer_word1 = (size_t*)pointer_bytes1;
            size_t *pointer_word2 = (size_t*)pointer_bytes2;

            size_t word_size = sizeof(size_t);
            while (size >= word_size) {
                if (*pointer_word1 != *pointer_word2) {
                    return false;
                }

                pointer_word1++;
                pointer_word2++;
                size -= word_size;
            }

            pointer_bytes1 = (unsigned char*)pointer_word1;
            pointer_bytes2 = (unsigned char*)pointer_word2;
            break;
        }
    }

    while (size-- > 0) {
        if (*pointer_bytes1 != *pointer_bytes2) {
            return false;
        }

        pointer_bytes1++;
        pointer_bytes2++;
    }

    return true;
}