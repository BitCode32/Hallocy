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
 * File: Allocator.h
 * Description:
 *  This file contains the functions for allocating, freeing and managing memory.
 *  It includes functions to allocate, reallocate, free, copy, move and set memory.
 * 
 * Author: BitCode32
 * -----------------------------------------------------------------------------
 */
#ifndef HALLOCY_ALLOCATOR
#define HALLOCY_ALLOCATOR

#include <stddef.h>

#define HALLOCY_LARGE_ALLOCATION 1048576
#define HALLOCY_SMALL_ALLOCATION 1024

void *hallocy_malloc(size_t size);
void *hallocy_calloc(size_t count, size_t size);
void *hallocy_realloc(void *pointer, size_t size);
void hallocy_free(void *pointer);

void *hallocy_set_memory(void *pointer, int value, size_t count);
void *hallocy_copy_memory(void *destination, const void *source, size_t size);
void *hallocy_move_memory(void *destination, const void *source, size_t size);

#endif