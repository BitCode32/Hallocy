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
 * File: Main.c
 * Description:
 *  This file is used as an example of how to use the library. When compiling 
 *  this file is used to create the HallocyApp.exe file.
 * 
 * Author: BitCode32
 * -----------------------------------------------------------------------------
 */
#include <Hallocy/Allocator.h>
#include <stdio.h>

int main() {
    printf("starting program...\n");
    
    char hello[6] = "Hello";
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
    printf("Test is %s to Test.\n", (hallocy_compare_memory("Test", "Test", 5)) ? "equal" : "not equal");
    printf("Test2 is %s to Test3.\n", (hallocy_compare_memory("Test2", "Test3", 6)) ? "equal" : "not equal");

    hallocy_free(medium_memory);

    printf("finished program!\n");
    return 0;
}