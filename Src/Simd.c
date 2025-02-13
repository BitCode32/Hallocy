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
 * File: Simd.c
 * Description:
 *  This file contains the function used to determine the simd support of a device.
 * 
 * Author: BitCode32
 * -----------------------------------------------------------------------------
 */
#include "../Include/Hallocy/Simd.h"

static hallocy_simd_type supported_simd = HALLOCY_SIMD_UNDEFINED;

hallocy_simd_type hallocy_supports_simd() {
    if (supported_simd != HALLOCY_SIMD_UNDEFINED) {
        return supported_simd;
    }

    #ifdef _MSC_VER
    int cpu_info[4] = { 0 };
    __cpuid(cpu_info, 7);
    if ((cpu_info[1] & (1 << 16)) != 0) {
        supported_simd = HALLOCY_SIMD_AVX512;
        return supported_simd;
    }
    
    if ((cpu_info[1] & (1 << 5)) != 0) {
        supported_simd = HALLOCY_SIMD_AVX2;
        return supported_simd;
    }

    __cpuid(cpu_info, 1);
    
    if ((cpu_info[2] & (1 << 28)) != 0) {
        supported_simd = HALLOCY_SIMD_AVX;
        return supported_simd;
    }

    if ((cpu_info[3] & (1 << 26)) != 0) {
        supported_simd = HALLOCY_SIMD_SSE2;
        return supported_simd;
    }

    if ((cpu_info[3] & (1 << 25)) != 0) {
        supported_simd = HALLOCY_SIMD_SSE2;
        return supported_simd;
    }
    #else
    unsigned int a, b, c, d;
    __asm__ __volatile__ (
        "cpuid"
        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
        : "a"(7)
    )

    if ((b & (1 << 16)) != 0) {
        supported_simd = HALLOCY_SIMD_AVX512;
        return supported_simd;
    }

    if ((b & (1 << 5)) != 0) {
        supported_simd = HALLOCY_SIMD_AVX2;
        return supported_simd;
    }

    __asm__ __volatile__ (
        "cpuid"
        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
        : "a"(1)
    )

    if ((c & (1 << 28)) != 0) {
        supported_simd = HALLOCY_SIMD_AVX;
        return supported_simd;
    }

    if ((c & (1 << 26)) != 0) {
        supported_simd = HALLOCY_SIMD_SSE2;
        return supported_simd;
    }

    if ((c & (1 << 25)) != 0) {
        supported_simd = HALLOCY_SIMD_SSE2;
        return supported_simd;
    }
    #endif

    supported_simd = HALLOCY_SIMD_NONE;
    return supported_simd;
}