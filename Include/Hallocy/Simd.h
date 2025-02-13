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
 * File: Simd.h
 * Description:
 *  This file contains the function and defines the enum used to determine the simd 
 *  support of a device.
 * 
 * Author: BitCode32
 * -----------------------------------------------------------------------------
 */
#ifndef HALLOCY_SIMD
#define HALLOCY_SIMD

#if defined(_MSC_VER)
    #if defined(_M_ARM64)
    #include <arm64intr.h>
    #else
    #include <intrin.h>
    #endif
#else
    #if defined(__aarch64__)
    #include <arm64intr.h>
    #elif defined(__arm__)
    #include <arm_neon.h>
    #else
    #include <immintrin.h>
    #endif
#endif

typedef enum {
    HALLOCY_SIMD_UNDEFINED,
    HALLOCY_SIMD_NONE,
    HALLOCY_SIMD_SSE,
    HALLOCY_SIMD_SSE2,
    HALLOCY_SIMD_AVX,
    HALLOCY_SIMD_AVX2,
    HALLOCY_SIMD_AVX512,
    HALLOCY_SIMD_NEON
} hallocy_simd_type;

hallocy_simd_type hallocy_supports_simd();

#endif