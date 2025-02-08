#ifndef HALLOCY_SIMD
#define HALLOCY_SIMD

typedef enum {
    HALLOCY_SIMD_UNDEFINED,
    HALLOCY_SIMD_NONE,
    HALLOCY_SIMD_SSE,
    HALLOCY_SIMD_SSE2,
    HALLOCY_SIMD_AVX,
    HALLOCY_SIMD_AVX2,
    HALLOCY_SIMD_AVX512
} hallocy_simd_type;

hallocy_simd_type hallocy_supports_simd();

#endif