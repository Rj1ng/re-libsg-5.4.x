//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
// Copyright (c) Retargetable Decompiler <info@retdec.com>
//

#include <stdint.h>

// ------------------- Function Prototypes --------------------

int64_t entry_point(void);
void function_1900(int64_t * d);
int64_t JNI_OnLoad(void);
int64_t JNI_OnUnload(void);

// --------------------- Global Variables ---------------------

int64_t g1 = 0x10102464c457f; // 0x0
int32_t g3;
int64_t * g2 = &g1; // 0x47000

// ------------------------ Functions -------------------------

// Address range: 0x1900 - 0x1910
void function_1900(int64_t * d) {
    // 0x1900
    __cxa_finalize(d);
}

// Address range: 0x1c90 - 0x1c9c
int64_t entry_point(void) {
    // 0x1c90
    __cxa_finalize((int64_t *)&g2);
    return &g3;
}

// Address range: 0x1df8 - 0x1e50
int64_t JNI_OnLoad(void) {
    // 0x1df8
    int64_t v1; // 0x1df8
    int64_t v2; // 0x1df8
    __asm_mrs(v2, v1);
    int64_t result; // 0x1df8
    return result;
}

// Address range: 0x1f54 - 0x1fb0
int64_t JNI_OnUnload(void) {
    // 0x1f54
    int64_t v1; // 0x1f54
    int64_t v2; // 0x1f54
    __asm_mrs(v2, v1);
    int64_t result; // 0x1f54
    return result;
}

// --------------- Dynamically Linked Functions ---------------

// void __cxa_finalize(void * d);

// --------------------- Meta-Information ---------------------

// Detected compiler/packer: gc
// Detected language: C++
// Detected functions: 4