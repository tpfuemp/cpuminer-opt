#ifndef RANDOMX_BUILDINFO_H
#define RANDOMX_BUILDINFO_H

/* Compile-time build selections of librandomx.a, reported from inside the
 * library. See randomx-buildinfo.cpp for why this cannot be asked elsewhere.
 */

#ifdef __cplusplus
extern "C" {
#endif

int randomx_build_have_aes(void);
int randomx_build_have_compiler(void);
int randomx_build_have_argon2_ssse3(void);
int randomx_build_have_argon2_avx2(void);
const char *randomx_build_jit_arch(void);
const char *randomx_build_simd(void);

#ifdef __cplusplus
}
#endif

#endif /* RANDOMX_BUILDINFO_H */
