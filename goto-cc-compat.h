/* Compatibility header for goto-cc compilation of kernel code */
#ifndef _GOTO_CC_COMPAT_H
#define _GOTO_CC_COMPAT_H

/* Disable segment register attributes */
#define __seg_gs
#define __seg_fs

/* Disable __CHECKER__ mode (Sparse static analysis) */
#undef __CHECKER__

/* Stub out const_true to always return false (disable BUILD_BUG_ON_ZERO checks) */
#define const_true(x) (false)

/* Stub out GENMASK_INPUT_CHECK to avoid compile-time constant checks */
#define GENMASK_INPUT_CHECK(h, l) (0)

/* Use runtime-only version of GENMASK to avoid constant expression requirements */
#define GENMASK(h, l) ((~0UL << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) ((~0ULL << (l)) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

/* Force use of out-of-line bit finding functions - disable inline optimizations */
#define small_const_nbits(nbits) (0)

/* Ensure KMSAN is enabled to avoid __auto_type usage in memset16/32 */
#ifndef CONFIG_KMSAN
#define CONFIG_KMSAN 1
#endif

/* Provide KBUILD_MODNAME for NL_SET_ERR_MSG_MOD macro */
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "verifier"
#endif

#endif /* _GOTO_CC_COMPAT_H */
