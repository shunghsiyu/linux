# Attempting to Compile kernel/bpf/verifier.c with goto-cc

## Goal

Compile the full `kernel/bpf/verifier.c` along with its dependencies using `goto-cc` to enable CBMC verification of the actual kernel code without extraction.

## Approach

1. Used `make defconfig && make olddefconfig` to get a default configuration
2. Enabled `CONFIG_BPF_SYSCALL=y` and `CONFIG_BPF_JIT=y` in `.config`
3. Successfully compiled `kernel/bpf/verifier.o` with regular gcc
4. Extracted the full compilation command from `.verifier.o.cmd` (after build)
5. Attempted to use goto-cc with the same flags

## Errors Encountered and Fixes

### Error 1: `__seg_gs` Syntax Error ✅ FIXED

```
./arch/x86/include/asm/preempt.h:27:1: error: syntax error before '__seg_gs'
```

**Root Cause**: `__seg_gs` is a GCC x86-64 extension for segment registers (per-CPU variables). goto-cc doesn't support this syntax.

**Location**: Defined in `arch/x86/include/asm/percpu.h:37` when `CONFIG_CC_HAS_NAMED_AS=y` and `__CHECKER__` is defined.

**Fix**: Added to compatibility header:
```c
#define __seg_gs
#define __seg_fs
#undef __CHECKER__
```

### Error 2: `__auto_type` Syntax Error ✅ FIXED

```
./arch/x86/include/asm/string_64.h:34:1: error: syntax error before '__auto_type'
	const __auto_type s0 = s;
```

**Root Cause**: `__auto_type` is a GNU C extension for automatic type inference (similar to C++ `auto`). Used in `memset16()` and `memset32()` inline functions in `arch/x86/include/asm/string_64.h`.

**Fix**: Enabled `CONFIG_KMSAN=1` to skip the `__auto_type` code paths. When KMSAN is enabled, the kernel uses C versions from `lib/string.c` instead of inline assembly versions.

```c
#ifndef CONFIG_KMSAN
#define CONFIG_KMSAN 1
#endif
```

### Error 3: `NL_SET_ERR_MSG_MOD` Macro Error ✅ FIXED

```
./include/net/flow_offload.h:379:1: error: syntax error
			NL_SET_ERR_MSG_MOD(extack, "Mixing HW stats types for actions is not supported");
```

**Root Cause**: `NL_SET_ERR_MSG_MOD` macro (defined in `include/linux/netlink.h:127`) expands to:
```c
NL_SET_ERR_MSG((extack), KBUILD_MODNAME ": " msg)
```
The `KBUILD_MODNAME` wasn't defined, causing string concatenation to fail.

**Fix**: Added `-DKBUILD_MODNAME=\"verifier\"` to compiler flags.

```c
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "verifier"
#endif
```

### Error 4: GENMASK Constant Expression Errors ❌ FUNDAMENTAL LIMITATION

```
./include/linux/find.h:69:1: error: expected constant expression, but got 'size + 18446744073709551615ul >= offset'
		val = *addr & GENMASK(size - 1, offset);
CONVERSION ERROR
```

**Root Cause**: The `GENMASK(h, l)` macro creates a bitmask from bit `l` to bit `h`. The kernel implements this with compile-time checks:

```c
// include/linux/bits.h
#define GENMASK_INPUT_CHECK(h, l) BUILD_BUG_ON_ZERO(const_true((l) > (h)))
#define GENMASK_TYPE(t, h, l)					\
	((t)(GENMASK_INPUT_CHECK(h, l) +			\
	     (type_max(t) << (l) &				\
	      type_max(t) >> (BITS_PER_TYPE(t) - 1 - (h)))))
#define GENMASK(h, l)		GENMASK_TYPE(unsigned long, h, l)
```

The `BUILD_BUG_ON_ZERO(const_true((l) > (h)))` checks at compile time that `l <= h`. This works fine when `l` and `h` are compile-time constants, but fails when they're variables, even when the code is properly guarded:

```c
// include/linux/find.h
static __always_inline
unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	if (small_const_nbits(size)) {  // Checks __builtin_constant_p(size)
		unsigned long val;
		// ...
		val = *addr & GENMASK(size - 1, offset);  // ERROR HERE
		return val ? __ffs(val) : size;
	}
	return _find_next_bit(addr, size, offset);
}
```

The problem is that `GENMASK(size - 1, offset)` uses variable arguments (`size` and `offset`), which causes goto-cc's parser to fail even though this branch would only execute when `size` is a compile-time constant (due to the `if (small_const_nbits(size))` guard with `__builtin_constant_p`).

**Attempted Fixes**:

1. **Stubbed out `BUILD_BUG_ON_ZERO`** ❌
   ```bash
   -DBUILD_BUG_ON_ZERO\(e\)=0
   ```
   Still failed - the check happens before this is evaluated.

2. **Stubbed out `GENMASK_INPUT_CHECK`** ❌
   ```c
   #define GENMASK_INPUT_CHECK(h, l) (0)
   ```
   Still failed - goto-cc still evaluates the full GENMASK_TYPE expression.

3. **Redefined `GENMASK` as runtime-only** ❌
   ```c
   #define GENMASK(h, l) ((~0UL << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
   ```
   Still failed - goto-cc's parser still rejects it.

4. **Disabled `small_const_nbits` optimization** ❌
   ```c
   #define small_const_nbits(nbits) (0)
   ```
   Still failed - goto-cc validates the dead code path anyway.

5. **Patched `include/linux/find.h`** ✅ Partially worked
   Commented out all `if (small_const_nbits(size))` blocks to force use of out-of-line functions.
   ```c
   static __always_inline
   unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
                               unsigned long offset)
   {
       /* Disabled inline optimization for goto-cc compatibility */
       /* if (small_const_nbits(size)) {
           unsigned long val;
           if (unlikely(offset >= size))
               return size;
           val = *addr & GENMASK(size - 1, offset);
           return val ? __ffs(val) : size;
       } */
       return _find_next_bit(addr, size, offset);
   }
   ```

   This resolved errors in `find.h`, but immediately encountered the same error in `bitmap.h`:
   ```
   ./include/linux/bitmap.h:473:1: error: expected constant expression, but got 'start + nbits + 4294967295u >= start'
   		*map |= GENMASK(start + nbits - 1, start);
   ```

**Analysis**: This is a systemic issue. The GENMASK macro is used throughout the kernel headers (`find.h`, `bitmap.h`, `bitops.h`, etc.) with variable arguments inside inline functions. goto-cc's parser validates all code paths during parsing, even dead code paths that would never execute, and rejects variable arguments to GENMASK even when properly guarded.

**Why This Happens**: goto-cc performs stricter compile-time checking than GCC. It validates expressions like `GENMASK(size - 1, offset)` during parsing and requires them to be constant expressions, even when they appear in dead code paths that are guarded by `__builtin_constant_p()` checks.

## Fundamental Incompatibility

goto-cc cannot compile full Linux kernel code due to:

### 1. Macro Metaprogramming

The kernel heavily uses:
- `__builtin_constant_p()` for conditional compilation
- `BUILD_BUG_ON_ZERO()` for compile-time assertions
- `const_true()` for constant expression validation
- Complex macro expansions with compile-time checks

goto-cc's parser doesn't fully support these patterns and fails even when the code would work correctly at runtime.

### 2. Dead Code Analysis

goto-cc analyzes all code paths during parsing, including branches that would never execute (like `if (__builtin_constant_p(size))` when `size` is not constant). It rejects code in these dead branches even though they would never run.

GCC, in contrast, optimizes away these branches early and doesn't validate expressions in unreachable code.

### 3. Pervasive Usage

GENMASK and similar macros are used in hundreds of places across kernel headers:
- `include/linux/find.h` - 17 occurrences
- `include/linux/bitmap.h` - multiple occurrences
- `include/linux/bitops.h` - multiple occurrences
- Many other headers

Patching all of them is impractical and would require maintaining a heavily modified kernel tree.

### 4. GCC Extensions

The kernel relies on many GCC-specific features that goto-cc has limited support for:
- `__seg_gs` and `__seg_fs` for segment registers
- `__auto_type` for type inference
- Inline assembly with complex constraints
- `__builtin_*` functions with specific GCC semantics

## Compatibility Header Created

Created `/home/user/linux/goto-cc-compat.h` with workarounds for goto-cc:

```c
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
```

## Files Modified

- `/home/user/linux/goto-cc-compat.h` - Created
- `/home/user/linux/include/linux/find.h` - Patched (backed up to `.orig`)
- `/home/user/linux/.config` - Modified to enable CONFIG_BPF_SYSCALL and CONFIG_BPF_JIT

## Conclusion

**goto-cc cannot compile full Linux kernel code** due to fundamental parser limitations with kernel macro metaprogramming. The workarounds required would involve:

1. Patching dozens of kernel header files (find.h, bitmap.h, bitops.h, etc.)
2. Maintaining these patches as the kernel evolves
3. Potentially breaking kernel functionality by disabling optimizations
4. Still likely encountering more incompatibilities deeper in the compilation

This approach defeats the purpose of verifying the actual kernel code, as we'd be verifying a heavily modified version.

## Recommended Path Forward

Given these findings, we should pursue **extraction and simplification**:

### Option A: Extract Functions for Verification

Extract the specific BPF verifier functions we want to verify (tnum operations, scalar arithmetic, etc.) into standalone C files that:

1. Include only the necessary data structures
2. Use simplified versions of kernel macros
3. Can be compiled with goto-cc without the full kernel header complexity
4. Maintain the same algorithmic logic as the kernel code

**Advantages**:
- ✅ Allows us to verify the actual algorithm logic
- ✅ Avoids kernel build system complexity
- ✅ Can be maintained alongside kernel updates
- ✅ Verification harnesses we already wrote can be used directly

**Disadvantages**:
- ❌ Requires manual extraction and maintenance
- ❌ May miss integration issues with other kernel subsystems
- ❌ Not verifying the exact kernel code (but same logic)

### Option B: Alternative Verification Tools

Consider tools better suited to kernel code:
- **KLEE** - Symbolic execution tool with better kernel support
- **Sparse** - Linux kernel's own static analysis tool
- **Smatch** - Static analysis tool for finding bugs
- **Coccinelle** - Pattern matching and transformation tool

### Recommendation

**Pursue Option A (extraction)** because:
1. We've already written correct verification harnesses
2. The algorithm logic is what matters for soundness proofs
3. CBMC is still the best tool for formal verification
4. Extraction is more practical than maintaining kernel patches

Next steps:
1. Extract tnum operations into standalone files
2. Extract scalar arithmetic operations
3. Run CBMC verification on extracted code
4. Document correspondence between extracted and kernel code
