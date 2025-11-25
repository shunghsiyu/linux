# CBMC Verification for BPF Verifier

This directory contains CBMC (C Bounded Model Checker) verification harnesses for the Linux kernel's BPF verifier, specifically focused on abstract interpretation and value tracking routines.

## Overview

The BPF verifier uses abstract interpretation to track possible values that BPF registers may hold. It's critical that these tracking routines make **safe** approximations - they don't need to be precise, but they must never exclude possible values that could actually occur at runtime.

CBMC allows us to formally verify that these tracking functions satisfy this safety property for **all** possible inputs.

## Prerequisites

### Install CBMC

CBMC provides `goto-cc` (a compiler frontend) and `cbmc` (the model checker).

#### Ubuntu/Debian
```bash
sudo apt-get install cbmc
```

#### Fedora/RHEL
```bash
sudo dnf install cbmc
```

#### From Source
```bash
git clone https://github.com/diffblue/cbmc.git
cd cbmc
cmake -S . -Bbuild -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

Verify installation:
```bash
goto-cc --version
cbmc --version
```

## Quick Start

### Verify an existing function

```bash
cd tools/verification/cbmc/bpf
make coerce_reg_to_size_sx_verify
```

This will:
1. Compile the BPF verifier sources with `goto-cc`
2. Link them with the verification harness
3. Run CBMC to verify the properties

### If verification fails

Get a counterexample trace:
```bash
make coerce_reg_to_size_sx_trace
```

Use simplified constraints for easier debugging:
```bash
make coerce_reg_to_size_sx_simple
```

## Understanding the Verification

### What is being verified?

We verify three categories of functions:

#### 1. Register State Tracking Functions

For `coerce_reg_to_size_sx()`, we verify:

**Property**: For any valid input register state containing value `x`, after calling `coerce_reg_to_size_sx(reg, size)`, the output register state must contain the sign-extended version of `x`.

This ensures the verifier's abstract interpretation correctly tracks all possible values after a sign-extension instruction.

#### 2. Scalar Arithmetic Operations

These functions track value ranges through arithmetic operations. We have verification for:

**64-bit operations:**
- `scalar_min_max_add(dst, src)` - Addition with overflow
- `scalar_min_max_sub(dst, src)` - Subtraction with underflow
- `scalar_min_max_mul(dst, src)` - Multiplication with overflow

**32-bit operations:**
- `scalar32_min_max_add(dst, src)` - 32-bit addition
- `scalar32_min_max_sub(dst, src)` - 32-bit subtraction
- `scalar32_min_max_mul(dst, src)` - 32-bit multiplication

**Example Property** (for `scalar_min_max_sub`): For any valid register states containing values `a` and `b`, after calling `scalar_min_max_sub(dst, src)`, the output state must contain `a - b` (with underflow wrapping).

#### 3. Tnum (Tristate Number) Operations

Tnums are the foundation of BPF verifier's bit-level abstract interpretation. Each bit can be:
- **0** - known to be zero
- **1** - known to be one
- **x** - unknown (could be 0 or 1)

We have **complete coverage** of all 14 tnum operations in `kernel/bpf/tnum.c`:

**Arithmetic Operations:**
- `tnum_add(a, b)` - Addition with carry propagation
- `tnum_sub(a, b)` - Subtraction with borrow propagation
- `tnum_mul(a, b)` - Multiplication using long multiplication algorithm
- `tnum_neg(a)` - Two's complement negation

**Bitwise Operations:**
- `tnum_and(a, b)` - Bitwise AND
- `tnum_or(a, b)` - Bitwise OR
- `tnum_xor(a, b)` - Bitwise XOR

**Shift Operations:**
- `tnum_lshift(a, shift)` - Logical left shift
- `tnum_rshift(a, shift)` - Logical right shift
- `tnum_arshift(a, shift, size)` - Arithmetic right shift (sign-aware)

**Set Operations:**
- `tnum_union(a, b)` - Set union (control flow merging)
- `tnum_intersect(a, b)` - Set intersection (constraint solving)

**Constructors/Utilities:**
- `tnum_range(min, max)` - Create tnum from range
- `tnum_cast(a, size)` - Truncate to smaller size

**Example Property** (for `tnum_add`): For any concrete values `a_val` and `b_val` represented by tnums `a` and `b`, the sum `a_val + b_val` must be represented by `tnum_add(a, b)`.

**Key Insight**: These properties ensure soundness - the abstract operations may over-approximate (be conservative), but they must never under-approximate (miss possible values).

### Verification harness structure

Each `*_verify.c` file contains:

1. **Assumptions/Setup**: Create symbolic inputs representing all possible valid states
   ```c
   struct bpf_reg_state reg = __bpf_reg_state_input();
   u64 x = __CPROVER_unsigned_long_long_input();
   __CPROVER_assume(valid_bpf_reg_state(&reg, true));
   __CPROVER_assume(val_in_reg(&reg, x));
   ```

2. **Operation**: Run the function under test
   ```c
   new_reg = reg;
   coerce_reg_to_size_sx(&new_reg, size);
   ```

3. **Property checking**: Verify the postcondition holds
   ```c
   new_x = (s64)((s64)x << (64 - size * 8)) >> (64 - size * 8);
   assert(val_in_reg(&new_reg, new_x));
   ```

### Helper functions

- `__bpf_reg_state_input()`: Creates a symbolic `bpf_reg_state` with CBMC's non-deterministic inputs
- `valid_bpf_reg_state()`: Ensures the register state satisfies all invariants
- `val_in_reg()`: Checks if a specific value is within all tracked ranges

## Adding New Verification Targets

### Step 1: Create a verification harness

Create `FUNCTION_verify.c`:

```c
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

/* Include helper functions from existing harnesses */

void main(void)
{
    /* 1. Set up symbolic inputs */
    struct bpf_reg_state src = __bpf_reg_state_input();
    struct bpf_reg_state dst = __bpf_reg_state_input();

    u64 src_val = __CPROVER_unsigned_long_long_input();
    u64 dst_val = __CPROVER_unsigned_long_long_input();

    /* 2. Assume inputs are valid */
    __CPROVER_assume(valid_bpf_reg_state(&src, true));
    __CPROVER_assume(valid_bpf_reg_state(&dst, true));
    __CPROVER_assume(val_in_reg(&src, src_val));
    __CPROVER_assume(val_in_reg(&dst, dst_val));

    /* 3. Run the function under test */
    your_function(&dst, &src);

    /* 4. Verify properties */
    u64 expected_val = /* compute expected result */;
    assert(val_in_reg(&dst, expected_val));
}
```

### Step 2: Add Makefile targets

Add to `Makefile`:

```makefile
$(BUILD_DIR)/FUNCTION_verify.goto: FUNCTION_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building FUNCTION verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c FUNCTION_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto \
	    -o $(BUILD_DIR)/FUNCTION_full.goto

FUNCTION_verify: $(BUILD_DIR)/FUNCTION_verify.goto
	@echo "$(GREEN)Running CBMC verification for FUNCTION...$(NC)"
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/FUNCTION_full.goto

FUNCTION_trace: $(BUILD_DIR)/FUNCTION_verify.goto
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/FUNCTION_full.goto

.PHONY: FUNCTION_verify FUNCTION_trace
```

### Step 3: Run verification

```bash
make FUNCTION_verify
```

## Debugging Failed Verifications

### 1. Start with trace output

```bash
make FUNCTION_trace
```

Look for the violated assertion and work backwards through the trace.

### 2. Add simplified constraints

In your `*_verify.c`, add `#ifdef CBMC_SIMPLE_CONSTRAINTS` blocks:

```c
#ifdef CBMC_SIMPLE_CONSTRAINTS
    /* Test smaller inputs */
    __CPROVER_assume(size == 1);

    /* Narrow the range */
    __CPROVER_assume((reg.umax_value - reg.umin_value) <= 3);

    /* Use simpler bit patterns */
    __CPROVER_assume(popcount(reg.umin_value) == 1);
#endif
```

Then rebuild with:
```bash
make FUNCTION_simple
```

### 3. Understanding counterexamples

CBMC's trace shows:
- Variable assignments with values in hex and binary
- Line-by-line execution
- Which assertion failed

Key things to check:
- Initial inputs to the function
- Intermediate values during computation
- Final state when assertion fails

### 4. Common issues

**Chained assignments**: Be careful with assignment order when types differ
```c
/* WRONG - truncates through u32 */
reg->umax_value = reg->u32_max_value = s64_max;

/* RIGHT - assigns to wider type first */
reg->u32_max_value = reg->umax_value = s64_max;
```

**Integer promotion**: C's type promotion can cause unexpected behavior
```c
/* May promote incorrectly */
ret &= reg->smin_value <= val;

/* Explicit cast ensures correct comparison */
ret &= reg->smin_value <= (s64)val;
```

## Performance Tips

### Limiting verification scope

CBMC's complexity grows with:
- Number of symbolic variables
- Size of value ranges
- Complexity of operations

Strategies:
1. **Use simplified constraints** during development
2. **Verify incrementally**: Test smaller pieces first
3. **Add bounds**: Use `__CPROVER_assume()` to limit ranges
4. **Unwind loops**: Use `--unwind N` flag for bounded loops

### Typical verification times

| Complexity | Time |
|------------|------|
| Simple (with constraints) | 1-5 minutes |
| Medium (full function) | 5-30 minutes |
| Complex (multiple functions) | 30+ minutes |

## Integration with Development Workflow

### Before submitting patches

```bash
# Verify your changes don't break properties
make coerce_reg_to_size_sx_verify
```

### When refactoring

```bash
# Verify old version
git stash
make FUNCTION_verify

# Verify new version
git stash pop
make FUNCTION_verify
```

Both should pass, proving the refactoring preserves correctness.

### In CI/CD

Add to `.github/workflows/` or similar:
```yaml
- name: Install CBMC
  run: sudo apt-get install -y cbmc

- name: Run BPF verifier verification
  run: make -C tools/verification/cbmc/bpf coerce_reg_to_size_sx_verify
```

## Advanced Topics

### Custom CBMC flags

Edit `CBMC_FLAGS` in Makefile:
```makefile
CBMC_FLAGS := --trace \
              --unwind 10 \          # Loop bound
              --unwinding-assertions \
              --depth 1000            # Recursion depth
```

### Extracting more kernel code

If your verification needs additional kernel functions:

1. Add to Makefile:
```makefile
$(BUILD_DIR)/helpers.goto: $(KERNEL_ROOT)/kernel/bpf/helpers.c
	$(GOTO_CC) $(CFLAGS) -c $< -o $@
```

2. Link with harness:
```makefile
$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto \
    $(BUILD_DIR)/helpers.goto -o $(BUILD_DIR)/FUNCTION_full.goto
```

### Verifying properties across multiple functions

Create a harness that calls multiple functions in sequence:
```c
void main(void) {
    struct bpf_reg_state reg = __bpf_reg_state_input();
    u64 val = __CPROVER_unsigned_long_long_input();

    __CPROVER_assume(valid_bpf_reg_state(&reg, true));
    __CPROVER_assume(val_in_reg(&reg, val));

    /* Call sequence */
    function1(&reg);
    function2(&reg);
    function3(&reg);

    /* Verify final state */
    assert(valid_bpf_reg_state(&reg, false));
}
```

## References

- [CBMC Documentation](https://www.cprover.org/cbmc/)
- [Sound, Precise, and Fast Abstract Interpretation with Tristate Numbers](https://arxiv.org/abs/2105.05398)
- [BPF Verifier Documentation](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
- Example article: "Using CBMC to verify the BPF verifier" (in this directory)

## Troubleshooting

### `goto-cc` not found
```bash
which goto-cc
# If not found, reinstall CBMC or add to PATH
export PATH=/path/to/cbmc/bin:$PATH
```

### Verification times out
- Add simplified constraints
- Reduce input space with `__CPROVER_assume()`
- Use `--depth` and `--unwind` flags

### Verification fails unexpectedly
- Check if you're testing a buggy version
- Verify your harness constraints are correct
- Use `make FUNCTION_trace` to debug

### Missing kernel headers
The Makefile uses relative paths. Ensure you're in the correct directory:
```bash
cd tools/verification/cbmc/bpf
pwd  # Should end in tools/verification/cbmc/bpf
```

## Contributing

When adding new verification harnesses:

1. Follow the naming convention: `FUNCTION_verify.c`
2. Document what property is being verified
3. Add comprehensive comments
4. Include simplified constraint blocks for debugging
5. Add Makefile targets
6. Test both success and failure cases

## License

This verification infrastructure is part of the Linux kernel and follows the same GPL-2.0 license.
