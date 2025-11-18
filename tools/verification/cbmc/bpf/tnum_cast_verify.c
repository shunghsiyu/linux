/*
 * CBMC Verification Harness for tnum_cast()
 *
 * Property being verified:
 *   For any tnum `a`, size parameter, and any concrete value `a_val`
 *   that is represented by `a`, the truncated value (a_val with upper
 *   bits cleared) must be represented by tnum_cast(a, size).
 *
 * tnum_cast truncates a tnum to a smaller size by clearing all but the
 * lowest `size` bytes. This is equivalent to:
 *   value &= (1ULL << (size * 8)) - 1
 *   mask &= (1ULL << (size * 8)) - 1
 *
 * This is used in the BPF verifier for:
 *   - 32-bit subreg operations
 *   - Type conversions (64-bit to 32-bit, etc.)
 *   - Extracting lower bytes
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_cast_verify
 *   make -C tools/verification/cbmc/bpf tnum_cast_trace
 *   make -C tools/verification/cbmc/bpf tnum_cast_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_cast(struct tnum a, u8 size);

/* Helper: Check if a concrete value is represented by a tnum */
static bool tnum_contains(struct tnum t, u64 v)
{
	return (v & ~t.mask) == t.value;
}

/* Helper: Create a symbolic tnum */
static struct tnum symbolic_tnum(void)
{
	struct tnum t;
	t.value = __CPROVER_unsigned_long_long_input();
	t.mask = __CPROVER_unsigned_long_long_input();
	return t;
}

/* Helper: Check if a tnum is valid */
static bool valid_tnum(struct tnum t)
{
	return (t.value & t.mask) == 0;
}

/*
 * Main verification harness
 */
void main(void)
{
	/* ==================== Setup ==================== */

	/* Create a symbolic tnum */
	struct tnum a = symbolic_tnum();

	/* Assume the tnum is valid */
	__CPROVER_assume(valid_tnum(a));

	/* Create a symbolic concrete value */
	u64 a_val = __CPROVER_unsigned_long_long_input();

	/* Assume the concrete value is represented by the tnum */
	__CPROVER_assume(tnum_contains(a, a_val));

	/* Create a symbolic size parameter */
	u8 size = __CPROVER_unsigned_char_input();

	/*
	 * Constrain size to valid values: 1, 2, 4, or 8 bytes.
	 * (Though the implementation works for any size, these are
	 * the typical uses in the BPF verifier)
	 */
	__CPROVER_assume(size >= 1 && size <= 8);

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 */

	/* Test common sizes */
	__CPROVER_assume(size == 1 || size == 2 || size == 4);

	/* Use small values */
	__CPROVER_assume(a_val <= 0xFFFFFFFF);

	/* Use simple masks */
	__CPROVER_assume((a.mask & 0xFFFFFFFF00000000ULL) == 0);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_cast to compute the abstract result */
	struct tnum result = tnum_cast(a, size);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result: truncate to `size` bytes.
	 */
	u64 mask = (1ULL << (size * 8)) - 1;
	if (size == 8) {
		/* Special case: avoid shifting by 64 which is undefined */
		mask = U64_MAX;
	}
	u64 result_val = a_val & mask;

	/*
	 * SOUNDNESS PROPERTY:
	 * The truncated value must be represented by tnum_cast result.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision checks:
	 */

	/* 1. All upper bits (beyond size bytes) should be known-0 */
	u64 upper_mask = ~mask;
	u64 result_upper_value = result.value & upper_mask;
	u64 result_upper_mask = result.mask & upper_mask;

	assert(result_upper_value == 0);
	assert(result_upper_mask == 0);

	/*
	 * 2. Lower bits should preserve the known bits from input.
	 * If a bit was known in the input and is within size bytes,
	 * it should still be known in the output.
	 */
	u64 input_known = ~a.mask;
	u64 lower_input_known = input_known & mask;
	u64 output_known = ~result.mask;
	u64 lower_output_known = output_known & mask;

	assert((lower_input_known & lower_output_known) == lower_input_known);

	/* For known bits, values should match */
	assert((result.value & lower_input_known) == (a.value & lower_input_known));
}
