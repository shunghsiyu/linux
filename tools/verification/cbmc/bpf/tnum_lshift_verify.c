/*
 * CBMC Verification Harness for tnum_lshift()
 *
 * Property being verified:
 *   For any tnum `a` and shift amount `shift`, and any concrete value `a_val`
 *   that is represented by `a`, the left shift (a_val << shift) must be
 *   represented by tnum_lshift(a, shift).
 *
 * Left shift is commonly used in BPF programs for:
 *   - Array index calculations
 *   - Bit manipulation
 *   - Pointer arithmetic
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_lshift_verify
 *   make -C tools/verification/cbmc/bpf tnum_lshift_trace
 *   make -C tools/verification/cbmc/bpf tnum_lshift_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_lshift(struct tnum a, u8 shift);

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

	/* Create a symbolic shift amount */
	u8 shift = __CPROVER_unsigned_char_input();

	/*
	 * Constrain shift to valid range [0, 63].
	 * Shifts >= 64 are undefined behavior in C.
	 */
	__CPROVER_assume(shift < 64);

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 */

	/* Use small values */
	__CPROVER_assume(a_val <= 255);

	/* Use small shift amounts */
	__CPROVER_assume(shift <= 8);

	/* Use simple masks (only lower bits unknown) */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);

	/* Use tnums with few unknown bits */
	__CPROVER_assume(__builtin_popcountll(a.mask) <= 2);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_lshift to compute the abstract result */
	struct tnum result = tnum_lshift(a, shift);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result.
	 * Left shift in C: shifts beyond the value width are undefined,
	 * but we've constrained shift < 64 above.
	 */
	u64 result_val = a_val << shift;

	/*
	 * SOUNDNESS PROPERTY:
	 * The concrete shift result must be represented by
	 * the abstract tnum_lshift result.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision check:
	 * Left shift should introduce known zeros in the lower bits.
	 * If we shift by N, the lower N bits should all be known zeros.
	 */
	if (shift > 0) {
		u64 lower_mask = (1ULL << shift) - 1;
		u64 lower_bits_value = result.value & lower_mask;
		u64 lower_bits_mask = result.mask & lower_mask;

		/* Lower bits should all be known (mask=0) and zero (value=0) */
		assert(lower_bits_mask == 0);
		assert(lower_bits_value == 0);
	}
}
