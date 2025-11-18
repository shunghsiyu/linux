/*
 * CBMC Verification Harness for tnum_rshift()
 *
 * Property being verified:
 *   For any tnum `a` and shift amount `shift`, and any concrete value `a_val`
 *   that is represented by `a`, the right shift (a_val >> shift) must be
 *   represented by tnum_rshift(a, shift).
 *
 * Right shift is commonly used in BPF programs for:
 *   - Extracting upper bits
 *   - Division by powers of 2
 *   - Bit field extraction
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_rshift_verify
 *   make -C tools/verification/cbmc/bpf tnum_rshift_trace
 *   make -C tools/verification/cbmc/bpf tnum_rshift_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_rshift(struct tnum a, u8 shift);

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
	__CPROVER_assume(a_val <= 65535);

	/* Use small shift amounts */
	__CPROVER_assume(shift <= 8);

	/* Use simple masks */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFF0000ULL) == 0);

	/* Use tnums with few unknown bits */
	__CPROVER_assume(__builtin_popcountll(a.mask) <= 3);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_rshift to compute the abstract result */
	struct tnum result = tnum_rshift(a, shift);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result.
	 * Right shift in C: logical shift for unsigned types.
	 */
	u64 result_val = a_val >> shift;

	/*
	 * SOUNDNESS PROPERTY:
	 * The concrete shift result must be represented by
	 * the abstract tnum_rshift result.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision check:
	 * Right shift should introduce known zeros in the upper bits.
	 * If we shift by N, the upper N bits should all be known zeros.
	 */
	if (shift > 0) {
		u64 upper_mask = ~((1ULL << (64 - shift)) - 1);
		u64 upper_bits_value = result.value & upper_mask;
		u64 upper_bits_mask = result.mask & upper_mask;

		/* Upper bits should all be known (mask=0) and zero (value=0) */
		assert(upper_bits_mask == 0);
		assert(upper_bits_value == 0);
	}
}
