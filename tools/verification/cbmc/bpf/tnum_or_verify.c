/*
 * CBMC Verification Harness for tnum_or()
 *
 * Property being verified:
 *   For any two tnums `a` and `b`, and any concrete values `a_val` and `b_val`
 *   that are represented by those tnums, the bitwise OR (a_val | b_val) must
 *   be represented by tnum_or(a, b).
 *
 * Bitwise OR is commonly used in BPF programs for:
 *   - Setting flags
 *   - Combining bit fields
 *   - Permission masks
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_or_verify
 *   make -C tools/verification/cbmc/bpf tnum_or_trace
 *   make -C tools/verification/cbmc/bpf tnum_or_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_or(struct tnum a, struct tnum b);

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

	/* Create two symbolic tnums */
	struct tnum a = symbolic_tnum();
	struct tnum b = symbolic_tnum();

	/* Assume both tnums are valid */
	__CPROVER_assume(valid_tnum(a));
	__CPROVER_assume(valid_tnum(b));

	/* Create two symbolic concrete values */
	u64 a_val = __CPROVER_unsigned_long_long_input();
	u64 b_val = __CPROVER_unsigned_long_long_input();

	/* Assume the concrete values are represented by the tnums */
	__CPROVER_assume(tnum_contains(a, a_val));
	__CPROVER_assume(tnum_contains(b, b_val));

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 */

	/* Use small values */
	__CPROVER_assume(a_val <= 255);
	__CPROVER_assume(b_val <= 255);

	/* Use simple bit patterns */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);
	__CPROVER_assume((b.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_or to compute the abstract result */
	struct tnum result = tnum_or(a, b);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result.
	 */
	u64 result_val = a_val | b_val;

	/*
	 * SOUNDNESS PROPERTY:
	 * The concrete bitwise OR result must be represented by
	 * the abstract tnum_or result.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision check:
	 * For bitwise OR, if either input has a known 1 bit,
	 * the output should also have a known 1 bit.
	 */
	u64 known_ones_a = a.value & ~a.mask;
	u64 known_ones_b = b.value & ~b.mask;
	u64 known_ones_result = result.value & ~result.mask;

	/* Any bit that is known-1 in either input should be known-1 in output */
	u64 expected_known_ones = known_ones_a | known_ones_b;
	assert((expected_known_ones & known_ones_result) == expected_known_ones);
}
