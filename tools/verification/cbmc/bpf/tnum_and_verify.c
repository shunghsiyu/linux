/*
 * CBMC Verification Harness for tnum_and()
 *
 * Property being verified:
 *   For any two tnums `a` and `b`, and any concrete values `a_val` and `b_val`
 *   that are represented by those tnums, the bitwise AND (a_val & b_val) must
 *   be represented by tnum_and(a, b).
 *
 * Bitwise operations are particularly important for BPF programs that do
 * bit manipulation, masking, and flag checking.
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_and_verify
 *   make -C tools/verification/cbmc/bpf tnum_and_trace
 *   make -C tools/verification/cbmc/bpf tnum_and_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_and(struct tnum a, struct tnum b);

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
	 * Bitwise operations are easier to verify than arithmetic.
	 */

	/* Use small values */
	__CPROVER_assume(a_val <= 255);
	__CPROVER_assume(b_val <= 255);

	/* Use simple bit patterns */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);
	__CPROVER_assume((b.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_and to compute the abstract result */
	struct tnum result = tnum_and(a, b);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result.
	 * Bitwise AND is straightforward - no overflow concerns.
	 */
	u64 result_val = a_val & b_val;

	/*
	 * SOUNDNESS PROPERTY:
	 * The concrete bitwise AND result must be represented by
	 * the abstract tnum_and result.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision check (not required for soundness):
	 * For bitwise AND, if both inputs have a known 0 bit,
	 * the output should also have a known 0 bit.
	 *
	 * This checks that tnum_and is not just sound, but also
	 * reasonably precise.
	 */
	u64 known_zeros_a = ~(a.value | a.mask);
	u64 known_zeros_b = ~(b.value | b.mask);
	u64 known_zeros_result = ~(result.value | result.mask);

	/* Any bit that is known-0 in either input should be known-0 in output */
	assert((known_zeros_a | known_zeros_b) <= known_zeros_result);
}
