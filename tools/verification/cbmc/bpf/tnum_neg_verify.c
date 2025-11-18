/*
 * CBMC Verification Harness for tnum_neg()
 *
 * Property being verified:
 *   For any tnum `a` and any concrete value `a_val` that is represented
 *   by `a`, the negation (0 - a_val) must be represented by tnum_neg(a).
 *
 * tnum_neg computes the two's complement negation of a tnum.
 * It is implemented as: tnum_sub(TNUM(0, 0), a)
 *
 * This is used in the BPF verifier for:
 *   - Signed arithmetic
 *   - Converting between positive and negative ranges
 *   - Implementing unary minus operations
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_neg_verify
 *   make -C tools/verification/cbmc/bpf tnum_neg_trace
 *   make -C tools/verification/cbmc/bpf tnum_neg_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_neg(struct tnum a);

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

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 */

	/* Use small values */
	__CPROVER_assume(a_val <= 20);

	/* Use simple masks (only lower bits unknown) */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);

	/* Use tnums with few unknown bits */
	__CPROVER_assume(__builtin_popcountll(a.mask) <= 2);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_neg to compute the abstract result */
	struct tnum result = tnum_neg(a);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result: two's complement negation.
	 * In C, this is just 0 - a_val (or equivalently, -a_val).
	 * Due to unsigned overflow wrapping, this computes correct two's complement.
	 */
	u64 result_val = 0 - a_val;  /* or: result_val = -a_val */

	/*
	 * SOUNDNESS PROPERTY:
	 * The concrete negation result must be represented by
	 * the abstract tnum_neg result.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional property check:
	 * Negating twice should give back a value in the original set.
	 * For any value represented by a, -(-value) should also be in a.
	 */
	u64 double_neg = 0 - result_val;
	assert(tnum_contains(a, double_neg));
}
