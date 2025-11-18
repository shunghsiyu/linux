/*
 * CBMC Verification Harness for tnum_intersect()
 *
 * Property being verified:
 *   For any two tnums `a` and `b`, and any concrete value `val` that is
 *   represented by BOTH `a` AND `b`, the value must be represented by
 *   tnum_intersect(a, b).
 *
 *   In other words: tnum_intersect computes a superset of the intersection
 *   of the concrete sets represented by a and b.
 *
 * tnum_intersect is used in the BPF verifier for:
 *   - Refining abstract states with additional constraints
 *   - Computing the meet of two abstract states
 *   - Constraint solving and bound tightening
 *
 * Note: When a and b disagree (one has known-1, other has known-0),
 * tnum_intersect over-approximates by making that bit known-1 in the result.
 * This is sound but imprecise for contradiction cases.
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_intersect_verify
 *   make -C tools/verification/cbmc/bpf tnum_intersect_trace
 *   make -C tools/verification/cbmc/bpf tnum_intersect_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_intersect(struct tnum a, struct tnum b);

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

	/* Create a symbolic concrete value */
	u64 val = __CPROVER_unsigned_long_long_input();

	/*
	 * Assume val is represented by BOTH a AND b.
	 * This models val being in the intersection of the sets.
	 */
	__CPROVER_assume(tnum_contains(a, val));
	__CPROVER_assume(tnum_contains(b, val));

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 */

	/* Use small values */
	__CPROVER_assume(val <= 255);

	/* Use simple bit patterns */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);
	__CPROVER_assume((b.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);

	/* Use tnums with few unknown bits */
	__CPROVER_assume(__builtin_popcountll(a.mask) <= 3);
	__CPROVER_assume(__builtin_popcountll(b.mask) <= 3);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_intersect to compute the abstract result */
	struct tnum result = tnum_intersect(a, b);

	/* ==================== Verification ==================== */

	/*
	 * SOUNDNESS PROPERTY:
	 * Any value in the intersection must be represented by the result.
	 *
	 * This verifies that tnum_intersect correctly over-approximates
	 * the intersection of the two sets. It's okay for the result to
	 * include additional values (over-approximation), but it must
	 * include all values from the intersection.
	 */
	assert(tnum_contains(result, val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision check:
	 * Bits that are known in both inputs should be known in the output,
	 * unless they contradict (which causes over-approximation).
	 */
	u64 known_bits_a = ~a.mask;
	u64 known_bits_b = ~b.mask;
	u64 both_known = known_bits_a & known_bits_b;
	u64 contradicting = both_known & (a.value ^ b.value);

	/*
	 * For non-contradicting bits that are known in both,
	 * they should remain known in the result.
	 */
	u64 non_contradicting = both_known & ~contradicting;
	u64 result_known = ~result.mask;

	assert((non_contradicting & result_known) == non_contradicting);
}
