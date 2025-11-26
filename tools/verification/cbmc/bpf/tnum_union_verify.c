/*
 * CBMC Verification Harness for tnum_union()
 *
 * Property being verified:
 *   For any two tnums `a` and `b`, and any concrete value `val` that is
 *   represented by EITHER `a` OR `b`, the value must be represented by
 *   tnum_union(a, b).
 *
 *   In other words: tnum_union computes a superset of the union of the
 *   concrete sets represented by a and b.
 *
 * tnum_union is used extensively in the BPF verifier for:
 *   - Control flow merging (combining states from different paths)
 *   - Computing the join of two abstract states
 *   - Widening operations in fixpoint computation
 *
 * This is one of the most critical tnum operations for verifier correctness.
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_union_verify
 *   make -C tools/verification/cbmc/bpf tnum_union_trace
 *   make -C tools/verification/cbmc/bpf tnum_union_simple
 */

#include "tnum_helpers.h"

/* Forward declarations */
extern struct tnum tnum_union(struct tnum a, struct tnum b);

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
	 * Create a symbolic choice: is val from a or from b?
	 * This models that val is in the union of sets represented by a and b.
	 */
	bool from_a = __CPROVER_bool_input();

	/* Assume val is represented by either a or b */
	if (from_a) {
		__CPROVER_assume(tnum_contains(a, val));
	} else {
		__CPROVER_assume(tnum_contains(b, val));
	}

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

	/* Call tnum_union to compute the abstract result */
	struct tnum result = tnum_union(a, b);

	/* ==================== Verification ==================== */

	/*
	 * SOUNDNESS PROPERTY:
	 * The value must be represented by the union result.
	 *
	 * This verifies that tnum_union correctly over-approximates
	 * the union of the two sets. It's okay for the result to
	 * include additional values (over-approximation), but it must
	 * include all values from both input tnums.
	 */
	assert(tnum_contains(result, val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision check:
	 * If both a and b have a known bit at the same position with
	 * the same value, the result should also have that bit known.
	 */
	u64 known_bits_a = ~a.mask;
	u64 known_bits_b = ~b.mask;
	u64 both_known = known_bits_a & known_bits_b;

	/* For bits known in both, check if they agree */
	u64 agreed_bits = both_known & ~(a.value ^ b.value);
	u64 result_known = ~result.mask;

	/*
	 * All bits that are known and agree in both inputs should be
	 * known in the output. This checks precision of tnum_union.
	 */
	assert((agreed_bits & result_known) == agreed_bits);
}
