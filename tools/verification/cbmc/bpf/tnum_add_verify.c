/*
 * CBMC Verification Harness for tnum_add()
 *
 * Property being verified:
 *   For any two tnums `a` and `b`, and any concrete values `a_val` and `b_val`
 *   that are represented by those tnums, the sum (a_val + b_val) must be
 *   represented by tnum_add(a, b).
 *
 * This ensures the abstract interpretation is sound - it may over-approximate
 * (be conservative), but it must never under-approximate (miss possible values).
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_add_verify
 *   make -C tools/verification/cbmc/bpf tnum_add_trace
 *   make -C tools/verification/cbmc/bpf tnum_add_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations of tnum functions (implemented in kernel/bpf/tnum.c) */
extern struct tnum tnum_add(struct tnum a, struct tnum b);
extern bool tnum_is_const(struct tnum a);

/*
 * Helper: Check if a concrete value is represented by a tnum
 *
 * A value v is represented by tnum t if:
 *   - For every bit position where t.mask is 0 (known bit),
 *     the bit in v matches the corresponding bit in t.value
 *   - For every bit position where t.mask is 1 (unknown bit),
 *     the bit in v can be anything
 *
 * Mathematically: (v & ~t.mask) == t.value
 */
static bool tnum_contains(struct tnum t, u64 v)
{
	return (v & ~t.mask) == t.value;
}

/*
 * Helper: Create a symbolic tnum with arbitrary value and mask
 *
 * Note: We don't constrain the tnum to be "valid" because tnum operations
 * should work correctly even on tnums that weren't constructed through
 * the standard constructors (as long as the invariant value & mask == 0 holds).
 */
static struct tnum symbolic_tnum(void)
{
	struct tnum t;
	t.value = __CPROVER_unsigned_long_long_input();
	t.mask = __CPROVER_unsigned_long_long_input();
	return t;
}

/*
 * Helper: Check if a tnum is valid
 *
 * A tnum is valid if value and mask don't overlap - i.e., a bit cannot
 * be both "known" (mask=0) and have its value be set in the mask.
 */
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

	/* Assume both tnums are valid (value & mask == 0) */
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
	 * Simplified constraints for easier debugging.
	 * These reduce the search space significantly.
	 */

	/* Use small values */
	__CPROVER_assume(a_val <= 15);
	__CPROVER_assume(b_val <= 15);

	/* Use simple masks (only lower bits unknown) */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);
	__CPROVER_assume((b.mask & 0xFFFFFFFFFFFFFF00ULL) == 0);

	/* Use tnums with few unknown bits */
	__CPROVER_assume(__builtin_popcountll(a.mask) <= 2);
	__CPROVER_assume(__builtin_popcountll(b.mask) <= 2);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_add to compute the abstract result */
	struct tnum result = tnum_add(a, b);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result.
	 * Note: Unsigned overflow is well-defined in C (wraps around).
	 */
	u64 result_val = a_val + b_val;

	/*
	 * SOUNDNESS PROPERTY:
	 * The concrete result must be represented by the abstract result.
	 *
	 * This is the fundamental property of abstract interpretation:
	 * the abstract operation must be a sound over-approximation of
	 * the concrete operation.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));
}
