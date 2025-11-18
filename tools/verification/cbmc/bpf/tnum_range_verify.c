/*
 * CBMC Verification Harness for tnum_range()
 *
 * Property being verified:
 *   For any min and max values with min <= max, and any concrete value `val`
 *   in the range [min, max], the value must be represented by
 *   tnum_range(min, max).
 *
 * tnum_range is a constructor that creates a tnum representing a range.
 * It may over-approximate. For example:
 *   tnum_range(0, 2) represents {0, 1, 2, 3} (not just {0, 1, 2})
 *   tnum_range(0, 3) represents {0, 1, 2, 3} (exact)
 *
 * This is documented in include/linux/tnum.h and is expected behavior.
 *
 * tnum_range is used extensively in the BPF verifier for:
 *   - Creating initial bounds from min/max values
 *   - Range-based abstract interpretation
 *   - Constraint propagation
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_range_verify
 *   make -C tools/verification/cbmc/bpf tnum_range_trace
 *   make -C tools/verification/cbmc/bpf tnum_range_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_range(u64 min, u64 max);

/* Helper: Check if a concrete value is represented by a tnum */
static bool tnum_contains(struct tnum t, u64 v)
{
	return (v & ~t.mask) == t.value;
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

	/* Create symbolic min and max values */
	u64 min = __CPROVER_unsigned_long_long_input();
	u64 max = __CPROVER_unsigned_long_long_input();

	/* Assume min <= max (valid range) */
	__CPROVER_assume(min <= max);

	/* Create a symbolic value in the range [min, max] */
	u64 val = __CPROVER_unsigned_long_long_input();
	__CPROVER_assume(val >= min);
	__CPROVER_assume(val <= max);

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 */

	/* Use small ranges */
	__CPROVER_assume(min <= 255);
	__CPROVER_assume(max <= 255);
	__CPROVER_assume((max - min) <= 15);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_range to compute the abstract result */
	struct tnum result = tnum_range(min, max);

	/* ==================== Verification ==================== */

	/*
	 * SOUNDNESS PROPERTY:
	 * Any value in [min, max] must be represented by tnum_range(min, max).
	 *
	 * Note: The result may over-approximate and include values outside
	 * [min, max]. This is expected and documented behavior.
	 */
	assert(tnum_contains(result, val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision checks:
	 */

	/* 1. If min == max, result should be a constant */
	if (min == max) {
		assert(result.mask == 0);
		assert(result.value == min);
	}

	/* 2. The result should definitely contain min and max */
	assert(tnum_contains(result, min));
	assert(tnum_contains(result, max));

	/*
	 * 3. Check that the result's value matches the common prefix of min/max.
	 * All bits that are the same in min and max should be known in result.
	 */
	u64 common_bits = ~(min ^ max);  /* Bits where min and max agree */
	u64 result_known = ~result.mask;

	/* Result should know at least the common bits */
	assert((common_bits & result_known) == common_bits);

	/* For known bits, they should match min (and max, since they agree) */
	assert((result.value & common_bits) == (min & common_bits));
}
