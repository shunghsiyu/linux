/*
 * CBMC Verification Harness for tnum_arshift()
 *
 * Property being verified:
 *   For any tnum `a`, shift amount `min_shift`, and bitness, and any concrete
 *   value `a_val` that is represented by `a`, the arithmetic right shift
 *   (a_val >> min_shift with sign extension) must be represented by
 *   tnum_arshift(a, min_shift, bitness).
 *
 * Arithmetic right shift (arsh) differs from logical right shift (rsh):
 *   - arsh preserves the sign bit (sign extension)
 *   - For negative numbers, fills with 1s from the left
 *   - For positive numbers, fills with 0s from the left
 *
 * This is used in the BPF verifier for:
 *   - Signed arithmetic operations
 *   - Division by powers of 2 (for signed values)
 *   - Extracting signed bit fields
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf tnum_arshift_verify
 *   make -C tools/verification/cbmc/bpf tnum_arshift_trace
 *   make -C tools/verification/cbmc/bpf tnum_arshift_simple
 */

#include <linux/types.h>
#include <linux/tnum.h>

/* Forward declarations */
extern struct tnum tnum_arshift(struct tnum a, u8 min_shift, u8 insn_bitness);

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

	/* Create symbolic shift amount and bitness */
	u8 min_shift = __CPROVER_unsigned_char_input();
	u8 insn_bitness = __CPROVER_unsigned_char_input();

	/*
	 * Constrain parameters to valid values:
	 * - min_shift must be less than bitness
	 * - insn_bitness is either 32 or 64
	 */
	__CPROVER_assume(insn_bitness == 32 || insn_bitness == 64);
	__CPROVER_assume(min_shift < insn_bitness);

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 * Arithmetic right shift is complex, so use very small values.
	 */

	/* Test only 64-bit for simplicity */
	__CPROVER_assume(insn_bitness == 64);

	/* Use small values to keep verification tractable */
	__CPROVER_assume((a_val & 0xFFFFFFFFFFFF0000ULL) == 0 ||
	                 (a_val & 0xFFFFFFFFFFFF0000ULL) == 0xFFFFFFFFFFFF0000ULL);

	/* Use small shift amounts */
	__CPROVER_assume(min_shift <= 8);

	/* Use simple masks */
	__CPROVER_assume((a.mask & 0xFFFFFFFFFFFF0000ULL) == 0);

	/* Use tnums with few unknown bits */
	__CPROVER_assume(__builtin_popcountll(a.mask) <= 2);
#endif

	/* ==================== Operation ==================== */

	/* Call tnum_arshift to compute the abstract result */
	struct tnum result = tnum_arshift(a, min_shift, insn_bitness);

	/* ==================== Verification ==================== */

	/*
	 * Compute the concrete result based on bitness.
	 * Arithmetic right shift preserves the sign bit.
	 */
	u64 result_val;
	if (insn_bitness == 32) {
		/* Cast to s32 for sign extension, shift, then cast to u32 then u64 */
		s32 signed_val = (s32)a_val;
		s32 shifted = signed_val >> min_shift;
		result_val = (u32)shifted;
	} else {
		/* 64-bit arithmetic right shift */
		s64 signed_val = (s64)a_val;
		s64 shifted = signed_val >> min_shift;
		result_val = (u64)shifted;
	}

	/*
	 * SOUNDNESS PROPERTY:
	 * The concrete arithmetic right shift result must be represented
	 * by the abstract tnum_arshift result.
	 */
	assert(tnum_contains(result, result_val));

	/*
	 * Additional sanity check: the result should be a valid tnum
	 */
	assert(valid_tnum(result));

	/*
	 * Optional precision check for 64-bit:
	 * After arithmetic right shift, if the original sign bit was known,
	 * all the shifted-in bits should have that value.
	 */
	if (insn_bitness == 64 && min_shift > 0) {
		bool sign_bit_known = (a.mask & (1ULL << 63)) == 0;

		if (sign_bit_known) {
			bool sign_bit_value = (a.value & (1ULL << 63)) != 0;

			/* Check shifted-in bits */
			u64 shifted_in_mask = ~((1ULL << (64 - min_shift)) - 1);
			u64 result_shifted_in_value = result.value & shifted_in_mask;
			u64 result_shifted_in_mask = result.mask & shifted_in_mask;

			/* All shifted-in bits should be known */
			assert(result_shifted_in_mask == 0);

			/* All shifted-in bits should match the sign bit */
			if (sign_bit_value) {
				assert(result_shifted_in_value == shifted_in_mask);
			} else {
				assert(result_shifted_in_value == 0);
			}
		}
	}
}
