/*
 * CBMC Verification Harness for BPF verifier's scalar32_min_max_add()
 *
 * Property being verified:
 *   For any valid src and dst register states containing values src_val and dst_val,
 *   after calling scalar32_min_max_add(dst, src), the output dst register state's
 *   32-bit bounds must contain the lower 32 bits of (dst_val + src_val).
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf scalar32_min_max_add_verify
 *   make -C tools/verification/cbmc/bpf scalar32_min_max_add_trace
 *   make -C tools/verification/cbmc/bpf scalar32_min_max_add_simple
 */

#include "bpf_reg_helpers.h"

/*
 * Main verification harness
 *
 * Verifies that scalar32_min_max_add() correctly tracks the 32-bit
 * signed and unsigned bounds after addition.
 */
void main(void)
{
	/* ==================== Setup ==================== */

	/* Create symbolic source and destination register states */
	struct bpf_reg_state src_reg = __bpf_reg_state_input();
	struct bpf_reg_state dst_reg = __bpf_reg_state_input();

	/* Create symbolic values that exist in those registers */
	u64 src_val = __CPROVER_unsigned_long_long_input();
	u64 dst_val = __CPROVER_unsigned_long_long_input();

	/* Assume both register states are valid */
	__CPROVER_assume(valid_bpf_reg_state(&src_reg, true));
	__CPROVER_assume(valid_bpf_reg_state(&dst_reg, true));

	/* Assume the 32-bit values are within the tracked 32-bit ranges */
	__CPROVER_assume(val32_in_reg(&src_reg, src_val));
	__CPROVER_assume(val32_in_reg(&dst_reg, dst_val));

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Simplified constraints for debugging.
	 * Use smaller ranges to get simpler counterexamples.
	 */

	/* Use small positive values */
	__CPROVER_assume(src_reg.s32_min_value >= 0);
	__CPROVER_assume(src_reg.s32_max_value <= 100);
	__CPROVER_assume(dst_reg.s32_min_value >= 0);
	__CPROVER_assume(dst_reg.s32_max_value <= 100);

	/* Use small ranges */
	__CPROVER_assume((src_reg.u32_max_value - src_reg.u32_min_value) <= 3);
	__CPROVER_assume((dst_reg.u32_max_value - dst_reg.u32_min_value) <= 3);
#endif

	/* ==================== Operation ==================== */

	/*
	 * Call scalar32_min_max_add() to update dst_reg based on adding src_reg.
	 * Note: This modifies dst_reg in place.
	 */
	scalar32_min_max_add(&dst_reg, &src_reg);

	/* ==================== Verification ==================== */

	/*
	 * Compute the actual result that would occur at runtime.
	 * For 32-bit addition, we care about the lower 32 bits.
	 */
	u32 dst_val32 = (u32)dst_val;
	u32 src_val32 = (u32)src_val;
	u32 result_val32 = dst_val32 + src_val32;  /* 32-bit overflow wraps */

	/*
	 * Verify the safety property:
	 * The output register state's 32-bit bounds must contain the actual result.
	 */
	assert(dst_reg.u32_min_value <= result_val32);
	assert(result_val32 <= dst_reg.u32_max_value);
	assert(dst_reg.s32_min_value <= (s32)result_val32);
	assert((s32)result_val32 <= dst_reg.s32_max_value);

	/*
	 * Additional sanity check: the output state should still be valid
	 * (though we only check the parts that scalar32_min_max_add touches)
	 */
	assert(dst_reg.s32_min_value <= dst_reg.s32_max_value);
	assert(dst_reg.u32_min_value <= dst_reg.u32_max_value);
}
