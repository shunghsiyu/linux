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

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

/* Forward declarations */
extern bool tnum_is_const(struct tnum t);
extern struct tnum tnum_const(u64 value);
extern struct tnum tnum_range(u64 min, u64 max);
extern bool tnum_contains(struct tnum t, u64 v);

/* Helper: Create symbolic bpf_reg_state */
static struct bpf_reg_state __bpf_reg_state_input(void)
{
	struct bpf_reg_state reg;

	reg.smin_value = __CPROVER_long_long_input();
	reg.smax_value = __CPROVER_long_long_input();
	reg.umin_value = __CPROVER_unsigned_long_long_input();
	reg.umax_value = __CPROVER_unsigned_long_long_input();
	reg.s32_min_value = __CPROVER_int_input();
	reg.s32_max_value = __CPROVER_int_input();
	reg.u32_min_value = __CPROVER_unsigned_int_input();
	reg.u32_max_value = __CPROVER_unsigned_int_input();
	reg.var_off.value = __CPROVER_unsigned_long_long_input();
	reg.var_off.mask = __CPROVER_unsigned_long_long_input();

	reg.type = SCALAR_VALUE;
	reg.off = 0;
	reg.id = 0;

	return reg;
}

/* Helper: Validate bpf_reg_state invariants */
static bool valid_bpf_reg_state(struct bpf_reg_state *reg, bool input)
{
	bool ret = true;

	/* Maximum >= minimum for all ranges */
	ret &= reg->umin_value <= reg->umax_value;
	ret &= reg->smin_value <= reg->smax_value;
	ret &= reg->u32_min_value <= reg->u32_max_value;
	ret &= reg->s32_min_value <= reg->s32_max_value;

	/* Valid tnum (value and mask don't overlap) */
	ret &= (reg->var_off.value & reg->var_off.mask) == 0;

	/* Tnum consistent with u64 range */
	ret &= reg->var_off.value <= reg->umin_value;
	ret &= (reg->var_off.value | reg->var_off.mask) >= reg->umax_value;

	/* 64-bit and 32-bit bounds consistent */
	ret &= reg->umin_value <= (u64)reg->u32_max_value;
	ret &= reg->umax_value >= (u64)reg->u32_min_value;
	ret &= (s64)reg->smin_value <= (s64)reg->s32_max_value;
	ret &= (s64)reg->smax_value >= (s64)reg->s32_min_value;

	if (!input)
		return ret;

	/* Additional constraints for input states */
	if (reg->var_off.value <= (u64)S64_MAX &&
	    (u64)S64_MIN <= (reg->var_off.value | reg->var_off.mask)) {
		ret &= reg->smin_value == S64_MIN && reg->smax_value == S64_MAX;
	} else if (reg->smin_value < 0 && reg->smax_value >= 0) {
		ret &= reg->var_off.value == 0 && reg->var_off.mask == U64_MAX;
		ret &= reg->umin_value == 0 && reg->umax_value == U64_MAX;
	} else {
		ret &= reg->umin_value == (u64)reg->smin_value;
		ret &= reg->umax_value == (u64)reg->smax_value;
	}

	return ret;
}

/* Helper: Check if the lower 32 bits of value are within register's 32-bit tracked ranges */
static bool val32_in_reg(struct bpf_reg_state *reg, u64 val)
{
	bool ret = true;
	u32 val32 = (u32)val;
	s32 sval32 = (s32)val32;

	ret &= reg->u32_min_value <= val32;
	ret &= val32 <= reg->u32_max_value;
	ret &= reg->s32_min_value <= sval32;
	ret &= sval32 <= reg->s32_max_value;

	/* Note: We skip 64-bit and tnum checks because scalar32_min_max_add()
	 * only updates the 32-bit bounds. In practice, other functions
	 * (like __reg_deduce_bounds) would update the rest.
	 */

	return ret;
}

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
