/*
 * CBMC Verification Harness for BPF verifier's coerce_reg_to_size_sx()
 *
 * This file provides a verification harness to check that coerce_reg_to_size_sx()
 * correctly tracks the possible values of BPF registers after sign extension.
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf coerce_reg_to_size_sx_verify
 *
 * To run with simplified constraints (for debugging):
 *   make -C tools/verification/cbmc/bpf coerce_reg_to_size_sx_verify SIMPLE=1
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

/* Forward declarations of kernel functions we need */
extern bool tnum_is_const(struct tnum t);
extern struct tnum tnum_const(u64 value);
extern struct tnum tnum_range(u64 min, u64 max);
extern bool tnum_contains(struct tnum t, u64 v);

/* Helper function to initialize 'struct bpf_reg_state' with symbolic values */
static struct bpf_reg_state __bpf_reg_state_input(void)
{
	struct bpf_reg_state reg;

	/* Initialize all scalar tracking fields with symbolic values */
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

	/* Initialize other fields to avoid uninitialized memory */
	reg.type = SCALAR_VALUE;
	reg.off = 0;
	reg.id = 0;

	return reg;
}

/* Helper function to ensure 'struct bpf_reg_state' is in a valid state */
static bool valid_bpf_reg_state(struct bpf_reg_state *reg, bool input)
{
	bool ret = true;

	/* Ensure maximum >= minimum for all ranges */
	ret &= reg->umin_value <= reg->umax_value;
	ret &= reg->smin_value <= reg->smax_value;
	ret &= reg->u32_min_value <= reg->u32_max_value;
	ret &= reg->s32_min_value <= reg->s32_max_value;

	/* Ensure tnum is valid (value and mask cannot overlap) */
	ret &= (reg->var_off.value & reg->var_off.mask) == 0;

	/* Relate tnum with unsigned 64-bit range */
	ret &= reg->var_off.value <= reg->umin_value;
	ret &= (reg->var_off.value | reg->var_off.mask) >= reg->umax_value;

	/* Ensure 64-bit bounds are consistent with 32-bit bounds */
	ret &= reg->umin_value <= (u64)reg->u32_max_value;
	ret &= reg->umax_value >= (u64)reg->u32_min_value;
	ret &= (s64)reg->smin_value <= (s64)reg->s32_max_value;
	ret &= (s64)reg->smax_value >= (s64)reg->s32_min_value;

	if (!input)
		return ret;

	/* Additional constraints for input 'struct bpf_reg_state' */
	/* Handle bound-crossing situations */
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

/* Helper function to check whether 'struct bpf_reg_state' contains a specific value */
static bool val_in_reg(struct bpf_reg_state *reg, u64 val)
{
	bool ret = true;

	/* Check unsigned 64-bit range */
	ret &= reg->umin_value <= val;
	ret &= val <= reg->umax_value;

	/* Check signed 64-bit range */
	ret &= reg->smin_value <= (s64)val;
	ret &= (s64)val <= reg->smax_value;

	/* Check unsigned 32-bit range */
	ret &= reg->u32_min_value <= (u32)val;
	ret &= (u32)val <= reg->u32_max_value;

	/* Check signed 32-bit range */
	ret &= reg->s32_min_value <= (s32)val;
	ret &= (s32)val <= reg->s32_max_value;

	/* Check tnum (bit pattern) */
	ret &= tnum_contains(reg->var_off, val);

	return ret;
}

/* Popcount function for debugging constraints */
static unsigned long long popcount(unsigned long long v)
{
	v = (v & 0x5555555555555555ULL) + ((v >> 1) & 0x5555555555555555ULL);
	v = (v & 0x3333333333333333ULL) + ((v >> 2) & 0x3333333333333333ULL);
	v = (v & 0x0F0F0F0F0F0F0F0FULL) + ((v >> 4) & 0x0F0F0F0F0F0F0F0FULL);
	v = (v & 0x00FF00FF00FF00FFULL) + ((v >> 8) & 0x00FF00FF00FF00FFULL);
	v = (v & 0x0000FFFF0000FFFFULL) + ((v >> 16) & 0x0000FFFF0000FFFFULL);
	v = (v & 0x00000000FFFFFFFFULL) + ((v >> 32) & 0x00000000FFFFFFFFULL);
	return v;
}

/*
 * Main verification harness
 *
 * This function sets up the verification conditions and checks the property:
 * "For any valid input register state containing value x, after calling
 *  coerce_reg_to_size_sx(), the output register state must contain the
 *  sign-extended version of x"
 */
void main(void)
{
	/* ==================== Assumptions and Setup ==================== */

	/*
	 * Create a symbolic input 'struct bpf_reg_state' representing the
	 * current knowledge of possible register values, and a symbolic value
	 * 'x' that could be any value currently in the register.
	 */
	struct bpf_reg_state reg = __bpf_reg_state_input();
	u64 x = __CPROVER_unsigned_long_long_input();

	/* Assume the input register state is valid */
	__CPROVER_assume(valid_bpf_reg_state(&reg, true));

	/* Assume x is within the ranges specified by reg */
	__CPROVER_assume(val_in_reg(&reg, x));

	/* Create storage for output and computed values */
	struct bpf_reg_state new_reg;
	u64 new_x;

	/* Get symbolic size argument (1, 2, or 4 bytes) */
	int size = __CPROVER_int_input();
	__CPROVER_assume(size == 1 || size == 2 || size == 4);

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/*
	 * Additional constraints to simplify counterexamples for debugging.
	 * These are optional and can be enabled with -DCBMC_SIMPLE_CONSTRAINTS
	 */

	/* Test only 8-bit sign extension */
	__CPROVER_assume(size == 1);

	/* Use a small range (only 2 values) */
	__CPROVER_assume((reg.umax_value - reg.umin_value) == 1);

	/* Use power-of-2 minimum values for easier debugging */
	__CPROVER_assume(popcount(reg.umin_value) == 1);
#endif

	/* ==================== Operation Under Test ==================== */

	/*
	 * Run coerce_reg_to_size_sx() on a copy of the input register state.
	 * (We use a copy to preserve the original for debugging purposes)
	 */
	new_reg = reg;
	coerce_reg_to_size_sx(&new_reg, size);

	/* ==================== Property Verification ==================== */

	/*
	 * Compute the actual sign-extended value that would result from
	 * the BPF instruction at runtime.
	 */
	new_x = (s64)((s64)x << (64 - size * 8)) >> (64 - size * 8);

	/*
	 * Verify that the output register state is valid and contains
	 * the sign-extended value.
	 */
	assert(valid_bpf_reg_state(&new_reg, false));
	assert(val_in_reg(&new_reg, new_x));
}
