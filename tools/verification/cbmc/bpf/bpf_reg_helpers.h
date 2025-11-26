/*
 * Common helper functions for BPF register state verification harnesses
 *
 * This header provides reusable helper functions for CBMC verification
 * of BPF verifier register tracking operations.
 */

#ifndef BPF_REG_HELPERS_H
#define BPF_REG_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

/*
 * Helper: Create symbolic bpf_reg_state
 *
 * Creates a symbolic register state with all fields initialized from
 * CBMC's non-deterministic input functions. This allows CBMC to explore
 * all possible register states during verification.
 */
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

/*
 * Helper: Validate bpf_reg_state invariants
 *
 * Checks that a register state satisfies all documented invariants:
 * - Max >= min for all range types
 * - Valid tnum (value and mask don't overlap)
 * - Tnum consistent with u64 range
 * - 64-bit and 32-bit bounds consistent
 *
 * When 'input' is true, additional constraints are applied that reflect
 * the state after BPF verifier initialization (e.g., sign/unsigned range
 * relationships).
 */
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

/*
 * Helper: Check if 64-bit value is within register's tracked 64-bit ranges
 *
 * Returns true if the value is within both the unsigned [umin, umax] and
 * signed [smin, smax] ranges tracked by the register.
 *
 * Note: This only checks 64-bit ranges. Functions that only update 64-bit
 * bounds (like scalar_min_max_add) don't need to check 32-bit ranges or tnum.
 */
static bool val_in_reg(struct bpf_reg_state *reg, u64 val)
{
	bool ret = true;

	ret &= reg->umin_value <= val;
	ret &= val <= reg->umax_value;
	ret &= reg->smin_value <= (s64)val;
	ret &= (s64)val <= reg->smax_value;

	return ret;
}

/*
 * Helper: Check if the lower 32 bits of value are within register's 32-bit ranges
 *
 * Returns true if the lower 32 bits of the value are within both the
 * unsigned [u32_min, u32_max] and signed [s32_min, s32_max] ranges.
 *
 * Used for verifying functions that only update 32-bit bounds.
 */
static bool val32_in_reg(struct bpf_reg_state *reg, u64 val)
{
	bool ret = true;
	u32 val32 = (u32)val;
	s32 sval32 = (s32)val32;

	ret &= reg->u32_min_value <= val32;
	ret &= val32 <= reg->u32_max_value;
	ret &= reg->s32_min_value <= sval32;
	ret &= sval32 <= reg->s32_max_value;

	return ret;
}

#endif /* BPF_REG_HELPERS_H */
