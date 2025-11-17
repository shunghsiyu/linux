#!/bin/bash
# Helper script to create a new CBMC verification harness for BPF verifier functions
#
# Usage: ./new_verify_harness.sh <function_name>
#
# Example: ./new_verify_harness.sh scalar_min_max_add

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <function_name>"
    echo ""
    echo "Example: $0 scalar_min_max_add"
    echo ""
    echo "This will create:"
    echo "  - ${1}_verify.c (verification harness)"
    echo "  - Makefile targets for verification"
    exit 1
fi

FUNC_NAME="$1"
HARNESS_FILE="${FUNC_NAME}_verify.c"

# Check if file already exists
if [ -f "$HARNESS_FILE" ]; then
    echo "Error: $HARNESS_FILE already exists!"
    exit 1
fi

# Create the verification harness from template
cat > "$HARNESS_FILE" << 'EOF'
/*
 * CBMC Verification Harness for BPF verifier's FUNCTION_NAME()
 *
 * Property being verified:
 *   TODO: Describe the property you're verifying
 *
 * To run this verification:
 *   make -C tools/verification/cbmc/bpf FUNCTION_NAME_verify
 *   make -C tools/verification/cbmc/bpf FUNCTION_NAME_trace    # With counterexample
 *   make -C tools/verification/cbmc/bpf FUNCTION_NAME_simple   # Simplified constraints
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

/* Forward declarations of kernel functions we need */
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

/* Helper: Check if value is within register's tracked ranges */
static bool val_in_reg(struct bpf_reg_state *reg, u64 val)
{
	bool ret = true;

	ret &= reg->umin_value <= val;
	ret &= val <= reg->umax_value;
	ret &= reg->smin_value <= (s64)val;
	ret &= (s64)val <= reg->smax_value;
	ret &= reg->u32_min_value <= (u32)val;
	ret &= (u32)val <= reg->u32_max_value;
	ret &= reg->s32_min_value <= (s32)val;
	ret &= (s32)val <= reg->s32_max_value;
	ret &= tnum_contains(reg->var_off, val);

	return ret;
}

/*
 * Main verification harness
 */
void main(void)
{
	/* ==================== Setup ==================== */

	/* TODO: Create symbolic inputs for your function
	 * Example for unary operation (one input register):
	 */
	struct bpf_reg_state reg = __bpf_reg_state_input();
	u64 val = __CPROVER_unsigned_long_long_input();

	__CPROVER_assume(valid_bpf_reg_state(&reg, true));
	__CPROVER_assume(val_in_reg(&reg, val));

	/* TODO: For binary operations (two input registers):
	 *
	 * struct bpf_reg_state src_reg = __bpf_reg_state_input();
	 * struct bpf_reg_state dst_reg = __bpf_reg_state_input();
	 * u64 src_val = __CPROVER_unsigned_long_long_input();
	 * u64 dst_val = __CPROVER_unsigned_long_long_input();
	 *
	 * __CPROVER_assume(valid_bpf_reg_state(&src_reg, true));
	 * __CPROVER_assume(valid_bpf_reg_state(&dst_reg, true));
	 * __CPROVER_assume(val_in_reg(&src_reg, src_val));
	 * __CPROVER_assume(val_in_reg(&dst_reg, dst_val));
	 */

#ifdef CBMC_SIMPLE_CONSTRAINTS
	/* TODO: Add simplified constraints for debugging
	 * Examples:
	 */
	__CPROVER_assume((reg.umax_value - reg.umin_value) <= 3);
	/* __CPROVER_assume(reg.umin_value < 1000); */
	/* __CPROVER_assume(val >= 0 && val <= 10); */
#endif

	/* ==================== Operation ==================== */

	/* TODO: Call your function under test
	 * Example:
	 */
	struct bpf_reg_state new_reg = reg;
	/* FUNCTION_NAME(&new_reg, ...); */

	/* ==================== Verification ==================== */

	/* TODO: Compute expected result and verify
	 * Example for addition:
	 *
	 * u64 expected_val = dst_val + src_val;
	 * assert(valid_bpf_reg_state(&new_reg, false));
	 * assert(val_in_reg(&new_reg, expected_val));
	 */

	/* TODO: Add your assertions here */
	assert(valid_bpf_reg_state(&new_reg, false));
	/* assert(val_in_reg(&new_reg, expected_val)); */
}
EOF

# Replace FUNCTION_NAME placeholders
sed -i "s/FUNCTION_NAME/$FUNC_NAME/g" "$HARNESS_FILE"

echo "Created $HARNESS_FILE"
echo ""
echo "Next steps:"
echo "  1. Edit $HARNESS_FILE and fill in TODOs"
echo "  2. Add Makefile targets (see template in Makefile)"
echo "  3. Run: make ${FUNC_NAME}_verify"
echo ""
echo "Makefile target template:"
echo ""
cat << EOF
\$(BUILD_DIR)/${FUNC_NAME}_verify.goto: ${FUNC_NAME}_verify.c \$(BUILD_DIR)/verifier.goto
	@echo "\$(YELLOW)Building ${FUNC_NAME} verification harness...\$(NC)"
	\$(GOTO_CC) \$(CFLAGS) -c ${FUNC_NAME}_verify.c -o \$@
	\$(GOTO_CC) \$@ \$(BUILD_DIR)/verifier.goto \$(BUILD_DIR)/tnum.goto -o \$(BUILD_DIR)/${FUNC_NAME}_full.goto

${FUNC_NAME}_verify: \$(BUILD_DIR)/${FUNC_NAME}_verify.goto
	@echo "\$(GREEN)Running CBMC verification for ${FUNC_NAME}...\$(NC)"
	\$(CBMC) \$(CBMC_FLAGS) --function main \$(BUILD_DIR)/${FUNC_NAME}_full.goto

${FUNC_NAME}_trace: \$(BUILD_DIR)/${FUNC_NAME}_verify.goto
	@echo "\$(GREEN)Running CBMC with trace output...\$(NC)"
	\$(CBMC) \$(CBMC_FLAGS) \$(TRACE_FLAGS) --function main \$(BUILD_DIR)/${FUNC_NAME}_full.goto

${FUNC_NAME}_simple: ${FUNC_NAME}_verify.c \$(BUILD_DIR)/verifier.goto
	@echo "\$(YELLOW)Building with simplified constraints...\$(NC)"
	\$(GOTO_CC) \$(CFLAGS) \$(SIMPLE_FLAGS) -c ${FUNC_NAME}_verify.c -o \$(BUILD_DIR)/${FUNC_NAME}_simple.goto
	\$(GOTO_CC) \$(BUILD_DIR)/${FUNC_NAME}_simple.goto \$(BUILD_DIR)/verifier.goto \$(BUILD_DIR)/tnum.goto -o \$(BUILD_DIR)/${FUNC_NAME}_simple_full.goto
	@echo "\$(GREEN)Running CBMC with simplified constraints...\$(NC)"
	\$(CBMC) \$(CBMC_FLAGS) \$(TRACE_FLAGS) --function main \$(BUILD_DIR)/${FUNC_NAME}_simple_full.goto

.PHONY: ${FUNC_NAME}_verify ${FUNC_NAME}_trace ${FUNC_NAME}_simple
EOF
echo ""
echo "Add the above to your Makefile"
