# CBMC Verification Makefile for BPF Verifier
#
# This Makefile provides targets to verify BPF verifier functions using CBMC.
#
# Prerequisites:
#   - CBMC installed (https://github.com/diffblue/cbmc)
#   - goto-cc available in PATH
#
# Usage:
#   make <target>_verify     - Run verification
#   make <target>_trace      - Run verification with counterexample trace
#   make <target>_simple     - Run with simplified constraints (for debugging)
#   make clean               - Clean build artifacts
#
# Example:
#   make coerce_reg_to_size_sx_verify
#   make coerce_reg_to_size_sx_trace

# Kernel source directories
KERNEL_ROOT := ../../../..
KERNEL_BPF := $(KERNEL_ROOT)/kernel/bpf
KERNEL_INCLUDE := $(KERNEL_ROOT)/include

# Tools
GOTO_CC := goto-cc
GOTO_INSTRUMENT := goto-instrument
CBMC := cbmc

# Compiler flags mimicking kernel build
CFLAGS := -I$(KERNEL_INCLUDE) \
          -I$(KERNEL_ROOT)/arch/x86/include \
          -I$(KERNEL_ROOT)/arch/x86/include/generated \
          -I$(KERNEL_ROOT)/arch/x86/include/uapi \
          -I$(KERNEL_ROOT)/include/uapi \
          -I$(KERNEL_ROOT)/include/generated/uapi \
          -D__KERNEL__ \
          -DCONFIG_X86_64 \
          -DCONFIG_64BIT \
          -nostdinc \
          -std=gnu11

# CBMC flags
CBMC_FLAGS := --trace \
              --stop-on-fail \
              --bounds-check \
              --pointer-check \
              --memory-leak-check \
              --div-by-zero-check \
              --signed-overflow-check \
              --unsigned-overflow-check \
              --conversion-check

# Additional flags for trace output
TRACE_FLAGS := --trace-show-code \
               --trace-show-function-calls

# Simplified flags for debugging (smaller state space)
SIMPLE_FLAGS := -DCBMC_SIMPLE_CONSTRAINTS

# Build directory
BUILD_DIR := build
$(shell mkdir -p $(BUILD_DIR))

# Color output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

.PHONY: all clean help

help:
	@echo "$(GREEN)CBMC Verification Targets for BPF Verifier$(NC)"
	@echo ""
	@echo "Verifier Register Tracking:"
	@echo "  coerce_reg_to_size_sx_verify - Verify sign extension tracking (unary op)"
	@echo ""
	@echo "Scalar Arithmetic Operations:"
	@echo "  64-bit:"
	@echo "    scalar_min_max_add_verify  - Verify 64-bit addition tracking"
	@echo "    scalar_min_max_sub_verify  - Verify 64-bit subtraction tracking"
	@echo "    scalar_min_max_mul_verify  - Verify 64-bit multiplication tracking"
	@echo "  32-bit:"
	@echo "    scalar32_min_max_add_verify - Verify 32-bit addition tracking"
	@echo "    scalar32_min_max_sub_verify - Verify 32-bit subtraction tracking"
	@echo "    scalar32_min_max_mul_verify - Verify 32-bit multiplication tracking"
	@echo ""
	@echo "Tnum (Tristate Number) Operations:"
	@echo "  Arithmetic:"
	@echo "    tnum_add_verify            - Verify tnum addition is sound"
	@echo "    tnum_sub_verify            - Verify tnum subtraction is sound"
	@echo "    tnum_mul_verify            - Verify tnum multiplication is sound"
	@echo "    tnum_neg_verify            - Verify tnum negation is sound"
	@echo "  Bitwise:"
	@echo "    tnum_and_verify            - Verify tnum bitwise AND is sound"
	@echo "    tnum_or_verify             - Verify tnum bitwise OR is sound"
	@echo "    tnum_xor_verify            - Verify tnum bitwise XOR is sound"
	@echo "  Shifts:"
	@echo "    tnum_lshift_verify         - Verify tnum left shift is sound"
	@echo "    tnum_rshift_verify         - Verify tnum right shift is sound"
	@echo "    tnum_arshift_verify        - Verify tnum arith right shift is sound"
	@echo "  Set Operations:"
	@echo "    tnum_union_verify          - Verify tnum union is sound"
	@echo "    tnum_intersect_verify      - Verify tnum intersection is sound"
	@echo "  Constructors/Utilities:"
	@echo "    tnum_range_verify          - Verify tnum range constructor is sound"
	@echo "    tnum_cast_verify           - Verify tnum cast/truncation is sound"
	@echo ""
	@echo "Each target has variants:"
	@echo "  <target>_verify              - Run verification"
	@echo "  <target>_trace               - Run with counterexample trace"
	@echo "  <target>_simple              - Run with simplified constraints"
	@echo ""
	@echo "General targets:"
	@echo "  clean                        - Remove build artifacts"
	@echo "  help                         - Show this help message"
	@echo ""
	@echo "Example workflow:"
	@echo "  1. make tnum_add_verify             # Run verification"
	@echo "  2. If it fails:"
	@echo "     make tnum_add_trace              # Get counterexample"
	@echo "  3. If counterexample is complex:"
	@echo "     make tnum_add_simple             # Simplify for debugging"

all: help

# Extract kernel BPF verifier functions to goto-binary
$(BUILD_DIR)/verifier.goto: $(KERNEL_BPF)/verifier.c $(KERNEL_BPF)/tnum.c
	@echo "$(YELLOW)Compiling BPF verifier to goto-binary...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c $(KERNEL_BPF)/verifier.c -o $(BUILD_DIR)/verifier.goto
	$(GOTO_CC) $(CFLAGS) -c $(KERNEL_BPF)/tnum.c -o $(BUILD_DIR)/tnum.goto

# coerce_reg_to_size_sx verification targets
$(BUILD_DIR)/coerce_reg_to_size_sx_verify.goto: coerce_reg_to_size_sx_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c coerce_reg_to_size_sx_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/coerce_reg_to_size_sx_full.goto

coerce_reg_to_size_sx_verify: $(BUILD_DIR)/coerce_reg_to_size_sx_verify.goto
	@echo "$(GREEN)Running CBMC verification for coerce_reg_to_size_sx...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/coerce_reg_to_size_sx_full.goto

coerce_reg_to_size_sx_trace: $(BUILD_DIR)/coerce_reg_to_size_sx_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/coerce_reg_to_size_sx_full.goto

coerce_reg_to_size_sx_simple: coerce_reg_to_size_sx_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c coerce_reg_to_size_sx_verify.c -o $(BUILD_DIR)/coerce_reg_to_size_sx_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/coerce_reg_to_size_sx_simple.goto $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/coerce_reg_to_size_sx_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/coerce_reg_to_size_sx_simple_full.goto

# scalar_min_max_add verification targets
$(BUILD_DIR)/scalar_min_max_add_verify.goto: scalar_min_max_add_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building scalar_min_max_add verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c scalar_min_max_add_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar_min_max_add_full.goto

scalar_min_max_add_verify: $(BUILD_DIR)/scalar_min_max_add_verify.goto
	@echo "$(GREEN)Running CBMC verification for scalar_min_max_add...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_add_full.goto

scalar_min_max_add_trace: $(BUILD_DIR)/scalar_min_max_add_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_add_full.goto

scalar_min_max_add_simple: scalar_min_max_add_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c scalar_min_max_add_verify.c -o $(BUILD_DIR)/scalar_min_max_add_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/scalar_min_max_add_simple.goto $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar_min_max_add_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_add_simple_full.goto

# scalar32_min_max_add verification targets
$(BUILD_DIR)/scalar32_min_max_add_verify.goto: scalar32_min_max_add_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building scalar32_min_max_add verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c scalar32_min_max_add_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar32_min_max_add_full.goto

scalar32_min_max_add_verify: $(BUILD_DIR)/scalar32_min_max_add_verify.goto
	@echo "$(GREEN)Running CBMC verification for scalar32_min_max_add...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_add_full.goto

scalar32_min_max_add_trace: $(BUILD_DIR)/scalar32_min_max_add_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_add_full.goto

scalar32_min_max_add_simple: scalar32_min_max_add_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c scalar32_min_max_add_verify.c -o $(BUILD_DIR)/scalar32_min_max_add_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/scalar32_min_max_add_simple.goto $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar32_min_max_add_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_add_simple_full.goto

# scalar_min_max_sub verification targets
$(BUILD_DIR)/scalar_min_max_sub_verify.goto: scalar_min_max_sub_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building scalar_min_max_sub verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c scalar_min_max_sub_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar_min_max_sub_full.goto

scalar_min_max_sub_verify: $(BUILD_DIR)/scalar_min_max_sub_verify.goto
	@echo "$(GREEN)Running CBMC verification for scalar_min_max_sub...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_sub_full.goto

scalar_min_max_sub_trace: $(BUILD_DIR)/scalar_min_max_sub_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_sub_full.goto

scalar_min_max_sub_simple: scalar_min_max_sub_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c scalar_min_max_sub_verify.c -o $(BUILD_DIR)/scalar_min_max_sub_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/scalar_min_max_sub_simple.goto $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar_min_max_sub_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_sub_simple_full.goto

# scalar32_min_max_sub verification targets
$(BUILD_DIR)/scalar32_min_max_sub_verify.goto: scalar32_min_max_sub_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building scalar32_min_max_sub verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c scalar32_min_max_sub_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar32_min_max_sub_full.goto

scalar32_min_max_sub_verify: $(BUILD_DIR)/scalar32_min_max_sub_verify.goto
	@echo "$(GREEN)Running CBMC verification for scalar32_min_max_sub...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_sub_full.goto

scalar32_min_max_sub_trace: $(BUILD_DIR)/scalar32_min_max_sub_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_sub_full.goto

scalar32_min_max_sub_simple: scalar32_min_max_sub_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c scalar32_min_max_sub_verify.c -o $(BUILD_DIR)/scalar32_min_max_sub_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/scalar32_min_max_sub_simple.goto $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar32_min_max_sub_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_sub_simple_full.goto

# scalar_min_max_mul verification targets
$(BUILD_DIR)/scalar_min_max_mul_verify.goto: scalar_min_max_mul_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building scalar_min_max_mul verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c scalar_min_max_mul_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar_min_max_mul_full.goto

scalar_min_max_mul_verify: $(BUILD_DIR)/scalar_min_max_mul_verify.goto
	@echo "$(GREEN)Running CBMC verification for scalar_min_max_mul...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_mul_full.goto

scalar_min_max_mul_trace: $(BUILD_DIR)/scalar_min_max_mul_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_mul_full.goto

scalar_min_max_mul_simple: scalar_min_max_mul_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c scalar_min_max_mul_verify.c -o $(BUILD_DIR)/scalar_min_max_mul_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/scalar_min_max_mul_simple.goto $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar_min_max_mul_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar_min_max_mul_simple_full.goto

# scalar32_min_max_mul verification targets
$(BUILD_DIR)/scalar32_min_max_mul_verify.goto: scalar32_min_max_mul_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building scalar32_min_max_mul verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c scalar32_min_max_mul_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar32_min_max_mul_full.goto

scalar32_min_max_mul_verify: $(BUILD_DIR)/scalar32_min_max_mul_verify.goto
	@echo "$(GREEN)Running CBMC verification for scalar32_min_max_mul...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_mul_full.goto

scalar32_min_max_mul_trace: $(BUILD_DIR)/scalar32_min_max_mul_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_mul_full.goto

scalar32_min_max_mul_simple: scalar32_min_max_mul_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c scalar32_min_max_mul_verify.c -o $(BUILD_DIR)/scalar32_min_max_mul_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/scalar32_min_max_mul_simple.goto $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/scalar32_min_max_mul_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/scalar32_min_max_mul_simple_full.goto

# tnum_add verification targets
$(BUILD_DIR)/tnum_add_verify.goto: tnum_add_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_add verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_add_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_add_full.goto

tnum_add_verify: $(BUILD_DIR)/tnum_add_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_add...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_add_full.goto

tnum_add_trace: $(BUILD_DIR)/tnum_add_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_add_full.goto

tnum_add_simple: tnum_add_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_add_verify.c -o $(BUILD_DIR)/tnum_add_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_add_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_add_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_add_simple_full.goto

# tnum_and verification targets
$(BUILD_DIR)/tnum_and_verify.goto: tnum_and_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_and verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_and_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_and_full.goto

tnum_and_verify: $(BUILD_DIR)/tnum_and_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_and...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_and_full.goto

tnum_and_trace: $(BUILD_DIR)/tnum_and_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_and_full.goto

tnum_and_simple: tnum_and_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_and_verify.c -o $(BUILD_DIR)/tnum_and_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_and_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_and_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_and_simple_full.goto

# tnum_lshift verification targets
$(BUILD_DIR)/tnum_lshift_verify.goto: tnum_lshift_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_lshift verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_lshift_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_lshift_full.goto

tnum_lshift_verify: $(BUILD_DIR)/tnum_lshift_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_lshift...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_lshift_full.goto

tnum_lshift_trace: $(BUILD_DIR)/tnum_lshift_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_lshift_full.goto

tnum_lshift_simple: tnum_lshift_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_lshift_verify.c -o $(BUILD_DIR)/tnum_lshift_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_lshift_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_lshift_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_lshift_simple_full.goto

# tnum_rshift verification targets
$(BUILD_DIR)/tnum_rshift_verify.goto: tnum_rshift_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_rshift verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_rshift_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_rshift_full.goto

tnum_rshift_verify: $(BUILD_DIR)/tnum_rshift_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_rshift...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_rshift_full.goto

tnum_rshift_trace: $(BUILD_DIR)/tnum_rshift_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_rshift_full.goto

tnum_rshift_simple: tnum_rshift_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_rshift_verify.c -o $(BUILD_DIR)/tnum_rshift_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_rshift_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_rshift_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_rshift_simple_full.goto

# tnum_sub verification targets
$(BUILD_DIR)/tnum_sub_verify.goto: tnum_sub_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_sub verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_sub_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_sub_full.goto

tnum_sub_verify: $(BUILD_DIR)/tnum_sub_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_sub...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_sub_full.goto

tnum_sub_trace: $(BUILD_DIR)/tnum_sub_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_sub_full.goto

tnum_sub_simple: tnum_sub_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_sub_verify.c -o $(BUILD_DIR)/tnum_sub_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_sub_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_sub_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_sub_simple_full.goto

# tnum_or verification targets
$(BUILD_DIR)/tnum_or_verify.goto: tnum_or_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_or verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_or_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_or_full.goto

tnum_or_verify: $(BUILD_DIR)/tnum_or_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_or...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_or_full.goto

tnum_or_trace: $(BUILD_DIR)/tnum_or_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_or_full.goto

tnum_or_simple: tnum_or_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_or_verify.c -o $(BUILD_DIR)/tnum_or_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_or_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_or_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_or_simple_full.goto

# tnum_xor verification targets
$(BUILD_DIR)/tnum_xor_verify.goto: tnum_xor_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_xor verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_xor_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_xor_full.goto

tnum_xor_verify: $(BUILD_DIR)/tnum_xor_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_xor...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_xor_full.goto

tnum_xor_trace: $(BUILD_DIR)/tnum_xor_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_xor_full.goto

tnum_xor_simple: tnum_xor_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_xor_verify.c -o $(BUILD_DIR)/tnum_xor_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_xor_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_xor_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_xor_simple_full.goto

# tnum_mul verification targets
$(BUILD_DIR)/tnum_mul_verify.goto: tnum_mul_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_mul verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_mul_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_mul_full.goto

tnum_mul_verify: $(BUILD_DIR)/tnum_mul_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_mul...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_mul_full.goto

tnum_mul_trace: $(BUILD_DIR)/tnum_mul_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_mul_full.goto

tnum_mul_simple: tnum_mul_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_mul_verify.c -o $(BUILD_DIR)/tnum_mul_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_mul_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_mul_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_mul_simple_full.goto

# tnum_neg verification targets
$(BUILD_DIR)/tnum_neg_verify.goto: tnum_neg_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_neg verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_neg_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_neg_full.goto

tnum_neg_verify: $(BUILD_DIR)/tnum_neg_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_neg...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_neg_full.goto

tnum_neg_trace: $(BUILD_DIR)/tnum_neg_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_neg_full.goto

tnum_neg_simple: tnum_neg_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_neg_verify.c -o $(BUILD_DIR)/tnum_neg_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_neg_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_neg_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_neg_simple_full.goto

# tnum_arshift verification targets
$(BUILD_DIR)/tnum_arshift_verify.goto: tnum_arshift_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_arshift verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_arshift_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_arshift_full.goto

tnum_arshift_verify: $(BUILD_DIR)/tnum_arshift_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_arshift...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_arshift_full.goto

tnum_arshift_trace: $(BUILD_DIR)/tnum_arshift_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_arshift_full.goto

tnum_arshift_simple: tnum_arshift_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_arshift_verify.c -o $(BUILD_DIR)/tnum_arshift_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_arshift_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_arshift_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_arshift_simple_full.goto

# tnum_union verification targets
$(BUILD_DIR)/tnum_union_verify.goto: tnum_union_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_union verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_union_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_union_full.goto

tnum_union_verify: $(BUILD_DIR)/tnum_union_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_union...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_union_full.goto

tnum_union_trace: $(BUILD_DIR)/tnum_union_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_union_full.goto

tnum_union_simple: tnum_union_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_union_verify.c -o $(BUILD_DIR)/tnum_union_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_union_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_union_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_union_simple_full.goto

# tnum_intersect verification targets
$(BUILD_DIR)/tnum_intersect_verify.goto: tnum_intersect_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_intersect verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_intersect_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_intersect_full.goto

tnum_intersect_verify: $(BUILD_DIR)/tnum_intersect_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_intersect...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_intersect_full.goto

tnum_intersect_trace: $(BUILD_DIR)/tnum_intersect_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_intersect_full.goto

tnum_intersect_simple: tnum_intersect_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_intersect_verify.c -o $(BUILD_DIR)/tnum_intersect_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_intersect_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_intersect_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_intersect_simple_full.goto

# tnum_range verification targets
$(BUILD_DIR)/tnum_range_verify.goto: tnum_range_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_range verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_range_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_range_full.goto

tnum_range_verify: $(BUILD_DIR)/tnum_range_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_range...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_range_full.goto

tnum_range_trace: $(BUILD_DIR)/tnum_range_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_range_full.goto

tnum_range_simple: tnum_range_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_range_verify.c -o $(BUILD_DIR)/tnum_range_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_range_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_range_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_range_simple_full.goto

# tnum_cast verification targets
$(BUILD_DIR)/tnum_cast_verify.goto: tnum_cast_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building tnum_cast verification harness...$(NC)"
	$(GOTO_CC) $(CFLAGS) -c tnum_cast_verify.c -o $@
	$(GOTO_CC) $@ $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_cast_full.goto

tnum_cast_verify: $(BUILD_DIR)/tnum_cast_verify.goto
	@echo "$(GREEN)Running CBMC verification for tnum_cast...$(NC)"
	@echo "This may take several minutes depending on complexity..."
	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/tnum_cast_full.goto

tnum_cast_trace: $(BUILD_DIR)/tnum_cast_verify.goto
	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_cast_full.goto

tnum_cast_simple: tnum_cast_verify.c $(BUILD_DIR)/verifier.goto
	@echo "$(YELLOW)Building with simplified constraints...$(NC)"
	$(GOTO_CC) $(CFLAGS) $(SIMPLE_FLAGS) -c tnum_cast_verify.c -o $(BUILD_DIR)/tnum_cast_simple.goto
	$(GOTO_CC) $(BUILD_DIR)/tnum_cast_simple.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/tnum_cast_simple_full.goto
	@echo "$(GREEN)Running CBMC with simplified constraints...$(NC)"
	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/tnum_cast_simple_full.goto

# Template for adding new verification targets
# Replace FUNCNAME with your function name
#
# $(BUILD_DIR)/FUNCNAME_verify.goto: FUNCNAME_verify.c $(BUILD_DIR)/verifier.goto
# 	@echo "$(YELLOW)Building FUNCNAME verification harness...$(NC)"
# 	$(GOTO_CC) $(CFLAGS) -c FUNCNAME_verify.c -o $@
# 	$(GOTO_CC) $@ $(BUILD_DIR)/verifier.goto $(BUILD_DIR)/tnum.goto -o $(BUILD_DIR)/FUNCNAME_full.goto
#
# FUNCNAME_verify: $(BUILD_DIR)/FUNCNAME_verify.goto
# 	@echo "$(GREEN)Running CBMC verification for FUNCNAME...$(NC)"
# 	$(CBMC) $(CBMC_FLAGS) --function main $(BUILD_DIR)/FUNCNAME_full.goto
#
# FUNCNAME_trace: $(BUILD_DIR)/FUNCNAME_verify.goto
# 	@echo "$(GREEN)Running CBMC with trace output...$(NC)"
# 	$(CBMC) $(CBMC_FLAGS) $(TRACE_FLAGS) --function main $(BUILD_DIR)/FUNCNAME_full.goto

clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf $(BUILD_DIR)
	@echo "$(GREEN)Clean complete$(NC)"

.PHONY: coerce_reg_to_size_sx_verify coerce_reg_to_size_sx_trace coerce_reg_to_size_sx_simple \
        scalar_min_max_add_verify scalar_min_max_add_trace scalar_min_max_add_simple \
        scalar32_min_max_add_verify scalar32_min_max_add_trace scalar32_min_max_add_simple \
        scalar_min_max_sub_verify scalar_min_max_sub_trace scalar_min_max_sub_simple \
        scalar32_min_max_sub_verify scalar32_min_max_sub_trace scalar32_min_max_sub_simple \
        scalar_min_max_mul_verify scalar_min_max_mul_trace scalar_min_max_mul_simple \
        scalar32_min_max_mul_verify scalar32_min_max_mul_trace scalar32_min_max_mul_simple \
        tnum_add_verify tnum_add_trace tnum_add_simple \
        tnum_sub_verify tnum_sub_trace tnum_sub_simple \
        tnum_mul_verify tnum_mul_trace tnum_mul_simple \
        tnum_neg_verify tnum_neg_trace tnum_neg_simple \
        tnum_and_verify tnum_and_trace tnum_and_simple \
        tnum_or_verify tnum_or_trace tnum_or_simple \
        tnum_xor_verify tnum_xor_trace tnum_xor_simple \
        tnum_lshift_verify tnum_lshift_trace tnum_lshift_simple \
        tnum_rshift_verify tnum_rshift_trace tnum_rshift_simple \
        tnum_arshift_verify tnum_arshift_trace tnum_arshift_simple \
        tnum_union_verify tnum_union_trace tnum_union_simple \
        tnum_intersect_verify tnum_intersect_trace tnum_intersect_simple \
        tnum_range_verify tnum_range_trace tnum_range_simple \
        tnum_cast_verify tnum_cast_trace tnum_cast_simple
