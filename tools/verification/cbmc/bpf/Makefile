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
          -I$(KERNEL_ROOT)/include/uapi \
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
	@echo "Available targets:"
	@echo "  coerce_reg_to_size_sx_verify - Verify sign extension tracking (unary op)"
	@echo "  scalar_min_max_add_verify    - Verify addition tracking (binary op)"
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
	@echo "  1. make coerce_reg_to_size_sx_verify   # Run verification"
	@echo "  2. If it fails:"
	@echo "     make coerce_reg_to_size_sx_trace    # Get counterexample"
	@echo "  3. If counterexample is complex:"
	@echo "     make coerce_reg_to_size_sx_simple   # Simplify for debugging"

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
        scalar_min_max_add_verify scalar_min_max_add_trace scalar_min_max_add_simple
