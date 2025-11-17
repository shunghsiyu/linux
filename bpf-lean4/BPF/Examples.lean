/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Realistic Examples

This module contains realistic BPF programs demonstrating practical use cases
such as packet filtering, system call filtering, and performance monitoring.
-/

import BPF.Core
import BPF.State
import BPF.Security
import BPF.Verifier

namespace BPF

/-! ## Packet Filtering Examples -/

/-- Simple packet length filter

    This program filters packets based on length:
    - Accept packets > 64 bytes
    - Reject packets <= 64 bytes

    Pseudo-C code:
    ```c
    if (ctx->len > 64)
        return 1;  // accept
    else
        return 0;  // reject
    ```
-/
def packetLengthFilter : Array Insn :=
  #[
    -- Load packet length from context (R1) into R0
    -- Assume ctx->len is at offset 0 for simplicity
    Insn.ldx MemSize.W Reg.R0 Reg.R1 0,

    -- Compare with 64
    Insn.movImm Reg.R2 64,
    Insn.jgt Reg.R0 Reg.R2 1,  -- if R0 > 64, skip next insn

    -- Reject: return 0
    Insn.movImm Reg.R0 0,
    Insn.exit,

    -- Accept: return 1
    Insn.movImm Reg.R0 1,
    Insn.exit
  ]

/-- Verify the packet length filter -/
def verifyPacketLengthFilter : Bool :=
  match verifyProgram packetLengthFilter with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Stack Usage Example -/

/-- Program demonstrating proper stack usage

    This program:
    1. Gets frame pointer (R10)
    2. Calculates stack slot address
    3. Stores a value to stack
    4. Loads it back
    5. Returns the value

    This demonstrates the pattern used in real BPF programs
    for temporary storage.
-/
def stackUsageExample : Array Insn :=
  #[
    -- R2 = R10 (frame pointer)
    Insn.mov Reg.R2 Reg.R10,

    -- R2 += -8 (stack slot at FP-8)
    Insn.addImm Reg.R2 (-8),

    -- Store immediate 42 to stack
    -- *(u64*)(R2) = 42
    Insn.movImm Reg.R3 42,
    Insn.stx MemSize.DW Reg.R2 Reg.R3 0,

    -- Load from stack
    -- R0 = *(u64*)(R2)
    Insn.ldx MemSize.DW Reg.R0 Reg.R2 0,

    -- Return R0
    Insn.exit
  ]

/-- Verify stack usage example -/
def verifyStackUsage : Bool :=
  match verifyProgram stackUsageExample with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Multiple Stack Slots Example -/

/-- Program using multiple stack slots

    Demonstrates using multiple stack variables:
    - slot1 at FP-8
    - slot2 at FP-16
-/
def multiStackExample : Array Insn :=
  #[
    -- Setup R2 = FP - 8 (slot 1)
    Insn.mov Reg.R2 Reg.R10,
    Insn.addImm Reg.R2 (-8),

    -- Setup R3 = FP - 16 (slot 2)
    Insn.mov Reg.R3 Reg.R10,
    Insn.addImm Reg.R3 (-16),

    -- Store 10 to slot1
    Insn.movImm Reg.R4 10,
    Insn.stx MemSize.DW Reg.R2 Reg.R4 0,

    -- Store 32 to slot2
    Insn.movImm Reg.R4 32,
    Insn.stx MemSize.DW Reg.R3 Reg.R4 0,

    -- Load from slot1 into R0
    Insn.ldx MemSize.DW Reg.R0 Reg.R2 0,

    -- Load from slot2 into R5
    Insn.ldx MemSize.DW Reg.R5 Reg.R3 0,

    -- R0 = R0 + R5 (should be 42)
    Insn.add Reg.R0 Reg.R5,

    -- Return
    Insn.exit
  ]

/-- Verify multi-stack example -/
def verifyMultiStack : Bool :=
  match verifyProgram multiStackExample with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Bit Manipulation Example -/

/-- Extract protocol field from packet header

    This demonstrates bit manipulation commonly used
    in packet processing to extract protocol fields.

    Example: Extract 4-bit field from position
-/
def extractProtocolField : Array Insn :=
  #[
    -- Load header word from context
    Insn.ldx MemSize.W Reg.R0 Reg.R1 0,

    -- Mask to extract bits [4:7]
    Insn.movImm Reg.R2 0xF0,
    Insn.and Reg.R0 Reg.R2,

    -- Shift right to get value
    Insn.movImm Reg.R3 4,
    Insn.rsh Reg.R0 Reg.R3,

    -- Return extracted value
    Insn.exit
  ]

/-- Verify protocol field extraction -/
def verifyExtractProtocol : Bool :=
  match verifyProgram extractProtocolField with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Comprehensive Test Suite -/

/-- Run all realistic example tests -/
def testRealisticExamples : IO Unit := do
  IO.println "Testing realistic BPF examples..."
  IO.println ""

  -- Test packet length filter
  if verifyPacketLengthFilter then
    IO.println "  ✓ Packet length filter verifies"
  else
    IO.println "  ✗ Packet length filter failed"

  -- Test stack usage
  if verifyStackUsage then
    IO.println "  ✓ Stack usage example verifies"
  else
    IO.println "  ✗ Stack usage example failed"

  -- Test multi-stack
  if verifyMultiStack then
    IO.println "  ✓ Multi-stack example verifies"
  else
    IO.println "  ✗ Multi-stack example failed"

  -- Test protocol extraction
  if verifyExtractProtocol then
    IO.println "  ✓ Protocol extraction verifies"
  else
    IO.println "  ✗ Protocol extraction failed"

  IO.println ""

/-! ## Example Execution -/

/-- Execute the stack usage example and show result -/
def runStackExample : IO Unit := do
  IO.println "=== Stack Usage Example ==="
  IO.println ""

  match certifyProgram stackUsageExample with
  | some cp => do
    IO.println "✓ Program certified"
    let result := cp.execute 100
    IO.println s!"Executed: halted = {result.halted}"
    IO.println s!"Final R0 = {(result.getReg Reg.R0).value}"
    IO.println "Expected: R0 = 42"
  | none =>
    IO.println "✗ Certification failed"

/-! ## Documentation -/

/--
These examples demonstrate common BPF programming patterns:

1. **Packet Filtering**: Making decisions based on packet data
   - Load packet metadata
   - Compare values
   - Conditional returns

2. **Stack Usage**: Using stack for temporary storage
   - Frame pointer manipulation
   - Stack offset calculation
   - Load/store operations

3. **Bit Manipulation**: Extract fields from packed data
   - Masking
   - Shifting
   - Common in protocol parsing

All examples follow BPF safety requirements:
- Bounded execution (no loops)
- All register reads from initialized registers
- All memory accesses within bounds
- All paths end with EXIT
-/

end BPF
