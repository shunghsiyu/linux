/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Demonstration

This file demonstrates the key features of the BPF verification system.
-/

import BPF

open BPF

/-! ## Example 1: Simple Valid Program -/

def example1 : IO Unit := do
  IO.println "=== Example 1: Simple Valid Program ==="
  IO.println ""

  -- Create program: MOV R0, 42; EXIT
  let prog := #[Insn.movImm Reg.R0 42, Insn.exit]

  IO.println "Program:"
  IO.println "  MOV R0, 42"
  IO.println "  EXIT"
  IO.println ""

  -- Verify
  let result := verifyProgram prog
  IO.println s!"Verification: {formatVerifyResult result}"
  IO.println ""

  -- Certify and execute
  match certifyProgram prog with
  | some cp => do
    IO.println "✓ Program certified"
    let finalState := cp.execute 100
    IO.println s!"Executed: R0 = {(finalState.getReg Reg.R0).value}"
  | none =>
    IO.println "✗ Certification failed"

  IO.println ""

/-! ## Example 2: Invalid Program (Uninitialized Read) -/

def example2 : IO Unit := do
  IO.println "=== Example 2: Invalid Program (Uninitialized Read) ==="
  IO.println ""

  -- Create program with uninitialized read
  let prog := #[Insn.add Reg.R0 Reg.R2, Insn.exit]

  IO.println "Program:"
  IO.println "  ADD R0, R2  // R0 and R2 not initialized!"
  IO.println "  EXIT"
  IO.println ""

  -- Verify
  let result := verifyProgram prog
  IO.println s!"Verification: {formatVerifyResult result}"
  IO.println ""

/-! ## Example 3: Register Operations -/

def example3 : IO Unit := do
  IO.println "=== Example 3: Register Operations ==="
  IO.println ""

  -- Program: Use initialized R1 (context pointer)
  let prog := #[
    Insn.mov Reg.R0 Reg.R1,    -- R1 is initialized as context
    Insn.add Reg.R0 Reg.R1,    -- Add R1 to R0
    Insn.exit
  ]

  IO.println "Program:"
  IO.println "  MOV R0, R1  // R1 contains context pointer"
  IO.println "  ADD R0, R1"
  IO.println "  EXIT"
  IO.println ""

  -- Verify
  let result := verifyProgram prog
  IO.println s!"Verification: {formatVerifyResult result}"
  IO.println ""

/-! ## Example 4: Size Limit Violation -/

def example4 : IO Unit := do
  IO.println "=== Example 4: Size Limit Violation ==="
  IO.println ""

  -- Create program that's too large
  let prog := Array.mkArray (MAX_INSNS + 1) Insn.exit

  IO.println s!"Program: {prog.size} instructions (max: {MAX_INSNS})"
  IO.println ""

  -- Verify
  let result := verifyProgram prog
  IO.println s!"Verification: {formatVerifyResult result}"
  IO.println ""

/-! ## Example 5: Abstract Interpretation -/

def example5 : IO Unit := do
  IO.println "=== Example 5: Abstract Interpretation ==="
  IO.println ""

  -- Demonstrate abstract interpretation of register values
  let r1 := RegState.scalar 10
  let r2 := RegState.scalar 32
  let result := abstractAdd r1 r2

  IO.println "Abstract Interpretation:"
  IO.println s!"  R1 = 10 (scalar)"
  IO.println s!"  R2 = 32 (scalar)"
  IO.println s!"  R1 + R2 = {result.value} (abstract add)"
  IO.println s!"  Type: {repr result.regType}"
  IO.println s!"  Bounds: [{result.umin}, {result.umax}]"
  IO.println ""

/-! ## Example 6: Security Policy -/

def example6 : IO Unit := do
  IO.println "=== Example 6: Security Policy Checks ==="
  IO.println ""

  -- Test various security checks
  IO.println "Stack bounds checks:"

  let valid := checkStackBounds 256
  IO.println s!"  Offset 256: {if valid.isSafe then "✓ Safe" else "✗ Unsafe"}"

  let overflow := checkStackBounds 1000
  IO.println s!"  Offset 1000: {if overflow.isSafe then "✓ Safe" else "✗ Unsafe"}"

  IO.println ""

/-! ## Example 7: Type System -/

def example7 : IO Unit := do
  IO.println "=== Example 7: Type System ==="
  IO.println ""

  IO.println "Register types:"
  let scalar := RegState.scalar 42
  IO.println s!"  Scalar value: isScalar={scalar.isScalar}, isPtr={scalar.isPtr}"

  let ptr := RegState.ptrToStack (-8)
  IO.println s!"  Pointer to stack: isScalar={ptr.isScalar}, isPtr={ptr.isPtr}"

  IO.println ""

/-! ## Example 8: Tri-state Numbers -/

def example8 : IO Unit := do
  IO.println "=== Example 8: Tri-state Number Analysis ==="
  IO.println ""

  let const42 := TNum.const 42
  let unknown := TNum.unknown

  IO.println "TNum operations:"
  IO.println s!"  const(42): isConst={const42.isConst}, value={repr const42.getConst?}"
  IO.println s!"  unknown: isConst={unknown.isConst}"

  let and_result := (TNum.const 0xFF).and (TNum.const 0x0F)
  IO.println s!"  0xFF AND 0x0F = {repr and_result.getConst?}"

  IO.println ""

/-! ## Main Demo -/

def main : IO Unit := do
  IO.println "╔════════════════════════════════════════════════╗"
  IO.println "║   BPF Verification in Lean 4 - Demonstration  ║"
  IO.println "╚════════════════════════════════════════════════╝"
  IO.println ""

  example1
  example2
  example3
  example4
  example5
  example6
  example7
  example8

  IO.println "╔════════════════════════════════════════════════╗"
  IO.println "║              Demo Complete                     ║"
  IO.println "╚════════════════════════════════════════════════╝"
