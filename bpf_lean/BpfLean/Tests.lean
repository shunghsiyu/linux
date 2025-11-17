/-
  BPF Tests and Examples

  This module contains test cases and example programs to verify
  the correctness of the BPF formalization.
-/

import BpfLean.Basic
import BpfLean.Instruction
import BpfLean.State
import BpfLean.Security
import BpfLean.Verifier

-- Helper function to create a simple instruction
def mkInsn (code : UInt8) (dst src : Nat) (off : Int16) (imm : Int32) : BpfInsn :=
  { code := code
  , dst_reg := ⟨dst % 16, by omega⟩
  , src_reg := ⟨src % 16, by omega⟩
  , off := off
  , imm := imm
  }

-- Example 1: Simple program that returns a constant
-- r0 = 42
-- exit
def exampleProgram1 : Array BpfInsn :=
  #[
    -- MOV64 r0, 42 (ALU64 | MOV | K)
    mkInsn 0xb7 0 0 0 42,
    -- EXIT (JMP | EXIT)
    mkInsn 0x95 0 0 0 0
  ]

-- Test: verify and run example program 1
def testExample1 : IO Unit := do
  IO.println "Testing example program 1: return 42"
  match verifyAndRun exampleProgram1 with
  | .error err =>
      IO.println s!"Verification failed: {repr err}"
  | .ok (finalState, result) =>
      match result with
      | .Exit retval =>
          IO.println s!"Program exited with value: {retval}"
          if retval == 42 then
            IO.println "✓ Test passed!"
          else
            IO.println "✗ Test failed: expected 42"
      | .Error msg =>
          IO.println s!"Execution error: {msg}"
      | .Continue =>
          IO.println "Unexpected: program still running"

-- Example 2: Program with arithmetic
-- r0 = 10
-- r0 += 5
-- r0 *= 2
-- exit
def exampleProgram2 : Array BpfInsn :=
  #[
    -- MOV64 r0, 10
    mkInsn 0xb7 0 0 0 10,
    -- ADD64 r0, 5
    mkInsn 0x07 0 0 0 5,
    -- MUL64 r0, 2
    mkInsn 0x27 0 0 0 2,
    -- EXIT
    mkInsn 0x95 0 0 0 0
  ]

def testExample2 : IO Unit := do
  IO.println "\nTesting example program 2: (10 + 5) * 2 = 30"
  match verifyAndRun exampleProgram2 with
  | .error err =>
      IO.println s!"Verification failed: {repr err}"
  | .ok (finalState, result) =>
      match result with
      | .Exit retval =>
          IO.println s!"Program exited with value: {retval}"
          if retval == 30 then
            IO.println "✓ Test passed!"
          else
            IO.println "✗ Test failed: expected 30"
      | .Error msg =>
          IO.println s!"Execution error: {msg}"
      | .Continue =>
          IO.println "Unexpected: program still running"

-- Example 3: Program with conditional jump
-- r0 = 5
-- r1 = 10
-- if r0 < r1 goto +1
-- r0 = 0
-- exit
def exampleProgram3 : Array BpfInsn :=
  #[
    -- MOV64 r0, 5
    mkInsn 0xb7 0 0 0 5,
    -- MOV64 r1, 10
    mkInsn 0xb7 1 0 0 10,
    -- JLT r0, r1, +1 (JMP | JLT | X)
    mkInsn 0xad 0 1 1 0,
    -- MOV64 r0, 0
    mkInsn 0xb7 0 0 0 0,
    -- EXIT
    mkInsn 0x95 0 0 0 0
  ]

def testExample3 : IO Unit := do
  IO.println "\nTesting example program 3: conditional jump"
  match verifyAndRun exampleProgram3 with
  | .error err =>
      IO.println s!"Verification failed: {repr err}"
  | .ok (finalState, result) =>
      match result with
      | .Exit retval =>
          IO.println s!"Program exited with value: {retval}"
          if retval == 5 then
            IO.println "✓ Test passed! (jump was taken)"
          else
            IO.println "✗ Test failed: expected 5"
      | .Error msg =>
          IO.println s!"Execution error: {msg}"
      | .Continue =>
          IO.println "Unexpected: program still running"

-- Example 4: Invalid program with uninitialized register
-- r0 = r5  (r5 is not initialized)
-- exit
def invalidProgram1 : Array BpfInsn :=
  #[
    -- MOV64 r0, r5 (ALU64 | MOV | X)
    mkInsn 0xbf 0 5 0 0,
    -- EXIT
    mkInsn 0x95 0 0 0 0
  ]

def testInvalid1 : IO Unit := do
  IO.println "\nTesting invalid program 1: uninitialized register"
  match verifyAndRun invalidProgram1 with
  | .error err =>
      IO.println s!"✓ Correctly rejected: {repr err}"
  | .ok _ =>
      IO.println "✗ Test failed: should have been rejected!"

-- Example 5: Program that creates a back edge (loop)
-- This should be rejected by the verifier
def invalidProgram2 : Array BpfInsn :=
  #[
    -- MOV64 r0, 0
    mkInsn 0xb7 0 0 0 0,
    -- JA -1 (jump back to previous instruction - creates a loop)
    mkInsn 0x05 0 0 (-1) 0
  ]

def testInvalid2 : IO Unit := do
  IO.println "\nTesting invalid program 2: back edge (loop)"
  match verifyAndRun invalidProgram2 with
  | .error err =>
      IO.println s!"✓ Correctly rejected: {repr err}"
  | .ok _ =>
      IO.println "✗ Test failed: should have been rejected!"

-- Run all tests
def main : IO Unit := do
  IO.println "=== BPF Formalization Tests ===\n"
  testExample1
  testExample2
  testExample3
  testInvalid1
  testInvalid2
  IO.println "\n=== Tests Complete ==="
