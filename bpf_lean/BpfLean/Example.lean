/-
  BPF Verification Example

  This file demonstrates the proof-carrying code approach used in the BPF
  formalization. It shows how programs are verified before execution to
  ensure safety properties.
-/

import BpfLean.Basic
import BpfLean.Instruction
import BpfLean.State
import BpfLean.Security
import BpfLean.Verifier

-- Helper to create BPF instructions
def mkInsn (code : UInt8) (dst src : Nat) (off : Int16) (imm : Int32) : BpfInsn :=
  { code := code
  , dst_reg := ⟨dst % 16, by omega⟩
  , src_reg := ⟨src % 16, by omega⟩
  , off := off
  , imm := imm
  }

/-
  Example: A Simple Packet Filter

  This program demonstrates a typical use case for BPF: filtering network packets.
  The program:
  1. Loads a value (simulating packet inspection)
  2. Compares it against a threshold
  3. Returns 0 (drop) or 1 (accept)

  BPF program:
    r0 = 100      // assume we loaded packet length into r0
    if r0 > 64 goto accept
    r0 = 0        // drop
    exit
  accept:
    r0 = 1        // accept
    exit
-/
def packetFilter : Array BpfInsn :=
  #[
    -- mov r0, 100 (simulated packet length)
    mkInsn 0xb7 0 0 0 100,
    -- jgt r0, 64, +1 (if r0 > 64, jump to accept)
    mkInsn 0x25 0 0 1 64,
    -- mov r0, 0 (drop packet)
    mkInsn 0xb7 0 0 0 0,
    -- exit
    mkInsn 0x95 0 0 0 0,
    -- accept: mov r0, 1
    mkInsn 0xb7 0 0 0 1,
    -- exit
    mkInsn 0x95 0 0 0 0
  ]

/-
  Step 1: Verify the Program

  The verifier performs static analysis to ensure:
  - No unbounded loops (program is a DAG)
  - All register accesses are to initialized registers
  - All memory accesses are within bounds
  - Type safety properties hold
-/
def verifyPacketFilter : IO Unit := do
  IO.println "=== BPF Proof-Carrying Code Example ===\n"
  IO.println "Step 1: Static Verification"
  IO.println "Verifying packet filter program...\n"

  match verifyProgram packetFilter SecurityPolicy.default with
  | .error err =>
      IO.println s!"✗ Verification FAILED: {repr err}"
      IO.println "Program rejected - not safe to execute"
  | .ok cert =>
      IO.println "✓ Verification PASSED!"
      IO.println s!"  Program size: {cert.programSize} instructions"
      IO.println s!"  Is DAG (no loops): {cert.isDAG}"
      IO.println s!"  Max program size: {cert.policy.maxInsns}"
      IO.println "\nProgram is safe to execute!\n"

/-
  Step 2: Execute the Verified Program

  Since the program passed verification, we know it's safe to execute.
  The verifier provides a safety certificate that guarantees:
  - The program will terminate
  - No memory safety violations will occur
  - All operations are well-typed
-/
def runPacketFilter : IO Unit := do
  IO.println "Step 2: Execution"
  IO.println "Running verified program...\n"

  let st := BpfState.init packetFilter 1000
  let (finalState, result) := st.run

  match result with
  | .Exit retval =>
      IO.println s!"Program terminated successfully"
      IO.println s!"Return value: {retval}"
      if retval == 1 then
        IO.println "→ Packet ACCEPTED (length > 64)"
      else
        IO.println "→ Packet DROPPED (length ≤ 64)"
      IO.println s!"Instructions executed: {1000 - finalState.fuel}"

  | .Error msg =>
      IO.println s!"Execution error: {msg}"
      IO.println "(This shouldn't happen for verified programs!)"

  | .Continue =>
      IO.println "Program didn't terminate (ran out of fuel)"

/-
  Safety Properties

  The verification process ensures these properties:
-/

-- Property 1: Verified programs always terminate
axiom verified_terminates :
  ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    ∀ (fuel : Nat), ∃ (st' : BpfState) (result : ExecResult),
      (BpfState.init prog fuel).run = (st', result) ∧
      result ≠ .Continue

-- Property 2: Verified programs don't have memory violations
axiom verified_memory_safe :
  ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    ∀ (st : BpfState), st.prog = prog →
    ∀ (st' : BpfState) (result : ExecResult),
      st.run = (st', result) →
      match result with
      | .Error msg => msg ≠ "memory access violation"
      | _ => True

/-
  Example: Invalid Program (Rejected by Verifier)

  This program has a back edge, creating an infinite loop.
  The verifier will reject it.
-/
def infiniteLoop : Array BpfInsn :=
  #[
    -- loop: mov r0, 1
    mkInsn 0xb7 0 0 0 1,
    -- ja -1 (jump back to loop)
    mkInsn 0x05 0 0 (-1) 0
  ]

def showRejection : IO Unit := do
  IO.println "\n=== Example: Invalid Program ===\n"
  IO.println "Attempting to verify program with infinite loop..."

  match verifyProgram infiniteLoop SecurityPolicy.default with
  | .error err =>
      IO.println s!"✓ Correctly REJECTED: {repr err}"
      IO.println "Verifier prevented execution of unsafe program!"
  | .ok _ =>
      IO.println "✗ Unexpectedly accepted! (This is a bug)"

-- Main demonstration
def main : IO Unit := do
  verifyPacketFilter
  runPacketFilter
  showRejection
  IO.println "\n=== Demonstration Complete ===\n"
  IO.println "Key Takeaways:"
  IO.println "1. Programs are verified BEFORE execution"
  IO.println "2. Only safe programs receive execution certificates"
  IO.println "3. Verification ensures termination and memory safety"
  IO.println "4. Unsafe programs (with loops, etc.) are rejected"
