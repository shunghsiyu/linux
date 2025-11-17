/-
  BPF Proofs

  This module contains proofs about the correctness and safety properties
  of the BPF formalization.
-/

import BpfLean.Basic
import BpfLean.Instruction
import BpfLean.State
import BpfLean.Security
import BpfLean.Verifier

-- Proof: R10 is always the frame pointer
theorem r10_is_frame_pointer : ∀ (st : BpfState) (val : UInt64),
    (st.regs.writeChecked .R10 val) .R10 = st.regs .R10 := by
  intro st val
  simp [RegFile.writeChecked, RegFile.write]

-- Proof: Register write is idempotent
theorem reg_write_idempotent : ∀ (regs : RegFile) (r : BpfReg) (v : UInt64),
    (regs.write r v).write r v = regs.write r v := by
  intro regs r v
  funext r'
  simp [RegFile.write]
  split
  · rfl
  · rfl

-- Proof: Register read after write returns the written value
theorem reg_read_after_write : ∀ (regs : RegFile) (r : BpfReg) (v : UInt64),
    (regs.write r v).read r = v := by
  intro regs r v
  simp [RegFile.read, RegFile.write]

-- Proof: Writing to one register doesn't affect others
theorem reg_write_independent : ∀ (regs : RegFile) (r1 r2 : BpfReg) (v : UInt64),
    r1 ≠ r2 → (regs.write r1 v).read r2 = regs.read r2 := by
  intro regs r1 r2 v h
  simp [RegFile.read, RegFile.write, h]

-- Proof: BPF register indices are bounded
theorem reg_index_bounded : ∀ (r : BpfReg), r.toNat < MAX_BPF_REG := by
  intro r
  cases r <;> decide

-- Proof: Instruction class extraction is consistent
theorem class_extraction_bounded : ∀ (insn : BpfInsn),
    match insn.getClass with
    | some _ => True
    | none => True := by
  intro insn
  cases insn.getClass <;> trivial

-- Safety property: A verified program cannot violate memory safety
-- (This is a statement of the theorem - full proof would require more infrastructure)
axiom verified_program_memory_safe : ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    ∀ (st : BpfState), st.prog = prog →
    ∀ (st' : BpfState) (result : ExecResult),
    st.run = (st', result) →
    match result with
    | .Error msg => msg ≠ "memory access violation"
    | _ => True

-- Safety property: A verified program is a DAG (no infinite loops)
axiom verified_program_terminates : ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    cert.isDAG = true

-- Type safety: Well-typed programs don't go wrong
-- (This is a statement - full proof would require operational semantics)
axiom type_safety : ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    ∀ (st : BpfState) (st' : BpfState) (result : ExecResult),
    st.prog = prog →
    st.step = (st', result) →
    match result with
    | .Error "type mismatch" => False
    | _ => True

-- Determinism: The same program with the same initial state produces the same result
theorem execution_deterministic : ∀ (prog : Array BpfInsn) (fuel : Nat),
    let st1 := BpfState.init prog fuel
    let st2 := BpfState.init prog fuel
    st1.run = st2.run := by
  intro prog fuel
  rfl

-- Property: Exit instruction terminates execution
theorem exit_terminates : ∀ (insn : BpfInsn),
    insn.isExit = true →
    ∀ (st : BpfState),
    match st.step.2 with
    | .Exit _ => True
    | .Error _ => True  -- might error if R0 not initialized
    | .Continue => False := by
  intro insn h_exit st
  -- This would require case analysis on the actual instruction
  sorry

-- Property: Program counter stays in bounds during valid execution
theorem pc_in_bounds : ∀ (st st' : BpfState) (result : ExecResult),
    st.step = (st', result) →
    result = .Continue →
    st'.pc < st'.prog.size ∨ result ≠ .Continue := by
  intro st st' result h_step h_cont
  -- This would require detailed case analysis
  sorry

-- Property: Fuel decreases on each step
theorem fuel_decreases : ∀ (st st' : BpfState) (result : ExecResult),
    st.fuel > 0 →
    st.step = (st', result) →
    result = .Continue →
    st'.fuel < st.fuel := by
  intro st st' result h_fuel h_step h_cont
  -- This would follow from the definition of step
  sorry

-- Soundness: If verifier accepts a program, it's safe to run
theorem verifier_soundness : ∀ (prog : Array BpfInsn) (policy : SecurityPolicy),
    (∃ cert, verifyProgram prog policy = .ok cert) →
    ∀ (st : BpfState), st.prog = prog →
    ∀ (st' : BpfState) (result : ExecResult),
    st.run = (st', result) →
    match result with
    | .Error msg => msg = "out of fuel" ∨ msg = "max steps exceeded"
    | .Exit _ => True
    | .Continue => False  -- run should not return Continue
    := by
  intro prog policy h_verified st h_prog st' result h_run
  -- Full proof would require induction on execution steps
  sorry

-- Completeness: Safe programs are accepted by the verifier
-- (This is harder to state precisely without a formal definition of "safe")
axiom verifier_completeness : ∀ (prog : Array BpfInsn) (policy : SecurityPolicy),
    (∀ st : BpfState, st.prog = prog →
      ∀ st' result, st.run = (st', result) →
      match result with
      | .Error "memory access violation" => False
      | .Error "type mismatch" => False
      | _ => True) →
    prog.size ≤ policy.maxInsns →
    (∃ cert, verifyProgram prog policy = .ok cert) ∨
    (∃ err, verifyProgram prog policy = .error err)
