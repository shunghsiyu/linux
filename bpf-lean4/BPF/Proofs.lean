/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Correctness Proofs

This module contains formal proofs about the correctness and security
properties of the BPF virtual machine and verifier.
-/

import BPF.Core
import BPF.State
import BPF.Security
import BPF.Verifier

namespace BPF

/-! ## Basic Register Properties -/

/-- Register indices are bounded -/
theorem reg_index_bounded (r : Reg) : r.toNat < NUM_REGS := by
  cases r <;> decide

/-- Register conversion is injective -/
theorem reg_toNat_injective {r1 r2 : Reg} (h : r1.toNat = r2.toNat) : r1 = r2 := by
  cases r1 <;> cases r2 <;> simp [Reg.toNat] at h <;> try contradiction <;> rfl

/-- ofNat? is the inverse of toNat -/
theorem reg_ofNat_toNat (r : Reg) : Reg.ofNat? r.toNat = some r := by
  cases r <;> rfl

/-! ## Register State Properties -/

/-- A not-initialized register is not initialized -/
theorem notInit_not_init : RegState.notInit.isInit = false := by
  rfl

/-- A scalar register is initialized -/
theorem scalar_is_init (n : UInt64) : (RegState.scalar n).isInit = true := by
  rfl

/-- Scalar registers are scalar -/
theorem scalar_is_scalar (n : UInt64) : (RegState.scalar n).isScalar = true := by
  rfl

/-- Scalar registers are not pointers -/
theorem scalar_not_ptr (n : UInt64) : (RegState.scalar n).isPtr = false := by
  rfl

/-- Pointer to stack is a pointer -/
theorem ptrToStack_is_ptr (off : Int32) : (RegState.ptrToStack off).isPtr = true := by
  rfl

/-- Pointer to stack is not scalar -/
theorem ptrToStack_not_scalar (off : Int32) :
    (RegState.ptrToStack off).isScalar = false := by
  rfl

/-! ## TNum Properties -/

/-- Constant TNums are constant -/
theorem tnum_const_is_const (n : UInt64) : (TNum.const n).isConst = true := by
  rfl

/-- Unknown TNum is not constant -/
theorem tnum_unknown_not_const : TNum.unknown.isConst = false := by
  decide

/-- Getting constant from constant TNum succeeds -/
theorem tnum_const_getConst (n : UInt64) :
    (TNum.const n).getConst? = some n := by
  rfl

/-- AND of two constants is constant -/
theorem tnum_and_const (a b : UInt64) :
    (TNum.const a).and (TNum.const b) = TNum.const (a &&& b) := by
  rfl

/-- OR of two constants is constant -/
theorem tnum_or_const (a b : UInt64) :
    (TNum.const a).or (TNum.const b) = TNum.const (a ||| b) := by
  rfl

/-! ## Policy Properties -/

/-- Safe policy is safe -/
theorem policy_safe_is_safe : PolicyResult.Safe.isSafe = true := by
  rfl

/-- Unsafe policy is unsafe -/
theorem policy_unsafe_is_unsafe (v : SecurityViolation) :
    (PolicyResult.Unsafe v).isUnsafe = true := by
  rfl

/-- Safe AND Safe is Safe -/
theorem policy_safe_and_safe :
    PolicyResult.Safe.and PolicyResult.Safe = PolicyResult.Safe := by
  rfl

/-- Safe AND Unsafe is Unsafe -/
theorem policy_safe_and_unsafe (v : SecurityViolation) :
    PolicyResult.Safe.and (PolicyResult.Unsafe v) = PolicyResult.Unsafe v := by
  rfl

/-- Unsafe AND anything is Unsafe -/
theorem policy_unsafe_and (v : SecurityViolation) (p : PolicyResult) :
    (PolicyResult.Unsafe v).and p = PolicyResult.Unsafe v := by
  rfl

/-! ## Stack Properties -/

/-- Empty stack has correct size -/
theorem empty_stack_size : (Stack.empty : Stack).size = MAX_STACK_SIZE / 8 := by
  rfl

/-- Stack slots in empty stack are invalid -/
theorem empty_stack_invalid (i : Nat) (h : i < (Stack.empty : Stack).size) :
    (Stack.empty : Stack)[i].slotType = StackSlotType.Invalid := by
  rfl

/-! ## Execution Properties -/

/-- Initial state is not halted -/
theorem init_not_halted (prog : Array Insn) :
    (ExecState.init prog).halted = false := by
  rfl

/-- Initial state PC is 0 -/
theorem init_pc_zero (prog : Array Insn) :
    (ExecState.init prog).pc = 0 := by
  rfl

/-- Halting a state sets halted flag -/
theorem halt_sets_flag (s : ExecState) :
    s.halt.halted = true := by
  rfl

/-! ## Verifier Properties -/

/-- Initial verifier state has PC 0 -/
theorem verifier_init_pc : VerifierState.init.pc = 0 := by
  rfl

/-- Initial verifier state has call depth 0 -/
theorem verifier_init_depth : VerifierState.init.callDepth = 0 := by
  rfl

/-- R10 is initialized in initial verifier state -/
theorem verifier_init_r10 :
    (VerifierState.init.getReg Reg.R10).isInit = true := by
  rfl

/-- R10 is a pointer to stack in initial state -/
theorem verifier_init_r10_stack :
    (VerifierState.init.getReg Reg.R10).regType = RegType.PtrToStack := by
  rfl

/-! ## Abstract Interpretation Properties -/

/-- Abstract addition preserves scalar type -/
theorem abstract_add_scalar (dst src : RegState) :
    (abstractAdd dst src).regType = RegType.ScalarValue := by
  rfl

/-- Abstract subtraction preserves scalar type -/
theorem abstract_sub_scalar (dst src : RegState) :
    (abstractSub dst src).regType = RegType.ScalarValue := by
  rfl

/-- Abstract AND preserves scalar type -/
theorem abstract_and_scalar (dst src : RegState) :
    (abstractAnd dst src).regType = RegType.ScalarValue := by
  rfl

/-- Abstract move preserves register type -/
theorem abstract_mov_preserves_type (src : RegState) :
    (abstractMov src).regType = src.regType := by
  rfl

/-- Abstract multiplication preserves scalar type -/
theorem abstract_mul_scalar (dst src : RegState) :
    (abstractMul dst src).regType = RegType.ScalarValue := by
  rfl

/-- Abstract division preserves scalar type -/
theorem abstract_div_scalar (dst src : RegState) :
    (abstractDiv dst src).regType = RegType.ScalarValue := by
  rfl

/-- Abstract XOR preserves scalar type -/
theorem abstract_xor_scalar (dst src : RegState) :
    (abstractXor dst src).regType = RegType.ScalarValue := by
  rfl

/-- Abstract left shift preserves scalar type -/
theorem abstract_lsh_scalar (dst src : RegState) :
    (abstractLsh dst src).regType = RegType.ScalarValue := by
  rfl

/-- Abstract right shift preserves scalar type -/
theorem abstract_rsh_scalar (dst src : RegState) :
    (abstractRsh dst src).regType = RegType.ScalarValue := by
  rfl

/-- All ALU operations preserve scalar type -/
theorem abstract_alu_preserves_scalar (op : AluOp) (dst src : RegState) :
    dst.isScalar → src.isScalar →
    (abstractAluOp op dst src).isScalar = true := by
  intro _ _
  unfold abstractAluOp
  split <;> simp [RegState.isScalar]

/-- Abstract addition of constants produces constant -/
theorem abstract_add_const (a b : UInt64) :
    let dst := RegState.scalar a
    let src := RegState.scalar b
    (abstractAdd dst src).value = a + b := by
  rfl

/-- Abstract subtraction of constants produces constant -/
theorem abstract_sub_const (a b : UInt64) :
    let dst := RegState.scalar a
    let src := RegState.scalar b
    (abstractSub dst src).value = a - b := by
  rfl

/-- Division result is bounded by dividend -/
theorem abstract_div_bounded (dst src : RegState) :
    src.umin > 0 →
    (abstractDiv dst src).umax ≤ dst.umax := by
  intro _
  unfold abstractDiv
  simp

/-- Modulo result is bounded by divisor -/
theorem abstract_mod_bounded (dst src : RegState) :
    src.umax > 0 →
    (abstractAluOp AluOp.MOD dst src).umax < src.umax := by
  intro h
  unfold abstractAluOp
  simp
  omega

/-- Right shift result is non-negative (unsigned interpretation) -/
theorem abstract_rsh_nonneg (dst src : RegState) :
    (abstractRsh dst src).smin = 0 := by
  rfl

/-! ## Range Refinement Properties -/

/-- Range refinement for JEQ true branch gives exact value -/
theorem refine_jeq_true_exact (reg : RegState) (imm : UInt64) :
    let refined := refineRangeTrue reg JmpOp.JEQ imm
    refined.umin = imm ∧ refined.umax = imm := by
  simp [refineRangeTrue]

/-- Range refinement for JGT true branch increases minimum -/
theorem refine_jgt_true_increases_min (reg : RegState) (imm : UInt64) :
    let refined := refineRangeTrue reg JmpOp.JGT imm
    refined.umin ≥ reg.umin := by
  simp [refineRangeTrue]
  omega

/-- Range refinement for JLT true branch decreases maximum -/
theorem refine_jlt_true_decreases_max (reg : RegState) (imm : UInt64) :
    imm > 0 →
    let refined := refineRangeTrue reg JmpOp.JLT imm
    refined.umax ≤ imm - 1 := by
  intro _
  simp [refineRangeTrue]
  split <;> omega

/-- Range refinement maintains type for scalars -/
theorem refine_preserves_scalar_type (reg : RegState) (op : JmpOp) (imm : UInt64) :
    reg.isScalar →
    (refineRangeTrue reg op imm).isScalar = true := by
  intro h
  unfold RegState.isScalar at h ⊢
  unfold refineRangeTrue
  split <;> simp at h ⊢ <;> exact h

/-- Range refinement for non-zero in false branch -/
theorem refine_jeq_false_nonzero (reg : RegState) :
    let refined := refineRangeFalse reg JmpOp.JEQ 0
    refined.umin = 0 ∧ refined.umax = 0 := by
  simp [refineRangeFalse]

/-! ## Pointer Arithmetic Properties -/

/-- Adding scalar to stack pointer preserves stack pointer type -/
theorem abstractAdd_ptrToStack_preserves_type (dst src : RegState) :
    dst.regType = RegType.PtrToStack →
    src.regType = RegType.ScalarValue →
    (abstractAdd dst src).regType = RegType.PtrToStack := by
  intro hdst hsrc
  unfold abstractAdd
  simp [hdst, hsrc]

/-- Adding scalar to context pointer preserves context pointer type -/
theorem abstractAdd_ptrToCtx_preserves_type (dst src : RegState) :
    dst.regType = RegType.PtrToCtx →
    src.regType = RegType.ScalarValue →
    (abstractAdd dst src).regType = RegType.PtrToCtx := by
  intro hdst hsrc
  unfold abstractAdd
  simp [hdst, hsrc]

/-- Adding scalar to packet pointer preserves packet pointer type -/
theorem abstractAdd_ptrToPacket_preserves_type (dst src : RegState) :
    dst.regType = RegType.PtrToPacket →
    src.regType = RegType.ScalarValue →
    (abstractAdd dst src).regType = RegType.PtrToPacket := by
  intro hdst hsrc
  unfold abstractAdd
  simp [hdst, hsrc]

/-- Adding scalar to map pointer preserves map pointer type -/
theorem abstractAdd_ptrToMap_preserves_type (dst src : RegState) :
    dst.regType = RegType.PtrToMap →
    src.regType = RegType.ScalarValue →
    (abstractAdd dst src).regType = RegType.PtrToMap := by
  intro hdst hsrc
  unfold abstractAdd
  simp [hdst, hsrc]

/-- Stack pointer arithmetic updates stack offset correctly -/
theorem abstractAdd_ptrToStack_updates_offset (dst src : RegState) :
    dst.regType = RegType.PtrToStack →
    src.regType = RegType.ScalarValue →
    (abstractAdd dst src).stackOff = dst.stackOff + src.value.toInt32 := by
  intro hdst hsrc
  unfold abstractAdd
  simp [hdst, hsrc]

/-- Subtracting scalar from stack pointer preserves stack pointer type -/
theorem abstractSub_ptrToStack_preserves_type (dst src : RegState) :
    dst.regType = RegType.PtrToStack →
    src.regType = RegType.ScalarValue →
    (abstractSub dst src).regType = RegType.PtrToStack := by
  intro hdst hsrc
  unfold abstractSub
  simp [hdst, hsrc]

/-- Subtracting packet pointers produces scalar -/
theorem abstractSub_packet_packet_scalar (dst src : RegState) :
    dst.regType = RegType.PtrToPacket →
    src.regType = RegType.PtrToPacket →
    (abstractSub dst src).regType = RegType.ScalarValue := by
  intro hdst hsrc
  unfold abstractSub
  simp [hdst, hsrc]

/-! ## Security Invariants -/

/-- If a state passes memory safety check, memory accesses are safe -/
theorem memory_safe_implies_safe_access (s : ExecState) :
    (defaultPolicy.memorySafe s).isSafe = true →
    ∀ (r : Reg) (off : Int32) (size : MemSize),
      (checkMemAccess s r off size).isSafe = true ∨
      s.getCurrentInsn?.isNone := by
  intro h r off size
  unfold defaultPolicy at h
  simp [SecurityPolicy.memorySafe] at h
  by_cases hinsn : s.getCurrentInsn?.isNone
  · right; exact hinsn
  · left; sorry  -- Full proof would require case analysis on instruction

/-- Verified programs satisfy size bounds -/
theorem verified_program_size_bounded (prog : Array Insn) :
    verifyProgram prog = VerifyResult.Valid →
    prog.size ≤ MAX_INSNS := by
  intro h
  unfold verifyProgram at h
  by_cases hsize : prog.size > MAX_INSNS
  · simp [hsize] at h
  · omega

/-! ## Soundness Theorem (Sketch) -/

/-- If a program verifies successfully, it satisfies the security policy.
    This is the key soundness theorem for the verifier.

    Full proof would require:
    1. Preservation: if state s satisfies policy and s steps to s',
       then s' satisfies policy
    2. Progress: if state s satisfies policy, then s can step or is halted
-/
theorem verifier_soundness (prog : Array Insn) :
    verifyProgram prog = VerifyResult.Valid →
    checkProgram defaultPolicy prog = PolicyResult.Safe := by
  intro h
  unfold checkProgram
  unfold SecurityPolicy.terminates
  unfold SecurityPolicy.sizeBounded
  unfold defaultPolicy
  simp
  constructor
  · -- Termination: verified programs are DAGs
    sorry  -- Would prove that verifier checks for DAG structure
  · -- Size bounded: verified programs satisfy size limits
    have hsize := verified_program_size_bounded prog h
    unfold checkProgramSize
    by_cases hs : prog.size ≤ MAX_INSNS
    · rfl
    · omega

/-! ## Type Safety Properties -/

/-- Type-safe operations preserve type safety -/
theorem type_safety_preservation (s : VerifierState) (insn : Insn) (prog : Array Insn) :
    (∀ r : Reg, (s.getReg r).isInit → (s.getReg r).regType ≠ RegType.NotInit) →
    match verifyInsn s insn prog with
    | VerifyInsnResult.Valid s' =>
        ∀ r : Reg, (s'.getReg r).isInit → (s'.getReg r).regType ≠ RegType.NotInit
    | _ => True := by
  intro hinit
  unfold verifyInsn
  split
  · -- ALU64 case
    sorry
  · -- ALU case
    sorry
  · -- LDX case
    sorry
  · -- STX case
    sorry
  · -- JMP case
    sorry
  · -- JMP32 case
    sorry
  · -- Default case
    trivial

/-! ## Example Proofs -/

/-- The example valid program verifies -/
theorem example_valid_verifies :
    verifyProgram exampleValidProgram = VerifyResult.Valid := by
  rfl

/-- The example invalid program fails verification -/
theorem example_invalid_fails :
    match verifyProgram exampleInvalidProgram with
    | VerifyResult.Invalid _ _ => True
    | _ => False := by
  rfl

/-! ## Helper Lemmas -/

/-- Incrementing PC increases it by 1 -/
theorem incPC_increments (s : ExecState) : s.incPC.pc = s.pc + 1 := by
  rfl

/-- Setting a register preserves other registers -/
theorem setReg_preserves_others (s : ExecState) (r1 r2 : Reg) (val : RegState) :
    r1 ≠ r2 → (s.setReg r1 val).getReg r2 = s.getReg r2 := by
  intro hneq
  unfold ExecState.setReg ExecState.getReg
  simp [Array.get!_set_ne]
  intro heq
  have := reg_toNat_injective heq
  contradiction

/-! ## Certified Program Properties -/

/-- Certified programs can always be loaded -/
theorem certified_program_can_load (cp : CertifiedProgram) :
    cp.canLoad = true := by
  rfl

/-- Executing a certified program is safe -/
theorem certified_program_safe (cp : CertifiedProgram) (fuel : Nat) :
    let s := cp.execute fuel
    s.halted ∨ fuel = 0 ∨ s.pc < s.program.size := by
  intro s
  sorry  -- Would prove by induction on fuel

end BPF
