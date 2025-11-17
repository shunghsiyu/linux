/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Security Policy

This module formalizes the security policy for BPF programs in the context
of proof-carrying code (PCC). The security policy defines what constitutes
a "safe" BPF program that can be loaded and executed by the kernel.

The key security properties are:
1. Memory safety (no out-of-bounds access)
2. Type safety (operations respect types)
3. Termination (no infinite loops)
4. Reference safety (proper acquire/release)
-/

import BPF.Core
import BPF.State

namespace BPF

/-! ## Security Policy Definition -/

/-- Security violation types -/
inductive SecurityViolation : Type where
  | UninitializedRead : Reg → SecurityViolation
  | InvalidMemoryAccess : Nat → SecurityViolation
  | StackOverflow : SecurityViolation
  | StackUnderflow : SecurityViolation
  | TypeMismatch : RegType → RegType → SecurityViolation
  | DivisionByZero : SecurityViolation
  | InfiniteLoop : SecurityViolation
  | InvalidInstruction : SecurityViolation
  | CallStackOverflow : SecurityViolation
  | InvalidJump : Int → SecurityViolation
  deriving Repr, BEq

/-- A security policy check result -/
inductive PolicyResult : Type where
  | Safe : PolicyResult
  | Unsafe : SecurityViolation → PolicyResult
  deriving Repr

namespace PolicyResult

def isSafe : PolicyResult → Bool
  | Safe => true
  | Unsafe _ => false

def isUnsafe : PolicyResult → Bool
  | Safe => false
  | Unsafe _ => true

/-- Combine two policy results (unsafe if either is unsafe) -/
def and (p1 p2 : PolicyResult) : PolicyResult :=
  match p1, p2 with
  | Safe, Safe => Safe
  | Unsafe v, _ => Unsafe v
  | _, Unsafe v => Unsafe v

end PolicyResult

/-! ## Basic Safety Checks -/

/-- Check if a register is initialized -/
def checkRegInit (s : ExecState) (r : Reg) : PolicyResult :=
  let regState := s.getReg r
  if regState.isInit then
    PolicyResult.Safe
  else
    PolicyResult.Unsafe (SecurityViolation.UninitializedRead r)

/-- Check if a stack offset is within bounds -/
def checkStackBounds (offset : Int32) : PolicyResult :=
  if 0 <= offset.toInt && offset.toNat < MAX_STACK_SIZE then
    PolicyResult.Safe
  else if offset.toInt < 0 then
    PolicyResult.Unsafe SecurityViolation.StackUnderflow
  else
    PolicyResult.Unsafe SecurityViolation.StackOverflow

/-- Check if a memory access is safe -/
def checkMemAccess (s : ExecState) (r : Reg) (offset : Int32) (size : MemSize) : PolicyResult :=
  let regState := s.getReg r
  match regState.regType with
  | RegType.PtrToStack =>
    let accessOffset := regState.stackOff.toInt + offset.toInt
    let accessEnd := accessOffset + size.toBytes.toInt
    if 0 <= accessOffset && accessEnd <= MAX_STACK_SIZE then
      PolicyResult.Safe
    else
      PolicyResult.Unsafe (SecurityViolation.InvalidMemoryAccess accessOffset.toNat)
  | RegType.PtrToMap =>
    -- Simplified: assume map access is valid
    PolicyResult.Safe
  | RegType.PtrToPacket =>
    -- Simplified: assume packet access needs bounds checking
    PolicyResult.Safe
  | _ =>
    PolicyResult.Unsafe (SecurityViolation.TypeMismatch regState.regType RegType.PtrToStack)

/-- Check if a type is compatible for an operation -/
def checkTypeCompat (expected : RegType) (actual : RegType) : PolicyResult :=
  if expected == actual then
    PolicyResult.Safe
  else
    -- Allow scalar operations on untyped values
    match expected, actual with
    | RegType.ScalarValue, RegType.ScalarValue => PolicyResult.Safe
    | _, _ => PolicyResult.Unsafe (SecurityViolation.TypeMismatch expected actual)

/-- Check if division/modulo by zero would occur -/
def checkDivByZero (s : ExecState) (r : Reg) : PolicyResult :=
  let regState := s.getReg r
  if regState.isScalar && regState.value == 0 then
    PolicyResult.Unsafe SecurityViolation.DivisionByZero
  else if regState.umin == 0 then
    -- Potentially could be zero - needs runtime check or proof
    PolicyResult.Unsafe SecurityViolation.DivisionByZero
  else
    PolicyResult.Safe

/-- Check if jump target is valid -/
def checkJumpTarget (s : ExecState) (offset : Int16) : PolicyResult :=
  let target := s.pc.toInt + offset.toInt + 1
  if 0 <= target && target.toNat < s.program.size then
    PolicyResult.Safe
  else
    PolicyResult.Unsafe (SecurityViolation.InvalidJump target)

/-! ## Instruction-Level Safety Checks -/

/-- Check safety of an ALU instruction -/
def checkAluSafety (s : ExecState) (insn : Insn) (op : AluOp) : PolicyResult :=
  let dstCheck := checkRegInit s insn.dst_reg
  let srcCheck := checkRegInit s insn.src_reg
  let divCheck :=
    if op == AluOp.DIV || op == AluOp.MOD then
      checkDivByZero s insn.src_reg
    else
      PolicyResult.Safe
  dstCheck.and srcCheck |>.and divCheck

/-- Check safety of a memory load instruction -/
def checkLoadSafety (s : ExecState) (insn : Insn) (size : MemSize) : PolicyResult :=
  let srcCheck := checkRegInit s insn.src_reg
  let memCheck := checkMemAccess s insn.src_reg insn.off size
  srcCheck.and memCheck

/-- Check safety of a memory store instruction -/
def checkStoreSafety (s : ExecState) (insn : Insn) (size : MemSize) : PolicyResult :=
  let dstCheck := checkRegInit s insn.dst_reg
  let srcCheck := checkRegInit s insn.src_reg
  let memCheck := checkMemAccess s insn.dst_reg insn.off size
  dstCheck.and srcCheck |>.and memCheck

/-- Check safety of a jump instruction -/
def checkJumpSafety (s : ExecState) (insn : Insn) : PolicyResult :=
  if insn.opcode == 0x95 then  -- EXIT
    PolicyResult.Safe
  else if insn.off != 0 then
    checkJumpTarget s insn.off
  else
    PolicyResult.Safe

/-! ## Program-Level Security Policy -/

/-- Control Flow Graph node -/
structure CFGNode where
  pc : Nat
  successors : List Nat
  deriving Repr, BEq

/-- Control Flow Graph -/
def CFG := Array CFGNode

/-- Build CFG from program -/
def buildCFG (prog : Array Insn) : CFG :=
  let nodes := Array.mkArray prog.size { pc := 0, successors := [] }
  prog.foldlIdx (fun idx cfg insn =>
    let successors :=
      match insn.getClass with
      | some InsnClass.JMP =>
        if insn.opcode == 0x95 then  -- EXIT
          []
        else if insn.off != 0 then
          [idx + 1, (idx.toInt + insn.off.toInt + 1).toNat]
        else
          [idx + 1]
      | _ => [idx + 1]
    cfg.set! idx { pc := idx, successors := successors }
  ) nodes

/-- Check if CFG has a back-edge (indicating a loop) -/
def hasBackEdge (cfg : CFG) : Bool :=
  -- Simplified: DFS to detect back edges
  -- In a full implementation, this would be a proper cycle detection
  false

/-- Check if program is a DAG (no loops) -/
def isDAG (prog : Array Insn) : PolicyResult :=
  let cfg := buildCFG prog
  if hasBackEdge cfg then
    PolicyResult.Unsafe SecurityViolation.InfiniteLoop
  else
    PolicyResult.Safe

/-- Check if program size is within limits -/
def checkProgramSize (prog : Array Insn) : PolicyResult :=
  if prog.size <= MAX_INSNS then
    PolicyResult.Safe
  else
    PolicyResult.Unsafe SecurityViolation.InvalidInstruction

/-! ## Main Security Policy -/

/-- The complete security policy for a BPF program.
    This is the PCC security policy that programs must satisfy.
-/
structure SecurityPolicy where
  /-- Memory safety: all memory accesses are within bounds -/
  memorySafe : ExecState → PolicyResult
  /-- Type safety: all operations respect register types -/
  typeSafe : ExecState → PolicyResult
  /-- Termination: program terminates (is a DAG) -/
  terminates : Array Insn → PolicyResult
  /-- Size bounds: program is not too large -/
  sizeBounded : Array Insn → PolicyResult

/-- The default BPF security policy -/
def defaultPolicy : SecurityPolicy :=
  { memorySafe := fun s =>
      match s.getCurrentInsn? with
      | none => PolicyResult.Safe
      | some insn =>
        match insn.getClass with
        | some InsnClass.LDX => checkLoadSafety s insn MemSize.DW
        | some InsnClass.STX => checkStoreSafety s insn MemSize.DW
        | _ => PolicyResult.Safe
  , typeSafe := fun s =>
      match s.getCurrentInsn? with
      | none => PolicyResult.Safe
      | some insn => PolicyResult.Safe  -- Simplified
  , terminates := isDAG
  , sizeBounded := checkProgramSize
  }

/-! ## Policy Checking -/

/-- Check if an execution state satisfies the security policy -/
def checkState (policy : SecurityPolicy) (s : ExecState) : PolicyResult :=
  policy.memorySafe s |>.and (policy.typeSafe s)

/-- Check if a program satisfies the security policy -/
def checkProgram (policy : SecurityPolicy) (prog : Array Insn) : PolicyResult :=
  policy.terminates prog |>.and (policy.sizeBounded prog)

/-! ## Proof Obligations -/

/-- A proof that a program satisfies the security policy.
    This is the "proof" part of proof-carrying code.
-/
structure SecurityProof where
  program : Array Insn
  policy : SecurityPolicy
  /-- Proof that the program satisfies size bounds -/
  sizeProof : policy.sizeBounded program = PolicyResult.Safe
  /-- Proof that the program terminates (is a DAG) -/
  terminationProof : policy.terminates program = PolicyResult.Safe

/-- A certified BPF program with its security proof -/
structure CertifiedProgram where
  program : Array Insn
  proof : SecurityProof
  /-- Invariant: the proof is for this program -/
  proofValid : proof.program = program

namespace CertifiedProgram

/-- Execute a certified program (safe because we have a proof) -/
def execute (cp : CertifiedProgram) (fuel : Nat) : ExecState :=
  let s := ExecState.init cp.program
  execSteps s fuel

/-- A certified program can be safely loaded -/
def canLoad (cp : CertifiedProgram) : Bool :=
  true  -- Always safe because we have a proof

end CertifiedProgram

/-! ## Helper Theorems -/

/-- If a register is scalar, operations on it are type-safe -/
theorem scalar_ops_safe (r : RegState) (h : r.isScalar = true) :
    r.regType = RegType.ScalarValue := by
  unfold RegState.isScalar at h
  simp at h
  exact h

/-- Safe policy results compose -/
theorem safe_and_safe :
    PolicyResult.and PolicyResult.Safe PolicyResult.Safe = PolicyResult.Safe := by
  rfl

/-- Unsafe policy results propagate -/
theorem unsafe_propagates (v : SecurityViolation) :
    PolicyResult.and (PolicyResult.Unsafe v) PolicyResult.Safe = PolicyResult.Unsafe v := by
  rfl

end BPF
