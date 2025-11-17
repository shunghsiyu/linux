/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Verifier

This module implements the BPF verifier, which statically analyzes BPF programs
to ensure they satisfy the security policy before execution. This is a functional
implementation inspired by the Linux kernel's BPF verifier.

The verifier performs abstract interpretation over the program's control flow,
tracking register and stack state at each program point.
-/

import BPF.Core
import BPF.State
import BPF.Security

namespace BPF

/-! ## Verifier State -/

/-- Verifier state at a particular program point -/
structure VerifierState where
  /-- Program counter -/
  pc : Nat
  /-- Abstract register states -/
  regs : Array RegState
  /-- Abstract stack state -/
  stack : Stack
  /-- Call depth -/
  callDepth : Nat
  deriving Repr, BEq

namespace VerifierState

/-- Initial verifier state -/
def init : VerifierState :=
  let regs := Array.mkArray NUM_REGS RegState.notInit
  -- R1 initially contains pointer to context
  let regs := regs.set! 1 { RegState.notInit with regType := RegType.PtrToCtx }
  -- R10 is the frame pointer
  let regs := regs.set! 10 (RegState.ptrToStack 0)
  { pc := 0
  , regs := regs
  , stack := Stack.empty
  , callDepth := 0
  }

/-- Get register state -/
def getReg (s : VerifierState) (r : Reg) : RegState :=
  s.regs.get! r.toNat

/-- Set register state -/
def setReg (s : VerifierState) (r : Reg) (val : RegState) : VerifierState :=
  { s with regs := s.regs.set! r.toNat val }

/-- Mark a register as not initialized -/
def invalidateReg (s : VerifierState) (r : Reg) : VerifierState :=
  s.setReg r RegState.notInit

/-- Invalidate all caller-saved registers (R0-R5) after a call -/
def invalidateCallerSaved (s : VerifierState) : VerifierState :=
  s.invalidateReg Reg.R0
    |>.invalidateReg Reg.R1
    |>.invalidateReg Reg.R2
    |>.invalidateReg Reg.R3
    |>.invalidateReg Reg.R4
    |>.invalidateReg Reg.R5

end VerifierState

/-! ## Abstract Interpretation -/

/-- Abstract addition of two register states -/
def abstractAdd (dst src : RegState) : RegState :=
  { regType := RegType.ScalarValue
  , value := dst.value + src.value  -- concrete
  , tnum := dst.tnum.add src.tnum   -- abstract
  , smin := dst.smin + src.smin     -- conservative bounds
  , smax := dst.smax + src.smax
  , umin := dst.umin + src.umin
  , umax := if dst.umax.toNat + src.umax.toNat > UInt64.max.toNat
            then UInt64.max
            else dst.umax + src.umax
  , stackOff := 0
  }

/-- Abstract subtraction of two register states -/
def abstractSub (dst src : RegState) : RegState :=
  let concrete := dst.value - src.value
  -- For subtraction: dst - src
  -- smin = dst.smin - src.smax (most negative result)
  -- smax = dst.smax - src.smin (most positive result)
  let smin := dst.smin - src.smax
  let smax := dst.smax - src.smin
  -- For unsigned: be conservative due to wrap-around
  let umin := if dst.umin.toNat < src.umax.toNat then 0 else dst.umin - src.umax
  let umax := dst.umax
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := if dst.tnum.isConst && src.tnum.isConst then
              TNum.const concrete
            else
              TNum.unknown
  , smin := smin
  , smax := smax
  , umin := umin
  , umax := umax
  , stackOff := 0
  }

/-- Abstract bitwise AND -/
def abstractAnd (dst src : RegState) : RegState :=
  let concrete := dst.value &&& src.value
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := dst.tnum.and src.tnum
  , smin := Int64.min  -- Conservative (AND can change sign)
  , smax := Int64.max
  , umin := 0  -- AND can produce 0
  , umax := min dst.umax src.umax  -- AND can only make smaller (unsigned)
  , stackOff := 0
  }

/-- Abstract bitwise OR -/
def abstractOr (dst src : RegState) : RegState :=
  let concrete := dst.value ||| src.value
  -- If both operands have known upper bounds that are powers of 2 minus 1,
  -- we can compute a tight upper bound for OR
  let conservativeUmax := UInt64.max
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := dst.tnum.or src.tnum
  , smin := Int64.min  -- Conservative
  , smax := Int64.max
  , umin := max dst.umin src.umin  -- OR can only make larger (unsigned)
  , umax := conservativeUmax  -- Conservative (could be tighter)
  , stackOff := 0
  }

/-- Abstract bitwise XOR -/
def abstractXor (dst src : RegState) : RegState :=
  let concrete := dst.value ^^^ src.value
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := TNum.unknown  -- Conservative: XOR is complex
  , smin := Int64.min
  , smax := Int64.max
  , umin := 0
  , umax := UInt64.max  -- Conservative
  , stackOff := 0
  }

/-- Abstract multiplication -/
def abstractMul (dst src : RegState) : RegState :=
  let concrete := dst.value * src.value
  -- For multiplication, bounds can grow quickly
  -- Be conservative to avoid overflow issues
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := if dst.tnum.isConst && src.tnum.isConst then
              TNum.const concrete
            else
              TNum.unknown
  , smin := Int64.min  -- Conservative
  , smax := Int64.max
  , umin := if dst.umin == 0 || src.umin == 0 then 0 else dst.umin * src.umin
  , umax := UInt64.max  -- Conservative (could overflow)
  , stackOff := 0
  }

/-- Abstract division -/
def abstractDiv (dst src : RegState) : RegState :=
  let concrete := if src.value != 0 then dst.value / src.value else 0
  -- Division makes values smaller (unsigned)
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := if dst.tnum.isConst && src.tnum.isConst && src.value != 0 then
              TNum.const concrete
            else
              TNum.unknown
  , smin := Int64.min  -- Conservative
  , smax := Int64.max
  , umin := 0  -- Division can produce 0
  , umax := dst.umax  -- Result <= dividend (unsigned)
  , stackOff := 0
  }

/-- Abstract left shift -/
def abstractLsh (dst src : RegState) : RegState :=
  let shamt := if src.value.toNat > 63 then 63 else src.value.toNat
  let concrete := dst.value <<< shamt
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := TNum.unknown  -- Conservative
  , smin := Int64.min
  , smax := Int64.max
  , umin := dst.umin <<< shamt  -- Lower bound shifts up
  , umax := UInt64.max  -- Conservative (could overflow)
  , stackOff := 0
  }

/-- Abstract logical right shift -/
def abstractRsh (dst src : RegState) : RegState :=
  let shamt := if src.value.toNat > 63 then 63 else src.value.toNat
  let concrete := dst.value >>> shamt
  { regType := RegType.ScalarValue
  , value := concrete
  , tnum := TNum.unknown  -- Conservative
  , smin := 0  -- Right shift of unsigned is always non-negative
  , smax := Int64.max
  , umin := dst.umin >>> shamt  -- Lower bound shifts down
  , umax := dst.umax >>> shamt  -- Upper bound shifts down
  , stackOff := 0
  }

/-- Abstract move operation -/
def abstractMov (src : RegState) : RegState :=
  src

/-- Perform abstract interpretation of an ALU operation -/
def abstractAluOp (op : AluOp) (dst src : RegState) : RegState :=
  match op with
  | AluOp.ADD  => abstractAdd dst src
  | AluOp.SUB  => abstractSub dst src
  | AluOp.MUL  => abstractMul dst src
  | AluOp.DIV  => abstractDiv dst src
  | AluOp.AND  => abstractAnd dst src
  | AluOp.OR   => abstractOr dst src
  | AluOp.XOR  => abstractXor dst src
  | AluOp.LSH  => abstractLsh dst src
  | AluOp.RSH  => abstractRsh dst src
  | AluOp.MOV  => abstractMov src
  | AluOp.NEG  =>
    { regType := RegType.ScalarValue
    , value := -dst.value
    , tnum := TNum.unknown
    , smin := -dst.smax  -- Negation reverses min/max
    , smax := -dst.smin
    , umin := 0
    , umax := UInt64.max
    , stackOff := 0
    }
  | AluOp.MOD  =>
    let concrete := if src.value != 0 then dst.value % src.value else 0
    { regType := RegType.ScalarValue
    , value := concrete
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := 0
    , umax := if src.umax > 0 then src.umax - 1 else UInt64.max  -- x % n < n
    , stackOff := 0
    }
  | _ => RegState.scalar 0  -- ARSH, END: simplified

/-! ## Instruction Verification -/

/-- Verification result for a single instruction -/
inductive VerifyInsnResult : Type where
  | Valid : VerifierState → VerifyInsnResult
  | Invalid : SecurityViolation → VerifyInsnResult
  | Branch : VerifierState → VerifierState → VerifyInsnResult  -- true branch, false branch
  deriving Repr

/-- Verify an ALU instruction -/
def verifyAluInsn (s : VerifierState) (insn : Insn) : VerifyInsnResult :=
  -- Check that destination register is initialized
  let dstReg := s.getReg insn.dst_reg

  if ¬dstReg.isInit then
    VerifyInsnResult.Invalid (SecurityViolation.UninitializedRead insn.dst_reg)
  else
    -- Get source (register or immediate)
    let srcReg :=
      if insn.isImmediate then
        -- Immediate value - always initialized
        RegState.scalar insn.imm.toUInt64
      else
        s.getReg insn.src_reg

    -- Check source register initialization (if not immediate)
    if ¬insn.isImmediate && ¬srcReg.isInit then
      VerifyInsnResult.Invalid (SecurityViolation.UninitializedRead insn.src_reg)
    else
      -- Get ALU operation
      match insn.getAluOp with
      | none =>
        VerifyInsnResult.Invalid SecurityViolation.InvalidInstruction
      | some op =>
        -- Check for division by zero
        if (op == AluOp.DIV || op == AluOp.MOD) && srcReg.umin == 0 then
          VerifyInsnResult.Invalid SecurityViolation.DivisionByZero
        else
          -- Perform abstract interpretation
          let newReg := abstractAluOp op dstReg srcReg
          let newState := s.setReg insn.dst_reg newReg
          VerifyInsnResult.Valid { newState with pc := s.pc + 1 }

/-- Verify a load instruction -/
def verifyLoadInsn (s : VerifierState) (insn : Insn) (size : MemSize) : VerifyInsnResult :=
  let srcReg := s.getReg insn.src_reg

  if ¬srcReg.isInit then
    VerifyInsnResult.Invalid (SecurityViolation.UninitializedRead insn.src_reg)
  else
    -- Check memory access bounds
    match srcReg.regType with
    | RegType.PtrToStack =>
      let offset := srcReg.stackOff.toInt + insn.off.toInt
      let accessEnd := offset + size.toBytes.toInt
      if 0 <= offset && accessEnd <= MAX_STACK_SIZE then
        -- Valid stack access - load value
        let loadedValue := RegState.scalar 0  -- Simplified: unknown value
        let newState := s.setReg insn.dst_reg loadedValue
        VerifyInsnResult.Valid { newState with pc := s.pc + 1 }
      else
        VerifyInsnResult.Invalid (SecurityViolation.InvalidMemoryAccess offset.toNat)

    | RegType.PtrToMap =>
      -- Map access is valid (simplified)
      let loadedValue := RegState.scalar 0
      let newState := s.setReg insn.dst_reg loadedValue
      VerifyInsnResult.Valid { newState with pc := s.pc + 1 }

    | _ =>
      VerifyInsnResult.Invalid (SecurityViolation.TypeMismatch srcReg.regType RegType.PtrToStack)

/-- Verify a store instruction -/
def verifyStoreInsn (s : VerifierState) (insn : Insn) (size : MemSize) : VerifyInsnResult :=
  let dstReg := s.getReg insn.dst_reg
  let srcReg := s.getReg insn.src_reg

  if ¬dstReg.isInit then
    VerifyInsnResult.Invalid (SecurityViolation.UninitializedRead insn.dst_reg)
  else if ¬srcReg.isInit then
    VerifyInsnResult.Invalid (SecurityViolation.UninitializedRead insn.src_reg)
  else
    -- Check memory access bounds
    match dstReg.regType with
    | RegType.PtrToStack =>
      let offset := dstReg.stackOff.toInt + insn.off.toInt
      let accessEnd := offset + size.toBytes.toInt
      if 0 <= offset && accessEnd <= MAX_STACK_SIZE then
        -- Valid stack store
        VerifyInsnResult.Valid { s with pc := s.pc + 1 }
      else
        VerifyInsnResult.Invalid (SecurityViolation.InvalidMemoryAccess offset.toNat)

    | RegType.PtrToMap =>
      -- Map store is valid (simplified)
      VerifyInsnResult.Valid { s with pc := s.pc + 1 }

    | _ =>
      VerifyInsnResult.Invalid (SecurityViolation.TypeMismatch dstReg.regType RegType.PtrToStack)

/-- Verify a jump instruction -/
def verifyJumpInsn (s : VerifierState) (insn : Insn) (prog : Array Insn) : VerifyInsnResult :=
  -- Check for EXIT
  if insn.opcode == 0x95 then
    -- EXIT instruction - program terminates
    VerifyInsnResult.Valid s
  else if insn.off == 0 then
    -- Unconditional fall-through
    VerifyInsnResult.Valid { s with pc := s.pc + 1 }
  else
    -- Conditional or unconditional jump
    let target := s.pc.toInt + insn.off.toInt + 1
    if target < 0 || target.toNat >= prog.size then
      VerifyInsnResult.Invalid (SecurityViolation.InvalidJump target)
    else
      -- Branch: both true and false paths
      let trueBranch := { s with pc := target.toNat }
      let falseBranch := { s with pc := s.pc + 1 }
      VerifyInsnResult.Branch trueBranch falseBranch

/-- Verify a single instruction -/
def verifyInsn (s : VerifierState) (insn : Insn) (prog : Array Insn) : VerifyInsnResult :=
  match insn.getClass with
  | some InsnClass.ALU64 | some InsnClass.ALU =>
    -- ALU operation (use improved verifier)
    verifyAluInsn s insn

  | some InsnClass.LDX =>
    -- Load instruction - use actual memory size from instruction
    let size := insn.getMemSize.getD MemSize.DW
    verifyLoadInsn s insn size

  | some InsnClass.STX | some InsnClass.ST =>
    -- Store instruction - use actual memory size from instruction
    let size := insn.getMemSize.getD MemSize.DW
    verifyStoreInsn s insn size

  | some InsnClass.JMP | some InsnClass.JMP32 =>
    verifyJumpInsn s insn prog

  | some InsnClass.LD =>
    -- Wide immediate load (simplified: mark dst as scalar)
    let newReg := RegState.scalar 0
    let newState := s.setReg insn.dst_reg newReg
    VerifyInsnResult.Valid { newState with pc := s.pc + 1 }

  | none =>
    VerifyInsnResult.Invalid SecurityViolation.InvalidInstruction

/-! ## Program Verification -/

/-- State map: maps PC to verifier state at that program point -/
def StateMap := Std.HashMap Nat VerifierState

/-- Worklist for verification -/
structure Worklist where
  states : List VerifierState
  visited : StateMap
  deriving Repr

namespace Worklist

/-- Create an empty worklist -/
def empty : Worklist :=
  { states := [], visited := Std.HashMap.empty }

/-- Add a state to the worklist -/
def add (wl : Worklist) (s : VerifierState) : Worklist :=
  -- Check if we've already visited this PC with an equivalent state
  match wl.visited.find? s.pc with
  | none =>
    -- Never seen this PC before
    { states := s :: wl.states
    , visited := wl.visited.insert s.pc s }
  | some oldState =>
    -- We've seen this PC before - check if state changed
    if oldState == s then
      wl  -- No change, don't re-explore
    else
      -- State changed, need to re-explore
      { states := s :: wl.states
      , visited := wl.visited.insert s.pc s }

/-- Get next state from worklist -/
def next (wl : Worklist) : Option (VerifierState × Worklist) :=
  match wl.states with
  | [] => none
  | s :: rest => some (s, { wl with states := rest })

/-- Check if worklist is empty -/
def isEmpty (wl : Worklist) : Bool :=
  wl.states.isEmpty

end Worklist

/-- Verification result -/
inductive VerifyResult : Type where
  | Valid : VerifyResult
  | Invalid : SecurityViolation → Nat → VerifyResult  -- violation and PC
  | ComplexityLimit : VerifyResult  -- hit verification complexity limit
  deriving Repr

/-- Verify a program using abstract interpretation with worklist algorithm -/
partial def verifyProgram (prog : Array Insn) (fuel : Nat := 10000) : VerifyResult :=
  -- First check basic constraints
  if prog.size > MAX_INSNS then
    return VerifyResult.Invalid SecurityViolation.InvalidInstruction 0

  -- Initialize worklist with initial state
  let initState := VerifierState.init
  let worklist := Worklist.empty.add initState

  -- Process worklist
  let rec processWorklist (wl : Worklist) (remaining : Nat) : VerifyResult :=
    if remaining == 0 then
      VerifyResult.ComplexityLimit
    else
      match wl.next with
      | none => VerifyResult.Valid  -- Worklist empty, all paths verified
      | some (state, wl') =>
        -- Get instruction at current PC
        if state.pc >= prog.size then
          -- Reached end without EXIT - invalid
          VerifyResult.Invalid SecurityViolation.InvalidInstruction state.pc
        else
          let insn := prog.get! state.pc
          -- Verify this instruction
          match verifyInsn state insn prog with
          | VerifyInsnResult.Invalid violation =>
            VerifyResult.Invalid violation state.pc

          | VerifyInsnResult.Valid nextState =>
            -- Continue with next state
            let wl'' := wl'.add nextState
            processWorklist wl'' (remaining - 1)

          | VerifyInsnResult.Branch trueState falseState =>
            -- Add both branches to worklist
            let wl'' := wl'.add trueState |>.add falseState
            processWorklist wl'' (remaining - 1)

  processWorklist worklist fuel

/-! ## Verifier Interface -/

/-- Verify and certify a program -/
def certifyProgram (prog : Array Insn) : Option CertifiedProgram :=
  match verifyProgram prog with
  | VerifyResult.Valid =>
    -- Program is valid - construct proof
    -- In a real implementation, we'd construct actual proof terms
    let proof : SecurityProof :=
      { program := prog
      , policy := defaultPolicy
      , sizeProof := by rfl  -- Placeholder
      , terminationProof := by rfl  -- Placeholder
      }
    some { program := prog
         , proof := proof
         , proofValid := rfl
         }
  | _ => none

/-! ## Pretty Printing -/

/-- Format a security violation for display -/
def formatViolation : SecurityViolation → String
  | SecurityViolation.UninitializedRead reg =>
    s!"Uninitialized register read: {repr reg}"
  | SecurityViolation.InvalidMemoryAccess addr =>
    s!"Invalid memory access at offset {addr}"
  | SecurityViolation.StackOverflow =>
    "Stack overflow detected"
  | SecurityViolation.StackUnderflow =>
    "Stack underflow detected"
  | SecurityViolation.TypeMismatch expected actual =>
    s!"Type mismatch: expected {repr expected}, got {repr actual}"
  | SecurityViolation.DivisionByZero =>
    "Division or modulo by zero"
  | SecurityViolation.InfiniteLoop =>
    "Potential infinite loop detected (back-edge found)"
  | SecurityViolation.InvalidInstruction =>
    "Invalid or unsupported instruction"
  | SecurityViolation.CallStackOverflow =>
    s!"Call stack overflow (max depth: {MAX_CALL_FRAMES})"
  | SecurityViolation.InvalidJump offset =>
    s!"Invalid jump to offset {offset}"

/-- Format verification result for display -/
def formatVerifyResult : VerifyResult → String
  | VerifyResult.Valid =>
    "✓ Program verified successfully"
  | VerifyResult.Invalid violation pc =>
    s!"✗ Verification failed at instruction {pc}:\n  {formatViolation violation}"
  | VerifyResult.ComplexityLimit =>
    "✗ Verification complexity limit exceeded\n  Program is too complex to verify"

/-! ## Example Programs -/

/-- A simple valid program: mov r0, 42; exit -/
def exampleValidProgram : Array Insn :=
  #[Insn.movImm Reg.R0 42, Insn.exit]

/-- A program with uninitialized read -/
def exampleInvalidProgram : Array Insn :=
  #[Insn.add Reg.R0 Reg.R1,  -- R0 not initialized
    Insn.exit]

/-! ## Tests -/

/-- Test that valid program verifies -/
def testValidProgram : Bool :=
  match verifyProgram exampleValidProgram with
  | VerifyResult.Valid => true
  | _ => false

/-- Test that invalid program is rejected -/
def testInvalidProgram : Bool :=
  match verifyProgram exampleInvalidProgram with
  | VerifyResult.Invalid _ _ => true
  | _ => false

-- Example: #eval testValidProgram  -- should return true
-- Example: #eval testInvalidProgram  -- should return true

end BPF
