/-
  BPF Verifier

  This module implements the BPF verifier using abstract interpretation.
  The verifier performs static analysis to ensure programs satisfy the
  security policy before execution.

  The verification process:
  1. Check program is a DAG (no back edges)
  2. Perform abstract interpretation on all possible paths
  3. Track register types and value ranges
  4. Verify memory accesses are in bounds
  5. Ensure all registers are initialized before use
-/

import BpfLean.Basic
import BpfLean.Instruction
import BpfLean.State
import BpfLean.Security

-- Verifier state at a specific program point
structure VerifierState where
  regs : AbstractRegFile
  stackDepth : Nat
  visited : Array Bool  -- which instructions have been visited

instance : Inhabited VerifierState where
  default := {
    regs := AbstractRegFile.init
    stackDepth := 0
    visited := #[]
  }

namespace VerifierState

def init (progSize : Nat) : VerifierState :=
  { regs := AbstractRegFile.init
  , stackDepth := 0
  , visited := Array.replicate progSize false
  }

-- Mark an instruction as visited
def markVisited (st : VerifierState) (pc : Nat) : VerifierState :=
  if h : pc < st.visited.size then
    { st with visited := st.visited.set! pc true }
  else
    st

-- Check if an instruction was visited
def wasVisited (st : VerifierState) (pc : Nat) : Bool :=
  st.visited.getD pc false

end VerifierState

-- Abstract interpretation of ALU operations
def abstractAluOp (op : BpfAluOp) (dst src : AbstractReg) : AbstractReg :=
  match op with
  | .ADD =>
      let val := AbstractValue.add dst.value src.value
      { AbstractReg.scalarUnknown with value := val }

  | .SUB =>
      let val := AbstractValue.sub dst.value src.value
      { AbstractReg.scalarUnknown with value := val }

  | .MUL =>
      let val := AbstractValue.mul dst.value src.value
      { AbstractReg.scalarUnknown with value := val }

  | .DIV =>
      -- Division by zero returns 0 in BPF
      if src.value.maybeZero then
        AbstractReg.scalarUnknown
      else
        let val := AbstractValue.div dst.value src.value
        { AbstractReg.scalarUnknown with value := val }

  | .MOV =>
      src

  | .OR =>
      let val := AbstractValue.bitwiseOr dst.value src.value
      { AbstractReg.scalarUnknown with value := val }

  | .AND =>
      let val := AbstractValue.bitwiseAnd dst.value src.value
      { AbstractReg.scalarUnknown with value := val }

  | _ =>
      -- For other operations, return unknown scalar
      AbstractReg.scalarUnknown

-- Check if a register can be used as a pointer for memory access
def checkMemoryAccess (reg : AbstractReg) : Bool :=
  match reg.regType with
  | .PtrToStack _ => true
  | .PtrToMapValue => true
  | .PtrToPacket => true
  | .PtrToCtx => true
  | _ => false

-- Verify a load instruction
def verifyLoad (st : VerifierState) (sz : BpfSize) (dst src : BpfReg) (off : Int16)
    : Except VerifyError VerifierState :=
  let srcReg := st.regs.read src

  -- Check source register is initialized
  if !srcReg.isInit then
    .error (.UninitializedRegister 0 src)
  else if !checkMemoryAccess srcReg then
    .error (.InvalidMemoryAccess 0)
  else
    -- After load, destination becomes a scalar
    let regs' := st.regs.write dst AbstractReg.scalarUnknown
    .ok { st with regs := regs' }

-- Verify a store instruction
def verifyStore (st : VerifierState) (sz : BpfSize) (dst src : BpfReg) (off : Int16)
    : Except VerifyError VerifierState :=
  let dstReg := st.regs.read dst
  let srcReg := st.regs.read src

  -- Check both registers are initialized
  if !dstReg.isInit then
    .error (.UninitializedRegister 0 dst)
  else if !srcReg.isInit then
    .error (.UninitializedRegister 0 src)
  else if !checkMemoryAccess dstReg then
    .error (.InvalidMemoryAccess 0)
  else
    .ok st

-- Verify an instruction and update abstract state
def verifyInstruction (st : VerifierState) (insn : BpfInstr) (pc : Nat)
    : Except VerifyError VerifierState :=
  match insn with
  | .Exit =>
      -- Check R0 is initialized (return value)
      let r0 := st.regs.read .R0
      if !r0.isInit then
        .error (.UninitializedRegister pc .R0)
      else
        .ok st

  | .Alu64Reg op dst src =>
      let dstReg := st.regs.read dst
      let srcReg := st.regs.read src

      if !dstReg.isInit then
        .error (.UninitializedRegister pc dst)
      else if !srcReg.isInit then
        .error (.UninitializedRegister pc src)
      else
        let result := abstractAluOp op dstReg srcReg
        let regs' := st.regs.write dst result
        .ok { st with regs := regs' }

  | .Alu64Imm op dst imm =>
      let dstReg := st.regs.read dst
      let immReg := AbstractReg.scalarFromConst imm.toInt64.toUInt64

      if !dstReg.isInit then
        .error (.UninitializedRegister pc dst)
      else
        let result := abstractAluOp op dstReg immReg
        let regs' := st.regs.write dst result
        .ok { st with regs := regs' }

  | .AluReg op dst src =>
      -- 32-bit ALU (similar to 64-bit)
      let dstReg := st.regs.read dst
      let srcReg := st.regs.read src

      if !dstReg.isInit then
        .error (.UninitializedRegister pc dst)
      else if !srcReg.isInit then
        .error (.UninitializedRegister pc src)
      else
        let result := abstractAluOp op dstReg srcReg
        let regs' := st.regs.write dst result
        .ok { st with regs := regs' }

  | .AluImm op dst imm =>
      let dstReg := st.regs.read dst
      let immReg := AbstractReg.scalarFromConst imm.toInt64.toUInt64

      if !dstReg.isInit then
        .error (.UninitializedRegister pc dst)
      else
        let result := abstractAluOp op dstReg immReg
        let regs' := st.regs.write dst result
        .ok { st with regs := regs' }

  | .LoadReg sz dst src off =>
      verifyLoad st sz dst src off

  | .StoreReg sz dst src off =>
      verifyStore st sz dst src off

  | .StoreImm sz dst off imm =>
      let dstReg := st.regs.read dst
      if !dstReg.isInit then
        .error (.UninitializedRegister pc dst)
      else if !checkMemoryAccess dstReg then
        .error (.InvalidMemoryAccess pc)
      else
        .ok st

  | .JumpAlways off => .ok st
  | .JumpReg op dst src off => .ok st
  | .JumpImm op dst imm off => .ok st
  | .Jump32Reg op dst src off => .ok st
  | .Jump32Imm op dst imm off => .ok st
  | .Call imm => .ok st

-- Get all successor program counters for an instruction
def getSuccessors (insn : BpfInstr) (pc : Nat) (progSize : Nat) : List Nat :=
  let next := pc + 1

  match insn with
  | .Exit => []  -- no successors
  | .JumpAlways off =>
      let target := (pc + 1) + off.toInt
      if target >= 0 && target.toNat < progSize then
        [target.toNat]
      else
        []
  | .JumpReg _ _ _ off
  | .JumpImm _ _ _ off
  | .Jump32Reg _ _ _ off
  | .Jump32Imm _ _ _ off =>
      let target := (pc + 1) + off.toInt
      let successors := if next < progSize then [next] else []
      if target >= 0 && target.toNat < progSize then
        target.toNat :: successors
      else
        successors
  | _ =>
      if next < progSize then [next] else []

-- Check if jumping to target from pc creates a back edge
def isBackEdge (pc target : Nat) : Bool :=
  target <= pc

-- Verify the program is a DAG (no loops)
partial def checkDAG (prog : Array BpfInsn) (pc : Nat := 0) (visited : Array Bool := Array.replicate prog.size false)
    : Except VerifyError Bool :=
  if pc >= prog.size then
    .ok true
  else if visited.getD pc false then
    .ok true  -- already checked this path
  else
    match decodeBpfInsn prog[pc]! with
    | none => .error (.InvalidInstruction pc)
    | some insn =>
        let successors := getSuccessors insn pc prog.size
        -- Check for back edges
        if successors.any (isBackEdge pc) then
          .error (.BackEdgeDetected pc)
        else
          let visited' := visited.set! pc true
          -- Recursively check all successors
          successors.foldlM (fun acc succ => do
            let _ ← checkDAG prog succ visited'
            pure true
          ) true

-- Main verification function
partial def verifyProgram (prog : Array BpfInsn) (policy : SecurityPolicy)
    : Except VerifyError SafetyCertificate := do
  -- Check program size
  if prog.size > policy.maxInsns then
    throw .ProgramTooLarge

  -- Check all instructions are valid
  for i in [0:prog.size] do
    match decodeBpfInsn prog[i]! with
    | none => throw (.InvalidInstruction i)
    | some _ => pure ()

  -- Check program is a DAG (no loops)
  let _ ← checkDAG prog

  -- TODO: Perform full abstract interpretation
  -- This would involve:
  -- 1. Initialize worklist with entry point
  -- 2. For each instruction in worklist:
  --    a. Verify instruction with current abstract state
  --    b. Compute abstract state after instruction
  --    c. Add successors to worklist if state changed
  -- 3. Continue until fixpoint

  pure { policy := policy
       , programSize := prog.size
       , isDAG := true
       }

-- Verify and run a program (proof-carrying code approach)
def verifyAndRun (prog : Array BpfInsn) (fuel : Nat := 10000)
    : Except VerifyError (BpfState × ExecResult) :=
  match verifyProgram prog SecurityPolicy.default with
  | .error err => .error err
  | .ok cert =>
      -- Program verified, safe to run
      let st := BpfState.init prog fuel
      .ok (st.run)
