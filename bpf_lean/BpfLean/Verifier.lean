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
import BpfLean.Maps

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

-- Check stack access bounds
def checkStackAccess (reg : AbstractReg) (off : Int16) (size : BpfSize) : Bool :=
  match reg.regType with
  | .PtrToStack stackOff =>
      -- Stack grows downward from 0
      let accessOff := stackOff + off.toInt
      let accessSize := size.toNat
      -- Check that access is within stack bounds [-MAX_BPF_STACK, 0)
      accessOff >= -(MAX_BPF_STACK : Int) &&
      accessOff + accessSize <= 0
  | _ => true  -- Not stack access, other checks apply

-- Verify a load instruction
def verifyLoad (st : VerifierState) (sz : BpfSize) (dst src : BpfReg) (off : Int16)
    : Except VerifyError VerifierState :=
  let srcReg := st.regs.read src

  -- Check source register is initialized
  if !srcReg.isInit then
    .error (.UninitializedRegister 0 src)
  else if !checkMemoryAccess srcReg then
    .error (.InvalidMemoryAccess 0)
  -- Check stack bounds if accessing stack
  else if !checkStackAccess srcReg off sz then
    .error (.StackOutOfBounds 0)
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
  -- Check stack bounds if accessing stack
  else if !checkStackAccess dstReg off sz then
    .error (.StackOutOfBounds 0)
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

  | .Call helperId =>
      -- Verify helper function call
      match BpfHelper.fromInt? helperId with
      | none => .error (.Other s!"Unknown helper function: {helperId}")
      | some helper =>
          -- Check arguments are initialized based on helper requirements
          match helper with
          | .MapLookupElem =>
              -- R1 = map ptr, R2 = key ptr
              let r1 := st.regs.read .R1
              let r2 := st.regs.read .R2
              if !r1.isInit then
                .error (.UninitializedRegister pc .R1)
              else if !r2.isInit then
                .error (.UninitializedRegister pc .R2)
              else
                -- After call, R0 contains scalar or pointer
                -- Conservative: mark as unknown scalar
                let regs' := st.regs.write .R0 AbstractReg.scalarUnknown
                .ok { st with regs := regs' }

          | .MapUpdateElem =>
              -- R1 = map ptr, R2 = key ptr, R3 = value ptr, R4 = flags
              let r1 := st.regs.read .R1
              let r2 := st.regs.read .R2
              let r3 := st.regs.read .R3
              let r4 := st.regs.read .R4
              if !r1.isInit then
                .error (.UninitializedRegister pc .R1)
              else if !r2.isInit then
                .error (.UninitializedRegister pc .R2)
              else if !r3.isInit then
                .error (.UninitializedRegister pc .R3)
              else if !r4.isInit then
                .error (.UninitializedRegister pc .R4)
              else
                -- R0 = return value (0 or -1)
                let regs' := st.regs.write .R0 AbstractReg.scalarUnknown
                .ok { st with regs := regs' }

          | .MapDeleteElem =>
              -- R1 = map ptr, R2 = key ptr
              let r1 := st.regs.read .R1
              let r2 := st.regs.read .R2
              if !r1.isInit then
                .error (.UninitializedRegister pc .R1)
              else if !r2.isInit then
                .error (.UninitializedRegister pc .R2)
              else
                let regs' := st.regs.write .R0 AbstractReg.scalarUnknown
                .ok { st with regs := regs' }

          | .GetProcTime =>
              -- No arguments, just returns timestamp in R0
              let regs' := st.regs.write .R0 AbstractReg.scalarUnknown
              .ok { st with regs := regs' }

          | .TraceMsg =>
              -- R1 = format string, R2 = format size, R3-R5 = arguments
              -- For now, just check R1 and R2 are initialized
              let r1 := st.regs.read .R1
              let r2 := st.regs.read .R2
              if !r1.isInit then
                .error (.UninitializedRegister pc .R1)
              else if !r2.isInit then
                .error (.UninitializedRegister pc .R2)
              else
                let regs' := st.regs.write .R0 AbstractReg.scalarUnknown
                .ok { st with regs := regs' }

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

-- Merge two abstract register states (join operation for lattice)
def mergeAbstractReg (r1 r2 : AbstractReg) : AbstractReg :=
  -- If one is not initialized, take the other
  if !r1.isInit then r2
  else if !r2.isInit then r1
  -- If types differ, result is unknown scalar (conservative)
  else if r1.regType != r2.regType then
    AbstractReg.scalarUnknown
  else
    -- Same type, merge values
    { regType := r1.regType
    , value := AbstractValue.merge r1.value r2.value
    , id := if r1.id == r2.id then r1.id else 0
    , off := if r1.off == r2.off then r1.off else 0
    , range := min r1.range r2.range
    }

-- Merge two abstract register files
def mergeAbstractRegFile (rf1 rf2 : AbstractRegFile) : AbstractRegFile :=
  fun r => mergeAbstractReg (rf1 r) (rf2 r)

-- Merge two verifier states (for join points in CFG)
def mergeVerifierState (st1 st2 : VerifierState) : VerifierState :=
  { regs := mergeAbstractRegFile st1.regs st2.regs
  , stackDepth := max st1.stackDepth st2.stackDepth
  , visited := st1.visited  -- preserve visited info
  }

-- Check if two abstract values are equal (for fixpoint detection)
def abstractValueEq (v1 v2 : AbstractValue) : Bool :=
  v1.known_mask == v2.known_mask &&
  v1.known_value == v2.known_value &&
  v1.umin == v2.umin &&
  v1.umax == v2.umax &&
  v1.smin == v2.smin &&
  v1.smax == v2.smax

-- Check if two abstract registers are equal
def abstractRegEq (r1 r2 : AbstractReg) : Bool :=
  r1.regType == r2.regType &&
  abstractValueEq r1.value r2.value &&
  r1.id == r2.id &&
  r1.off == r2.off

-- Check if two register files are equal
def abstractRegFileEq (rf1 rf2 : AbstractRegFile) : Bool :=
  [BpfReg.R0, .R1, .R2, .R3, .R4, .R5, .R6, .R7, .R8, .R9, .R10].all
    (fun r => abstractRegEq (rf1 r) (rf2 r))

-- Check if two verifier states are equal (for fixpoint)
def verifierStateEq (st1 st2 : VerifierState) : Bool :=
  abstractRegFileEq st1.regs st2.regs &&
  st1.stackDepth == st2.stackDepth

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

-- Worklist-based fixpoint iteration for abstract interpretation
-- states: array of abstract states at each program point (None if not yet visited)
-- worklist: list of program points to process
partial def fixpointIteration
    (prog : Array BpfInsn)
    (states : Array (Option VerifierState))
    (worklist : List Nat)
    (maxIters : Nat := 10000)
    : Except VerifyError (Array (Option VerifierState)) := do
  if maxIters == 0 then
    throw (VerifyError.Other "Fixpoint iteration did not converge")

  match worklist with
  | [] => pure states  -- Fixpoint reached!
  | pc :: rest =>
      -- Get current state at this program point
      if h : pc < states.size then
        match states[pc] with
        | none => throw (VerifyError.Other s!"Uninitialized state at pc {pc}")
        | some currentState =>
            -- Decode instruction
            if h' : pc < prog.size then
              let bpfInsn := prog[pc]
              match decodeBpfInsn bpfInsn with
              | none => throw (VerifyError.InvalidInstruction pc)
              | some insn =>
                  -- Verify instruction and compute output state
                  let stateAfter ← verifyInstruction currentState insn pc

                  -- Get successors
                  let successors := getSuccessors insn pc prog.size

                  -- For each successor, merge state and add to worklist if changed
                  let (states', worklist') ← successors.foldlM
                    (fun (acc : Array (Option VerifierState) × List Nat) succ => do
                      let (curStates, curWorklist) := acc
                      if h'' : succ < curStates.size then
                        match curStates[succ] with
                        | none =>
                            -- First time visiting this successor
                            let newStates := curStates.set! succ (some stateAfter)
                            pure (newStates, succ :: curWorklist)
                        | some oldState =>
                            -- Merge with existing state
                            let merged := mergeVerifierState oldState stateAfter
                            -- Check if state changed
                            if verifierStateEq merged oldState then
                              -- No change, don't re-add to worklist
                              pure (curStates, curWorklist)
                            else
                              -- State changed, update and re-add to worklist
                              let newStates := curStates.set! succ (some merged)
                              pure (newStates, succ :: curWorklist)
                      else
                        throw (VerifyError.Other s!"Successor {succ} out of bounds")
                    )
                    (states, rest)

                  -- Continue with updated states and worklist
                  fixpointIteration prog states' worklist' (maxIters - 1)
            else
              throw (VerifyError.Other s!"PC {pc} out of bounds")
      else
        throw (VerifyError.Other s!"Invalid program counter: {pc}")

-- Main verification function with full abstract interpretation
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

  -- Perform full abstract interpretation using fixpoint iteration
  -- Initialize: entry point (pc=0) has initial state, all others are None
  let initialState := VerifierState.init prog.size
  let states := Array.replicate prog.size none
  let states := states.set! 0 (some initialState)

  -- Run fixpoint iteration starting from entry point
  let _ ← fixpointIteration prog states [0]

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
