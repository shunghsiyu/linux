/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF State Machine

This module defines the state machine model for BPF virtual machine execution,
including register state, memory state, and execution semantics.
-/

import BPF.Core

namespace BPF

/-! ## Register Type System -/

/-- Register types for the BPF type system.
    This is a simplified version of the kernel's bpf_reg_type.
-/
inductive RegType : Type where
  | NotInit      : RegType  -- register not initialized
  | ScalarValue  : RegType  -- scalar value (not a pointer)
  | PtrToCtx     : RegType  -- pointer to BPF context
  | PtrToStack   : RegType  -- pointer to stack
  | PtrToPacket  : RegType  -- pointer to packet data
  | PtrToMap     : RegType  -- pointer to map value
  | ConstPtrToMap : RegType -- const pointer to map
  deriving Repr, BEq, DecidableEq

/-! ## BPF Maps -/

/-- BPF map types -/
inductive MapType : Type where
  | Hash      : MapType  -- Hash table
  | Array     : MapType  -- Array map
  | ProgArray : MapType  -- Program array (for tail calls)
  | PerfEvent : MapType  -- Perf event array
  | PerCpuHash : MapType  -- Per-CPU hash table
  | PerCpuArray : MapType -- Per-CPU array
  | StackTrace : MapType  -- Stack trace map
  | LruHash : MapType     -- LRU hash table
  deriving Repr, BEq, DecidableEq

/-- BPF map descriptor -/
structure MapDef where
  /-- Map ID -/
  id : Nat
  /-- Type of map -/
  mapType : MapType
  /-- Size of key in bytes -/
  keySize : Nat
  /-- Size of value in bytes -/
  valueSize : Nat
  /-- Maximum number of entries -/
  maxEntries : Nat
  deriving Repr, BEq

namespace MapDef

/-- Check if key size is valid for this map -/
def isKeyValid (m : MapDef) (size : Nat) : Bool :=
  size == m.keySize

/-- Check if value size is valid for this map -/
def isValueValid (m : MapDef) (size : Nat) : Bool :=
  size == m.valueSize

/-- Get value pointer type after map lookup -/
def valueRegType (m : MapDef) : RegType :=
  RegType.PtrToMap

end MapDef

/-! ## Abstract Value Tracking -/

/-- Tri-state number for abstract interpretation.
    Tracks which bits are known constants and their values.
-/
structure TNum where
  value : UInt64  -- bits that are known to be 1
  mask : UInt64   -- bits that are unknown (1 = unknown, 0 = known)
  deriving Repr, BEq

namespace TNum

/-- Create a TNum representing an exact constant -/
def const (n : UInt64) : TNum :=
  { value := n, mask := 0 }

/-- Create a TNum representing a completely unknown value -/
def unknown : TNum :=
  { value := 0, mask := UInt64.max }

/-- Check if the TNum represents an exact constant -/
def isConst (t : TNum) : Bool :=
  t.mask == 0

/-- Get the constant value (if it is a constant) -/
def getConst? (t : TNum) : Option UInt64 :=
  if t.isConst then some t.value else none

/-- Bitwise AND of two TNums -/
def and (a b : TNum) : TNum :=
  { value := a.value &&& b.value
  , mask := a.mask ||| b.mask
  }

/-- Bitwise OR of two TNums -/
def or (a b : TNum) : TNum :=
  { value := a.value ||| b.value
  , mask := a.mask ||| b.mask
  }

/-- Addition of two TNums (conservative approximation) -/
def add (a b : TNum) : TNum :=
  if a.isConst && b.isConst then
    const (a.value + b.value)
  else
    unknown

end TNum

/-! ## Register State -/

/-- State of a single register, tracking both concrete and abstract values -/
structure RegState where
  regType : RegType
  /-- Concrete value (for interpretation) -/
  value : UInt64
  /-- Abstract value tracking (for verification) -/
  tnum : TNum
  /-- Signed minimum possible value -/
  smin : Int64
  /-- Signed maximum possible value -/
  smax : Int64
  /-- Unsigned minimum possible value -/
  umin : UInt64
  /-- Unsigned maximum possible value -/
  umax : UInt64
  /-- Stack offset (for PTR_TO_STACK) -/
  stackOff : Int32
  deriving Repr, BEq

namespace RegState

/-- Initialize a register as not initialized -/
def notInit : RegState :=
  { regType := RegType.NotInit
  , value := 0
  , tnum := TNum.unknown
  , smin := Int64.min
  , smax := Int64.max
  , umin := UInt64.min
  , umax := UInt64.max
  , stackOff := 0
  }

/-- Create a scalar register with a constant value -/
def scalar (n : UInt64) : RegState :=
  { regType := RegType.ScalarValue
  , value := n
  , tnum := TNum.const n
  , smin := n.toInt64
  , smax := n.toInt64
  , umin := n
  , umax := n
  , stackOff := 0
  }

/-- Create a pointer to stack -/
def ptrToStack (off : Int32) : RegState :=
  { regType := RegType.PtrToStack
  , value := 0  -- Frame pointer is conceptually at 0
  , tnum := TNum.unknown
  , smin := Int64.min
  , smax := Int64.max
  , umin := UInt64.min
  , umax := UInt64.max
  , stackOff := off
  }

/-- Check if register is initialized -/
def isInit (r : RegState) : Bool :=
  r.regType != RegType.NotInit

/-- Check if register is a scalar value -/
def isScalar (r : RegState) : Bool :=
  r.regType == RegType.ScalarValue

/-- Check if register is a pointer -/
def isPtr (r : RegState) : Bool :=
  match r.regType with
  | RegType.PtrToCtx => true
  | RegType.PtrToStack => true
  | RegType.PtrToPacket => true
  | RegType.PtrToMap => true
  | RegType.ConstPtrToMap => true
  | _ => false

end RegState

/-! ## Memory State -/

/-- Stack slot state -/
inductive StackSlotType : Type where
  | Invalid : StackSlotType  -- uninitialized
  | Spill   : StackSlotType  -- register spilled to stack
  | Misc    : StackSlotType  -- arbitrary data
  deriving Repr, BEq, DecidableEq

structure StackSlot where
  slotType : StackSlotType
  value : UInt64  -- concrete value
  spilledReg : Option RegState  -- if spilled, which register
  deriving Repr, BEq

/-- Stack state (array of 8-byte slots) -/
def Stack := Array StackSlot

namespace Stack

/-- Create an empty stack of given size -/
def empty (size : Nat := MAX_STACK_SIZE / 8) : Stack :=
  Array.mkArray size { slotType := StackSlotType.Invalid
                      , value := 0
                      , spilledReg := none }

/-- Read a value from stack at given offset (in bytes) -/
def read? (stack : Stack) (offset : Nat) (size : MemSize) : Option UInt64 :=
  let slotIdx := offset / 8
  if h : slotIdx < stack.size then
    let slot := stack[slotIdx]
    if slot.slotType != StackSlotType.Invalid then
      some slot.value
    else
      none
  else
    none

/-- Write a value to stack at given offset -/
def write (stack : Stack) (offset : Nat) (value : UInt64) : Stack :=
  let slotIdx := offset / 8
  if h : slotIdx < stack.size then
    stack.set ⟨slotIdx, h⟩ { slotType := StackSlotType.Misc
                            , value := value
                            , spilledReg := none }
  else
    stack

/-- Spill a register to stack -/
def spillReg (stack : Stack) (offset : Nat) (reg : RegState) : Stack :=
  let slotIdx := offset / 8
  if h : slotIdx < stack.size then
    stack.set ⟨slotIdx, h⟩ { slotType := StackSlotType.Spill
                            , value := reg.value
                            , spilledReg := some reg }
  else
    stack

end Stack

/-! ## Execution State -/

/-- Complete execution state of the BPF VM -/
structure ExecState where
  /-- Program counter -/
  pc : Nat
  /-- Register file -/
  regs : Array RegState
  /-- Stack -/
  stack : Stack
  /-- Call stack depth -/
  callDepth : Nat
  /-- Program instructions -/
  program : Array Insn
  /-- Execution completed -/
  halted : Bool
  deriving Repr, BEq

namespace ExecState

/-- Initialize execution state with a program -/
def init (prog : Array Insn) : ExecState :=
  let regs := Array.mkArray NUM_REGS RegState.notInit
  -- R1 initially contains pointer to context
  let regs := regs.set! 0 { RegState.notInit with regType := RegType.PtrToCtx }
  -- R10 is the frame pointer
  let regs := regs.set! 10 (RegState.ptrToStack 0)
  { pc := 0
  , regs := regs
  , stack := Stack.empty
  , callDepth := 0
  , program := prog
  , halted := false
  }

/-- Get register state -/
def getReg (s : ExecState) (r : Reg) : RegState :=
  s.regs.get! r.toNat

/-- Set register state -/
def setReg (s : ExecState) (r : Reg) (val : RegState) : ExecState :=
  { s with regs := s.regs.set! r.toNat val }

/-- Get current instruction -/
def getCurrentInsn? (s : ExecState) : Option Insn :=
  if s.pc < s.program.size then
    some (s.program.get! s.pc)
  else
    none

/-- Increment program counter -/
def incPC (s : ExecState) : ExecState :=
  { s with pc := s.pc + 1 }

/-- Jump to offset -/
def jump (s : ExecState) (offset : Int) : ExecState :=
  { s with pc := (s.pc.toInt + offset + 1).toNat }

/-- Halt execution -/
def halt (s : ExecState) : ExecState :=
  { s with halted := true }

end ExecState

/-! ## Execution Semantics -/

/-- Result of executing a single instruction -/
inductive StepResult : Type where
  | Continue : ExecState → StepResult
  | Halt : ExecState → StepResult
  | Error : String → StepResult
  deriving Repr

/-- Mask value to 32 bits -/
def mask32 (v : UInt64) : UInt64 :=
  v &&& 0xFFFFFFFF

/-- Sign extend from 32 to 64 bits -/
def signExtend32 (v : UInt64) : UInt64 :=
  if (v &&& 0x80000000) != 0 then
    v ||| 0xFFFFFFFF00000000
  else
    v &&& 0xFFFFFFFF

/-- Execute a single ALU operation -/
def execAlu (op : AluOp) (dst : UInt64) (src : UInt64) (is64 : Bool) : Option UInt64 :=
  let result := match op with
    | AluOp.ADD => some (dst + src)
    | AluOp.SUB => some (dst - src)
    | AluOp.MUL => some (dst * src)
    | AluOp.DIV => if src != 0 then some (dst / src) else none
    | AluOp.OR  => some (dst ||| src)
    | AluOp.AND => some (dst &&& src)
    | AluOp.LSH =>
      -- Shifts beyond 63 are implementation-defined, clamp to 63
      let shamt := if src.toNat > 63 then 63 else src.toNat
      some (dst <<< shamt)
    | AluOp.RSH =>
      let shamt := if src.toNat > 63 then 63 else src.toNat
      some (dst >>> shamt)
    | AluOp.NEG => some (-dst)
    | AluOp.MOD => if src != 0 then some (dst % src) else none
    | AluOp.XOR => some (dst ^^^ src)
    | AluOp.MOV => some src
    | AluOp.ARSH =>
      -- Arithmetic shift right (sign-extending)
      let shamt := if src.toNat > 63 then 63 else src.toNat
      some (dst.toInt64 >>> shamt).toUInt64
    | AluOp.END => some dst  -- Endianness conversion (simplified)
  -- Apply 32-bit masking if not 64-bit operation
  result.map fun v => if is64 then v else mask32 v

/-- Execute a jump condition -/
def evalJmpCond (op : JmpOp) (dst : UInt64) (src : UInt64) : Bool :=
  match op with
  | JmpOp.JEQ  => dst == src
  | JmpOp.JNE  => dst != src
  | JmpOp.JGT  => dst > src
  | JmpOp.JGE  => dst >= src
  | JmpOp.JLT  => dst < src
  | JmpOp.JLE  => dst <= src
  | JmpOp.JSGT => dst.toInt64 > src.toInt64
  | JmpOp.JSGE => dst.toInt64 >= src.toInt64
  | JmpOp.JSLT => dst.toInt64 < src.toInt64
  | JmpOp.JSLE => dst.toInt64 <= src.toInt64
  | JmpOp.JSET => (dst &&& src) != 0
  | _ => false

/-- Execute a single instruction -/
def step (s : ExecState) : StepResult :=
  if s.halted then
    StepResult.Halt s
  else
    match s.getCurrentInsn? with
    | none => StepResult.Error "PC out of bounds"
    | some insn =>
      match insn.getClass with
      | some InsnClass.ALU64 | some InsnClass.ALU =>
        -- ALU operation (64-bit or 32-bit)
        let is64 := insn.is64Bit
        let dstReg := s.getReg insn.dst_reg

        -- Get source value (register or immediate)
        let srcVal :=
          if insn.isImmediate then
            insn.imm.toUInt64
          else
            (s.getReg insn.src_reg).value

        -- Get ALU operation
        match insn.getAluOp with
        | some op =>
          -- Execute ALU operation
          match execAlu op dstReg.value srcVal is64 with
          | some result =>
            let newReg := RegState.scalar result
            StepResult.Continue (s.setReg insn.dst_reg newReg |>.incPC)
          | none =>
            StepResult.Error "ALU operation failed (division by zero?)"
        | none =>
          StepResult.Error "Invalid ALU opcode"

      | some InsnClass.LDX =>
        -- Load from memory
        let srcReg := s.getReg insn.src_reg
        let offset := srcReg.stackOff.toInt + insn.off.toInt

        -- Check if it's a stack access
        if srcReg.regType == RegType.PtrToStack then
          match s.stack.read? offset.toNat (insn.getMemSize.getD MemSize.DW) with
          | some value =>
            let newReg := RegState.scalar value
            StepResult.Continue (s.setReg insn.dst_reg newReg |>.incPC)
          | none =>
            StepResult.Error "Invalid memory read"
        else
          -- Simplified: assume successful read
          let newReg := RegState.scalar 0
          StepResult.Continue (s.setReg insn.dst_reg newReg |>.incPC)

      | some InsnClass.STX | some InsnClass.ST =>
        -- Store to memory
        let dstReg := s.getReg insn.dst_reg
        let srcVal :=
          if insn.getClass == some InsnClass.STX then
            (s.getReg insn.src_reg).value
          else
            insn.imm.toUInt64

        let offset := dstReg.stackOff.toInt + insn.off.toInt

        -- Update stack if it's a stack pointer
        if dstReg.regType == RegType.PtrToStack then
          let newStack := s.stack.write offset.toNat srcVal
          StepResult.Continue { s with stack := newStack, pc := s.pc + 1 }
        else
          -- Simplified: ignore other stores
          StepResult.Continue (s.incPC)

      | some InsnClass.JMP | some InsnClass.JMP32 =>
        -- Check for EXIT
        if insn.opcode == 0x95 then
          StepResult.Halt s
        else if insn.off == 0 then
          -- No jump offset, just continue
          StepResult.Continue (s.incPC)
        else
          -- Conditional or unconditional jump
          let dstVal := (s.getReg insn.dst_reg).value
          let srcVal :=
            if insn.isImmediate then
              insn.imm.toUInt64
            else
              (s.getReg insn.src_reg).value

          -- Determine jump type from opcode
          let shouldJump :=
            let opBits := insn.opcode.toNat &&& 0xf0
            match opBits with
            | 0x00 => true  -- JA (unconditional)
            | 0x10 => dstVal == srcVal  -- JEQ
            | 0x50 => dstVal != srcVal  -- JNE
            | 0x20 => dstVal > srcVal   -- JGT
            | 0xa0 => dstVal < srcVal   -- JLT
            | _ => false

          if shouldJump then
            StepResult.Continue (s.jump insn.off.toInt)
          else
            StepResult.Continue (s.incPC)

      | some InsnClass.LD =>
        -- Wide immediate load (simplified)
        StepResult.Continue (s.incPC)

      | none =>
        StepResult.Error "Invalid instruction class"

/-- Execute program for up to n steps -/
def execSteps (s : ExecState) (fuel : Nat) : ExecState :=
  match fuel with
  | 0 => s
  | n + 1 =>
    match step s with
    | StepResult.Continue s' => execSteps s' n
    | StepResult.Halt s' => s'
    | StepResult.Error _ => s

end BPF
