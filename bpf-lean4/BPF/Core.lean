/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Core Definitions

This module defines the core types and structures for the BPF virtual machine,
including instructions, registers, and basic operations.

Based on the Linux kernel BPF implementation (include/uapi/linux/bpf.h)
-/

namespace BPF

/-! ## Register Definitions -/

/-- BPF has 11 registers (R0-R10):
    - R0: return value
    - R1-R5: function arguments
    - R6-R9: callee-saved registers
    - R10: read-only frame pointer
-/
inductive Reg : Type where
  | R0 : Reg  -- return register
  | R1 : Reg  -- arg1
  | R2 : Reg  -- arg2
  | R3 : Reg  -- arg3
  | R4 : Reg  -- arg4
  | R5 : Reg  -- arg5
  | R6 : Reg  -- callee saved
  | R7 : Reg  -- callee saved
  | R8 : Reg  -- callee saved
  | R9 : Reg  -- callee saved
  | R10 : Reg -- frame pointer (read-only)
  deriving Repr, BEq, DecidableEq

/-- Convert register to its numeric value (0-10) -/
def Reg.toNat : Reg → Nat
  | R0 => 0
  | R1 => 1
  | R2 => 2
  | R3 => 3
  | R4 => 4
  | R5 => 5
  | R6 => 6
  | R7 => 7
  | R8 => 8
  | R9 => 9
  | R10 => 10

/-- Convert natural number to register (with bounds checking) -/
def Reg.ofNat? : Nat → Option Reg
  | 0 => some R0
  | 1 => some R1
  | 2 => some R2
  | 3 => some R3
  | 4 => some R4
  | 5 => some R5
  | 6 => some R6
  | 7 => some R7
  | 8 => some R8
  | 9 => some R9
  | 10 => some R10
  | _ => none

/-! ## Instruction Classes -/

/-- BPF instruction classes (3 bits) -/
inductive InsnClass : Type where
  | LD    : InsnClass  -- load
  | LDX   : InsnClass  -- load from memory
  | ST    : InsnClass  -- store
  | STX   : InsnClass  -- store to memory
  | ALU   : InsnClass  -- 32-bit ALU ops
  | JMP   : InsnClass  -- jumps
  | JMP32 : InsnClass  -- 32-bit jumps
  | ALU64 : InsnClass  -- 64-bit ALU ops
  deriving Repr, BEq, DecidableEq

/-! ## ALU/JMP Operations -/

/-- ALU operations -/
inductive AluOp : Type where
  | ADD   : AluOp
  | SUB   : AluOp
  | MUL   : AluOp
  | DIV   : AluOp
  | OR    : AluOp
  | AND   : AluOp
  | LSH   : AluOp  -- left shift
  | RSH   : AluOp  -- right shift (logical)
  | NEG   : AluOp
  | MOD   : AluOp
  | XOR   : AluOp
  | MOV   : AluOp
  | ARSH  : AluOp  -- arithmetic right shift
  | END   : AluOp  -- endianness conversion
  deriving Repr, BEq, DecidableEq

/-- Jump operations -/
inductive JmpOp : Type where
  | JA    : JmpOp  -- unconditional jump
  | JEQ   : JmpOp  -- jump if equal
  | JGT   : JmpOp  -- jump if greater (unsigned)
  | JGE   : JmpOp  -- jump if greater or equal (unsigned)
  | JSET  : JmpOp  -- jump if bitwise AND is non-zero
  | JNE   : JmpOp  -- jump if not equal
  | JLT   : JmpOp  -- jump if less than (unsigned)
  | JLE   : JmpOp  -- jump if less than or equal (unsigned)
  | JSGT  : JmpOp  -- jump if greater (signed)
  | JSGE  : JmpOp  -- jump if greater or equal (signed)
  | JSLT  : JmpOp  -- jump if less than (signed)
  | JSLE  : JmpOp  -- jump if less than or equal (signed)
  | CALL  : JmpOp  -- function call
  | EXIT  : JmpOp  -- return from program
  deriving Repr, BEq, DecidableEq

/-! ## Memory Access Modes -/

/-- Memory access size -/
inductive MemSize : Type where
  | B  : MemSize  -- 8-bit
  | H  : MemSize  -- 16-bit (half word)
  | W  : MemSize  -- 32-bit (word)
  | DW : MemSize  -- 64-bit (double word)
  deriving Repr, BEq, DecidableEq

def MemSize.toBytes : MemSize → Nat
  | B => 1
  | H => 2
  | W => 4
  | DW => 8

/-- Memory addressing mode -/
inductive MemMode : Type where
  | IMM : MemMode  -- immediate
  | ABS : MemMode  -- absolute (packet access)
  | IND : MemMode  -- indirect (packet access)
  | MEM : MemMode  -- memory access
  deriving Repr, BEq, DecidableEq

/-! ## Instruction Source -/

/-- Instruction source operand -/
inductive InsnSrc : Type where
  | K : InsnSrc  -- immediate constant
  | X : InsnSrc  -- source register
  deriving Repr, BEq, DecidableEq

/-! ## BPF Instruction -/

/-- A BPF instruction is 64 bits (8 bytes):
    - opcode: 8 bits
    - dst_reg: 4 bits
    - src_reg: 4 bits
    - off: 16 bits (signed offset)
    - imm: 32 bits (signed immediate)
-/
structure Insn where
  opcode : UInt8
  dst_reg : Reg
  src_reg : Reg
  off : Int16
  imm : Int32
  deriving Repr, BEq

namespace Insn

/-- Extract instruction class from opcode -/
def getClass (insn : Insn) : Option InsnClass :=
  let cls := insn.opcode.toNat &&& 0x07
  match cls with
  | 0x00 => some InsnClass.LD
  | 0x01 => some InsnClass.LDX
  | 0x02 => some InsnClass.ST
  | 0x03 => some InsnClass.STX
  | 0x04 => some InsnClass.ALU
  | 0x05 => some InsnClass.JMP
  | 0x06 => some InsnClass.JMP32
  | 0x07 => some InsnClass.ALU64
  | _ => none

/-- Check if instruction is a 64-bit operation -/
def is64Bit (insn : Insn) : Bool :=
  match insn.getClass with
  | some InsnClass.ALU64 => true
  | _ => false

/-- Create a MOV instruction -/
def mov (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0xBF  -- BPF_ALU64 | BPF_MOV | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create a MOV immediate instruction -/
def movImm (dst : Reg) (imm : Int32) : Insn :=
  { opcode := 0xB7  -- BPF_ALU64 | BPF_MOV | BPF_K
  , dst_reg := dst
  , src_reg := Reg.R0
  , off := 0
  , imm := imm
  }

/-- Create an ADD instruction -/
def add (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x0F  -- BPF_ALU64 | BPF_ADD | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create an EXIT instruction -/
def exit : Insn :=
  { opcode := 0x95  -- BPF_JMP | BPF_EXIT
  , dst_reg := Reg.R0
  , src_reg := Reg.R0
  , off := 0
  , imm := 0
  }

end Insn

/-! ## Constants -/

/-- Maximum number of instructions in a BPF program -/
def MAX_INSNS : Nat := 4096

/-- Maximum call stack depth -/
def MAX_CALL_FRAMES : Nat := 8

/-- Maximum stack size in bytes -/
def MAX_STACK_SIZE : Nat := 512

/-- Number of registers -/
def NUM_REGS : Nat := 11

end BPF
