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

/-! ## BPF Helper Functions -/

/-- BPF helper function IDs.
    These are kernel-provided functions that BPF programs can call.
    Based on include/uapi/linux/bpf.h
-/
inductive HelperFunc : Type where
  | MapLookupElem     : HelperFunc  -- bpf_map_lookup_elem
  | MapUpdateElem     : HelperFunc  -- bpf_map_update_elem
  | MapDeleteElem     : HelperFunc  -- bpf_map_delete_elem
  | GetPrandomU32     : HelperFunc  -- bpf_get_prandom_u32
  | KtimeGetNs        : HelperFunc  -- bpf_ktime_get_ns
  | TracePrintk       : HelperFunc  -- bpf_trace_printk
  | GetSmpProcessorId : HelperFunc  -- bpf_get_smp_processor_id
  | ProbeRead         : HelperFunc  -- bpf_probe_read
  deriving Repr, BEq, DecidableEq

namespace HelperFunc

/-- Convert helper function to ID number -/
def toId : HelperFunc → Nat
  | MapLookupElem     => 1
  | MapUpdateElem     => 2
  | MapDeleteElem     => 3
  | GetPrandomU32     => 7
  | KtimeGetNs        => 5
  | TracePrintk       => 6
  | GetSmpProcessorId => 8
  | ProbeRead         => 4

/-- Get helper function from ID -/
def ofId? : Nat → Option HelperFunc
  | 1 => some MapLookupElem
  | 2 => some MapUpdateElem
  | 3 => some MapDeleteElem
  | 4 => some ProbeRead
  | 5 => some KtimeGetNs
  | 6 => some TracePrintk
  | 7 => some GetPrandomU32
  | 8 => some GetSmpProcessorId
  | _ => none

/-- Get helper function name -/
def name : HelperFunc → String
  | MapLookupElem     => "bpf_map_lookup_elem"
  | MapUpdateElem     => "bpf_map_update_elem"
  | MapDeleteElem     => "bpf_map_delete_elem"
  | GetPrandomU32     => "bpf_get_prandom_u32"
  | KtimeGetNs        => "bpf_ktime_get_ns"
  | TracePrintk       => "bpf_trace_printk"
  | GetSmpProcessorId => "bpf_get_smp_processor_id"
  | ProbeRead         => "bpf_probe_read"

end HelperFunc

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

/-- Opcode field extraction masks -/
def BPF_CLASS_MASK : UInt8 := 0x07
def BPF_OP_MASK : UInt8 := 0xf0
def BPF_SRC_MASK : UInt8 := 0x08
def BPF_SIZE_MASK : UInt8 := 0x18

/-- Extract instruction class from opcode -/
def getClass (insn : Insn) : Option InsnClass :=
  let cls := insn.opcode.toNat &&& BPF_CLASS_MASK.toNat
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

/-- Extract ALU operation from opcode -/
def getAluOp (insn : Insn) : Option AluOp :=
  let op := insn.opcode.toNat &&& BPF_OP_MASK.toNat
  match op with
  | 0x00 => some AluOp.ADD
  | 0x10 => some AluOp.SUB
  | 0x20 => some AluOp.MUL
  | 0x30 => some AluOp.DIV
  | 0x40 => some AluOp.OR
  | 0x50 => some AluOp.AND
  | 0x60 => some AluOp.LSH
  | 0x70 => some AluOp.RSH
  | 0x80 => some AluOp.NEG
  | 0x90 => some AluOp.MOD
  | 0xa0 => some AluOp.XOR
  | 0xb0 => some AluOp.MOV
  | 0xc0 => some AluOp.ARSH
  | 0xd0 => some AluOp.END
  | _ => none

/-- Extract source type (register vs immediate) -/
def getInsnSrc (insn : Insn) : InsnSrc :=
  if (insn.opcode.toNat &&& BPF_SRC_MASK.toNat) == 0 then
    InsnSrc.K  -- immediate
  else
    InsnSrc.X  -- register

/-- Extract memory size from opcode -/
def getMemSize (insn : Insn) : Option MemSize :=
  let size := insn.opcode.toNat &&& BPF_SIZE_MASK.toNat
  match size with
  | 0x00 => some MemSize.W   -- 32-bit
  | 0x08 => some MemSize.H   -- 16-bit
  | 0x10 => some MemSize.B   -- 8-bit
  | 0x18 => some MemSize.DW  -- 64-bit
  | _ => none

/-- Check if instruction is a 64-bit operation -/
def is64Bit (insn : Insn) : Bool :=
  match insn.getClass with
  | some InsnClass.ALU64 => true
  | _ => false

/-- Check if instruction uses immediate operand -/
def isImmediate (insn : Insn) : Bool :=
  insn.getInsnSrc == InsnSrc.K

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

/-- Create an ADD immediate instruction -/
def addImm (dst : Reg) (imm : Int32) : Insn :=
  { opcode := 0x07  -- BPF_ALU64 | BPF_ADD | BPF_K
  , dst_reg := dst
  , src_reg := Reg.R0
  , off := 0
  , imm := imm
  }

/-- Create a SUB instruction -/
def sub (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x1F  -- BPF_ALU64 | BPF_SUB | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create a MUL instruction -/
def mul (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x2F  -- BPF_ALU64 | BPF_MUL | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create a DIV instruction -/
def div (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x3F  -- BPF_ALU64 | BPF_DIV | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create an AND instruction -/
def and (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x5F  -- BPF_ALU64 | BPF_AND | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create an OR instruction -/
def or (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x4F  -- BPF_ALU64 | BPF_OR | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create an XOR instruction -/
def xor (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0xAF  -- BPF_ALU64 | BPF_XOR | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create a left shift instruction -/
def lsh (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x6F  -- BPF_ALU64 | BPF_LSH | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create a logical right shift instruction -/
def rsh (dst : Reg) (src : Reg) : Insn :=
  { opcode := 0x7F  -- BPF_ALU64 | BPF_RSH | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := 0
  , imm := 0
  }

/-- Create a load instruction (LDX) -/
def ldx (size : MemSize) (dst : Reg) (src : Reg) (off : Int16) : Insn :=
  let sizeCode := match size with
    | MemSize.B => 0x10
    | MemSize.H => 0x08
    | MemSize.W => 0x00
    | MemSize.DW => 0x18
  { opcode := 0x01 ||| sizeCode  -- BPF_LDX | BPF_MEM | size
  , dst_reg := dst
  , src_reg := src
  , off := off
  , imm := 0
  }

/-- Create a store instruction (STX) -/
def stx (size : MemSize) (dst : Reg) (src : Reg) (off : Int16) : Insn :=
  let sizeCode := match size with
    | MemSize.B => 0x10
    | MemSize.H => 0x08
    | MemSize.W => 0x00
    | MemSize.DW => 0x18
  { opcode := 0x03 ||| sizeCode  -- BPF_STX | BPF_MEM | size
  , dst_reg := dst
  , src_reg := src
  , off := off
  , imm := 0
  }

/-- Create a conditional jump if equal -/
def jeq (dst : Reg) (src : Reg) (off : Int16) : Insn :=
  { opcode := 0x1D  -- BPF_JMP | BPF_JEQ | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := off
  , imm := 0
  }

/-- Create a conditional jump if not equal -/
def jne (dst : Reg) (src : Reg) (off : Int16) : Insn :=
  { opcode := 0x5D  -- BPF_JMP | BPF_JNE | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := off
  , imm := 0
  }

/-- Create a conditional jump if greater than (unsigned) -/
def jgt (dst : Reg) (src : Reg) (off : Int16) : Insn :=
  { opcode := 0x2D  -- BPF_JMP | BPF_JGT | BPF_X
  , dst_reg := dst
  , src_reg := src
  , off := off
  , imm := 0
  }

/-- Create an unconditional jump -/
def ja (off : Int16) : Insn :=
  { opcode := 0x05  -- BPF_JMP | BPF_JA
  , dst_reg := Reg.R0
  , src_reg := Reg.R0
  , off := off
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

/-- Create a CALL instruction to a helper function -/
def call (helper : HelperFunc) : Insn :=
  { opcode := 0x85  -- BPF_JMP | BPF_CALL
  , dst_reg := Reg.R0
  , src_reg := Reg.R0
  , off := 0
  , imm := helper.toId.toInt32
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
