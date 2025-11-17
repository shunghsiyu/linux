/-
  Basic types and definitions for BPF (Berkeley Packet Filter) formalization.

  This module defines the fundamental types used throughout the BPF virtual machine,
  including registers, instruction classes, and basic operations.
-/

-- BPF has 11 registers: R0-R10
-- R0: return value
-- R1-R5: function arguments
-- R6-R9: callee-saved registers
-- R10: read-only frame pointer
inductive BpfReg : Type where
  | R0 : BpfReg
  | R1 : BpfReg
  | R2 : BpfReg
  | R3 : BpfReg
  | R4 : BpfReg
  | R5 : BpfReg
  | R6 : BpfReg
  | R7 : BpfReg
  | R8 : BpfReg
  | R9 : BpfReg
  | R10 : BpfReg
  deriving Repr, DecidableEq, Inhabited

-- Convert register to index (0-10)
def BpfReg.toNat : BpfReg → Nat
  | .R0 => 0
  | .R1 => 1
  | .R2 => 2
  | .R3 => 3
  | .R4 => 4
  | .R5 => 5
  | .R6 => 6
  | .R7 => 7
  | .R8 => 8
  | .R9 => 9
  | .R10 => 10

-- BPF instruction classes (from bpf_common.h)
inductive BpfClass : Type where
  | LD    : BpfClass  -- 0x00: load
  | LDX   : BpfClass  -- 0x01: load from memory
  | ST    : BpfClass  -- 0x02: store
  | STX   : BpfClass  -- 0x03: store to memory
  | ALU   : BpfClass  -- 0x04: 32-bit ALU ops
  | JMP   : BpfClass  -- 0x05: 64-bit jump ops
  | JMP32 : BpfClass  -- 0x06: 32-bit jump ops
  | ALU64 : BpfClass  -- 0x07: 64-bit ALU ops
  deriving Repr, DecidableEq, Inhabited

-- Memory access sizes
inductive BpfSize : Type where
  | W  : BpfSize  -- 32-bit
  | H  : BpfSize  -- 16-bit
  | B  : BpfSize  -- 8-bit
  | DW : BpfSize  -- 64-bit (eBPF)
  deriving Repr, DecidableEq, Inhabited

def BpfSize.toNat : BpfSize → Nat
  | .B => 1
  | .H => 2
  | .W => 4
  | .DW => 8

-- ALU/ALU64 operations
inductive BpfAluOp : Type where
  | ADD  : BpfAluOp
  | SUB  : BpfAluOp
  | MUL  : BpfAluOp
  | DIV  : BpfAluOp
  | OR   : BpfAluOp
  | AND  : BpfAluOp
  | LSH  : BpfAluOp  -- left shift
  | RSH  : BpfAluOp  -- right shift (logical)
  | NEG  : BpfAluOp
  | MOD  : BpfAluOp
  | XOR  : BpfAluOp
  | MOV  : BpfAluOp  -- move/copy
  | ARSH : BpfAluOp  -- arithmetic right shift
  deriving Repr, DecidableEq, Inhabited

-- Jump operations
inductive BpfJmpOp : Type where
  | JA   : BpfJmpOp  -- unconditional jump
  | JEQ  : BpfJmpOp  -- jump ==
  | JGT  : BpfJmpOp  -- jump > (unsigned)
  | JGE  : BpfJmpOp  -- jump >= (unsigned)
  | JLT  : BpfJmpOp  -- jump < (unsigned)
  | JLE  : BpfJmpOp  -- jump <= (unsigned)
  | JSET : BpfJmpOp  -- jump if bit set
  | JNE  : BpfJmpOp  -- jump !=
  | JSGT : BpfJmpOp  -- jump > (signed)
  | JSGE : BpfJmpOp  -- jump >= (signed)
  | JSLT : BpfJmpOp  -- jump < (signed)
  | JSLE : BpfJmpOp  -- jump <= (signed)
  | CALL : BpfJmpOp  -- function call
  | EXIT : BpfJmpOp  -- exit program
  deriving Repr, DecidableEq, Inhabited

-- Source operand: register or immediate
inductive BpfSrc : Type where
  | K : BpfSrc  -- immediate (constant)
  | X : BpfSrc  -- register
  deriving Repr, DecidableEq, Inhabited

-- Constants
def BPF_MAXINSNS : Nat := 4096
def MAX_BPF_REG : Nat := 11
def MAX_BPF_STACK : Nat := 512
