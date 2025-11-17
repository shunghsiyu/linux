/-
  BPF Instruction Set Architecture

  This module defines the BPF instruction format and provides functions
  to decode and classify instructions. The instruction format matches
  the Linux kernel's struct bpf_insn.
-/

import BpfLean.Basic

-- BPF instruction encoding (matches struct bpf_insn from kernel)
structure BpfInsn where
  code : UInt8         -- opcode
  dst_reg : Fin 16     -- destination register (4 bits)
  src_reg : Fin 16     -- source register (4 bits)
  off : Int16          -- signed offset
  imm : Int32          -- signed immediate constant
  deriving Repr, DecidableEq, Inhabited

namespace BpfInsn

-- Extract instruction class from opcode (lower 3 bits)
def getClass (insn : BpfInsn) : Option BpfClass :=
  match insn.code.toNat &&& 0x07 with
  | 0x00 => some .LD
  | 0x01 => some .LDX
  | 0x02 => some .ST
  | 0x03 => some .STX
  | 0x04 => some .ALU
  | 0x05 => some .JMP
  | 0x06 => some .JMP32
  | 0x07 => some .ALU64
  | _ => none

-- Extract size field for load/store instructions
def getSize (insn : BpfInsn) : Option BpfSize :=
  match (insn.code.toNat &&& 0x18) >>> 3 with
  | 0x0 => some .W   -- 32-bit
  | 0x1 => some .H   -- 16-bit
  | 0x2 => some .B   -- 8-bit
  | 0x3 => some .DW  -- 64-bit
  | _ => none

-- Extract ALU operation from opcode
def getAluOp (insn : BpfInsn) : Option BpfAluOp :=
  match (insn.code.toNat &&& 0xf0) with
  | 0x00 => some .ADD
  | 0x10 => some .SUB
  | 0x20 => some .MUL
  | 0x30 => some .DIV
  | 0x40 => some .OR
  | 0x50 => some .AND
  | 0x60 => some .LSH
  | 0x70 => some .RSH
  | 0x80 => some .NEG
  | 0x90 => some .MOD
  | 0xa0 => some .XOR
  | 0xb0 => some .MOV
  | 0xc0 => some .ARSH
  | _ => none

-- Extract jump operation from opcode
def getJmpOp (insn : BpfInsn) : Option BpfJmpOp :=
  match (insn.code.toNat &&& 0xf0) with
  | 0x00 => some .JA
  | 0x10 => some .JEQ
  | 0x20 => some .JGT
  | 0x30 => some .JGE
  | 0x40 => some .JSET
  | 0x50 => some .JNE
  | 0x60 => some .JSGT
  | 0x70 => some .JSGE
  | 0x80 => some .CALL
  | 0x90 => some .EXIT
  | 0xa0 => some .JLT
  | 0xb0 => some .JLE
  | 0xc0 => some .JSLT
  | 0xd0 => some .JSLE
  | _ => none

-- Extract source type (register or immediate)
def getSrc (insn : BpfInsn) : BpfSrc :=
  if (insn.code.toNat &&& 0x08) != 0 then .X else .K

-- Convert 4-bit register field to BpfReg
def regFromFin (r : Fin 16) : Option BpfReg :=
  match r.val with
  | 0 => some .R0
  | 1 => some .R1
  | 2 => some .R2
  | 3 => some .R3
  | 4 => some .R4
  | 5 => some .R5
  | 6 => some .R6
  | 7 => some .R7
  | 8 => some .R8
  | 9 => some .R9
  | 10 => some .R10
  | _ => none  -- Invalid register

def getDstReg (insn : BpfInsn) : Option BpfReg :=
  regFromFin insn.dst_reg

def getSrcReg (insn : BpfInsn) : Option BpfReg :=
  regFromFin insn.src_reg

-- Check if instruction is a call
def isCall (insn : BpfInsn) : Bool :=
  match getClass insn, getJmpOp insn with
  | some (.JMP), some (.CALL) => true
  | _, _ => false

-- Check if instruction is an exit
def isExit (insn : BpfInsn) : Bool :=
  match getClass insn, getJmpOp insn with
  | some (.JMP), some (.EXIT) => true
  | _, _ => false

-- Check if instruction is a jump
def isJump (insn : BpfInsn) : Bool :=
  match getClass insn with
  | some (.JMP) => true
  | some (.JMP32) => true
  | _ => false

end BpfInsn

-- High-level instruction representation for easier reasoning
inductive BpfInstr : Type where
  -- ALU operations
  | AluReg (op : BpfAluOp) (dst : BpfReg) (src : BpfReg) : BpfInstr
  | AluImm (op : BpfAluOp) (dst : BpfReg) (imm : Int32) : BpfInstr
  | Alu64Reg (op : BpfAluOp) (dst : BpfReg) (src : BpfReg) : BpfInstr
  | Alu64Imm (op : BpfAluOp) (dst : BpfReg) (imm : Int32) : BpfInstr

  -- Memory operations
  | LoadReg (size : BpfSize) (dst : BpfReg) (src : BpfReg) (off : Int16) : BpfInstr
  | StoreReg (size : BpfSize) (dst : BpfReg) (src : BpfReg) (off : Int16) : BpfInstr
  | StoreImm (size : BpfSize) (dst : BpfReg) (off : Int16) (imm : Int32) : BpfInstr

  -- Jump operations
  | JumpAlways (off : Int16) : BpfInstr
  | JumpReg (op : BpfJmpOp) (dst : BpfReg) (src : BpfReg) (off : Int16) : BpfInstr
  | JumpImm (op : BpfJmpOp) (dst : BpfReg) (imm : Int32) (off : Int16) : BpfInstr
  | Jump32Reg (op : BpfJmpOp) (dst : BpfReg) (src : BpfReg) (off : Int16) : BpfInstr
  | Jump32Imm (op : BpfJmpOp) (dst : BpfReg) (imm : Int32) (off : Int16) : BpfInstr

  -- Special operations
  | Call (imm : Int32) : BpfInstr  -- helper function call
  | Exit : BpfInstr                -- program exit

  deriving Repr, Inhabited

-- Decode a low-level BpfInsn into high-level BpfInstr
def decodeBpfInsn (insn : BpfInsn) : Option BpfInstr :=
  match insn.getClass with
  | some .ALU =>
      match insn.getAluOp, insn.getDstReg with
      | some op, some dst =>
          if insn.getSrc == .X then
            insn.getSrcReg.map (fun src => .AluReg op dst src)
          else
            some (.AluImm op dst insn.imm)
      | _, _ => none

  | some .ALU64 =>
      match insn.getAluOp, insn.getDstReg with
      | some op, some dst =>
          if insn.getSrc == .X then
            insn.getSrcReg.map (fun src => .Alu64Reg op dst src)
          else
            some (.Alu64Imm op dst insn.imm)
      | _, _ => none

  | some .LDX =>
      match insn.getSize, insn.getDstReg, insn.getSrcReg with
      | some sz, some dst, some src =>
          some (.LoadReg sz dst src insn.off)
      | _, _, _ => none

  | some .STX =>
      match insn.getSize, insn.getDstReg, insn.getSrcReg with
      | some sz, some dst, some src =>
          some (.StoreReg sz dst src insn.off)
      | _, _, _ => none

  | some .ST =>
      match insn.getSize, insn.getDstReg with
      | some sz, some dst =>
          some (.StoreImm sz dst insn.off insn.imm)
      | _, _ => none

  | some .JMP =>
      match insn.getJmpOp with
      | some .CALL => some (.Call insn.imm)
      | some .EXIT => some .Exit
      | some .JA => some (.JumpAlways insn.off)
      | some op =>
          match insn.getDstReg with
          | some dst =>
              if insn.getSrc == .X then
                insn.getSrcReg.map (fun src => .JumpReg op dst src insn.off)
              else
                some (.JumpImm op dst insn.imm insn.off)
          | none => none
      | none => none

  | some .JMP32 =>
      match insn.getJmpOp, insn.getDstReg with
      | some op, some dst =>
          if insn.getSrc == .X then
            insn.getSrcReg.map (fun src => .Jump32Reg op dst src insn.off)
          else
            some (.Jump32Imm op dst insn.imm insn.off)
      | _, _ => none

  | _ => none
