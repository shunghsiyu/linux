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

/-! ## Subprograms (BPF-to-BPF calls) -/

/-- Subprogram information -/
structure Subprog where
  /-- Start instruction offset -/
  start : Nat
  /-- Whether this subprogram has been verified -/
  verified : Bool
  deriving Repr, BEq

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
  /-- Loop nesting depth (for detecting loops) -/
  loopDepth : Nat
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
  , loopDepth := 0
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

/-! ## State Merging (Join Operation) -/

/-- Merge two TNum values by computing their join (least upper bound).
    The result conservatively approximates both inputs.

    This is the join operation in the abstract interpretation lattice.
    Used when two control flow paths converge (e.g., after if/else).

    Examples:
    - const(5) ∨ const(5) = const(5)  -- Same constant preserved
    - const(5) ∨ const(10) = unknown  -- Different constants → unknown
    - const(5) ∨ unknown = unknown    -- Conservative approximation
-/
def mergeTNum (a b : TNum) : TNum :=
  if a == b then
    a
  else if a.isConst && b.isConst then
    -- Two different constants: result is unknown
    TNum.unknown
  else
    -- Conservative: mark all differing bits as unknown
    { value := a.value &&& b.value  -- Bits that are 1 in both
    , mask := a.mask ||| b.mask ||| (a.value ^^^ b.value)  -- Unknown bits
    }

/-- Merge two register states by computing their join.
    Used when two control flow paths converge.
-/
def mergeRegState (a b : RegState) : RegState :=
  -- If types differ, result is scalar (conservative)
  let regType := if a.regType == b.regType then a.regType else RegType.ScalarValue

  -- For pointer types, if they're the same type, preserve it
  -- For stack pointers, if offsets differ, use conservative bounds
  let stackOff :=
    if a.regType == RegType.PtrToStack && b.regType == RegType.PtrToStack then
      if a.stackOff == b.stackOff then a.stackOff else 0  -- Conservative
    else
      0

  { regType := regType
  , value := 0  -- Unknown concrete value at merge points
  , tnum := mergeTNum a.tnum b.tnum
  , smin := min a.smin b.smin  -- Take wider signed range
  , smax := max a.smax b.smax
  , umin := min a.umin b.umin  -- Take wider unsigned range
  , umax := max a.umax b.umax
  , stackOff := stackOff
  }

/-- Merge two verifier states by merging all registers and stack slots.
    This computes the join (least upper bound) in the abstract interpretation lattice.
-/
def mergeVerifierState (a b : VerifierState) : VerifierState :=
  -- Merge each register
  let regs := Array.mkArray NUM_REGS RegState.notInit
  let regs := Array.range NUM_REGS |>.foldl (fun regs i =>
    let regA := a.regs.get! i
    let regB := b.regs.get! i
    regs.set! i (mergeRegState regA regB)
  ) regs

  -- Use the PC from the first state (they should be the same at merge points)
  { pc := a.pc
  , regs := regs
  , stack := a.stack  -- Conservative: use first state's stack
  , callDepth := max a.callDepth b.callDepth
  , loopDepth := max a.loopDepth b.loopDepth
  }

/-! ## Abstract Interpretation -/

/-- Abstract addition of two register states.

    Handles both scalar arithmetic and pointer arithmetic:
    - Scalar + Scalar: Normal arithmetic with range propagation
    - Pointer + Scalar: Pointer arithmetic (preserves pointer type)

    For pointer arithmetic, this models the C pattern:
    ```c
    void *ptr = ...;
    void *new_ptr = ptr + offset;  // Preserves pointer type
    ```
-/
def abstractAdd (dst src : RegState) : RegState :=
  -- Handle pointer + scalar addition (pointer arithmetic)
  match dst.regType, src.regType with
  | RegType.PtrToStack, RegType.ScalarValue =>
    -- Stack pointer + offset: preserve pointer type, update stack offset
    { regType := RegType.PtrToStack
    , value := dst.value + src.value
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := UInt64.min
    , umax := UInt64.max
    , stackOff := dst.stackOff + src.value.toInt32  -- Track offset change
    }
  | RegType.PtrToCtx, RegType.ScalarValue =>
    -- Context pointer + offset: preserve pointer type
    { regType := RegType.PtrToCtx
    , value := dst.value + src.value
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := UInt64.min
    , umax := UInt64.max
    , stackOff := 0
    }
  | RegType.PtrToPacket, RegType.ScalarValue =>
    -- Packet pointer + offset: preserve pointer type
    -- This is common in packet parsing: pkt_ptr + 14 to skip Ethernet header
    { regType := RegType.PtrToPacket
    , value := dst.value + src.value
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := UInt64.min
    , umax := UInt64.max
    , stackOff := 0
    }
  | RegType.PtrToMap, RegType.ScalarValue =>
    -- Map value pointer + offset: preserve pointer type
    { regType := RegType.PtrToMap
    , value := dst.value + src.value
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := UInt64.min
    , umax := UInt64.max
    , stackOff := 0
    }
  | _, _ =>
    -- Scalar + scalar: normal arithmetic
    { regType := RegType.ScalarValue
    , value := dst.value + src.value
    , tnum := dst.tnum.add src.tnum
    , smin := dst.smin + src.smin
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
  match dst.regType, src.regType with
  | RegType.PtrToStack, RegType.ScalarValue =>
    -- Stack pointer - offset: preserve pointer type, update stack offset
    { regType := RegType.PtrToStack
    , value := concrete
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := UInt64.min
    , umax := UInt64.max
    , stackOff := dst.stackOff - src.value.toInt32
    }
  | RegType.PtrToCtx, RegType.ScalarValue =>
    -- Context pointer - offset
    { regType := RegType.PtrToCtx
    , value := concrete
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := UInt64.min
    , umax := UInt64.max
    , stackOff := 0
    }
  | RegType.PtrToPacket, RegType.ScalarValue =>
    -- Packet pointer - offset
    { regType := RegType.PtrToPacket
    , value := concrete
    , tnum := TNum.unknown
    , smin := Int64.min
    , smax := Int64.max
    , umin := UInt64.min
    , umax := UInt64.max
    , stackOff := 0
    }
  | RegType.PtrToPacket, RegType.PtrToPacket =>
    -- Packet pointer - packet pointer = scalar offset
    -- This is used to compute packet length: packet_end - packet_start
    let smin := dst.smin - src.smax
    let smax := dst.smax - src.smin
    let umin := if dst.umin.toNat < src.umax.toNat then 0 else dst.umin - src.umax
    { regType := RegType.ScalarValue
    , value := concrete
    , tnum := TNum.unknown
    , smin := smin
    , smax := smax
    , umin := umin
    , umax := dst.umax
    , stackOff := 0
    }
  | _, _ =>
    -- Scalar - scalar: normal arithmetic
    let smin := dst.smin - src.smax
    let smax := dst.smax - src.smin
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

/-! ## Helper Function Abstract Interpretation -/

/-- Abstract interpretation of a helper function call.
    Models the effect of helper functions on register state.
-/
def abstractHelperCall (s : VerifierState) (helper : HelperFunc) : VerifierState :=
  match helper with
  | HelperFunc.MapLookupElem =>
    -- Returns pointer to map value (or NULL)
    -- R0 = map_lookup(R1 = map_ptr, R2 = key_ptr)
    let r0 := RegState.mk RegType.PtrToMap 0 TNum.unknown Int64.min Int64.max 0 UInt64.max 0
    s.setReg Reg.R0 r0
      |>.invalidateCallerSaved  -- Invalidate R1-R5

  | HelperFunc.MapUpdateElem =>
    -- Returns 0 on success, negative on error
    -- R0 = map_update(R1 = map_ptr, R2 = key_ptr, R3 = value_ptr, R4 = flags)
    let r0 := RegState.scalar 0
    s.setReg Reg.R0 { r0 with smin := -1, smax := 0, umin := 0 }
      |>.invalidateCallerSaved

  | HelperFunc.MapDeleteElem =>
    -- Returns 0 on success, negative on error
    let r0 := RegState.scalar 0
    s.setReg Reg.R0 { r0 with smin := -1, smax := 0, umin := 0 }
      |>.invalidateCallerSaved

  | HelperFunc.GetPrandomU32 =>
    -- Returns a random u32 value
    let r0 := RegState.scalar 0
    s.setReg Reg.R0 { r0 with
        umin := 0
        umax := UInt64.ofNat (UInt32.size - 1)
        smin := 0
        smax := Int64.ofNat (UInt32.size - 1)
        tnum := TNum.unknown
      }
      |>.invalidateCallerSaved

  | HelperFunc.KtimeGetNs =>
    -- Returns current time in nanoseconds (u64)
    let r0 := RegState.scalar 0
    s.setReg Reg.R0 { r0 with
        umin := 0
        umax := UInt64.max
        smin := 0
        smax := Int64.max
        tnum := TNum.unknown
      }
      |>.invalidateCallerSaved

  | HelperFunc.TracePrintk =>
    -- Returns number of bytes written
    let r0 := RegState.scalar 0
    s.setReg Reg.R0 { r0 with smin := 0, smax := Int64.max, umin := 0 }
      |>.invalidateCallerSaved

  | HelperFunc.GetSmpProcessorId =>
    -- Returns current CPU ID (bounded by number of CPUs)
    let r0 := RegState.scalar 0
    s.setReg Reg.R0 { r0 with
        umin := 0
        umax := 4096  -- Conservative upper bound on CPU count
        smin := 0
        smax := 4096
      }
      |>.invalidateCallerSaved

  | HelperFunc.ProbeRead =>
    -- Returns 0 on success, negative on error
    let r0 := RegState.scalar 0
    s.setReg Reg.R0 { r0 with smin := -1, smax := 0, umin := 0 }
      |>.invalidateCallerSaved

/-! ## Map Verification -/

/-- Check if a map operation is valid.
    This validates:
    - Map pointer is initialized and correct type
    - Key pointer is initialized
    - For updates: value pointer is initialized
-/
def checkMapOperation (s : VerifierState) (mapReg keyReg : Reg) (valueReg? : Option Reg := none) : Bool :=
  -- Check map register is a pointer (could be PTR_TO_MAP or passed as argument)
  let mapState := s.getReg mapReg
  let mapValid := mapState.isInit

  -- Check key register is initialized
  let keyState := s.getReg keyReg
  let keyValid := keyState.isInit

  -- Check value register if provided
  let valueValid := match valueReg? with
    | none => true
    | some valueReg =>
      let valueState := s.getReg valueReg
      valueState.isInit

  mapValid && keyValid && valueValid

/-- Create a sample map definition for testing -/
def sampleHashMap : MapDef :=
  { id := 1
  , mapType := MapType.Hash
  , keySize := 4      -- 32-bit key
  , valueSize := 8    -- 64-bit value
  , maxEntries := 1024
  }

/-- Create a sample array map for testing -/
def sampleArrayMap : MapDef :=
  { id := 2
  , mapType := MapType.Array
  , keySize := 4      -- 32-bit index
  , valueSize := 16   -- 128-bit value
  , maxEntries := 256
  }

/-! ## Instruction Verification -/

/-- Verification result for a single instruction -/
inductive VerifyInsnResult : Type where
  | Valid : VerifierState → VerifyInsnResult
  | Invalid : SecurityViolation → VerifyInsnResult
  | Branch : VerifierState → VerifierState → VerifyInsnResult  -- true branch, false branch
  deriving Repr

/-! ## Range Refinement -/

/-- Refine register bounds based on a comparison that evaluated to true.
    This is a key verifier optimization that makes bounds tracking precise.

    For example:
    - if (R0 < 100) becomes true → refine R0.umax to 99
    - if (R0 >= 10) becomes true → refine R0.umin to 10
-/
def refineRangeTrue (reg : RegState) (op : JmpOp) (imm : UInt64) : RegState :=
  match op with
  | JmpOp.JEQ =>
    -- R == imm, so R is exactly imm
    { reg with
      value := imm
      tnum := TNum.const imm
      smin := imm.toInt64
      smax := imm.toInt64
      umin := imm
      umax := imm
    }
  | JmpOp.JNE =>
    -- R != imm, can't refine much (would need more complex tracking)
    reg
  | JmpOp.JGT =>
    -- R > imm (unsigned), so R >= imm + 1
    -- Guard against overflow: if imm == UInt64.max, no valid value > imm
    if imm == UInt64.max then
      reg  -- No refinement possible (unreachable branch)
    else
      let newMin := imm + 1
      { reg with
        umin := max reg.umin newMin
        -- Also try to refine signed bounds
        smin := if newMin.toInt64 > reg.smin then newMin.toInt64 else reg.smin
      }
  | JmpOp.JGE =>
    -- R >= imm (unsigned)
    { reg with
      umin := max reg.umin imm
      smin := if imm.toInt64 > reg.smin then imm.toInt64 else reg.smin
    }
  | JmpOp.JLT =>
    -- R < imm (unsigned), so R <= imm - 1
    -- Guard against underflow: if imm == 0, no valid value < 0
    if imm == 0 then
      reg  -- No refinement possible (unreachable branch)
    else
      let newMax := imm - 1
      { reg with
        umax := min reg.umax newMax
      }
  | JmpOp.JLE =>
    -- R <= imm (unsigned)
    { reg with
      umax := min reg.umax imm
    }
  | JmpOp.JSGT =>
    -- R > imm (signed), so R >= imm + 1
    -- Guard against overflow
    if imm.toInt64 == Int64.max then
      reg  -- No refinement possible
    else
      let newMin := imm.toInt64 + 1
      { reg with
        smin := max reg.smin newMin
      }
  | JmpOp.JSGE =>
    -- R >= imm (signed)
    { reg with
      smin := max reg.smin imm.toInt64
    }
  | JmpOp.JSLT =>
    -- R < imm (signed), so R <= imm - 1
    -- Guard against underflow
    if imm.toInt64 == Int64.min then
      reg  -- No refinement possible
    else
      let newMax := imm.toInt64 - 1
      { reg with
        smax := min reg.smax newMax
      }
  | JmpOp.JSLE =>
    -- R <= imm (signed)
    { reg with
      smax := min reg.smax imm.toInt64
    }
  | _ => reg

/-- Refine register bounds for the false branch (condition was false) -/
def refineRangeFalse (reg : RegState) (op : JmpOp) (imm : UInt64) : RegState :=
  match op with
  | JmpOp.JEQ =>
    -- R != imm (can't refine precisely without complex tracking)
    reg
  | JmpOp.JNE =>
    -- R == imm
    { reg with
      value := imm
      tnum := TNum.const imm
      smin := imm.toInt64
      smax := imm.toInt64
      umin := imm
      umax := imm
    }
  | JmpOp.JGT =>
    -- !(R > imm) means R <= imm
    { reg with
      umax := min reg.umax imm
    }
  | JmpOp.JGE =>
    -- !(R >= imm) means R < imm, so R <= imm - 1
    -- Guard against underflow
    if imm == 0 then
      reg  -- No refinement possible (unreachable branch)
    else
      let newMax := imm - 1
      { reg with
        umax := min reg.umax newMax
      }
  | JmpOp.JLT =>
    -- !(R < imm) means R >= imm
    { reg with
      umin := max reg.umin imm
    }
  | JmpOp.JLE =>
    -- !(R <= imm) means R > imm, so R >= imm + 1
    -- Guard against overflow
    if imm == UInt64.max then
      reg  -- No refinement possible (unreachable branch)
    else
      let newMin := imm + 1
      { reg with
        umin := max reg.umin newMin
      }
  | JmpOp.JSGT =>
    -- !(R > imm) means R <= imm (signed)
    { reg with
      smax := min reg.smax imm.toInt64
    }
  | JmpOp.JSGE =>
    -- !(R >= imm) means R < imm (signed), so R <= imm - 1
    -- Guard against underflow
    if imm.toInt64 == Int64.min then
      reg  -- No refinement possible (unreachable branch)
    else
      { reg with
        smax := min reg.smax (imm.toInt64 - 1)
      }
  | JmpOp.JSLT =>
    -- !(R < imm) means R >= imm (signed)
    { reg with
      smin := max reg.smin imm.toInt64
    }
  | JmpOp.JSLE =>
    -- !(R <= imm) means R > imm (signed), so R >= imm + 1
    -- Guard against overflow
    if imm.toInt64 == Int64.max then
      reg  -- No refinement possible (unreachable branch)
    else
      { reg with
        smin := max reg.smin (imm.toInt64 + 1)
      }
  | _ => reg

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
        -- Check for division/modulo by zero
        -- srcReg.mayBeZero means source could potentially be 0
        if (op == AluOp.DIV || op == AluOp.MOD) && srcReg.mayBeZero then
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

    | RegType.PtrToPacket =>
      -- Packet access: bounds must be checked at runtime or via range analysis
      -- For now, allow with conservative analysis
      let loadedValue := RegState.scalar 0
      let newState := s.setReg insn.dst_reg loadedValue
      VerifyInsnResult.Valid { newState with pc := s.pc + 1 }

    | RegType.PtrToCtx =>
      -- Context access: allowed for specific offsets
      -- Simplified: allow all context reads
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

    | RegType.PtrToPacket =>
      -- Packet writes are generally not allowed (read-only in most contexts)
      VerifyInsnResult.Invalid (SecurityViolation.TypeMismatch dstReg.regType RegType.PtrToStack)

    | RegType.PtrToCtx =>
      -- Context writes may be allowed for specific fields (simplified: reject)
      VerifyInsnResult.Invalid (SecurityViolation.TypeMismatch dstReg.regType RegType.PtrToStack)

    | _ =>
      VerifyInsnResult.Invalid (SecurityViolation.TypeMismatch dstReg.regType RegType.PtrToStack)

/-- Verify a jump instruction -/
def verifyJumpInsn (s : VerifierState) (insn : Insn) (prog : Array Insn) : VerifyInsnResult :=
  -- Check for EXIT
  if insn.opcode == 0x95 then
    -- EXIT instruction - program terminates
    VerifyInsnResult.Valid s
  else if insn.opcode == 0x85 then
    -- CALL instruction: could be helper or BPF-to-BPF call
    if insn.src_reg.toNat == 0 then
      -- src_reg == 0: Helper function call
      match HelperFunc.ofId? insn.imm.toNat with
      | some helper =>
        -- Apply helper function's abstract interpretation
        let s' := abstractHelperCall s helper
        VerifyInsnResult.Valid { s' with pc := s'.pc + 1 }
      | none =>
        -- Unknown helper function
        VerifyInsnResult.Invalid SecurityViolation.InvalidInstruction
    else
      -- src_reg != 0: BPF-to-BPF function call
      -- Calculate target: pc + imm + 1
      let target := s.pc.toInt + insn.imm.toInt + 1
      if target < 0 || target.toNat >= prog.size then
        VerifyInsnResult.Invalid (SecurityViolation.InvalidJump target)
      else if s.callDepth >= MAX_CALL_FRAMES then
        VerifyInsnResult.Invalid SecurityViolation.CallStackOverflow
      else
        -- Save return state and jump to subprogram
        -- For simplicity, we invalidate caller-saved registers
        let s' := s.invalidateCallerSaved
        let s'' := { s' with
          pc := target.toNat
          callDepth := s'.callDepth + 1
        }
        VerifyInsnResult.Valid s''
  else if insn.off == 0 then
    -- Unconditional fall-through
    VerifyInsnResult.Valid { s with pc := s.pc + 1 }
  else
    -- Conditional or unconditional jump
    let target := s.pc.toInt + insn.off.toInt + 1
    if target < 0 || target.toNat >= prog.size then
      VerifyInsnResult.Invalid (SecurityViolation.InvalidJump target)
    else
      -- Check for back-edge (loop)
      let isBackEdge := target.toNat <= s.pc

      -- For now, reject loops (classic BPF behavior)
      -- Modern BPF allows bounded loops, which could be added later
      if isBackEdge then
        VerifyInsnResult.Invalid SecurityViolation.InfiniteLoop
      else
        -- Get jump operation for range refinement
        match getJmpOp insn with
        | none =>
          -- Unknown jump type, just branch without refinement
          let trueBranch := { s with pc := target.toNat }
          let falseBranch := { s with pc := s.pc + 1 }
          VerifyInsnResult.Branch trueBranch falseBranch

        | some JmpOp.JA =>
          -- Unconditional jump
          VerifyInsnResult.Valid { s with pc := target.toNat }

        | some jmpOp =>
        -- Conditional jump: apply range refinement
        let dstReg := s.getReg insn.dst_reg

        -- Get comparison value (immediate or register)
        let cmpVal := if insn.isImmediate then
          insn.imm.toUInt64
        else
          (s.getReg insn.src_reg).value

        -- Refine ranges for both branches
        let dstRegTrue := refineRangeTrue dstReg jmpOp cmpVal
        let dstRegFalse := refineRangeFalse dstReg jmpOp cmpVal

        -- Create refined states
        let trueBranch := (s.setReg insn.dst_reg dstRegTrue).incPC.jump insn.off.toInt
        let falseBranch := (s.setReg insn.dst_reg dstRegFalse).incPC

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
