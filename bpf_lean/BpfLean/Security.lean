/-
  BPF Security Policy (Proof-Carrying Code)

  This module defines the security policy for BPF programs.
  The policy ensures:
  1. Type safety: registers have well-defined types
  2. Memory safety: all memory accesses are within bounds
  3. Control flow safety: no unbounded loops
  4. Resource safety: references are properly acquired and released

  This is the "proof" part of proof-carrying code - the verifier checks
  that the program satisfies these properties before execution.
-/

import BpfLean.Basic
import BpfLean.Instruction
import BpfLean.State

-- Register types tracked by the verifier
inductive RegType where
  | NotInit : RegType                    -- uninitialized
  | ScalarValue : RegType                -- scalar (integer) value
  | PtrToCtx : RegType                   -- pointer to context
  | PtrToStack (off : Int) : RegType     -- pointer to stack + offset
  | PtrToMapValue : RegType              -- pointer to map value
  | PtrToMapValueOrNull : RegType        -- nullable map value pointer
  | PtrToPacket : RegType                -- pointer to packet data
  | ConstPtrToMap : RegType              -- constant pointer to map
  deriving Repr, DecidableEq, Inhabited

-- Abstract value tracking bounds
structure AbstractValue where
  -- Tristate number (tnum) - tracks which bits are known
  known_mask : UInt64   -- bits that are known (1 = known, 0 = unknown)
  known_value : UInt64  -- values of known bits

  -- Value ranges (signed and unsigned)
  umin : UInt64         -- minimum unsigned value
  umax : UInt64         -- maximum unsigned value
  smin : Int64          -- minimum signed value
  smax : Int64          -- maximum signed value

  -- 32-bit ranges
  u32_min : UInt32
  u32_max : UInt32
  s32_min : Int32
  s32_max : Int32
  deriving Repr, Inhabited

namespace AbstractValue

-- Create an abstract value from a constant
def fromConst (c : UInt64) : AbstractValue :=
  { known_mask := 0xffffffffffffffff
  , known_value := c
  , umin := c
  , umax := c
  , smin := c.toInt64
  , smax := c.toInt64
  , u32_min := (c &&& 0xffffffff).toUInt32
  , u32_max := (c &&& 0xffffffff).toUInt32
  , s32_min := (c &&& 0xffffffff).toUInt32.toInt32
  , s32_max := (c &&& 0xffffffff).toUInt32.toInt32
  }

-- Unknown value
def unknown : AbstractValue :=
  { known_mask := 0
  , known_value := 0
  , umin := 0
  , umax := 0xffffffffffffffff
  , smin := -9223372036854775808  -- Int64.min
  , smax := 9223372036854775807   -- Int64.max
  , u32_min := 0
  , u32_max := 0xffffffff
  , s32_min := -2147483648  -- Int32.min
  , s32_max := 2147483647   -- Int32.max
  }

-- Check if value could be zero
def maybeZero (v : AbstractValue) : Bool :=
  v.umin == 0 || (v.umin <= 0 && 0 <= v.umax)

-- Check if value is definitely not zero
def definitelyNonZero (v : AbstractValue) : Bool :=
  v.umin > 0

-- Abstract addition
def add (a b : AbstractValue) : AbstractValue :=
  { known_mask := a.known_mask &&& b.known_mask &&& ~~~(a.known_value ^^^ b.known_value)
  , known_value := a.known_value + b.known_value
  , umin := a.umin + b.umin
  , umax := a.umax + b.umax
  , smin := a.smin + b.smin
  , smax := a.smax + b.smax
  , u32_min := a.u32_min + b.u32_min
  , u32_max := a.u32_max + b.u32_max
  , s32_min := a.s32_min + b.s32_min
  , s32_max := a.s32_max + b.s32_max
  }

-- Abstract subtraction
def sub (a b : AbstractValue) : AbstractValue :=
  { known_mask := a.known_mask &&& b.known_mask &&& ~~~(a.known_value ^^^ ~~~b.known_value)
  , known_value := a.known_value - b.known_value
  , umin := if a.umin >= b.umax then a.umin - b.umax else 0
  , umax := a.umax - b.umin  -- may overflow, simplified
  , smin := a.smin - b.smax
  , smax := a.smax - b.smin
  , u32_min := if a.u32_min >= b.u32_max then a.u32_min - b.u32_max else 0
  , u32_max := a.u32_max - b.u32_min
  , s32_min := a.s32_min - b.s32_max
  , s32_max := a.s32_max - b.s32_min
  }

-- Abstract multiplication (simplified - loses precision)
def mul (_a _b : AbstractValue) : AbstractValue := unknown

-- Abstract division (simplified)
def div (_a _b : AbstractValue) : AbstractValue := unknown

-- Bitwise OR
def bitwiseOr (a b : AbstractValue) : AbstractValue :=
  let known := a.known_mask &&& b.known_mask
  let value := a.known_value ||| b.known_value
  { known_mask := known
  , known_value := value
  , umin := a.umin ||| b.umin  -- conservative approximation
  , umax := a.umax ||| b.umax
  , smin := -9223372036854775808  -- Int64.min
  , smax := 9223372036854775807   -- Int64.max
  , u32_min := a.u32_min ||| b.u32_min
  , u32_max := a.u32_max ||| b.u32_max
  , s32_min := -2147483648  -- Int32.min
  , s32_max := 2147483647   -- Int32.max
  }

-- Bitwise AND
def bitwiseAnd (a b : AbstractValue) : AbstractValue :=
  let known := a.known_mask &&& b.known_mask
  let value := a.known_value &&& b.known_value
  { known_mask := known
  , known_value := value
  , umin := 0  -- conservative
  , umax := min a.umax b.umax  -- AND can only make values smaller
  , smin := -9223372036854775808  -- Int64.min
  , smax := 9223372036854775807   -- Int64.max
  , u32_min := 0
  , u32_max := min a.u32_max b.u32_max
  , s32_min := -2147483648  -- Int32.min
  , s32_max := 2147483647   -- Int32.max
  }

-- Merge two abstract values (join in abstract interpretation lattice)
-- This is used at control flow join points to create a safe over-approximation
def merge (a b : AbstractValue) : AbstractValue :=
  -- Only bits known in both are known in the result
  let known := a.known_mask &&& b.known_mask
  -- For known bits, they must have the same value in both
  let consistent := ~~~(a.known_value ^^^ b.known_value)
  let final_known := known &&& consistent
  let final_value := a.known_value &&& final_known

  { known_mask := final_known
  , known_value := final_value
  , umin := min a.umin b.umin
  , umax := max a.umax b.umax
  , smin := min a.smin b.smin
  , smax := max a.smax b.smax
  , u32_min := min a.u32_min b.u32_min
  , u32_max := max a.u32_max b.u32_max
  , s32_min := min a.s32_min b.s32_min
  , s32_max := max a.s32_max b.s32_max
  }

end AbstractValue

-- Taint tracking for data flow analysis
inductive TaintSource where
  | UserInput : TaintSource      -- from user-controlled input (packet, etc.)
  | MapValue : TaintSource       -- from map lookup
  | Trusted : TaintSource        -- from trusted source
  deriving Repr, DecidableEq, Inhabited

-- Taint information
structure TaintInfo where
  tainted : Bool
  source : TaintSource
  deriving Repr, Inhabited

namespace TaintInfo

def trusted : TaintInfo :=
  { tainted := false, source := .Trusted }

def fromUserInput : TaintInfo :=
  { tainted := true, source := .UserInput }

def fromMapValue : TaintInfo :=
  { tainted := true, source := .MapValue }

-- Taint propagates through operations
def merge (t1 t2 : TaintInfo) : TaintInfo :=
  if t1.tainted || t2.tainted then
    -- If either is tainted, result is tainted
    -- Source is the more dangerous one (UserInput > MapValue > Trusted)
    match t1.source, t2.source with
    | .UserInput, _ => { tainted := true, source := .UserInput }
    | _, .UserInput => { tainted := true, source := .UserInput }
    | .MapValue, _ => { tainted := true, source := .MapValue }
    | _, .MapValue => { tainted := true, source := .MapValue }
    | _, _ => t1
  else
    .trusted

end TaintInfo

-- Pointer bounds information for safety checking
structure PointerBounds where
  -- For stack pointers: offset range
  minOffset : Int
  maxOffset : Int
  -- For packet pointers: valid data range
  validRange : Nat
  -- Alignment requirement (power of 2)
  alignment : Nat
  deriving Repr, Inhabited

namespace PointerBounds

def stack (minOff maxOff : Int) : PointerBounds :=
  { minOffset := minOff
  , maxOffset := maxOff
  , validRange := 0
  , alignment := 1
  }

def packet (range : Nat) (align : Nat := 1) : PointerBounds :=
  { minOffset := 0
  , maxOffset := (range : Int)
  , validRange := range
  , alignment := align
  }

-- Merge bounds (take intersection for safety)
def merge (b1 b2 : PointerBounds) : PointerBounds :=
  { minOffset := max b1.minOffset b2.minOffset
  , maxOffset := min b1.maxOffset b2.maxOffset
  , validRange := min b1.validRange b2.validRange
  , alignment := Nat.gcd b1.alignment b2.alignment
  }

-- Add constant offset to bounds
def addOffset (b : PointerBounds) (off : Int) : PointerBounds :=
  { b with
    minOffset := b.minOffset + off
    maxOffset := b.maxOffset + off
  }

-- Check if offset is within bounds
def inBounds (b : PointerBounds) (off : Int) (size : Nat) : Bool :=
  let accessStart := off
  let accessEnd := off + (size : Int)
  b.minOffset <= accessStart && accessEnd <= b.maxOffset

end PointerBounds

-- Abstract register state (what the verifier tracks)
structure AbstractReg where
  regType : RegType
  value : AbstractValue
  -- Additional metadata
  id : Nat                    -- for tracking related pointers
  off : Int                   -- constant offset for pointers
  range : Nat                 -- valid range for packet pointers
  deriving Repr, Inhabited

namespace AbstractReg

def notInit : AbstractReg :=
  { regType := .NotInit
  , value := AbstractValue.unknown
  , id := 0
  , off := 0
  , range := 0
  }

def scalarFromConst (c : UInt64) : AbstractReg :=
  { regType := .ScalarValue
  , value := AbstractValue.fromConst c
  , id := 0
  , off := 0
  , range := 0
  }

def scalarUnknown : AbstractReg :=
  { regType := .ScalarValue
  , value := AbstractValue.unknown
  , id := 0
  , off := 0
  , range := 0
  }

def ptrToStack (offset : Int) : AbstractReg :=
  { regType := .PtrToStack offset
  , value := AbstractValue.unknown
  , id := 0
  , off := offset
  , range := 0
  }

-- Check if register is initialized
def isInit (r : AbstractReg) : Bool :=
  r.regType != .NotInit

-- Check if register is a pointer type
def isPointer (r : AbstractReg) : Bool :=
  match r.regType with
  | .NotInit => false
  | .ScalarValue => false
  | _ => true

-- Get taint info for a register (conservative)
def getTaint (r : AbstractReg) : TaintInfo :=
  match r.regType with
  | .NotInit => TaintInfo.trusted
  | .ScalarValue => TaintInfo.trusted  -- scalars are trusted by default
  | .PtrToPacket => TaintInfo.fromUserInput  -- packet data is user-controlled
  | .PtrToMapValue => TaintInfo.fromMapValue
  | .PtrToMapValueOrNull => TaintInfo.fromMapValue
  | _ => TaintInfo.trusted

-- Get pointer bounds for a register
def getBounds (r : AbstractReg) : Option PointerBounds :=
  match r.regType with
  | .PtrToStack stackOff =>
      -- Stack pointer: offset range based on stack offset
      some (PointerBounds.stack (stackOff - 512) stackOff)
  | .PtrToPacket =>
      -- Packet pointer: use range field
      some (PointerBounds.packet r.range)
  | .PtrToMapValue =>
      -- Map value: assume some reasonable bounds
      some (PointerBounds.stack 0 4096)
  | _ => none  -- Not a pointer or unknown bounds

-- Check if register can be safely used for memory access
def canAccessMemory (r : AbstractReg) (off : Int) (size : Nat) : Bool :=
  match r.getBounds with
  | none => false  -- Not a valid pointer
  | some bounds => bounds.inBounds (r.off + off) size

-- Pointer arithmetic: add scalar to pointer
def addScalar (ptr : AbstractReg) (scalar : AbstractReg) : AbstractReg :=
  if !ptr.isPointer then
    scalar  -- Not a pointer, return scalar
  else if !scalar.isInit then
    AbstractReg.notInit  -- Uninitialized scalar
  else
    -- Add scalar value to pointer offset
    let newOff := ptr.off + scalar.value.smin.toInt
    { ptr with off := newOff }

-- Create a register from packet pointer with bounds
def packetPtr (range : Nat) : AbstractReg :=
  { regType := .PtrToPacket
  , value := AbstractValue.unknown
  , id := 1
  , off := 0
  , range := range
  }

-- Create a tainted scalar (from user input)
def taintedScalar : AbstractReg :=
  { regType := .ScalarValue
  , value := AbstractValue.unknown
  , id := 0
  , off := 0
  , range := 0
  }

end AbstractReg

-- Abstract state of all registers
def AbstractRegFile := BpfReg → AbstractReg

namespace AbstractRegFile

-- Initial state: R1 has context pointer, R10 has stack pointer, others uninitialized
def init : AbstractRegFile :=
  fun r => match r with
  | .R1 => { AbstractReg.notInit with regType := .PtrToCtx }
  | .R10 => AbstractReg.ptrToStack 0
  | _ => AbstractReg.notInit

def read (regs : AbstractRegFile) (r : BpfReg) : AbstractReg :=
  regs r

def write (regs : AbstractRegFile) (r : BpfReg) (val : AbstractReg) : AbstractRegFile :=
  fun r' => if r == r' then val else regs r'

end AbstractRegFile

-- Security policy: properties that must hold
structure SecurityPolicy where
  -- Maximum program size
  maxInsns : Nat := BPF_MAXINSNS

  -- Maximum stack size
  maxStack : Nat := MAX_BPF_STACK

  -- No unbounded loops (enforced by DAG check)
  noLoops : Bool := true

  -- All memory accesses must be in bounds
  boundsCheck : Bool := true

  -- All registers must be initialized before use
  initCheck : Bool := true

  -- Division by zero returns 0 (not an error)
  divByZeroSafe : Bool := true

  deriving Repr, Inhabited

namespace SecurityPolicy

def default : SecurityPolicy := {}

end SecurityPolicy

-- Verification error
inductive VerifyError where
  | ProgramTooLarge : VerifyError
  | InvalidInstruction (pc : Nat) : VerifyError
  | UninitializedRegister (pc : Nat) (reg : BpfReg) : VerifyError
  | InvalidMemoryAccess (pc : Nat) : VerifyError
  | InvalidJump (pc : Nat) : VerifyError
  | BackEdgeDetected (pc : Nat) : VerifyError
  | TypeMismatch (pc : Nat) (expected : RegType) (actual : RegType) : VerifyError
  | StackOutOfBounds (pc : Nat) : VerifyError
  | Other (msg : String) : VerifyError
  deriving Repr

-- Safety certificate: proof that a program satisfies the security policy
structure SafetyCertificate where
  policy : SecurityPolicy
  programSize : Nat
  isDAG : Bool
  -- In a full implementation, this would contain:
  -- - Type annotations for each instruction
  -- - Invariants at each program point
  -- - Proof obligations that have been discharged
  deriving Repr, Inhabited

-- Check if a program satisfies the basic security policy requirements
def checkBasicPolicy (prog : Array BpfInsn) (policy : SecurityPolicy) : Option VerifyError :=
  -- Check program size
  if prog.size > policy.maxInsns then
    some .ProgramTooLarge
  else
    -- Additional basic checks would go here
    none

-- Check if all instructions are valid
def checkInstructionsValid (prog : Array BpfInsn) : Option VerifyError :=
  prog.findIdx? (fun insn => decodeBpfInsn insn |>.isNone)
    |>.map (fun idx => .InvalidInstruction idx)

-- Placeholder: full verification would track abstract state through all paths
def verify (prog : Array BpfInsn) (policy : SecurityPolicy) : Except VerifyError SafetyCertificate :=
  -- Check basic properties
  match checkBasicPolicy prog policy with
  | some err => .error err
  | none =>
      match checkInstructionsValid prog with
      | some err => .error err
      | none =>
          -- Would perform full abstract interpretation here
          .ok { policy := policy
              , programSize := prog.size
              , isDAG := true  -- Simplified
              }
