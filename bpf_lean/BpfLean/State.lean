/-
  BPF Virtual Machine State

  This module defines the state of the BPF virtual machine, including
  registers, memory, and execution control flow. It also provides the
  state machine semantics for instruction execution.
-/

import BpfLean.Basic
import BpfLean.Instruction
import BpfLean.Maps

-- Register file: maps each BPF register to a 64-bit value
def RegFile := BpfReg → UInt64

namespace RegFile

def init : RegFile := fun _ => 0

def read (regs : RegFile) (r : BpfReg) : UInt64 :=
  regs r

def write (regs : RegFile) (r : BpfReg) (val : UInt64) : RegFile :=
  fun r' => if r == r' then val else regs r'

-- R10 (frame pointer) is read-only, writes are ignored
def writeChecked (regs : RegFile) (r : BpfReg) (val : UInt64) : RegFile :=
  if r == .R10 then regs else write regs r val

end RegFile

-- Memory: byte-addressable memory
-- For simplicity, we model this as a function from addresses to bytes
-- In practice, BPF has limited memory: stack + map values + packet data
structure Memory where
  data : UInt64 → Option UInt8
  deriving Inhabited

namespace Memory

def init : Memory := ⟨fun _ => none⟩

def read8 (mem : Memory) (addr : UInt64) : Option UInt8 :=
  mem.data addr

def write8 (mem : Memory) (addr : UInt64) (val : UInt8) : Memory :=
  ⟨fun addr' => if addr == addr' then some val else mem.data addr'⟩

-- Read multi-byte values (little-endian)
def read16 (mem : Memory) (addr : UInt64) : Option UInt16 :=
  match read8 mem addr, read8 mem (addr + 1) with
  | some b0, some b1 =>
      some (b0.toUInt16 ||| (b1.toUInt16 <<< 8))
  | _, _ => none

def read32 (mem : Memory) (addr : UInt64) : Option UInt32 :=
  match read16 mem addr, read16 mem (addr + 2) with
  | some w0, some w1 =>
      some (w0.toUInt32 ||| (w1.toUInt32 <<< 16))
  | _, _ => none

def read64 (mem : Memory) (addr : UInt64) : Option UInt64 :=
  match read32 mem addr, read32 mem (addr + 4) with
  | some d0, some d1 =>
      some (d0.toUInt64 ||| (d1.toUInt64 <<< 32))
  | _, _ => none

-- Write multi-byte values (little-endian)
def write16 (mem : Memory) (addr : UInt64) (val : UInt16) : Memory :=
  let b0 := (val &&& 0xff).toUInt8
  let b1 := ((val >>> 8) &&& 0xff).toUInt8
  write8 (write8 mem addr b0) (addr + 1) b1

def write32 (mem : Memory) (addr : UInt64) (val : UInt32) : Memory :=
  let w0 := (val &&& 0xffff).toUInt16
  let w1 := ((val >>> 16) &&& 0xffff).toUInt16
  write16 (write16 mem addr w0) (addr + 2) w1

def write64 (mem : Memory) (addr : UInt64) (val : UInt64) : Memory :=
  let d0 := (val &&& 0xffffffff).toUInt32
  let d1 := ((val >>> 32) &&& 0xffffffff).toUInt32
  write32 (write32 mem addr d0) (addr + 4) d1

end Memory

-- Execution result
inductive ExecResult where
  | Continue : ExecResult           -- continue execution
  | Exit (ret : UInt64) : ExecResult  -- program exited with return value
  | Error (msg : String) : ExecResult -- execution error
  deriving Repr, Inhabited

-- BPF VM State
structure BpfState where
  regs : RegFile           -- register file
  mem : Memory             -- memory
  pc : Nat                 -- program counter
  prog : Array BpfInsn     -- the program
  fuel : Nat               -- execution fuel (for termination)
  maps : MapTable          -- available maps (for helper calls)

instance : Inhabited BpfState where
  default := {
    regs := RegFile.init
    mem := Memory.init
    pc := 0
    prog := #[]
    fuel := 0
    maps := MapTable.empty
  }

namespace BpfState

def init (prog : Array BpfInsn) (fuel : Nat := 10000) (maps : MapTable := MapTable.empty) : BpfState :=
  { regs := RegFile.init
  , mem := Memory.init
  , pc := 0
  , prog := prog
  , fuel := fuel
  , maps := maps
  }

-- Execute ALU operations
def execAluOp (op : BpfAluOp) (x y : UInt64) (is64bit : Bool) : Option UInt64 :=
  let truncate (v : UInt64) := if is64bit then v else (v &&& 0xffffffff)
  let x' := if is64bit then x else (x &&& 0xffffffff)
  let y' := if is64bit then y else (y &&& 0xffffffff)

  match op with
  | .ADD => some (truncate (x' + y'))
  | .SUB => some (truncate (x' - y'))
  | .MUL => some (truncate (x' * y'))
  | .DIV => if y' == 0 then some 0 else some (truncate (x' / y'))
  | .OR => some (truncate (x' ||| y'))
  | .AND => some (truncate (x' &&& y'))
  | .LSH => if y' < 64 then some (truncate (x'.shiftLeft y')) else some 0
  | .RSH => if y' < 64 then some (truncate (x'.shiftRight y')) else some 0
  | .NEG => some (truncate (~~~x'))
  | .MOD => if y' == 0 then some x' else some (truncate (x' % y'))
  | .XOR => some (truncate (x' ^^^ y'))
  | .MOV => some y'
  | .ARSH =>
      -- Arithmetic right shift (sign-extending)
      -- For simplicity, we implement this as logical shift
      -- A proper implementation would handle sign extension
      if y' < 64 then
        if is64bit then
          some (truncate (x'.shiftRight y'))
        else
          let x32 := x' &&& 0xffffffff
          some (truncate (x32.shiftRight y'))
      else
        some 0

-- Execute jump condition
def evalJmpCond (op : BpfJmpOp) (x y : UInt64) (is32bit : Bool) : Bool :=
  let x' := if is32bit then (x &&& 0xffffffff) else x
  let y' := if is32bit then (y &&& 0xffffffff) else y

  match op with
  | .JEQ => x' == y'
  | .JNE => x' != y'
  | .JGT => x' > y'  -- unsigned
  | .JGE => x' >= y'
  | .JLT => x' < y'
  | .JLE => x' <= y'
  | .JSET => (x' &&& y') != 0
  | .JSGT => x'.toInt64 > y'.toInt64  -- signed
  | .JSGE => x'.toInt64 >= y'.toInt64
  | .JSLT => x'.toInt64 < y'.toInt64
  | .JSLE => x'.toInt64 <= y'.toInt64
  | _ => false

-- Helper function: convert UInt64 to byte list (little-endian)
def uint64ToBytes (val : UInt64) : List UInt8 :=
  let b0 := ((val >>> 0) &&& 0xff).toUInt8
  let b1 := ((val >>> 8) &&& 0xff).toUInt8
  let b2 := ((val >>> 16) &&& 0xff).toUInt8
  let b3 := ((val >>> 24) &&& 0xff).toUInt8
  let b4 := ((val >>> 32) &&& 0xff).toUInt8
  let b5 := ((val >>> 40) &&& 0xff).toUInt8
  let b6 := ((val >>> 48) &&& 0xff).toUInt8
  let b7 := ((val >>> 56) &&& 0xff).toUInt8
  [b0, b1, b2, b3, b4, b5, b6, b7]

-- Helper function: convert byte list to UInt64 (little-endian)
def bytesToUInt64 (bytes : List UInt8) : UInt64 :=
  match bytes with
  | [b0, b1, b2, b3, b4, b5, b6, b7] =>
      b0.toUInt64 |||
      (b1.toUInt64 <<< 8) |||
      (b2.toUInt64 <<< 16) |||
      (b3.toUInt64 <<< 24) |||
      (b4.toUInt64 <<< 32) |||
      (b5.toUInt64 <<< 40) |||
      (b6.toUInt64 <<< 48) |||
      (b7.toUInt64 <<< 56)
  | _ => 0  -- Invalid length, return 0

-- Execute a helper function call
-- Arguments are in R1-R5, result goes in R0
-- Returns updated state and whether call succeeded
def execHelper (st : BpfState) (helperId : Int32) : BpfState × Bool :=
  match BpfHelper.fromInt? helperId with
  | none => (st, false)  -- Unknown helper

  | some .MapLookupElem =>
      -- R1 = map fd (as pointer), R2 = key pointer
      -- Returns pointer to value in R0, or 0 if not found
      let mapFd := st.regs.read .R1
      let keyPtr := st.regs.read .R2

      -- For simulation, treat mapFd as direct index
      match st.maps.get mapFd.toNat with
      | none =>
          -- Invalid map, return null
          let regs' := st.regs.writeChecked .R0 0
          ({ st with regs := regs' }, true)
      | some map =>
          -- Read key from memory (simplified: assume 8-byte key at keyPtr)
          match st.mem.read64 keyPtr with
          | none =>
              let regs' := st.regs.writeChecked .R0 0
              ({ st with regs := regs' }, true)
          | some keyVal =>
              let keyBytes := uint64ToBytes keyVal
              -- Lookup in map
              match map.lookup keyBytes with
              | MapValue.None =>
                  let regs' := st.regs.writeChecked .R0 0
                  ({ st with regs := regs' }, true)
              | MapValue.Some _value =>
                  -- Return a fake pointer (in real BPF, this would be actual pointer)
                  -- For simulation, return keyPtr + 0x1000 to indicate success
                  let regs' := st.regs.writeChecked .R0 (keyPtr + 0x1000)
                  ({ st with regs := regs' }, true)

  | some .MapUpdateElem =>
      -- R1 = map fd, R2 = key pointer, R3 = value pointer, R4 = flags
      let mapFd := st.regs.read .R1
      let keyPtr := st.regs.read .R2
      let valPtr := st.regs.read .R3

      match st.maps.get mapFd.toNat with
      | none =>
          -- Invalid map, return error (-1)
          let regs' := st.regs.writeChecked .R0 (UInt64.ofNat (2^64 - 1))
          ({ st with regs := regs' }, true)
      | some map =>
          -- Read key and value from memory
          match st.mem.read64 keyPtr, st.mem.read64 valPtr with
          | some keyVal, some value =>
              let keyBytes := uint64ToBytes keyVal
              let valBytes := uint64ToBytes value
              -- Update map
              let map' := map.update keyBytes valBytes
              let maps' := st.maps.set mapFd.toNat map'
              -- Return success (0)
              let regs' := st.regs.writeChecked .R0 0
              ({ st with regs := regs', maps := maps' }, true)
          | _, _ =>
              -- Memory read failed, return error
              let regs' := st.regs.writeChecked .R0 (UInt64.ofNat (2^64 - 1))
              ({ st with regs := regs' }, true)

  | some .MapDeleteElem =>
      -- R1 = map fd, R2 = key pointer
      let mapFd := st.regs.read .R1
      let keyPtr := st.regs.read .R2

      match st.maps.get mapFd.toNat with
      | none =>
          let regs' := st.regs.writeChecked .R0 (UInt64.ofNat (2^64 - 1))
          ({ st with regs := regs' }, true)
      | some map =>
          match st.mem.read64 keyPtr with
          | some keyVal =>
              let keyBytes := uint64ToBytes keyVal
              let map' := map.delete keyBytes
              let maps' := st.maps.set mapFd.toNat map'
              let regs' := st.regs.writeChecked .R0 0
              ({ st with regs := regs', maps := maps' }, true)
          | none =>
              let regs' := st.regs.writeChecked .R0 (UInt64.ofNat (2^64 - 1))
              ({ st with regs := regs' }, true)

  | some .GetProcTime =>
      -- Return a fake timestamp (nanoseconds)
      let regs' := st.regs.writeChecked .R0 1234567890
      ({ st with regs := regs' }, true)

  | some .TraceMsg =>
      -- R1 = format string, R2 = format string size, R3-R5 = arguments
      -- For simulation, just return success
      let regs' := st.regs.writeChecked .R0 0
      ({ st with regs := regs' }, true)

-- Execute a single instruction
def step (st : BpfState) : BpfState × ExecResult :=
  if st.fuel == 0 then
    (st, .Error "out of fuel")
  else if st.pc >= st.prog.size then
    (st, .Error "pc out of bounds")
  else
    let insn := st.prog[st.pc]!
    let st' := { st with pc := st.pc + 1, fuel := st.fuel - 1 }

    match decodeBpfInsn insn with
    | none => (st, .Error "invalid instruction")

    | some .Exit =>
        let retval := st.regs.read .R0
        (st', .Exit retval)

    | some (.Alu64Reg op dst src) =>
        let x := st.regs.read dst
        let y := st.regs.read src
        match execAluOp op x y true with
        | some result =>
            let regs' := st.regs.writeChecked dst result
            ({ st' with regs := regs' }, .Continue)
        | none => (st, .Error "alu operation failed")

    | some (.Alu64Imm op dst imm) =>
        let x := st.regs.read dst
        let y := imm.toInt64.toUInt64
        match execAluOp op x y true with
        | some result =>
            let regs' := st.regs.writeChecked dst result
            ({ st' with regs := regs' }, .Continue)
        | none => (st, .Error "alu operation failed")

    | some (.AluReg op dst src) =>
        let x := st.regs.read dst
        let y := st.regs.read src
        match execAluOp op x y false with
        | some result =>
            let regs' := st.regs.writeChecked dst result
            ({ st' with regs := regs' }, .Continue)
        | none => (st, .Error "alu operation failed")

    | some (.AluImm op dst imm) =>
        let x := st.regs.read dst
        let y := imm.toInt64.toUInt64
        match execAluOp op x y false with
        | some result =>
            let regs' := st.regs.writeChecked dst result
            ({ st' with regs := regs' }, .Continue)
        | none => (st, .Error "alu operation failed")

    | some (.LoadReg sz dst src off) =>
        let addr := st.regs.read src + off.toInt64.toUInt64
        match sz with
        | .B => match st.mem.read8 addr with
            | some b =>
                let regs' := st.regs.writeChecked dst b.toUInt64
                ({ st' with regs := regs' }, .Continue)
            | none => (st, .Error "memory read failed")
        | .H => match st.mem.read16 addr with
            | some h =>
                let regs' := st.regs.writeChecked dst h.toUInt64
                ({ st' with regs := regs' }, .Continue)
            | none => (st, .Error "memory read failed")
        | .W => match st.mem.read32 addr with
            | some w =>
                let regs' := st.regs.writeChecked dst w.toUInt64
                ({ st' with regs := regs' }, .Continue)
            | none => (st, .Error "memory read failed")
        | .DW => match st.mem.read64 addr with
            | some dw =>
                let regs' := st.regs.writeChecked dst dw
                ({ st' with regs := regs' }, .Continue)
            | none => (st, .Error "memory read failed")

    | some (.StoreReg sz dst src off) =>
        let addr := st.regs.read dst + off.toInt64.toUInt64
        let val := st.regs.read src
        let mem' := match sz with
          | .B => st.mem.write8 addr (val &&& 0xff).toUInt8
          | .H => st.mem.write16 addr (val &&& 0xffff).toUInt16
          | .W => st.mem.write32 addr (val &&& 0xffffffff).toUInt32
          | .DW => st.mem.write64 addr val
        ({ st' with mem := mem' }, .Continue)

    | some (.StoreImm sz dst off imm) =>
        let addr := st.regs.read dst + off.toInt64.toUInt64
        let val := imm.toInt64.toUInt64
        let mem' := match sz with
          | .B => st.mem.write8 addr (val &&& 0xff).toUInt8
          | .H => st.mem.write16 addr (val &&& 0xffff).toUInt16
          | .W => st.mem.write32 addr (val &&& 0xffffffff).toUInt32
          | .DW => st.mem.write64 addr val
        ({ st' with mem := mem' }, .Continue)

    | some (.JumpAlways off) =>
        let target := st.pc + 1 + off.toInt
        if target >= 0 && target.toNat < st.prog.size then
          ({ st' with pc := target.toNat }, .Continue)
        else
          (st, .Error "jump out of bounds")

    | some (.JumpReg op dst src off) =>
        let x := st.regs.read dst
        let y := st.regs.read src
        if evalJmpCond op x y false then
          let target := st.pc + 1 + off.toInt
          if target >= 0 && target.toNat < st.prog.size then
            ({ st' with pc := target.toNat }, .Continue)
          else
            (st, .Error "jump out of bounds")
        else
          (st', .Continue)

    | some (.JumpImm op dst imm off) =>
        let x := st.regs.read dst
        let y := imm.toInt64.toUInt64
        if evalJmpCond op x y false then
          let target := st.pc + 1 + off.toInt
          if target >= 0 && target.toNat < st.prog.size then
            ({ st' with pc := target.toNat }, .Continue)
          else
            (st, .Error "jump out of bounds")
        else
          (st', .Continue)

    | some (.Jump32Reg op dst src off) =>
        let x := st.regs.read dst
        let y := st.regs.read src
        if evalJmpCond op x y true then
          let target := st.pc + 1 + off.toInt
          if target >= 0 && target.toNat < st.prog.size then
            ({ st' with pc := target.toNat }, .Continue)
          else
            (st, .Error "jump out of bounds")
        else
          (st', .Continue)

    | some (.Jump32Imm op dst imm off) =>
        let x := st.regs.read dst
        let y := imm.toInt64.toUInt64
        if evalJmpCond op x y true then
          let target := st.pc + 1 + off.toInt
          if target >= 0 && target.toNat < st.prog.size then
            ({ st' with pc := target.toNat }, .Continue)
          else
            (st, .Error "jump out of bounds")
        else
          (st', .Continue)

    | some (.Call helperId) =>
        -- Execute helper function
        let (st'', success) := execHelper st' helperId
        if success then
          (st'', .Continue)
        else
          (st, .Error s!"unknown helper function: {helperId}")

-- Run the VM until termination or error
partial def run (st : BpfState) (maxSteps : Nat := 10000) : BpfState × ExecResult :=
  if maxSteps == 0 then
    (st, .Error "max steps exceeded")
  else
    let (st', result) := step st
    match result with
    | .Continue => run st' (maxSteps - 1)
    | _ => (st', result)

end BpfState
