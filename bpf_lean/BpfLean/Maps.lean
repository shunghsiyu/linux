/-
  BPF Maps

  This module models BPF maps, which are key-value stores used for:
  - Sharing data between kernel and userspace
  - Communication between BPF programs
  - Per-CPU data structures
  - Hash tables, arrays, and other data structures

  Maps in BPF:
  - Are created by userspace
  - Have fixed key and value sizes
  - Support lookup, update, and delete operations
  - Can be accessed via helper functions
-/

import BpfLean.Basic

-- Map types (subset of real BPF map types)
inductive BpfMapType where
  | Array : BpfMapType           -- Simple array indexed by integers
  | HashMap : BpfMapType         -- Hash table for arbitrary keys
  | PerCpuArray : BpfMapType     -- Per-CPU array
  | PerCpuHashMap : BpfMapType   -- Per-CPU hash map
  deriving Repr, DecidableEq, Inhabited

-- Map definition (metadata)
structure BpfMapDef where
  mapType : BpfMapType
  keySize : Nat
  valueSize : Nat
  maxEntries : Nat
  deriving Repr, Inhabited

-- Map value: either present or not
inductive MapValue where
  | Some : List UInt8 → MapValue    -- Value present (as byte array)
  | None : MapValue                  -- Value not present
  deriving Repr, Inhabited

-- Map key type (simplified to list of bytes)
abbrev MapKey := List UInt8

-- Simple map implementation (for simulation)
-- In reality, different map types have different implementations
structure BpfMap where
  mapDef : BpfMapDef
  -- Storage: key bytes → value bytes
  -- Simplified model using a function
  storage : MapKey → MapValue

namespace BpfMap

instance : Inhabited BpfMap where
  default := {
    mapDef := default
    storage := fun _ => MapValue.None
  }

-- Create an empty map
def empty (mapDef : BpfMapDef) : BpfMap :=
  { mapDef := mapDef
  , storage := fun _ => MapValue.None
  }

-- Lookup a value by key
def lookup (m : BpfMap) (key : MapKey) : MapValue :=
  if key.length == m.mapDef.keySize then
    m.storage key
  else
    MapValue.None

-- Update a value (returns new map)
def update (m : BpfMap) (key : MapKey) (value : List UInt8) : BpfMap :=
  if key.length == m.mapDef.keySize && value.length == m.mapDef.valueSize then
    { m with storage := fun k =>
        if k == key then MapValue.Some value
        else m.storage k
    }
  else
    m

-- Delete a key (returns new map)
def delete (m : BpfMap) (key : List UInt8) : BpfMap :=
  { m with storage := fun k =>
      if k == key then MapValue.None
      else m.storage k
  }

-- Check if a key exists
def contains (m : BpfMap) (key : List UInt8) : Bool :=
  match m.lookup key with
  | MapValue.Some _ => true
  | MapValue.None => false

end BpfMap

-- Helper function identifiers (subset used for map operations)
inductive BpfHelper where
  | MapLookupElem : BpfHelper      -- lookup element in map
  | MapUpdateElem : BpfHelper      -- update element in map
  | MapDeleteElem : BpfHelper      -- delete element from map
  | GetProcTime : BpfHelper        -- get current time
  | TraceMsg : BpfHelper           -- print debug message
  deriving Repr, DecidableEq

namespace BpfHelper

-- Convert helper ID to integer (matching kernel convention)
def toInt (h : BpfHelper) : Int32 :=
  match h with
  | .MapLookupElem => 1
  | .MapUpdateElem => 2
  | .MapDeleteElem => 3
  | .GetProcTime => 5
  | .TraceMsg => 6

-- Try to decode helper from integer
def fromInt? (n : Int32) : Option BpfHelper :=
  match n with
  | 1 => some .MapLookupElem
  | 2 => some .MapUpdateElem
  | 3 => some .MapDeleteElem
  | 5 => some .GetProcTime
  | 6 => some .TraceMsg
  | _ => none

end BpfHelper

-- Map file descriptor (index into map table)
abbrev MapFd := Nat

-- Map table: holds all maps accessible to a program
structure MapTable where
  maps : Array (Option BpfMap)
  deriving Inhabited

namespace MapTable

def empty : MapTable :=
  { maps := #[] }

-- Get a map by file descriptor
def get (mt : MapTable) (fd : MapFd) : Option BpfMap :=
  if h : fd < mt.maps.size then
    mt.maps[fd]
  else
    none

-- Add a map to the table (returns fd)
def add (mt : MapTable) (m : BpfMap) : MapTable × MapFd :=
  let fd := mt.maps.size
  let maps' := mt.maps.push (some m)
  ({ maps := maps' }, fd)

-- Update a map in the table
def set (mt : MapTable) (fd : MapFd) (m : BpfMap) : MapTable :=
  if h : fd < mt.maps.size then
    { mt with maps := mt.maps.set! fd (some m) }
  else
    mt

end MapTable

-- Example: Create a simple array map
def exampleArrayMap : BpfMap :=
  BpfMap.empty {
    mapType := .Array
    keySize := 4      -- 32-bit index
    valueSize := 8    -- 64-bit value
    maxEntries := 100
  }

-- Example: Store a value in the map
def exampleMapUsage : BpfMap :=
  let m := exampleArrayMap
  let key := [0, 0, 0, 5]  -- index 5 (little-endian)
  let value := [0, 0, 0, 0, 0, 0, 0, 42]  -- value 42
  m.update key value
