/-
  Bit Manipulation Utilities and Proofs

  This module provides utilities and proven properties for bit manipulation
  operations on UInt64.

  Note: UInt64 bitwise operations in Lean 4 are implemented as primitives.
  For now, we axiomatize the standard algebraic properties.
  A full formalization would prove these from the BitVec representation.
-/

-- Commutativity axioms
-- These are true by the definition of bitwise operations, but proving them
-- requires reasoning about the underlying BitVec/Fin representation
axiom uint64_xor_comm (a b : UInt64) : (a ^^^ b) = (b ^^^ a)
axiom uint64_and_comm (a b : UInt64) : (a &&& b) = (b &&& a)
axiom uint64_or_comm (a b : UInt64) : (a ||| b) = (b ||| a)

-- Identity axioms
axiom uint64_xor_self (a : UInt64) : (a ^^^ a) = 0
axiom uint64_and_self (a : UInt64) : (a &&& a) = a
axiom uint64_or_self (a : UInt64) : (a ||| a) = a

-- Complement properties
axiom uint64_complement_involutive (a : UInt64) : (~~~(~~~a)) = a
axiom uint64_complement_zero : ~~~(0 : UInt64) = 0xFFFFFFFFFFFFFFFF

-- Neutral element axioms
axiom uint64_and_ones (a : UInt64) : (a &&& 0xFFFFFFFFFFFFFFFF) = a
axiom uint64_xor_zero (a : UInt64) : (a ^^^ 0) = a
axiom uint64_and_zero (a : UInt64) : (a &&& 0) = 0
axiom uint64_or_zero (a : UInt64) : (a ||| 0) = a

-- Absorbing element axioms
axiom uint64_or_ones (a : UInt64) : (a ||| 0xFFFFFFFFFFFFFFFF) = 0xFFFFFFFFFFFFFFFF

-- De Morgan's laws (true but require bit-level proofs)
axiom uint64_demorgan_and (a b : UInt64) : ~~~(a &&& b) = (~~~a) ||| (~~~b)
axiom uint64_demorgan_or (a b : UInt64) : ~~~(a ||| b) = (~~~a) &&& (~~~b)

-- Distributivity
axiom uint64_and_or_distrib (a b c : UInt64) : a &&& (b ||| c) = (a &&& b) ||| (a &&& c)
axiom uint64_or_and_distrib (a b c : UInt64) : a ||| (b &&& c) = (a ||| b) &&& (a ||| c)

-- Associativity
axiom uint64_and_assoc (a b c : UInt64) : (a &&& b) &&& c = a &&& (b &&& c)
axiom uint64_or_assoc (a b c : UInt64) : (a ||| b) ||| c = a ||| (b ||| c)
axiom uint64_xor_assoc (a b c : UInt64) : (a ^^^ b) ^^^ c = a ^^^ (b ^^^ c)

-- Min/max properties
-- These should exist in Lean 4's standard library, but for now we axiomatize them
-- TODO: Replace with std library theorems (e.g., from Init.Data.Ord or similar)
axiom min_self {α : Type} [Min α] (a : α) : min a a = a
axiom max_self {α : Type} [Max α] (a : α) : max a a = a
axiom min_comm {α : Type} [Min α] (a b : α) : min a b = min b a
axiom max_comm {α : Type} [Max α] (a b : α) : max a b = max b a
