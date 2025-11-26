/*
 * Common helper functions for tnum (tristate number) verification harnesses
 *
 * This header provides reusable helper functions for CBMC verification
 * of BPF verifier tnum operations.
 */

#ifndef TNUM_HELPERS_H
#define TNUM_HELPERS_H

#include <linux/types.h>
#include <linux/tnum.h>

/*
 * Helper: Check if a concrete value is represented by a tnum
 *
 * A value v is represented by tnum t if:
 *   - For every bit position where t.mask is 0 (known bit),
 *     the bit in v matches the corresponding bit in t.value
 *   - For every bit position where t.mask is 1 (unknown bit),
 *     the bit in v can be anything
 *
 * Mathematically: (v & ~t.mask) == t.value
 *
 * This is the fundamental property we verify for all tnum operations:
 * if input values are represented by input tnums, the output value
 * must be represented by the output tnum.
 */
static bool tnum_contains(struct tnum t, u64 v)
{
	return (v & ~t.mask) == t.value;
}

/*
 * Helper: Create a symbolic tnum with arbitrary value and mask
 *
 * Creates a tnum with symbolic (non-deterministic) value and mask fields.
 * This allows CBMC to explore all possible tnums during verification.
 *
 * Note: We don't constrain the tnum to be "valid" because tnum operations
 * should work correctly even on tnums that weren't constructed through
 * the standard constructors (as long as the invariant value & mask == 0 holds).
 */
static struct tnum symbolic_tnum(void)
{
	struct tnum t;
	t.value = __CPROVER_unsigned_long_long_input();
	t.mask = __CPROVER_unsigned_long_long_input();
	return t;
}

/*
 * Helper: Check if a tnum is valid
 *
 * A tnum is valid if value and mask don't overlap - i.e., a bit cannot
 * be both "known" (mask=0 means known, so bit should be in value) and
 * unknown (mask=1 means unknown, so bit shouldn't be in value).
 *
 * Invariant: value & mask == 0
 *
 * This is the core invariant that all tnum operations must maintain.
 */
static bool valid_tnum(struct tnum t)
{
	return (t.value & t.mask) == 0;
}

#endif /* TNUM_HELPERS_H */
