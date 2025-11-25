# CBMC BPF Verifier Verification Roadmap

## Current Status

**Completed: 21 verification harnesses**

### Verifier Register Tracking (2/~30)
- ✅ coerce_reg_to_size_sx - Sign extension tracking

### Scalar Arithmetic Operations (6/10) - Phase 2 Completed
- ✅ scalar_min_max_add, scalar_min_max_sub, scalar_min_max_mul (64-bit)
- ✅ scalar32_min_max_add, scalar32_min_max_sub, scalar32_min_max_mul (32-bit)

### Tnum Operations (14/14) - ✅ COMPLETE
- ✅ tnum_add, tnum_sub, tnum_mul, tnum_neg (Arithmetic)
- ✅ tnum_and, tnum_or, tnum_xor (Bitwise)
- ✅ tnum_lshift, tnum_rshift, tnum_arshift (Shifts)
- ✅ tnum_union, tnum_intersect (Set Operations)
- ✅ tnum_range, tnum_cast (Constructors/Utilities)

---

## High-Priority Targets

### ✅ Phase 1: Complete Tnum Library (6 operations) - COMPLETED

**Achievement:** Full formal verification of all tnum operations in `kernel/bpf/tnum.c`

Completed operations:
1. ✅ **tnum_arshift** - Arithmetic right shift with sign bit propagation
2. ✅ **tnum_union** - Set union for control flow merging
3. ✅ **tnum_intersect** - Set intersection for constraint solving
4. ✅ **tnum_range** - Range constructor with over-approximation
5. ✅ **tnum_cast** - Truncation to smaller size
6. ✅ **tnum_neg** - Two's complement negation

**Value delivered:** ⭐⭐⭐⭐⭐ Complete coverage of the BPF verifier's core abstraction

---

### ✅ Phase 2: Scalar Arithmetic Operations (5 operations) - COMPLETED

**Achievement:** Formal verification of core scalar min/max tracking operations

Completed operations:
1. ✅ **scalar32_min_max_add** - 32-bit addition with overflow handling
2. ✅ **scalar_min_max_sub** - 64-bit subtraction with underflow handling
3. ✅ **scalar32_min_max_sub** - 32-bit subtraction with underflow handling
4. ✅ **scalar_min_max_mul** - 64-bit multiplication with complex overflow cases
5. ✅ **scalar32_min_max_mul** - 32-bit multiplication with complex overflow cases

**Value delivered:** ⭐⭐⭐⭐ Verification of the most common BPF program operations

---

### 🔥 Phase 3: Critical Integration Functions (2 operations)

**Why:** These maintain invariants across all BPF verifier state updates.

1. **reg_bounds_sanity_check** - Invariant checking
   - **Complexity:** Medium
   - **Impact:** Very High (catches verifier bugs)
   - **Unique challenge:** Verify the checker itself is sound
   - **Property to verify:** All register states satisfy documented invariants

2. **__reg_bound_offset** - Tnum refinement from ranges
   - **Complexity:** High (combines tnum_intersect + tnum_range)
   - **Impact:** Very High (used in every bounds update)
   - **Unique challenge:** Integration of multiple tnum operations
   - **Property to verify:** Result is tighter than input

**Estimated effort:** 3-4 hours
**Value:** ⭐⭐⭐⭐⭐ (Verifies verifier correctness)

---

## Medium-Priority Targets

### Category 4: Bitwise Operations (6 operations)

All scalar_min_max_{and,or,xor} in 32 and 64-bit variants.

**Estimated effort:** 5-6 hours
**Value:** ⭐⭐⭐ (Completeness)

### Category 5: Shift Operations (6 operations)

All scalar_min_max_{lsh,rsh,arsh} in 32 and 64-bit variants.

**Estimated effort:** 5-6 hours
**Value:** ⭐⭐⭐ (Completeness)

### Category 6: Bounds Deduction (5 operations)

- `__reg_deduce_bounds`
- `__reg64_deduce_bounds`
- `__reg32_deduce_bounds`
- `__reg_deduce_mixed_bounds`
- `__reg_assign_32_into_64`

**Estimated effort:** 6-8 hours
**Value:** ⭐⭐⭐⭐ (Core logic)

---

## Recommended Next Steps

### 🎯 Phase 1: Complete Tnum Library (RECOMMENDED)

**Goal:** 100% formal verification of tnum operations

**Tasks:**
1. tnum_arshift (2-3 hours)
2. tnum_union (1 hour)
3. tnum_intersect (1 hour)
4. tnum_range (2 hours)
5. tnum_cast (1 hour)
6. tnum_neg (30 min)

**Total:** ~8 hours
**Result:** Complete formal verification of 14 tnum operations

**Impact:**
- ✅ Full soundness proof for tnum library
- ✅ Foundation for verifying higher-level operations
- ✅ Can publish as "Formally Verified Tristate Number Library"

---

### 🎯 Phase 2: Critical Scalar Operations

**Goal:** Verify most-used register tracking operations

**Tasks:**
1. scalar_min_max_sub (1.5 hours)
2. scalar_min_max_mul (2 hours)
3. scalar32_min_max_add (1 hour)
4. scalar32_min_max_sub (1.5 hours)
5. scalar32_min_max_mul (2 hours)

**Total:** ~8 hours
**Result:** Arithmetic operations verified for 32 and 64-bit

---

### 🎯 Phase 3: Invariant Verification

**Goal:** Verify that BPF verifier maintains its invariants

**Tasks:**
1. Formalize register state invariants
2. Verify reg_bounds_sanity_check (2 hours)
3. Verify __reg_bound_offset (3 hours)
4. Verify reg_bounds_sync integration (4 hours)

**Total:** ~9 hours
**Result:** Proof that verifier maintains invariants

**Impact:**
- ✅ Catches verifier bugs automatically
- ✅ Proves correctness of state management
- ✅ Enables verification of higher-level properties

---

## Special Opportunities

### 🌟 Verify Known Bug Fixes

Look at past BPF verifier CVEs and create regression tests:
- Verify the fix is correct
- Prove the bug cannot recur
- Examples: CVE-2021-3490, CVE-2021-31440, etc.

### 🌟 Property-Based Verification

Instead of per-function verification, verify high-level properties:
- "All operations maintain register bounds consistency"
- "Tnum operations never lose known bits"
- "Range tracking is monotonic (never expands)"

### 🌟 Comparative Verification

Verify equivalences:
- `tnum_add(a, b) ≡ tnum_add(b, a)` (commutativity)
- `scalar_min_max_add ∘ scalar_min_max_add ≡ scalar_min_max_mul(const(2))` (for specific cases)

---

## Success Metrics

**Short term (1-2 weeks):**
- [ ] 14/14 tnum operations verified (100%)
- [ ] 10+ scalar operations verified
- [ ] 1+ invariant function verified

**Medium term (1 month):**
- [ ] 30+ total verification harnesses
- [ ] All arithmetic operations verified
- [ ] Integration with CI/CD

**Long term (3 months):**
- [ ] 50+ verification harnesses
- [ ] Property-based verification framework
- [ ] Published paper/blog post
- [ ] Upstreamed to Linux kernel

---

## Technical Debt & Improvements

1. **Automation:** Script to generate verification harnesses from function signatures
2. **CI Integration:** Run verification on every commit
3. **Performance:** Parallel CBMC runs for faster verification
4. **Coverage:** Automated coverage tracking (what % of verifier is verified)
5. **Documentation:** User guide for writing new harnesses

---

## Key Insights from Analysis

1. **tnum_union** is called extensively - high-value target
2. **reg_bounds_sanity_check** already documents invariants - perfect for verification
3. **Multiplication** is complex due to multiple overflow cases - challenging but valuable
4. **Integration functions** like `__reg_bound_offset` combine multiple operations - good integration tests
5. **32-bit variants** are often overlooked but equally important

---

## Questions for Discussion

1. Should we prioritize breadth (cover all operations) or depth (verify invariants)?
2. Are there specific CVEs or bugs you want to ensure can't happen?
3. Should we create a verification test suite for regression testing?
4. Would you like to verify higher-level properties (e.g., "verifier never accepts unsafe programs")?
