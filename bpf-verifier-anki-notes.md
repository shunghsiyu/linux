# BPF Verifier — Anki notes

Notes drafted while reading `kernel/bpf/verifier.c`. Format is Q/A so they drop
straight into Anki (one card per `Q:` / `A:` pair). Grouped by topic; build
gradually.

Anchors are given as `verifier.c:<line>` or symbol names so the fact can be
re-checked against the source (line numbers drift across commits — trust the
symbol).

---

## 1. High-level model

**Q:** In one sentence, what is `bpf_check()` / the BPF verifier?
**A:** A static code analyzer that walks an eBPF program instruction by
instruction, tracking the type and value range of every register and stack
slot, and proves that *all* execution paths are safe before the program is
allowed to run. (File header comment, `verifier.c:56`.)

**Q:** What are the two main passes of the verifier, and what does each do?
**A:** (1) A depth-first search that checks the program is a DAG — rejects
programs that are too large, contain loops (back-edges), have unreachable
instructions, or have malformed/out-of-bounds jumps. (2) An all-paths descent
from the first instruction that simulates every reachable path and updates
register/stack state. (`verifier.c:60`.)

**Q:** Why does walking "all paths" not blow up, and what three limits bound it?
**A:** The verifier prunes paths using state equivalence (it stops exploring a
path whose state is a subset of one already verified). Hard caps:
- `BPF_COMPLEXITY_LIMIT_INSNS = 1,000,000` — total instructions *processed*
  across all paths (`env->insn_processed`).
- `BPF_COMPLEXITY_LIMIT_JMP_SEQ = 8192` — max depth of the pushed-state stack.
- `BPF_COMPLEXITY_LIMIT_STATES = 64`.

**Q:** What is `BPF_MAXINSNS` and how does it relate to the 1M limit?
**A:** `BPF_MAXINSNS = 4096` is the cap on the *static* number of instructions
in a single program. `BPF_COMPLEXITY_LIMIT_INSNS = 1,000,000` is separate: it
caps how many instructions the verifier *processes* while exploring all paths,
which can far exceed the static size because branches re-walk instructions.

---

## 2. Registers (calling convention)

**Q:** How wide is every BPF register?
**A:** All BPF registers are 64-bit. (`verifier.c:77`.)

**Q:** What is the role of each register R0–R10?
**A:**
- R0 — return value register.
- R1–R5 — argument-passing registers (caller-saved; set to `NOT_INIT` after a
  call).
- R6–R9 — callee-saved registers.
- R10 — frame pointer, **read-only**.
(`verifier.c:78`.)

**Q:** At program entry, what is the type of R1?
**A:** `PTR_TO_CTX` — a pointer to the `bpf_context` for that program type.
(`verifier.c:83`.)

---

## 3. Value tracking (scalars)

**Q:** What *two* complementary representations does the verifier keep for every
`SCALAR_VALUE` register, and why two?
**A:** (1) a **tnum** (`var_off`) tracking knowledge per *bit*, and (2) a set of
**min/max bounds** (`smin/smax/umin/umax_value` plus 32-bit `s32/u32_*`
variants) tracking the value as a *range*. They capture different shapes of
knowledge — bit-level facts vs. contiguous ranges — and the verifier
cross-refines one from the other. (`bpf_reg_state`, `bpf_verifier.h:117`.)

**Q:** What is a *tnum* (tracked / tristate number) and how is it stored?
**A:** A `struct tnum { u64 value; u64 mask; }` where each bit is either *known*
(0 or 1) or *unknown* (x). `mask` has a 1 in every unknown-bit position; `value`
holds the known bits. So `tnum_const(C)` has `mask == 0`; `tnum_unknown` has
`mask == all ones`. Arithmetic ops propagate the unknown bits so the result
covers every possible value of the operands. (`tnum.h`.)

**Q:** Give a concrete example of knowledge a tnum captures that a min/max range
*cannot*.
**A:** Alignment. If the low 3 bits are known-zero (`mask` has 0s there,
`value` 0s there), the tnum proves the value is 8-byte aligned — a fact about
*which* values are possible, not their span. A range like `0..N` says nothing
about alignment.

**Q:** Give a concrete example of knowledge a min/max range captures that a tnum
represents poorly.
**A:** A tight contiguous bound like `0 <= x <= 5`. tnums can only represent
sets that are "bit-superset" shaped, so the smallest tnum containing {0..5}
also admits 6 and 7. The unsigned/signed min-max fields express `5` exactly.

**Q:** Why is `tnum_range(min, max)` described as an *over-approximation*?
**A:** Because a tnum can only describe a bitwise superset, not an arbitrary
interval. `tnum_range(0, 2)` is represented as {0,1,2,**3**} — it includes 3
even though 3 is outside the intended range. (`tnum.h` comment on
`tnum_range`.)

**Q:** What does it mean for a scalar register to be *precise*, and what is the
default?
**A:** *Precise* means the verifier must enforce that register's exact value /
range during state comparison (it can't be generalized away). Scalars start
**imprecise** by default — except for unprivileged programs, where
`reg->precise` is forced true (`reg->precise = !env->bpf_capable`). Imprecision
is what makes state pruning effective. (`verifier.c:1806`.)

**Q:** Why does the verifier track signed *and* unsigned bounds (and 32-bit
variants) separately?
**A:** Because the same 64 bits mean different ordered ranges under signed vs.
unsigned interpretation, and BPF has both signed and unsigned compares plus
32-bit sub-register ALU ops. Keeping `smin/smax`, `umin/umax`, and the `s32/u32`
versions lets a comparison or operation tighten exactly the interpretation it
constrains, then propagate back to the others. (`bpf_reg_state`,
`bpf_verifier.h:123`.)
