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
