# BPF Subsystem Major Changes Report

**Report Date:** 2025-11-19
**Baseline:** Linux v6.13 (commit `ffd294d34`)
**Current:** Linux v6.18-rc6 (commit `6a23ae0a9`)

**Note:** The requested v6.12 tag does not exist in this repository. This report covers changes from v6.13 through v6.18-rc6.

---

## Executive Summary

The BPF subsystem has undergone significant enhancements between v6.13 and v6.18, introducing major new features including:
- BPF struct_ops support for Qdisc (queueing disciplines)
- Dynamic pointer (dynptr) support for skb metadata access
- XDP data pulling capability via new kfunc
- Signed BPF program support
- Path-insensitive stack analysis in the verifier
- Enhanced JIT support for may_goto instruction
- Task work scheduling kfuncs

---

## 1. BPF Qdisc Support (struct_ops)

**Status:** ✅ Implemented
**Location:** `net/sched/bpf_qdisc.c`
**Test:** `tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c`

### Overview
A groundbreaking feature that allows queueing disciplines (qdiscs) to be implemented entirely in BPF using the struct_ops framework. This enables custom packet scheduling logic to run in kernel space with BPF's safety guarantees.

### Implementation Details

The implementation provides:
- **BPF struct_ops for Qdisc_ops:** Full struct_ops implementation allowing BPF programs to define qdisc behavior
- **Required operations:** `enqueue`, `dequeue`, `init`, `reset`, `destroy`
- **Automatic prologue/epilogue generation:** Special code injection for initialization and cleanup

#### Key kfuncs introduced:
```c
__bpf_kfunc u32 bpf_skb_get_hash(struct sk_buff *skb)
__bpf_kfunc void bpf_kfree_skb(struct sk_buff *skb)
__bpf_kfunc void bpf_qdisc_skb_drop(struct sk_buff *skb, struct bpf_sk_buff_ptr *to_free)
__bpf_kfunc void bpf_qdisc_watchdog_schedule(struct Qdisc *sch, u64 expire, u64 delta_ns)
__bpf_kfunc void bpf_qdisc_bstats_update(struct Qdisc *sch, const struct sk_buff *skb)
```

**Reference:** `net/sched/bpf_qdisc.c:189-270`

### Access Control
BPF programs can access limited fields in Qdisc and sk_buff structures:
- **Qdisc fields:** `limit`, `q.qlen`, `qstats`
- **sk_buff fields:** `tstamp`, `cb.data[]` (qdisc control block)

**Reference:** `net/sched/bpf_qdisc.c:54-131`

### Example Usage
The FIFO qdisc implementation demonstrates:
- Using BPF linked lists to queue packets
- Spin locks for concurrency control
- kptr for sk_buff ownership management
- Statistics tracking

**Reference:** `tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c:1-80`

### Deployment
Can be used with standard `tc qdisc` commands:
```bash
tc qdisc add dev eth0 root bpf_fifo
```

---

## 2. Dynamic Pointer (dynptr) SKB Metadata Support

**Status:** ✅ Implemented
**Location:** `net/core/filter.c`
**Merge:** Part of stable branch merged to both bpf-next and net-next (v6.18)

### Overview
Introduces dynptr-based access to skb metadata regions, providing a safe and flexible API for reading/writing skb metadata allocated via `bpf_xdp_adjust_meta()`.

### New kfuncs

#### 1. `bpf_dynptr_from_skb_meta()`
```c
__bpf_kfunc int bpf_dynptr_from_skb_meta(struct __sk_buff *skb_, u64 flags,
                                          struct bpf_dynptr *ptr__uninit)
```

**Purpose:** Initialize a dynptr to access the skb metadata area
**Features:**
- Alternative to direct `__sk_buff->data_meta` access
- Read-only for cloned skbs (shares data with original)
- Dynptr type: `BPF_DYNPTR_TYPE_SKB_META`

**Reference:** `net/core/filter.c:12053-12070`

#### 2. Supporting Infrastructure
```c
void *bpf_skb_meta_pointer(struct sk_buff *skb, u32 offset)
```

Helper function to get mutable pointers within metadata area.

**Reference:** `net/core/filter.c:12010-12017`

### Use Cases
- TC programs can preserve and access metadata even after packet modifications
- Safe metadata access without bounds checking complexity
- Integration with existing dynptr ecosystem (slice, copy, etc.)

### Related Test
**Reference:** `tools/testing/selftests/bpf/progs/test_xdp_meta.c`

---

## 3. XDP Pull Data Support

**Status:** ✅ Implemented
**Location:** `net/core/filter.c`
**Author:** Amery Hung
**Merge:** Stable branch merged to both bpf-next and net-next (v6.18)

### Overview
New kfunc `bpf_xdp_pull_data()` allows XDP programs to pull fragmented data from `xdp_buff` fragments into the linear area, similar to `pskb_may_pull()` for skbs.

### Implementation

```c
__bpf_kfunc int bpf_xdp_pull_data(struct xdp_md *x, u32 len)
```

**Functionality:**
- Pulls data from non-linear fragments into linear head
- Validates requested length against total buffer length
- Handles headroom and tailroom constraints
- Recalculates metadata pointers if necessary
- Returns 0 on success, -EINVAL on invalid length

**Reference:** `net/core/filter.c:12254-12276`

### Algorithm
1. Check if requested length already in linear area (fast path)
2. Validate total buffer length
3. Calculate available headroom/tailroom
4. Shift data and collapse fragments as needed
5. Update xdp_buff pointers

### Use Cases
- Parsing headers that span multiple fragments
- Protocol processing requiring contiguous data
- XDP programs needing reliable header access

### Test Coverage
**Reference:** `tools/testing/selftests/bpf/progs/test_xdp_pull_data.c:24-46`

Example test verifies:
- Pulling 1024+ bytes from fragmented buffer
- Data integrity after pull operation
- Proper error handling

---

## 4. Netkit Head/Tailroom Configuration

**Status:** ✅ Implemented
**Location:** `drivers/net/netkit.c`

### Overview
Added ability to configure headroom and tailroom for netkit virtual network devices, providing better control over packet buffer allocation.

### Implementation

```c
static void netkit_set_headroom(struct net_device *dev, int headroom)
```

**Features:**
- Dynamic headroom configuration
- Synchronizes headroom between peer devices
- Defaults to `NET_SKB_PAD` if negative value provided
- Updates `needed_headroom` for both device and peer

**Reference:** `drivers/net/netkit.c:185-203`

### Storage
Headroom value stored in device-private structure:
```c
struct netkit {
    enum netkit_mode mode;
    bool primary;
    u32 headroom;  // Per-device headroom setting
};
```

**Reference:** `drivers/net/netkit.c:26-30`

---

## 5. Signed BPF Programs Support

**Status:** ✅ Implemented
**Author:** KP Singh
**Version:** v6.18
**Merge Commit:** `ae28ed457`

### Overview
Major security feature enabling cryptographic signing and verification of BPF programs. This provides integrity guarantees and enables trust models for BPF program deployment.

### Components

#### bpftool Signing Support
New signing functionality in bpftool:
- Sign BPF programs with private keys
- Verify signatures before loading
- Integration with kernel asymmetric key infrastructure

**Reference:** `tools/bpf/bpftool/sign.c:1-211`

#### Kernel Verification
- Leverages existing kernel PKCS#7 verification
- Integration with keyring subsystem
- Extended verification hooks

**Reference:** `crypto/asymmetric_keys/pkcs7_verify.c` (modified)
**Reference:** `include/linux/verification.h` (extended)

### Impact
- Enables trusted BPF program distribution
- Foundation for BPF program attestation
- Critical for production deployments requiring provenance

---

## 6. Verifier Enhancements

### 6.1 Path-Insensitive Stack Analysis

**Status:** ✅ Implemented
**Author:** Eduard Zingerman
**Version:** v6.18

**Overview:**
Fundamental change in verification logic from path-sensitive to path-insensitive live stack analysis. This represents a significant improvement in verification efficiency and precision.

**Impact:**
- Improved verification performance for complex programs
- Better handling of loops and conditional branches
- Reduced state explosion in verifier

**Reference:** Commit message in `ae28ed457` (bpf-next-6.18 merge)
**Test:** `tools/testing/selftests/bpf/progs/verifier_live_stack.c:1-294`

### 6.2 Enhanced Bounds Checking

Improvements to bounds verification:
- Better tnum (tracked number) precision for multiplication operations
- Improved `is_branch_taken()` logic using tnums
- Enhanced narrower load error messages

**Author:** Paul Chaignon, Nandakumar Edamana
**Test:** `tools/testing/selftests/bpf/progs/verifier_bounds.c` (79 line additions)

### 6.3 Union Argument Access

**Feature:** Allow access to union arguments in tracing programs
**Author:** Leon Hwang

Enables BPF tracing programs to properly handle functions with union parameters.

---

## 7. JIT Enhancements

### may_goto Instruction Support

**Architectures:** s390, arm64
**Authors:** Ilya Leoshkevich (s390), Puranjay Mohan (arm64)
**Version:** v6.18

The `may_goto` instruction support has been extended to additional architectures, improving BPF program portability and enabling bounded loops on more platforms.

---

## 8. BPF Arena Enhancements

### Signed Load Support

**Status:** ✅ Implemented
**Authors:** Kumar Kartikeya Dwivedi, Puranjay Mohan
**Version:** v6.18

#### Features:
- Support for signed loads from BPF arena memory regions
- Enhanced RISC-V JIT support for atomic operations in arena
- Arena fault reporting to BPF error stream

**References:**
- `tools/testing/selftests/bpf/progs/verifier_arena_large.c` (modified)
- `tools/testing/selftests/bpf/progs/verifier_ldsx.c` (178 line additions)

### Fault Reporting
**Author:** Puranjay Mohan

Arena memory faults are now reported through the BPF error stream, improving debuggability of arena-using programs.

---

## 9. Task Work Scheduling Kfuncs

**Status:** ✅ Implemented
**Author:** Mykyta Yatsenko
**Version:** v6.18

### Overview
New kfuncs `bpf_task_work_schedule*()` enable scheduling deferred execution of BPF callbacks in the context of specific tasks using the kernel's task_work infrastructure.

### Use Cases
- Deferred processing in specific task context
- User-space upcalls from BPF
- Async event handling tied to specific processes

### Implementation Notes
- Uses kernel task_work infrastructure
- Proper RCU and task lifetime management
- Context-aware execution guarantees

---

## 10. KFuncs and Helper Enhancements

### 10.1 RCU Protection Enforcement

**Author:** Kumar Kartikeya Dwivedi
**Version:** v6.18

Enhanced enforcement of RCU protection for `KF_RCU_PROTECTED` kfuncs, ensuring proper synchronization.

### 10.2 New String Kfunc

```c
__bpf_kfunc int bpf_strcasecmp(const char *s1, const char *s2)
```

**Author:** Rong Tao
Case-insensitive string comparison kfunc.

### 10.3 Map Operation Enhancement

**Feature:** `lookup_and_delete_elem` for `BPF_MAP_STACK_TRACE`
**Author:** Tao Chen

Added atomic lookup-and-delete operation for stack trace maps, improving performance for trace consumers.

**Test:** `tools/testing/selftests/bpf/prog_tests/bpf_obj_pinning.c` (modified)

---

## 11. Program Type Extensions

### 11.1 Uprobe Context Modification

**Status:** ✅ Implemented
**Author:** Jiri Olsa
**Version:** v6.18

Allows uprobe-attached BPF programs to modify context registers, enabling:
- Return value modification
- Argument injection
- Control flow manipulation

### 11.2 Kprobe Write Context

Similar capability for kprobe programs to write to context.

**Tests:**
- `tools/testing/selftests/bpf/prog_tests/bpf_obj_id.c` (modified)
- Uprobe and kprobe context modification tests

---

## 12. Additional Features and Fixes

### 12.1 Tailcall Compatibility

**Feature:** Enforce `expected_attach_type` for tailcall compatibility
**Author:** Daniel Borkmann
**Version:** v6.18

Ensures type safety when using BPF tail calls by enforcing matching attach types.

### 12.2 RCU Optimization

**Feature:** Optimize `rcu_read_lock()` + `migrate_disable()` combination
**Author:** Menglong Dong

Performance optimization for common BPF subsystem patterns.

### 12.3 bpf_d_path() Constification

**Commit:** `de7342228`

Finished constification of first parameter of `bpf_d_path()` for better const-correctness.

**Reference:** Commit `de7342228` in git log

### 12.4 BPF Timer Memory Control

**Commit:** `6d78b4473`

Ensures memcg uses `allow_spinning=false` path in `bpf_timer_init()` for better memory accounting under PREEMPT_RT.

**Reference:** Commit `6d78b4473` in git log

---

## 13. Features From Mailing List (Verification Status)

Based on the mailing list announcements provided, here's the status of mentioned features:

### ✅ Confirmed Implemented:
1. **BPF qdisc support** - Section 1
2. **XDP pull data kfunc** - Section 3
3. **Dynptr skb metadata support** - Section 2
4. **Netkit head/tailroom configuration** - Section 4
5. **Signed BPF programs** - Section 5

### 🔍 Requires Further Investigation:
The following features mentioned in the mailing list were not found in the current codebase:

1. **XDP metadata support for tun driver** (Marcus Wichelmann)
2. **bpf_getsockopt support for TCP_BPF_RTO_MIN and TCP_BPf_DELACK_MAX** (Jason Xing)
3. **UDP/TCP bpf_iter improvements** (Jordan Rife)
4. **Global per-protocol memory accounting bypass** (Kuniyuki Iwashima)
5. **TC metadata preservation** (Jakub Sitnicki)
6. **af_smc bpf_struct_ops support** (D. Wythe)
7. **Various test migrations and improvements**

**Note:** These features may be:
- Merged in earlier versions (pre-v6.13)
- Scheduled for future versions
- In review/not yet merged
- Present but not easily discoverable in current search

---

## 14. Infrastructure and Tooling

### 14.1 libbpf Changes

**SHA-256 Implementation:** Replace AF_ALG with open-coded SHA-256 for GitHub compatibility

**Commit:** `4ef77dd58`
**Reason:** Better portability and reduced kernel dependencies

### 14.2 bpftool Enhancements

1. **Tracefs search order:** Search for tracefs at `/sys/kernel/tracing` first
   - **Author:** Quentin Monnet

2. **Signing support:** New `sign.c` module (Section 5)

### 14.3 Selftest Framework

Extensive selftest additions and improvements across all new features:
- Qdisc tests: `bpf_qdisc.c`, `bpf_qdisc_fifo.c`, `bpf_qdisc_fq.c`
- Verifier tests: `verifier_live_stack.c` (+294 lines)
- Bounds tests: `verifier_bounds.c` (+79 lines)
- Arena tests: `verifier_ldsx.c` (+178 lines)

---

## 15. Bug Fixes and Stability

Notable fixes in the v6.13-v6.18 timeframe:

1. **Memory leak fixes:**
   - `__lookup_instance` error path (`f6fddc6df`)
   - `__bpf_redirect_neigh_v{4,6}` metadata_dst leak (`23f3770e1`)

2. **Context and RCU fixes:**
   - RCU context warning for htab with internal structs (`4f375ade6`)
   - Preemption handling in `bpf_test_run()` (`7c33e97a6`)

3. **Verifier fixes:**
   - Negative offset rejection for ALU ops (`55c0ced59`)
   - Scalar adjustment skip for BPF_NEG with pointer dst (`34904582b`)
   - Stack depth accounting in `widen_imprecise_scalars()` (`b0c8e6d3d`)

4. **Synchronization fixes:**
   - Sync pending IRQ work before freeing ring buffer (`4e9077638`)
   - Conditional dynptr copy kfuncs inclusion (`8ce93aabb`)

**Reference:** Git log commits ffd294d34..6a23ae0a9

---

## Summary Statistics

**Time Period:** v6.13 (Nov 2024) - v6.18-rc6 (Nov 2025)
**Major BPF Merges:** 1 major (bpf-next-6.18)
**Commits Analyzed:** ~197 commits in bpf-next-6.18 alone
**New Features:** 10+ major features
**Key Areas:**
- struct_ops expansion (Qdisc)
- Memory access (dynptr, XDP pull)
- Security (signed programs)
- Verifier improvements (path-insensitive analysis)
- JIT support expansion

---

## References

### Key Files Analyzed:
- `net/sched/bpf_qdisc.c` - BPF qdisc implementation
- `net/core/filter.c` - XDP and dynptr kfuncs
- `drivers/net/netkit.c` - Netkit headroom support
- `kernel/bpf/verifier.c` - Verifier enhancements
- `tools/bpf/bpftool/sign.c` - BPF program signing

### Key Commits:
- `ae28ed457` - bpf-next-6.18 merge (major features)
- `ffd294d34` - Linux 6.13 release
- `6a23ae0a9` - Linux 6.18-rc6 (current)

### Documentation:
- `Documentation/bpf/kfuncs.rst` - Kfunc documentation
- `Documentation/bpf/verifier.rst` - Verifier changes (264 line changes)

---

## Conclusion

The BPF subsystem has seen substantial growth between v6.13 and v6.18, with major architectural additions (struct_ops for qdisc, signed programs), significant verifier improvements (path-insensitive analysis), and practical enhancements (dynptr metadata, XDP pull). These changes demonstrate BPF's evolution toward more complex use cases while maintaining safety and verifiability guarantees.

The introduction of signed programs is particularly noteworthy as it addresses enterprise deployment requirements, while the qdisc struct_ops support opens entirely new use cases for BPF in network traffic management.

---

**Report compiled:** 2025-11-19
**Methodology:** Git log analysis, source code examination, commit message review
**Baseline:** Linux v6.13 (ffd294d34)
**Current:** Linux v6.18-rc6 (6a23ae0a9)
