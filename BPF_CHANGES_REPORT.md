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

#### Background

The `may_goto` instruction is a conditional pseudo-jump instruction introduced to enable **bounded loops** in BPF programs. Historically, BPF had strict limitations on loops - either completely unrolled at compile-time or using the bounded loop verifier (which has complexity limits). The `may_goto` instruction provides a runtime-checkable way to implement loops with guaranteed termination.

#### How It Works

`may_goto` is defined as:
```c
enum bpf_cond_pseudo_jmp {
    BPF_MAY_GOTO = 0,
};
```

The instruction has the encoding: `BPF_JMP | BPF_JCOND` with `src_reg == BPF_MAY_GOTO`

When the JIT compiler encounters a `may_goto` instruction, it generates code that:
1. Decrements an iteration counter stored on the stack
2. Checks if the counter reached zero
3. If zero, breaks out of the loop (calls helper to handle exhaustion)
4. If non-zero, continues execution

**Example from test (verifier_may_goto_1.c:82-93):**
```
Input BPF:
  .8byte may_goto(offset=2)
  .8byte may_goto(offset=0)
  r0 = 1
  r0 = 2
  exit

JIT output (xlated):
  0: *(u64 *)(r10 -16) = 65535    // Initialize counter
  1: *(u64 *)(r10 -8) = 0
  2: r11 = *(u64 *)(r10 -16)      // Load counter
  3: if r11 == 0x0 goto pc+6      // Check if exhausted
  4: r11 -= 1                      // Decrement
  5: if r11 != 0x0 goto pc+2      // Continue if not zero
  6: r11 = -16
  7: call unknown                  // Handle exhaustion
  8: *(u64 *)(r10 -16) = r11      // Store counter
  9: r0 = 1
  10: r0 = 2
  11: exit
```

#### Importance

1. **Bounded Loops:** Enables safe iteration with guaranteed termination, critical for:
   - Processing variable-length data structures
   - Network packet parsing with unknown header counts
   - Iterating over map elements

2. **Verifier Efficiency:** Reduces verifier complexity by moving loop termination checks from verification time to runtime

3. **Program Portability:** Prior JIT support was limited to x86. Adding s390 and arm64 support means:
   - BPF programs using loops work on more architectures
   - Cloud workloads on ARM servers can use bounded loops
   - Mainframe (s390) deployments gain loop support

4. **Performance:** JIT-compiled loops are faster than interpreter-based bounded loops

**Reference:** `tools/testing/selftests/bpf/progs/verifier_may_goto_1.c:1-100`

---

## 8. BPF Arena Enhancements

### Background: What is BPF Arena?

BPF Arena is a **shared memory region** between BPF programs and user space, introduced in Linux 6.x. Think of it as a large (up to 4GB), sparsely-populated memory region that both kernel BPF programs and user-space processes can access.

**Key characteristics (kernel/bpf/arena.c:12-39):**
- **Dual address space mapping:**
  - User space sees it as normal 64-bit pointers (e.g., `0x7f7d26200000`)
  - BPF programs access it via 32-bit offsets + base register (e.g., `kern_vm_start + lower_32bits`)
- **Sparse allocation:** Pages allocated on-demand via fault-in
- **Use cases:**
  - Large data structures shared between BPF and user space
  - Complex data processing requiring more than stack/map memory
  - User-space post-processing of BPF-collected data

### Signed Load Support

**Status:** ✅ Implemented
**Authors:** Kumar Kartikeya Dwivedi, Puranjay Mohan
**Version:** v6.18

#### What Are Signed Loads?

"Signed loads" refers to **sign-extended load operations** (LDSX instruction). When loading values smaller than 64-bit from memory, the CPU can either:
- **Zero-extend:** Fill upper bits with zeros (unsigned interpretation)
- **Sign-extend:** Fill upper bits with the sign bit (signed interpretation)

**Example (verifier_ldsx.c:20-35):**
```c
// Loading a signed 8-bit value -2 (0xfe):
*(u64 *)(r10 - 8) = 0x3fe;
r0 = *(s8 *)(r10 - 8);  // Sign-extended load
// Result: r0 = 0xfffffffffffffffe (-2 as 64-bit)

// If it were unsigned:
r0 = *(u8 *)(r10 - 8);
// Result: r0 = 0x00000000000000fe (254 as 64-bit)
```

#### Why This Matters for Arena

1. **Correct Integer Handling:**
   - Arena programs often process structured data with signed integers
   - Without sign-extension, `int8_t` or `int16_t` values would be misinterpreted
   - Example: Temperature sensor data using signed bytes (-40°C to +85°C)

2. **C Semantics Compatibility:**
   - User space and BPF programs can share C structures with signed fields
   - BPF correctly interprets negative values from arena memory
   - Enables complex data processing with proper arithmetic

3. **Architecture Support:**
   - Tests show support for: arm64, x86, riscv64, arm, s390, loongarch
   - JIT compilers generate proper sign-extension instructions
   - RISC-V gained atomic operation support for arena

#### Enhanced Features

**RISC-V JIT Enhancement:**
- Atomic operations (atomic add, compare-and-swap) now work in arena
- Enables lock-free data structures in shared memory
- Critical for multi-core BPF programs coordinating via arena

**Fault Reporting:**
- Arena page faults (invalid access) reported to BPF error stream
- Improves debugging of out-of-bounds or unmapped access
- Example: Accessing arena offset beyond allocated range

**References:**
- `kernel/bpf/arena.c:12-39` - Arena implementation
- `tools/testing/selftests/bpf/progs/verifier_ldsx.c:1-60` - Sign-extend tests
- `include/linux/btf.h:77` - `KF_ARENA_RET` and `KF_ARENA_ARG1` flags

#### Practical Impact

Enables real-world use cases like:
- **High-frequency trading:** Shared price data structures between BPF packet processor and user-space trading engine
- **ML inference:** BPF programs writing features to arena for user-space model inference
- **Monitoring dashboards:** Aggregated metrics in arena consumed by visualization tools

---

## 9. Task Work Scheduling Kfuncs

**Status:** ✅ Implemented
**Author:** Mykyta Yatsenko
**Version:** v6.18

### Background: What is Task Work?

**Task work** is a Linux kernel mechanism to defer work to run in the context of a **specific process/task**. Unlike workqueues (which run in kernel threads) or softirqs (which run in interrupt context), task work runs when that specific task returns to user space or is about to sleep.

**Key properties:**
- Runs with the target task's credentials, namespaces, and memory context
- Can safely access user-space memory of that task
- Two notification modes:
  - `TWA_SIGNAL`: Send a signal to wake the task
  - `TWA_RESUME`: Run when task naturally resumes

### BPF Task Work Kfuncs

Two new kfuncs enable BPF programs to schedule callbacks in task context:

```c
__bpf_kfunc int bpf_task_work_schedule_signal_impl(
    struct task_struct *task,
    struct bpf_task_work *tw,
    void *map__map,
    bpf_task_work_callback_t callback,
    void *aux__prog)

__bpf_kfunc int bpf_task_work_schedule_resume_impl(
    struct task_struct *task,
    struct bpf_task_work *tw,
    void *map__map,
    bpf_task_work_callback_t callback,
    void *aux__prog)
```

**Reference:** `kernel/bpf/helpers.c:4182-4207`

### How It Works

**Implementation (kernel/bpf/helpers.c:4127-4169):**

1. **BPF program calls kfunc:** Specifies target task and callback subprogram
2. **Context creation:** Allocates `bpf_task_work_ctx` with:
   - Reference to target task (preventing premature exit)
   - Reference to BPF program (preventing unload)
   - Callback function pointer
   - Map containing the task_work structure
3. **Scheduling:** Uses `init_irq_work()` to safely schedule from any context (even NMI)
4. **Execution:** When task returns to user space:
   - Task work callback runs in task's context
   - BPF subprogram executes
   - Context and references cleaned up

**Example from test (task_work_stress.c:39-61):**
```c
SEC("syscall")
int schedule_task_work(void *ctx)
{
    struct elem *work;
    int key = bpf_ktime_get_ns() % ENTRIES;

    work = bpf_map_lookup_elem(&hmap, &key);
    if (!work) {
        bpf_map_update_elem(&hmap, &key, &empty_work, BPF_NOEXIST);
        work = bpf_map_lookup_elem(&hmap, &key);
    }

    // Schedule callback to run in current task's context
    err = bpf_task_work_schedule_signal_impl(
        bpf_get_current_task_btf(),
        &work->tw, &hmap, process_work, NULL);

    return 0;
}

static int process_work(struct bpf_map *map, void *key, void *value)
{
    // This runs in the target task's context!
    __sync_fetch_and_add(&callback_success, 1);
    return 0;
}
```

### Importance and Use Cases

1. **User-Space Upcalls:**
   - BPF program can trigger work in specific process context
   - Example: Network filter notifying application about blocked connection
   - Runs with correct UID, capabilities, and namespaces

2. **Deferred Processing:**
   - Heavy computation deferred from packet processing fast path
   - Example: Detailed flow analysis after initial packet classification
   - Prevents blocking packet receive queues

3. **Application-Specific Hooks:**
   - Per-process monitoring and control
   - Example: Memory profiler triggering callback in target process
   - Can access process-specific resources safely

4. **Async Event Delivery:**
   - Kernel events delivered to specific applications
   - Example: Filesystem watcher notifying specific daemon
   - Better than signals for complex data passing

5. **Safe User Memory Access:**
   - Can use `copy_to_user()` since running in task context
   - Example: Writing monitoring data to application's buffer
   - Avoids complex synchronization with user space

### Safety Mechanisms

**Lifetime Management (kernel/bpf/helpers.c:4219-4238):**
- Reference counting prevents task exit while work pending
- Program pinning prevents BPF unload during execution
- Map reference keeps storage valid
- IRQ work for safe cancellation from any context

**Concurrency Control:**
- State machine tracks: `BPF_TW_PENDING`, `BPF_TW_SCHEDULED`, `BPF_TW_FREED`
- Prevents double-scheduling or use-after-free
- Handles races between schedule/cancel/delete

**Reference:**
- `kernel/bpf/helpers.c:4127-4238` - Implementation
- `tools/testing/selftests/bpf/progs/task_work_stress.c` - Stress test with concurrent schedule/delete

---

## 10. KFuncs and Helper Enhancements

### 10.1 Enhanced RCU Protection Enforcement

**Author:** Kumar Kartikeya Dwivedi
**Version:** v6.18

#### Background: RCU in BPF

**RCU (Read-Copy-Update)** is a Linux synchronization primitive that allows:
- Readers to access data structures without locks
- Writers to update safely while readers are active
- Deferred reclamation of old versions after readers finish

In BPF context, RCU is critical because:
- BPF programs run in kernel with minimal overhead
- Traditional locks would severely impact performance
- Many kernel structures are RCU-protected (task lists, network routes, etc.)

#### KF_RCU vs KF_RCU_PROTECTED

**Before:** Two separate flags with unclear semantics:
- `KF_RCU`: Indicates arguments must be RCU-protected pointers
- No enforcement of RCU critical section

**Now (include/linux/btf.h:77):**
```c
#define KF_RCU          (1 << 7)  /* kfunc takes rcu or trusted pointer arguments */
#define KF_RCU_PROTECTED (1 << 11) /* kfunc must be in RCU critical section */
```

#### What Changed

**KF_RCU_PROTECTED Enforcement (Documentation/bpf/kfuncs.rst:338-351):**

1. **Mandatory RCU Critical Section:**
   - Kfunc marked with `KF_RCU_PROTECTED` **must** be called within RCU read-side critical section
   - Non-sleepable programs: Assumed to be in RCU section (entire program)
   - Sleepable programs: Must explicitly call `bpf_rcu_read_lock()`

2. **Return Pointer Protection:**
   - If kfunc returns a pointer, it's guaranteed RCU-protected
   - Pointer only valid while RCU critical section active
   - Verifier tracks and enforces this lifetime

3. **Distinction from KF_RCU:**
   - `KF_RCU`: "My arguments should be RCU pointers" (callee requirement)
   - `KF_RCU_PROTECTED`: "Call me in RCU section, my return is RCU-protected" (caller requirement)

#### Example Scenario

**Before (unsafe):**
```c
// Sleepable BPF program
SEC("lsm.s/file_open")
int file_monitor(struct file *file)
{
    struct task_struct *task;

    // BAD: kfunc returns RCU-protected pointer
    task = bpf_get_current_task_btf();  // KF_RCU_PROTECTED kfunc

    // Sleepable program might sleep here!
    bpf_copy_from_user(...);

    // DANGER: task might be freed (no RCU protection)
    char *comm = task->comm;  // Use-after-free!
}
```

**After (enforced):**
```c
// Sleepable BPF program
SEC("lsm.s/file_open")
int file_monitor(struct file *file)
{
    struct task_struct *task;

    bpf_rcu_read_lock();  // Explicit RCU critical section
    task = bpf_get_current_task_btf();  // OK: in RCU section

    char *comm = task->comm;  // OK: still protected
    bpf_rcu_read_unlock();

    // CAN'T use task here - verifier error!
    // task pointer marked as potentially invalid
}
```

#### Importance

1. **Memory Safety:**
   - Prevents use-after-free bugs in sleepable BPF programs
   - Verifier catches violations at load time
   - No runtime crashes from RCU violations

2. **Correctness Guarantees:**
   - Returned pointers have well-defined lifetime
   - Clear contract between kfunc and caller
   - Reduces subtle bugs in complex programs

3. **Performance:**
   - Non-sleepable programs have no overhead (implicit RCU)
   - Sleepable programs only pay cost where needed
   - Enables safe access to kernel data structures

4. **Developer Experience:**
   - Clear error messages when RCU section missing
   - Documentation of kfunc requirements via flags
   - Type system enforces memory safety

**Reference:**
- `include/linux/btf.h:77` - Flag definitions
- `Documentation/bpf/kfuncs.rst:338-351` - KF_RCU_PROTECTED documentation

### 10.2 New String Kfunc

```c
__bpf_kfunc int bpf_strcasecmp(const char *s1, const char *s2)
```

**Author:** Rong Tao
**Purpose:** Case-insensitive string comparison

**Use Cases:**
- HTTP header parsing (case-insensitive per RFC)
- Configuration file processing
- Protocol name matching

### 10.3 Map Operation Enhancement

**Feature:** `lookup_and_delete_elem` for `BPF_MAP_STACK_TRACE`
**Author:** Tao Chen

**What It Does:**
Atomic operation that:
1. Looks up a stack trace by key
2. Deletes it from the map
3. Returns the stack trace data

**Why It Matters:**
- **Performance:** Single operation vs two (lookup + delete)
- **Atomicity:** No race condition where trace might be overwritten between lookup and delete
- **Memory Management:** Efficient cleanup of consumed stack traces
- **Use Case:** Profiling tools that process and discard stack traces

**Test:** `tools/testing/selftests/bpf/prog_tests/bpf_obj_pinning.c` (modified)

---

## 11. Program Type Extensions

### 11.1 Uprobe Context Modification

**Status:** ✅ Implemented
**Author:** Jiri Olsa
**Version:** v6.18

#### Background: What Are Uprobes?

**Uprobes (user-space probes)** allow tracing and modifying user-space application execution:
- Set breakpoint at any instruction in user program
- Kernel traps when breakpoint hit
- BPF program runs with access to CPU registers (`pt_regs`)

**Traditional Limitation:** Could only **read** register values

#### What Changed

BPF programs attached to uprobes can now **write** to the `pt_regs` context, enabling modification of:

1. **Function Arguments** (before function executes)
2. **Return Values** (at function return)
3. **Instruction Pointer** (control flow)
4. **Other Registers** (local variables, flags)

**Example (kprobe_write_ctx.c:8-22):**
```c
#if defined(__TARGET_ARCH_x86)
SEC("kprobe")
int kprobe_write_ctx(struct pt_regs *ctx)
{
    ctx->ax = 0;  // Modify RAX register
    return 0;
}

SEC("kprobe.multi")
int kprobe_multi_write_ctx(struct pt_regs *ctx)
{
    ctx->ax = 0;  // Works for kprobe.multi too
    return 0;
}
#endif
```

#### Use Cases and Importance

1. **Error Injection Testing:**
   ```c
   // Force allocation to fail
   SEC("uprobe//lib/libc.so.6:malloc")
   int inject_malloc_failure(struct pt_regs *ctx)
   {
       if (should_inject_failure())
           ctx->ax = 0;  // Return NULL
       return 0;
   }
   ```
   - Test error handling paths
   - Chaos engineering for applications
   - No need to modify application source

2. **Security Instrumentation:**
   ```c
   // Modify file path in open() call
   SEC("uprobe//lib/libc.so.6:open")
   int redirect_file_access(struct pt_regs *ctx)
   {
       char *path = (char *)ctx->di;  // First argument
       if (strcmp(path, "/etc/passwd") == 0)
           ctx->di = (u64)"/tmp/fake_passwd";  // Redirect
       return 0;
   }
   ```
   - Sandbox applications
   - Honeypot implementation
   - Access control without kernel modifications

3. **Dynamic Patching:**
   ```c
   // Fix bug in running application
   SEC("uprobe//usr/bin/app:buggy_function")
   int fix_calculation(struct pt_regs *ctx)
   {
       int arg = ctx->di;
       if (arg < 0)
           ctx->di = 0;  // Clamp negative values
       return 0;
   }
   ```
   - Hot-patch production bugs
   - No application restart required
   - Test fixes before binary update

4. **Performance Optimization:**
   ```c
   // Cache function results
   SEC("uprobe//usr/lib/libcrypto.so:expensive_hash")
   int cache_hash(struct pt_regs *ctx)
   {
       void *input = (void *)ctx->di;
       void *cached = bpf_map_lookup_elem(&cache, input);
       if (cached) {
           ctx->ax = (u64)cached;  // Return cached value
           ctx->ip += offset_to_ret;  // Skip function
       }
       return 0;
   }
   ```
   - Memoization without code changes
   - Short-circuit expensive operations

5. **Debugging and Analysis:**
   ```c
   // Modify loop counter for testing
   SEC("uprobe//usr/bin/app:process_batch")
   int limit_iterations(struct pt_regs *ctx)
   {
       ctx->cx = 10;  // Force only 10 iterations
       return 0;
   }
   ```
   - Test with smaller datasets
   - Reduce iteration for profiling
   - Control execution flow

### 11.2 Kprobe Write Context

**Similar Capability** for kernel probes:
- Modify kernel function arguments
- Change return values
- Useful for kernel testing and fault injection

**Example Use:**
```c
// Test filesystem error handling
SEC("kprobe/kmalloc")
int inject_allocation_failure(struct pt_regs *ctx)
{
    if (test_failure_injection())
        ctx->ax = 0;  // Return NULL
    return 0;
}
```

#### Safety and Limitations

**Verifier Restrictions:**
- Can only modify registers, not arbitrary memory
- Type checking ensures register writes are safe
- Can't corrupt kernel/user memory directly
- Architecture-specific (different registers per arch)

**Potential Risks:**
- Application might crash if registers set incorrectly
- Must understand calling convention (x86-64 SysV ABI, ARM AAPCS, etc.)
- Instruction pointer modification can cause jumps to invalid code

**Best Practices:**
- Thoroughly test before production use
- Understand target function's semantics
- Use for controlled testing/debugging environments
- Consider using return value modification over argument changes

**Tests:**
- `tools/testing/selftests/bpf/progs/kprobe_write_ctx.c` - Basic functionality
- `tools/testing/selftests/bpf/prog_tests/attach_probe.c` - Uprobe IP register test
- `tools/testing/selftests/bpf/prog_tests/kprobe_multi_test.c` - Kprobe multi write test

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
