# Linux Kernel Ring Buffer: Detailed Architectural Analysis

This document provides an in-depth comparison of ring buffer implementations in the Linux kernel, focusing on their unique characteristics, design trade-offs, and requirements.

## Table of Contents

1. [Overview](#overview)
2. [Detailed Implementation Analysis](#detailed-implementation-analysis)
3. [Comparison Tables](#comparison-tables)
4. [Design Patterns and Trade-offs](#design-patterns-and-trade-offs)
5. [Selection Guide](#selection-guide)

---

## Overview

Ring buffers (circular buffers) are fundamental data structures in the Linux kernel, used for efficient producer-consumer communication. Different implementations optimize for different requirements: latency, throughput, safety, context compatibility, and more.

This analysis examines 11 major ring buffer implementations to understand their architectural differences.

---

## Detailed Implementation Analysis

### 1. BPF Ring Buffer

**Location**: `kernel/bpf/ringbuf.c`

#### Overflow Behavior
- **Policy**: Returns error when full (NULL or -EAGAIN)
- **Space check**: `new_prod_pos - cons_pos > rb->mask` (lines 446-450)
- **No overwrite**: Never drops old data
- **User-space producer mode**: Can skip discarded samples (lines 707-714)

#### Memory Model
- **Allocation**: Individual pages via `alloc_pages_node()` (lines 125-130)
- **Double-mapping trick**: ✅ YES - Data pages mapped twice
  ```
  | meta pages | real data pages | same data pages |
  |            | 1 2 3 4 5 6 7 8 | 1 2 3 4 5 6 7 8 |
  ```
- **Benefit**: Eliminates wrap-around handling - reads can be contiguous
- **Virtual mapping**: `vmap()` creates contiguous virtual address space (line 135)
- **Shared memory**: mmap-able to userspace with different permissions:
  - **Kernel producer**: producer_pos + data are read-only to userspace
  - **User producer**: only consumer_pos is read-only to userspace
- **Size requirements**: Power-of-2 and page-aligned (line 199)
- **Zero-copy**: ✅ YES via mmap

#### Synchronization Mechanisms
- **Lock type**: `rqspinlock_t` (raw IRQ spinlock) for kernel producers (line 33)
- **Alternative**: `atomic_t busy` bit for user-space producers (lines 34-48)
  - Prevents holding locks across BPF program execution
- **Memory barriers**:
  - `smp_load_acquire()` for consumer_pos/producer_pos reads (lines 302-303)
  - `smp_store_release()` for producer_pos updates (line 458)
- **Producer/Consumer model**:
  - Kernel mode: MPSC (multiple BPF programs, single consumer)
  - User mode: SPSC (single user producer, single kernel consumer)
- **NMI/IRQ safety**: ✅ YES - uses IRQ spinlock with contention fallback (lines 422-423)
- **BUSY_BIT**: Records have in-flight state in header (line 454)

#### Data Organization
- **Record type**: Variable-size with 8-byte header
- **Header structure**: `struct bpf_ringbuf_hdr { u32 len; u32 pg_off; }`
- **Max record size**: UINT_MAX/4 (~1GB)
- **Alignment**: 8-byte aligned (line 416)
- **Metadata trick**: Page offset in header allows restoring ringbuf pointer (lines 389-405)

#### Performance Optimizations
- **Cache alignment**: producer_pos, consumer_pos, busy on separate cache lines
- **Double-mapping**: Eliminates conditional wrap-around logic
- **Discard support**: Records can be discarded without committing (lines 484-496)
- **Notification control**:
  - `irq_work` for wakeups (lines 151-155)
  - Flags: `BPF_RB_NO_WAKEUP`, `BPF_RB_FORCE_WAKEUP` (lines 506-509)
- **Poll support**: epoll/poll integration (lines 312-336)

#### Unique Features
- **Reserve-commit model**: Three-phase operation: reserve → write → commit/discard
- **Bidirectional**: Supports both kernel→user and user→kernel modes
- **Permission separation**: Different mmap permissions based on producer
- **Restore from record**: Can recover ringbuf pointer from any record header
- **Pending position**: Tracks uncommitted records (lines 425-438)

#### Use Case
- **Primary purpose**: Fast BPF program to userspace event streaming
- **Latency**: Low - lock-free reads, minimal barriers
- **Throughput**: High - zero-copy via mmap
- **Data loss tolerance**: No - returns error, caller decides
- **Context**: NMI/IRQ safe for kernel producers

---

### 2. Perf Event Ring Buffer

**Location**: `kernel/events/ring_buffer.c`

#### Overflow Behavior
- **Two modes**:
  - **Non-overwrite** (default): Returns -ENOSPC when full (lines 203-207, 263-270)
  - **Overwrite mode**: Silently drops oldest data (line 203)
- **Lost event tracking**: Maintains `rb->lost` counter and injects PERF_RECORD_LOST events (lines 248-259)
- **Pause support**: Can pause ring buffer via `rb->paused` (lines 178-184)

#### Memory Model
- **Allocation strategy**:
  - Small systems: `alloc_pages_node()` individual pages
  - Large systems: `vmalloc_user()` for contiguous virtual space
- **Page arrays**: Stores page pointers in `rb->data_pages[]`
- **Shared memory**: ✅ mmap-able with user_page for metadata
- **AUX buffer**: Separate auxiliary buffer for hardware tracing (lines 677-790)
  - Supports high-order allocations for contiguous memory
  - Both scatter-gather and contiguous modes
  - Used for Intel PT, ARM CoreSight
- **Zero-copy**: ✅ YES via mmap

#### Synchronization Mechanisms
- **Lock-free design**: Uses atomic operations and memory barriers
- **Nesting support**: Handles nested events (NMI inside IRQ) via `rb->nest` counter (lines 42-68)
  - Critical for profiling - NMI can interrupt IRQ handler
- **Memory barriers**:
  - Producer: `smp_wmb()` before updating data_head (line 113)
  - Consumer: `smp_rmb()` after reading data_tail (lines 93-99)
  - Control dependency separates tail load from data stores
- **Producer/Consumer**: MPSC (multiple CPUs/contexts can produce, single consumer per CPU)
- **NMI safety**: ✅ YES - explicit nesting handling (lines 33-38)
- **Preemption**: Disabled during output (line 44)

#### Data Organization
- **Variable-size events**: ✅ YES
- **Page-based organization**: Events stored in pages with metadata
- **Page order**: Configurable multi-page "sub-buffers" (lines 241-246)
- **Wrap handling**: Via page linking, not double-mapping
- **Lost event injection**: PERF_RECORD_LOST events inserted when data dropped

#### Performance Optimizations
- **Per-CPU buffers**: Separate buffer per CPU - eliminates cross-CPU contention
- **Wakeup control**: Watermark-based wakeups reduce syscall overhead (lines 238-239)
- **IRQ work**: Delayed wakeups via irq_work (line 29)
- **Backward ring**: Can write backward from tail for snapshot profiling (lines 145-149, 222-225)
  - Allows "snapshot on demand" without continuous overhead
- **Tunable page order**: Configurable sub-buffer size for batching

#### Unique Features
- **Dual buffer design**: Main ring + optional AUX buffer
- **AUX buffer modes**: Separate overwrite/non-overwrite control for hardware tracing
- **Backward mode**: Unique feature for low-overhead snapshot profiling
- **Lost event records**: Explicitly tracked in event stream
- **Hardware integration**: Special support for hardware tracing (Intel PT, CoreSight)
- **Per-event buffers**: Each perf event can have its own buffer

#### Use Case
- **Primary purpose**: CPU profiling, hardware tracing, performance monitoring
- **Latency**: Low for sampling, bounded for tracing
- **Throughput**: Very high - designed for high-frequency CPU events
- **Data loss tolerance**: Both modes available
- **Context**: NMI/IRQ/process - fully reentrant

---

### 3. Ftrace Ring Buffer

**Location**: `kernel/trace/ring_buffer.c`

#### Overflow Behavior
- **Configurable modes**:
  - **Non-overwrite** (default): Drops new events when full
  - **Overwrite mode**: Drops oldest events (like a flight recorder)
- **Per-CPU tracking**: Separate `lost_events` and `last_overrun` counters per CPU
- **Overrun counters**: Distinguish between different types of drops

#### Memory Model
- **Per-CPU buffers**: Dedicated buffer per CPU (lines 477-500)
- **Page lists**: Linked list of `buffer_page` structures (lines 359-369, 488)
- **Allocation**: Individual pages via `free_pages()`
- **Reader page swap**: Special reader page swapped with ring pages (lines 92-154)
  ```
  Before swap:     After swap:
  [Reader]         [Reader]──┐
     ↓                       ↓
  ┌──┬──┬──┐      ┌──┬──┬──┐
  │A →B →C │      │B →C →A │
  └──┴──┴──┘      └──┴──┴──┘
  ```
- **Sub-buffer support**: Configurable sub-buffer order for larger atomic units
- **Range mapping**: Can use pre-allocated memory range
- **Zero-copy**: ✅ via splice and mmap support

#### Synchronization Mechanisms
- **Per-CPU design**: Lock-free within same CPU
- **Locks**:
  - `arch_spinlock_t lock` for writer synchronization (line 483)
  - `raw_spinlock_t reader_lock` for readers (line 482)
- **Context tracking**: 5-level nesting (lines 458-465):
  1. NORMAL (process context)
  2. SOFTIRQ
  3. IRQ (hard interrupt)
  4. NMI
  5. TRANSITION
- **NMI safety**: ✅ YES - explicit per-context handling
- **Atomic operations**: Uses `local_t` for per-CPU atomics (lines 342, 361-363)

#### Data Organization
- **Variable-size events**: ✅ YES with compressed header
- **Event header**: 5-bit type_len, 27-bit time_delta (lines 71-85)
  - Extremely compact - only 32 bits for small events
- **Alignment**: 4-byte (RB_ALIGNMENT = 4)
- **Time encoding**: Delta encoding with extension records for large deltas
  - Most events need only 27 bits for time delta
  - TIME_EXTEND records for larger deltas
- **Page structure**: Each page has write, commit, entries count
- **Meta pages**: Support for memory-mapped access

#### Performance Optimizations
- **Reader page swap**: Lockless reader via page swapping - unique design
  - Reader gets entire page atomically
  - Zero-copy reads possible
- **Per-CPU**: No cross-CPU synchronization in fast path
- **Cache-aligned pages**: Buffer pages cache-line aligned
- **Batched commits**: Multiple events committed together
- **Event filtering**: Can discard events before commit
- **Nested context**: Optimized for deep interrupt nesting (MAX_NEST = 5)
- **IRQ work notifications**: Batched wakeups

#### Unique Features
- **Most complex ring buffer**: Handles all kernel contexts
- **Reader page design**: Innovative zero-copy read mechanism
- **Time stamp compression**: Delta encoding saves massive space
- **Sub-buffer atomicity**: Configurable atomic operation units
- **Range mapping**: External memory range support
- **Splice support**: Efficient extraction via splice() syscall
- **Extensive self-tests**: Built-in test suite (ring_buffer_test.c)

#### Use Case
- **Primary purpose**: Kernel function tracing, event tracing
- **Latency**: Very low - designed for minimal tracing overhead
- **Throughput**: Extremely high - millions of events/second
- **Data loss tolerance**: Acceptable in overwrite mode, tracked otherwise
- **Context**: ALL contexts (NMI, IRQ, softirq, process)

---

### 4. Printk Ring Buffer

**Location**: `kernel/printk/printk_ringbuffer.c`

#### Overflow Behavior
- **Always overwrites**: Silently drops oldest messages when full (lines 74-80)
- **Descriptor lifecycle**: reserved → committed → finalized → reusable (lines 47-64)
- **Tail advancement**: Automatically pushes tail when space needed

#### Memory Model
- **Three-ring architecture** (lines 17-31):
  1. **desc_ring**: Descriptors with metadata and atomic state
  2. **text_data_ring**: Variable-length text data
  3. **info array**: `printk_info` metadata (level, timestamp, etc.)
- **Allocation**: Simple arrays, power-of-2 sized
- **Descriptor ID**: Array index + wrap counter (prevents ABA issues on 32-bit systems)
- **Logical positions**: Array index + wrap counter for data blocks
- **Not mmap-able**: Kernel-only access

#### Synchronization Mechanisms
- **Fully lock-free**: No locks whatsoever - uses atomic state machine
- **State machine**: Atomic state transitions via cmpxchg (lines 43-80)
  - reserved: Writer modifying
  - committed: Data written, consistent
  - finalized: Complete, cannot reopen
  - reusable: May be recycled
- **Memory barriers**: Extensively documented with LMM (Linux Memory Model) labels (lines 261-311)
  - Release semantics for commits
  - Acquire semantics for reads
  - Every barrier documented and proven
- **Producer/Consumer**: MPMC (multiple writers, multiple readers)
- **NMI safety**: ✅ YES - primary design goal for printk from NMI
- **No locks**: Pure atomic operations

#### Data Organization
- **Variable-size records**: ✅ YES
- **Data blocks**: ID prefix + variable data (lines 342-354)
- **Wrap handling**: ID-only block at end, full block wraps to start (lines 129-134)
- **Descriptor states**: Atomic state tracks validity
- **Separated metadata**: Descriptors, info, and text in separate rings
  - Reduces cache line contention
  - Allows independent sizing

#### Performance Optimizations
- **Lock-free**: Zero lock contention
- **Separated metadata**: Three separate rings minimize false sharing
- **State-based coordination**: Eliminates need for locks
- **Carefully ordered barriers**: Minimal barriers for correctness
- **ABA prevention**: Tagged pointers with wrap counters

#### Unique Features
- **Three-ring architecture**: Most sophisticated lock-free design
- **Descriptor finalization**: Three-phase lifecycle with reopening capability
- **Record extending**: Can reopen and extend committed (but not finalized) records (lines 87-106)
  - Useful for multi-line messages
- **NMI printk**: Primary goal - printk from anywhere including crash handlers
- **ABA prevention**: Comprehensive ABA problem mitigation on 32-bit
- **State machine**: Complex 4-state atomic state machine
- **Extensively documented**: 300+ lines of documentation and memory ordering proofs

#### Use Case
- **Primary purpose**: Kernel logging, crash diagnostics
- **Latency**: Very low - must not impact system
- **Throughput**: Moderate - not designed for high volume
- **Data loss tolerance**: Always acceptable - debug logs can be lost
- **Context**: NMI safe - absolute requirement for crash logging

---

### 5. circ_buf (Circular Buffer Helper)

**Location**: `include/linux/circ_buf.h`

#### Overflow Behavior
- **No built-in handling**: User must check space before writing
- **Helper macros**: `CIRC_SPACE()` returns available space
- **Full condition**: Leaves one slot empty (head == tail means empty, not full)

#### Memory Model
- **Simple structure**: `char *buf; int head; int tail;` (lines 9-13)
- **User allocates**: Buffer allocation is user's responsibility
- **Any memory type**: Works with kmalloc, vmalloc, DMA buffers, static arrays
- **Power-of-2 requirement**: ✅ Implicit in macros (uses size-1 mask)

#### Synchronization Mechanisms
- **No built-in locks**: User must provide synchronization
- **Designed for SPSC**: Documentation suggests lock-free for single reader/writer
- **Memory barriers**: User's responsibility to add appropriate barriers
- **Producer/Consumer**: Designed for SPSC but user enforces

#### Data Organization
- **User-defined**: Can be fixed or variable size
- **Byte-based**: Uses `char *` buffer
- **Simple indexing**: head and tail wrap via `(index) & (size-1)` mask

#### Performance Optimizations
- **Minimal overhead**: Just macro-based index calculations
- **Cache-friendly**: Sequential access patterns
- **Zero abstraction cost**: Compiles to simple arithmetic
- **No function calls**: Everything inline macros

#### Unique Features
- **Header-only**: Just helper macros, not an implementation
- **Generic**: Used by 200+ drivers (serial, DMA, etc.)
- **Battle-tested**: Decades old, extremely stable
- **Minimal**: Simplest possible circular buffer abstraction
- **Educational**: Perfect example of circular buffer basics

#### Use Case
- **Primary purpose**: General-purpose driver helper for serial ports, DMA, etc.
- **Latency**: Minimal - just index arithmetic
- **Throughput**: Depends on user implementation
- **Data loss tolerance**: User decides
- **Context**: User decides - typically device drivers

---

### 6. kfifo

**Location**: `include/linux/kfifo.h`, `lib/kfifo.c`

#### Overflow Behavior
- **Returns actual count**: `kfifo_in()` returns number of elements actually stored
- **Partial writes**: Accepts what fits, returns count written
- **No overwrite**: Never overwrites old data
- **Caller checks**: Return value indicates overflow condition

#### Memory Model
- **Two allocation modes**:
  - **Static**: Buffer embedded in structure (`STRUCT_KFIFO`)
  - **Dynamic**: Allocated via `kfifo_alloc()` using `kmalloc_array()`
- **Power-of-2**: Size automatically rounded up to power-of-2
- **Type-safe**: Macros provide compile-time type checking
- **Generic**: Works with any element type

#### Synchronization Mechanisms
- **Lock-free for SPSC**: Single producer/single consumer needs no locks (lines 30-37)
- **Memory barriers**: `smp_wmb()` after in/out pointer updates
- **Spinlock variants**: `kfifo_in_spinlocked()` for multiple producers
- **Multiple variants**: regular, irq, bh, irqsave for different contexts
- **Optional locking**: User chooses lock type if needed

#### Data Organization
- **Fixed-size elements**: Each element same size (configurable)
- **Record mode**: Optional variable-size records with 1 or 2-byte length prefix
- **Mask-based indexing**: Uses size-1 mask for fast wraparound
- **Contiguous layout**: Simple array storage

#### Performance Optimizations
- **Lock-free SPSC**: Zero locks for single producer/consumer
- **Contiguous copies**: Optimized `memcpy()` paths when possible
- **DMA support**: Built-in scatterlist preparation for DMA engines (lines 309-376)
- **Batching**: Can operate on multiple elements at once
- **Peek support**: Can peek without consuming (lines 481-516)
- **User-space copy**: Optimized `copy_from_user`/`copy_to_user` paths

#### Unique Features
- **Type-safe macros**: Compile-time type checking via clever macro use
- **Record mode**: Variable-length records with automatic length prefix
- **DMA integration**: Built-in scatterlist support for DMA engines
- **Multiple element sizes**: Supports 1, 2, 4, 8 byte or arbitrary element sizes
- **Rich API**: Dozens of helper functions for various use cases
- **Widely used**: 200+ usage sites across kernel

#### Use Case
- **Primary purpose**: General kernel FIFO - networking, storage, drivers
- **Latency**: Low - designed for real-time systems
- **Throughput**: High for SPSC, moderate with locks
- **Data loss tolerance**: Not acceptable - returns count, caller decides
- **Context**: Process or IRQ (with appropriate spinlock variant)

---

### 7. ptr_ring

**Location**: `include/linux/ptr_ring.h`

#### Overflow Behavior
- **Returns error**: Returns -ENOSPC when full
- **No overwrite**: Never drops data
- **Caller handles**: User must handle -ENOSPC appropriately

#### Memory Model
- **Pointer array**: Stores only void* pointers (not data)
- **Allocation**: `kvmalloc_array()` for pointer array
- **Size**: Not required to be power-of-2 (unlike most ring buffers)
- **Batch setting**: Auto-calculated based on cache line size
- **NULL = empty**: Uses NULL to indicate free slots

#### Synchronization Mechanisms
- **Dual spinlocks**: Separate producer and consumer locks
  - Allows concurrent produce and consume
- **Lock variants**: Multiple lock types (regular, irq, bh, any)
- **Cache-line separation**: Producer and consumer on different cache lines
  - Prevents false sharing
- **Batching**: Deferred invalidation for cache efficiency
- **Resize support**: Can resize with proper locking coordination

#### Data Organization
- **Pointer-only**: Stores only pointers, not data itself
- **NULL = empty slot**: Simple full/empty detection
- **Batch invalidation**: Accumulates slot clearing operations
  - `consumer_head`: Next to read
  - `consumer_tail`: Next to invalidate (batched)
- **Simple array**: Just array of void* pointers

#### Performance Optimizations
- **Cache-line alignment**: producer, consumer_head, size on separate cache lines
- **Batched consume**: Delays slot clearing to reduce cache traffic
  - Clears multiple slots at once
- **Zero-copy**: Just passes pointers around
- **Multiple lock variants**: Optimized for different calling contexts
- **Batch API**: `__ptr_ring_consume_batched()` for efficient bulk operations

#### Unique Features
- **Pointer-only**: Specialized for pointer FIFO only
- **Batch invalidation**: Innovative cache-line optimization technique
- **Unconsume support**: Can push back to ring (undo consume)
- **Resize support**: Can dynamically resize while in use
- **Multi-ring resize**: Can resize multiple rings atomically
  - Important for virtio with multiple queues
- **Swap support**: Can atomically swap ring contents

#### Use Case
- **Primary purpose**: Networking pointer passing (virtio, tap/tun, packet scheduling)
- **Latency**: Low - cache-optimized
- **Throughput**: Very high for pointer passing
- **Data loss tolerance**: Not acceptable
- **Context**: Any with appropriate lock variant
- **Typical users**: virtio drivers, TUN/TAP devices, network stack

---

### 8. io_uring

**Location**: `io_uring/` directory

#### Overflow Behavior
- **SQ (Submission Queue)**: User-space manages, kernel only reads
  - User responsible for not overwriting unprocessed entries
- **CQ (Completion Queue)**:
  - Can overflow if userspace doesn't consume fast enough
  - Overflow entries stored in `rb->overflow_list` linked list
  - Flag `IORING_SQ_CQ_OVERFLOW` set when overflowing
  - Userspace can detect and drain overflow

#### Memory Model
- **Shared memory**: Both SQ and CQ mmap-ed between kernel and userspace
- **Layout**:
  - SQ ring: Array of SQE indices (unless `IORING_SETUP_NO_SQARRAY`)
  - CQ ring: Array of CQEs
  - SQEs: Separate array of submission queue entries
- **Allocation**: Pages allocated, then mapped to userspace
- **Two rings**: Independent submission (SQ) and completion (CQ) rings
- **Power-of-2**: Both rings must be power-of-2 sized
- **Size variants**: Can use 32-byte or 128-byte SQEs, 16-byte or 32-byte CQEs
- **Zero-copy**: ✅ Complete zero-copy via shared memory

#### Synchronization Mechanisms
- **Memory barriers**:
  - **SQ**: Application `smp_wmb()` before updating tail, kernel `smp_load_acquire()` reading tail
  - **CQ**: Kernel `smp_wmb()` before updating head, application `smp_rmb()` after reading head
  - **CQ consumer**: Application `smp_mb()` before updating CQ head
- **Lock-free**: Pure memory barrier-based synchronization
- **SQPOLL mode**: Kernel thread can poll SQ eliminating syscalls
- **Producer/Consumer**:
  - SQ: User produces, kernel consumes (typically SPSC)
  - CQ: Kernel produces, user consumes (SPSC or MPSC with shared wq)
- **Context**: Process context for I/O submission

#### Data Organization
- **Fixed-size entries**:
  - SQE: 64 bytes (or 128 bytes with `IORING_SETUP_SQE128`)
  - CQE: 16 bytes (or 32 bytes with `IORING_SETUP_CQE32`)
- **SQE structure**: opcode, flags, fd, offset, addr, len, user_data, etc.
- **CQE structure**: res (result), user_data (matches SQE), flags
- **Indirection**: SQ can use index array to SQEs for submission ordering
- **User data**: Arbitrary 64-bit value passed from SQE to CQE for correlation

#### Performance Optimizations
- **Zero-copy**: Everything via shared memory - no data copying
- **Batch submission**: Submit multiple operations at once
- **Batch completion**: Retrieve multiple completions at once
- **SQPOLL**: Kernel thread polling SQ eliminates syscalls entirely
  - Application can run without any syscalls
- **CQ event fd control**: Can disable eventfd notifications when polling
- **Skip CQE**: Can skip posting CQEs for successful ops (`IOSQE_CQE_SKIP_SUCCESS`)
- **No-op syscall mode**: With SQPOLL + polling, truly zero syscalls possible
- **Registered buffers/files**: Pre-register for even faster access

#### Unique Features
- **Dual-ring design**: Separate submission and completion rings
- **Versatile operations**: Supports dozens of operation types:
  - File I/O: read, write, readv, writev, fsync, etc.
  - Network: accept, connect, send, recv, etc.
  - Advanced: splice, poll, timeout, openat, statx, etc.
- **Request linking**: Chain requests with `IOSQE_IO_LINK`
  - Following request only submitted if previous succeeds
- **Request draining**: `IOSQE_IO_DRAIN` ensures ordering
- **Buffer selection**: Automatic buffer selection from registered pools
- **Polled I/O**: Can bypass block layer completely (`IORING_SETUP_IOPOLL`)
- **Most feature-rich**: Most complex and feature-rich ring buffer in kernel

#### Use Case
- **Primary purpose**: High-performance async I/O interface
- **Latency**: Very low - designed for microsecond-scale latency
- **Throughput**: Extremely high - millions of operations/second possible
- **Data loss tolerance**: CQ can overflow (tracked and recoverable)
- **Context**: Process context, async I/O workers
- **Users**: Databases, web servers, storage systems, network applications

---

### 9. XDP Socket Rings (AF_XDP)

**Location**: `net/xdp/xsk_queue.h`

#### Overflow Behavior
- **Producer returns error**: Returns -ENOSPC when full
- **Validation**: Descriptors validated on consume, invalid ones tracked
- **Statistics**: Maintains `invalid_descs` and `queue_empty_descs` counters
- **No overwrite**: Does not drop old data

#### Memory Model
- **Four-ring architecture**:
  1. **RX ring**: Kernel produces received packets to user
  2. **TX ring**: User produces packets to send to kernel
  3. **Fill ring**: User provides receive buffers to kernel
  4. **Completion ring**: Kernel returns sent buffers to user
- **All shared memory**: All four rings mmap-ed
- **Allocation**: Rings allocated via `vmalloc()`
- **UMEM (User Memory)**: Separate shared memory region for packet data
  - Not part of rings, but referenced by descriptors
- **Descriptor types**:
  - RX/TX: `struct xdp_desc` (addr, len, options)
  - Fill/Completion: Just u64 addresses
- **Power-of-2**: All rings power-of-2 sized

#### Synchronization Mechanisms
- **Memory barriers** (extensively documented):
  - Producer: `smp_store_release()` for index updates
  - Consumer: `smp_load_acquire()` for index reads
  - Control dependency separates consumer load from stores
- **Lock-free**: Pure lock-free with memory barriers only
- **Producer/Consumer**: SPSC per ring (kernel/user split)
- **Index caching**: Cached prod/cons indices reduce memory traffic
  - `cached_prod` and `cached_cons` in struct

#### Data Organization
- **Fixed-size descriptors**: All descriptors fixed size
- **Cache-line alignment**: Indices on separate cache lines
  - `producer` at cache line boundary
  - `pad1` preventing prefetcher interference
  - `consumer` at next cache line boundary
  - Explicit padding to prevent false sharing
- **Mask-based indexing**: Power-of-2 sizing with mask
- **Descriptor validation**: Extensive validation of user-provided descriptors

#### Performance Optimizations
- **Zero-copy**: True zero-copy packet I/O via UMEM
- **Cache-line alignment**: Prevents false sharing between producer/consumer
- **Index caching**: Avoids repeated memory reads/writes
- **Batching**: Batch descriptor operations (up to 256 at once)
- **Direct kernel bypass**: Minimal kernel overhead - packets go straight to/from NIC
- **Multi-buffer support**: Packets can span multiple buffers (for jumbo frames)

#### Unique Features
- **Four-ring coordination**: Most complex multi-ring state management
  - RX and Fill rings coordinate for receive
  - TX and Completion rings coordinate for transmit
- **UMEM regions**: Separate packet data memory region
  - Flexible: can use huge pages, can share between sockets
- **Aligned/unaligned modes**: Different address validation schemes
- **Multi-buffer packets**: Packets can span descriptors (options field)
- **Hardware integration**: Direct NIC integration via XDP
- **Copy vs zero-copy**: Can operate in copy mode for compatibility

#### Use Case
- **Primary purpose**: Ultra-high-performance packet I/O, userspace networking
- **Latency**: Extremely low - microsecond level
- **Throughput**: Multi-million packets per second
- **Data loss tolerance**: Not acceptable (errors returned)
- **Context**: Process (userspace) and softirq (network stack)
- **Users**: DPDK alternatives, custom network stacks, packet processors

---

### 10. Virtio Ring

**Location**: `drivers/virtio/virtio_ring.c`, `include/uapi/linux/virtio_ring.h`

#### Overflow Behavior
- **Returns error**: Returns -ENOSPC when no free descriptors
- **Guest manages**: Guest driver checks available space before adding
- **No overwrite**: Descriptors reused only after device marks them used
- **Event suppression**: Can suppress notifications when not needed

#### Memory Model
- **Two format standards**:
  - **Split virtqueue** (traditional):
    - Descriptor ring: Pool of descriptors
    - Available ring: Indices of descriptor chain heads
    - Used ring: Device completion notifications
  - **Packed virtqueue** (newer, more efficient):
    - Single ring with wrap counters
    - More cache-efficient
- **Allocation**:
  - DMA coherent memory if IOMMU/platform requires
  - Or `alloc_pages_exact()` for direct mapping
- **Shared with device**: Shared between guest and hypervisor/hardware device
- **Alignment**: Device-specific alignment requirements

#### Synchronization Mechanisms
- **Memory barriers**: Weak barriers where platform allows (virt_mb)
  - Weaker than normal barriers since just crossing VM boundary
- **Availability flags**: Control when notifications needed
  - Can suppress interrupts when guest is polling
- **Event suppression**: Precise control of notifications (event idx)
- **Lock-free**: No locks, uses descriptor state transitions
- **Notification callback**: Device-specific (virtio_notify)

#### Data Organization
- **Descriptor chains**: Multiple descriptors can be chained for scatter-gather
- **Direct and indirect**: Supports indirect descriptor tables
  - Indirect: One descriptor points to table of descriptors
  - Saves descriptor space for large I/Os
- **Fixed descriptor size**: 16 bytes per descriptor
- **Separate state**: Per-descriptor state tracked separately in driver

#### Performance Optimizations
- **Indirect descriptors**: Reduces descriptor consumption for large I/Os
  - Single descriptor can reference entire scatter-gather list
- **Batching**: Multiple descriptors can be added before notification
- **Event idx**: Precise notification control reduces interrupts
- **Weak barriers**: Uses lighter barriers (virt_mb) on platforms that allow
- **Packed ring format**: Newer format is more cache-efficient

#### Unique Features
- **Hypervisor interface**: Designed specifically for virtual machine I/O
- **Two format support**: Both split and packed rings
- **Indirect descriptors**: Unique two-level descriptor mechanism
- **Cross-platform**: Works with KVM, Xen, QEMU, VMware, Hyper-V (with different backends)
- **Standardized**: Part of OASIS VirtIO specification
- **Device types**: Used for net, block, console, GPU, crypto, etc.

#### Use Case
- **Primary purpose**: Virtual device I/O (network, block, console in VMs)
- **Latency**: Moderate - crossing VM boundary adds overhead
- **Throughput**: High - designed for VM I/O bandwidth
- **Data loss tolerance**: Not acceptable
- **Context**: Guest OS driver context
- **Users**: All virtio devices in virtual machines

---

### 11. AF_PACKET Ring (PACKET_MMAP)

**Location**: `net/packet/af_packet.c`

#### Overflow Behavior
- **V1/V2**: Drop packets when ring full (`tp_drops` counter incremented)
- **V3**: Block-based, can retire blocks on timeout
- **Status flags**: `TP_STATUS_LOSING` indicates drops occurred
- **Statistics**: Extensive stats tracking packets, drops, freeze queue, etc.
- **Drop policy**: Silent drops - no error to user

#### Memory Model
- **Three versions**:
  - **TPACKET_V1**: Basic fixed-size frames
  - **TPACKET_V2**: Improved with nanosecond timestamps
  - **TPACKET_V3**: Block-based batching (recommended)
- **Allocation**:
  - vmalloc for ring buffer
  - Or get_user_pages if user provides memory
- **Frame structure**:
  - `tp_block_size`: Block size (must be page multiple)
  - `tp_frame_size`: Frame size within block (must align)
  - `tp_block_nr`: Number of blocks
  - `tp_frame_nr`: Total frames
- **Shared memory**: mmap-ed between kernel and userspace
- **RX and TX**: Separate rings for receive and transmit

#### Synchronization Mechanisms
- **Status field**: Atomic status in each frame/block header
  - `TP_STATUS_KERNEL`: Owned by kernel
  - `TP_STATUS_USER`: Owned by userspace
  - Status transitions indicate ownership
- **Memory barriers**: `smp_wmb()` and cache flushes before status updates
- **Spinlock**: For ring buffer management (not data path)
- **Producer/Consumer**:
  - RX: Kernel produces, user consumes
  - TX: User produces, kernel consumes

#### Data Organization
- **Block-based (V3)**: Groups multiple frames into blocks
  - `block_status`: Block-level state
  - `num_pkts`: Number of packets in block
  - `offset_to_first_pkt`: First packet location
  - Amortizes syscall overhead
- **Frame-based (V1/V2)**: Individual frame per packet
- **Alignment**: `TPACKET_ALIGNMENT` = 16 bytes
- **Variable packet size**: Within fixed frame size
- **Metadata per frame**: Timestamp, length, status, snaplen, etc.

#### Performance Optimizations
- **Zero-copy**: Packet data directly in mmap-ed ring
- **Block aggregation (V3)**: Batch multiple packets per syscall/notification
- **Timeout-based retire**: Retire blocks on timer to reduce latency
- **RX/TX hash support**: Hardware flow classification
- **VLAN offload**: Hardware VLAN tag support
- **Fanout support**: Multi-socket load balancing
  - `PACKET_FANOUT_HASH`: Hash-based distribution
  - `PACKET_FANOUT_LB`: Round-robin load balancing
  - `PACKET_FANOUT_CPU`: Per-CPU distribution
  - `PACKET_FANOUT_ROLLOVER`: Rollover on overflow

#### Unique Features
- **Three versions**: Evolution over decades with different trade-offs
- **Block abstraction (V3)**: Unique batching mechanism
  - Groups packets into blocks
  - Reduces syscall overhead significantly
- **Both RX and TX**: Bidirectional packet rings
- **Fanout modes**: Load balancing across multiple sockets
- **Legacy protocol**: TPACKET_V1 dating back to 1990s
- **BPF filter integration**: Can attach BPF filters
- **Packet timestamping**: Hardware and software timestamps

#### Use Case
- **Primary purpose**: Packet capture and raw packet transmission
- **Latency**: Low for packet capture
- **Throughput**: High - designed for multi-gigabit capture
- **Data loss tolerance**: Acceptable (drops tracked)
- **Context**: Process (userspace) and softirq (kernel)
- **Users**: tcpdump, wireshark, snort, suricata, custom packet tools

---

## Comparison Tables

### Table 1: Overflow Behavior and Data Loss

| Implementation | Full Behavior | Overwrite Mode | Drop Tracking | Data Loss Acceptable |
|---------------|---------------|----------------|---------------|---------------------|
| BPF ringbuf | Return error | No | N/A | No - caller decides |
| Perf event | Error or overwrite | Configurable | Yes - explicit events | Configurable |
| Ftrace | Drop new/old | Configurable | Yes - counters | Yes (overwrite mode) |
| Printk | Overwrite oldest | Always | No | Yes - always acceptable |
| circ_buf | User decides | User decides | User decides | User decides |
| kfifo | Return partial count | No | Implicit in return | No |
| ptr_ring | Return -ENOSPC | No | No | No |
| io_uring | CQ overflow list | No (SQ user-managed) | Yes - overflow flag | CQ: recoverable |
| XDP rings | Return -ENOSPC | No | Yes - counters | No |
| Virtio ring | Return -ENOSPC | No | No | No |
| AF_PACKET | Drop silently | No | Yes - tp_drops | Yes - packet loss OK |

### Table 2: Memory Architecture

| Implementation | Allocation | Shared Memory | Zero-Copy | Double-Mapping | Power-of-2 Required |
|---------------|-----------|---------------|-----------|----------------|---------------------|
| BPF ringbuf | Pages + vmap | Yes (mmap) | Yes | Yes | Yes + page-aligned |
| Perf event | Pages/vmalloc | Yes (mmap) | Yes | No | No |
| Ftrace | Page lists | splice/mmap | Yes | No | No |
| Printk | Arrays | No | No | No | Yes |
| circ_buf | User allocated | User decides | N/A | No | Yes (implicit) |
| kfifo | kmalloc/embedded | No | No | No | Yes (auto round-up) |
| ptr_ring | kvmalloc | No | Pointers only | No | No |
| io_uring | Pages (mmap) | Yes | Yes | No | Yes |
| XDP rings | vmalloc | Yes (4 rings) | Yes (UMEM) | No | Yes |
| Virtio ring | DMA/pages | Yes (with device) | Device-dependent | No | Yes |
| AF_PACKET | vmalloc/user pages | Yes (mmap) | Yes | No | Block size: multiple of page |

### Table 3: Synchronization Mechanisms

| Implementation | Primary Sync | Lock-Free | NMI-Safe | IRQ-Safe | Producer/Consumer Model |
|---------------|-------------|-----------|----------|----------|------------------------|
| BPF ringbuf | IRQ spinlock / atomic | No (has lock) | Yes | Yes | Kernel: MPSC, User: SPSC |
| Perf event | Memory barriers | Yes | Yes | Yes | MPSC (per-CPU) |
| Ftrace | Per-CPU + arch_spinlock | Per-CPU only | Yes | Yes | Per-CPU |
| Printk | Atomic state machine | Yes | Yes | Yes | MPMC |
| circ_buf | User provides | User decides | User decides | User decides | Designed for SPSC |
| kfifo | Optional spinlock | SPSC yes | Optional | Yes (with locks) | SPSC or locked |
| ptr_ring | Dual spinlocks | No | No | Yes (irq variant) | SPSC with locks |
| io_uring | Memory barriers | Yes | No | No | SQ: SPSC, CQ: SPSC/MPSC |
| XDP rings | Memory barriers | Yes | No | Yes (softirq) | SPSC per ring |
| Virtio ring | Weak barriers | Yes-ish | No | Depends | SPSC (guest-device) |
| AF_PACKET | Status flags + spinlock | No | No | Yes | SPSC per ring |

### Table 4: Data Organization

| Implementation | Record Size | Alignment | Metadata | Time Encoding | Max Size |
|---------------|-------------|-----------|----------|---------------|----------|
| BPF ringbuf | Variable | 8-byte | 8-byte header | No | ~1GB |
| Perf event | Variable | Page-based | Per-event | Yes (explicit) | Configurable |
| Ftrace | Variable | 4-byte | Compressed header | Delta + extend | Per-event limit |
| Printk | Variable | Natural | Separate info ring | Yes (64-bit ns) | ~64KB per message |
| circ_buf | User decides | User decides | No | No | User decides |
| kfifo | Fixed or records | Natural | Optional record length | No | 2^32 - 1 |
| ptr_ring | Fixed (pointer) | Pointer size | No | No | Limited by memory |
| io_uring | Fixed (SQE/CQE) | 64/128 (SQE), 16/32 (CQE) | In structure | No | Fixed structure |
| XDP rings | Fixed descriptor | Cache-line aligned | In descriptor | No | 64-bit addr |
| Virtio ring | Fixed descriptor | 16-byte | Separate | No | Chained |
| AF_PACKET | Variable (in frame) | 16-byte (TPACKET) | Per-frame header | Yes (ns timestamp) | Frame size |

### Table 5: Performance Characteristics

| Implementation | Primary Optimization | Cache Optimization | Batching | Notification Control |
|---------------|---------------------|-------------------|----------|---------------------|
| BPF ringbuf | Double-mapping | Cache-line separated | Reserve-commit | Wakeup flags |
| Perf event | Per-CPU buffers | Per-CPU | Multi-page sub-buffers | Watermark |
| Ftrace | Reader page swap | Per-CPU | Sub-buffers | IRQ work |
| Printk | Lock-free state machine | Separated metadata | No | No |
| circ_buf | Minimal overhead | User decides | No | No |
| kfifo | Lock-free SPSC | Contiguous copies | Yes | No |
| ptr_ring | Batched invalidation | Cache-line separated | Yes | No |
| io_uring | Zero syscalls (SQPOLL) | Shared memory | Yes | eventfd control |
| XDP rings | Zero-copy UMEM | Cache-line alignment | Yes (up to 256) | No |
| Virtio ring | Indirect descriptors | Weak barriers | Yes | Event suppression |
| AF_PACKET | Block batching (V3) | Zero-copy mmap | Block-level (V3) | Timeout retire |

### Table 6: Unique Characteristics

| Implementation | Unique Feature 1 | Unique Feature 2 | Unique Feature 3 | Primary Use Case |
|---------------|------------------|------------------|------------------|------------------|
| BPF ringbuf | Double-mapping | Bidirectional (kernel↔user) | Permission separation | BPF events |
| Perf event | Backward ring mode | AUX buffer | Hardware tracing | CPU profiling |
| Ftrace | Reader page swap | 5-level context nesting | Time delta compression | Function tracing |
| Printk | 3-ring lock-free | Record extending | NMI printk | Kernel logging |
| circ_buf | Header-only macros | Minimal abstraction | Battle-tested | Driver helper |
| kfifo | Type-safe macros | Record mode | DMA integration | General FIFO |
| ptr_ring | Batched invalidation | Resize support | Pointer-only | virtio networking |
| io_uring | Dual rings (SQ/CQ) | Request linking | Most versatile | Async I/O |
| XDP rings | 4-ring coordination | UMEM regions | Multi-buffer packets | Ultra-fast packet I/O |
| Virtio ring | Two formats (split/packed) | Indirect descriptors | Standardized spec | VM I/O |
| AF_PACKET | 3 versions (V1/V2/V3) | Block batching (V3) | Fanout modes | Packet capture |

---

## Design Patterns and Trade-offs

### 1. Overflow Handling Strategies

#### Pattern: Error Return
**Used by**: BPF ringbuf, kfifo, ptr_ring, io_uring (CQ), XDP rings, Virtio ring

**Advantages**:
- No silent data loss
- Caller controls policy
- Backpressure to producer

**Disadvantages**:
- Caller must handle errors
- Can complicate error paths
- May require retry logic

**When to use**: Applications where data loss is unacceptable and backpressure is desired.

---

#### Pattern: Overwrite Oldest
**Used by**: Printk (always), Ftrace (configurable), Perf event (configurable)

**Advantages**:
- Never blocks producers
- Flight recorder behavior
- Simple implementation

**Disadvantages**:
- Silent data loss
- No backpressure
- Consumer can miss data

**When to use**: Logging, debugging, tracing where recent data is most important.

---

#### Pattern: Drop Newest
**Used by**: Ftrace (non-overwrite mode), AF_PACKET

**Advantages**:
- Preserves old data
- Consumer always sees consistent history
- No corruption risk

**Disadvantages**:
- May lose important recent events
- No backpressure to producer

**When to use**: When historical data preservation is important.

---

### 2. Memory Management Strategies

#### Pattern: Double-Mapping
**Used by**: BPF ringbuf

**Implementation**:
```
| meta pages | real data pages | same data pages |
|            | 1 2 3 4 5 6 7 8 | 1 2 3 4 5 6 7 8 |
```

**Advantages**:
- Eliminates wrap-around logic
- Simplifies reads (always contiguous)
- Faster read paths

**Disadvantages**:
- Requires vmalloc
- Uses 2x virtual address space
- More complex setup

**When to use**: When read simplicity and performance are critical.

---

#### Pattern: Reader Page Swap
**Used by**: Ftrace

**Implementation**:
- Dedicated reader page separate from ring
- Atomically swap reader page with ring page
- Reader gets entire page of data

**Advantages**:
- True zero-copy reads
- Lock-free reader
- Entire page atomic

**Disadvantages**:
- Complex implementation
- Page-level granularity
- Extra page overhead

**When to use**: High-frequency tracing with continuous readers.

---

#### Pattern: Shared Memory (mmap)
**Used by**: BPF ringbuf, Perf event, io_uring, XDP rings, Virtio, AF_PACKET

**Advantages**:
- True zero-copy
- No syscalls for data access
- Efficient kernel-user communication

**Disadvantages**:
- More complex setup
- Requires careful synchronization
- TLB pressure

**When to use**: High-throughput kernel-userspace communication.

---

### 3. Synchronization Strategies

#### Pattern: Lock-Free with Memory Barriers
**Used by**: Perf event, Printk, io_uring, XDP rings

**Advantages**:
- No lock contention
- Scalable
- NMI/IRQ safe

**Disadvantages**:
- Complex correctness reasoning
- Memory barrier overhead
- ABA problems on 32-bit

**When to use**: High-performance, high-contention scenarios.

---

#### Pattern: Per-CPU Buffers
**Used by**: Ftrace, Perf event

**Advantages**:
- No cross-CPU synchronization
- Excellent scalability
- Cache-friendly

**Disadvantages**:
- Memory overhead (N buffers)
- Out-of-order across CPUs
- Consumer must merge

**When to use**: Tracing, profiling with per-CPU data sources.

---

#### Pattern: Dual Spinlocks
**Used by**: ptr_ring

**Advantages**:
- Concurrent produce and consume
- Simple reasoning
- Cache-line separation reduces contention

**Disadvantages**:
- Lock overhead
- Not lock-free
- Not NMI-safe

**When to use**: Pointer passing where simplicity is valued over absolute performance.

---

### 4. Batching Strategies

#### Pattern: Block-Based Batching
**Used by**: AF_PACKET V3, Ftrace sub-buffers

**Advantages**:
- Amortizes syscall overhead
- Reduces wakeup frequency
- Better cache behavior

**Disadvantages**:
- Increased latency
- Complexity
- Memory overhead

**When to use**: High-volume data transfer where latency is less critical.

---

#### Pattern: Deferred Operations
**Used by**: ptr_ring (batched invalidation), XDP rings (cached indices)

**Advantages**:
- Reduces memory traffic
- Better cache utilization
- Batches memory barriers

**Disadvantages**:
- Increased complexity
- Delayed resource reclaim
- More state to track

**When to use**: Cache-sensitive high-frequency operations.

---

### 5. Metadata Organization

#### Pattern: Separated Metadata
**Used by**: Printk (3 rings), Ftrace (separate time encoding)

**Advantages**:
- Reduced cache line contention
- Independent sizing
- Flexible access patterns

**Disadvantages**:
- More memory accesses
- Complexity
- Harder reasoning

**When to use**: Lock-free designs requiring minimal contention.

---

#### Pattern: Compressed Headers
**Used by**: Ftrace (5-bit type + 27-bit delta), BPF ringbuf (8-byte header)

**Advantages**:
- Space efficient
- Better cache utilization
- More data fits in cache

**Disadvantages**:
- Encoding/decoding overhead
- Limited range (need extension records)
- Complexity

**When to use**: High-volume events where space is at premium.

---

## Selection Guide

### Question 1: What context will produce data?

- **NMI context required**: → Printk, Ftrace, Perf event
- **IRQ context**: → BPF ringbuf, Ftrace, Perf event, kfifo (with spinlock)
- **Process context only**: → io_uring, XDP rings, AF_PACKET, kfifo (lock-free)

### Question 2: What is your performance requirement?

- **Absolute lowest latency**: → XDP rings, io_uring
- **Highest throughput**: → Ftrace (millions/sec), Perf event, XDP rings
- **Balanced**: → BPF ringbuf, kfifo

### Question 3: Can you tolerate data loss?

- **No data loss acceptable**: → BPF ringbuf (error return), kfifo, ptr_ring, io_uring, XDP rings
- **Can lose old data**: → Printk, Ftrace (overwrite), Perf event (overwrite)
- **Can lose new data**: → AF_PACKET, Ftrace (non-overwrite)

### Question 4: Kernel-only or kernel-userspace?

- **Kernel-only**: → Printk, circ_buf, kfifo, ptr_ring
- **Kernel ↔ Userspace**: → BPF ringbuf, Perf event, io_uring, XDP rings, AF_PACKET

### Question 5: What data characteristics?

- **Fixed-size small data**: → kfifo, circ_buf
- **Variable-size data**: → BPF ringbuf, Ftrace, Printk, Perf event
- **Pointers only**: → ptr_ring
- **Packets**: → XDP rings, AF_PACKET
- **I/O operations**: → io_uring

### Question 6: Special requirements?

- **Need zero-copy**: → BPF ringbuf, io_uring, XDP rings, AF_PACKET
- **Need batching**: → AF_PACKET V3, io_uring, ptr_ring
- **Need time correlation**: → Ftrace, Perf event
- **Need hardware integration**: → Perf event (PT, CoreSight), XDP rings (NIC), Virtio (hypervisor)
- **Need to resize**: → ptr_ring
- **Simplest possible**: → circ_buf

### Decision Tree

```
Start
│
├─ Kernel-only data?
│  ├─ Yes → Logging/debug? → Printk
│  │     → FIFO queue? → kfifo or circ_buf
│  │     → Pointers? → ptr_ring
│  │
│  └─ No (kernel ↔ user)
│     ├─ Packet I/O? → Ultra-fast? → XDP rings
│     │              → Packet capture? → AF_PACKET
│     │
│     ├─ Async I/O? → io_uring
│     │
│     ├─ BPF events? → BPF ringbuf
│     │
│     ├─ Profiling/tracing? → CPU sampling? → Perf event
│     │                     → Function tracing? → Ftrace
│     │
│     └─ VM I/O? → Virtio ring
```

### Common Use Cases

| Use Case | Recommended | Alternative | Avoid |
|----------|-------------|-------------|-------|
| Serial port driver | circ_buf | kfifo | Complex ones |
| Network packet capture | AF_PACKET V3 | XDP rings | BPF ringbuf |
| Ultra-fast packet I/O | XDP rings | AF_PACKET | io_uring |
| Kernel function tracing | Ftrace | Perf event | Printk |
| CPU profiling | Perf event | Ftrace | BPF ringbuf |
| BPF program events | BPF ringbuf | Perf event | AF_PACKET |
| Async file I/O | io_uring | N/A | kfifo |
| Kernel logging | Printk | Ftrace | BPF ringbuf |
| Pointer queue (networking) | ptr_ring | kfifo | circ_buf |
| Storage driver queue | kfifo | circ_buf | Printk |
| VM network I/O | Virtio ring | N/A | AF_PACKET |

---

## Conclusion

The Linux kernel provides a rich ecosystem of ring buffer implementations, each optimized for specific use cases:

- **Simplest**: circ_buf (just helper macros)
- **Most versatile**: io_uring (dozens of operations)
- **Fastest**: XDP rings (multi-million pps)
- **Safest**: Printk (works from anywhere, even crashes)
- **Most complex**: Printk (3-ring lock-free) or Ftrace (reader page swap)
- **Best for tracing**: Ftrace (designed for it)
- **Best for profiling**: Perf event (hardware support)
- **Best for BPF**: BPF ringbuf (optimized for BPF use)
- **Best for packets**: XDP rings (ultra-fast) or AF_PACKET (feature-rich)

Understanding these implementations provides insight into:
- Lock-free algorithm design
- Memory barrier usage
- Cache optimization techniques
- Kernel-userspace communication
- High-performance I/O patterns

Each implementation represents years of refinement for its specific use case. Choose based on your specific requirements for context, performance, data loss tolerance, and feature needs.
