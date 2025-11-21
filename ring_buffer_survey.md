# Comprehensive Linux Kernel Ring Buffer Survey

This document provides an extensive survey of ring buffer implementations found throughout the Linux kernel. Ring buffers (also known as circular buffers) are fundamental data structures used for efficient producer-consumer communication, especially in high-performance and real-time scenarios.

## Table of Contents

1. [Core Kernel Infrastructure](#1-core-kernel-infrastructure)
2. [Tracing & Debugging](#2-tracing--debugging)
3. [Hypervisor & Virtualization](#3-hypervisor--virtualization)
4. [Networking](#4-networking)
5. [GPU/DRM](#5-gpudrm)
6. [Audio (ALSA/Sound)](#6-audio-alsasound)
7. [Media/Video](#7-mediavideo)
8. [Block Devices & Storage](#8-block-devices--storage)
9. [USB](#9-usb)
10. [Serial/TTY](#10-serialtty)
11. [Input Devices](#11-input-devices)
12. [IPC & File Systems](#12-ipc--file-systems)
13. [IIO (Industrial I/O)](#13-iio-industrial-io)
14. [Remote Processor & Messaging](#14-remote-processor--messaging)
15. [Modem/WWAN](#15-modemwwan)
16. [RDMA/InfiniBand](#16-rdmainfiniband)
17. [Mailbox](#17-mailbox)
18. [Crypto](#18-crypto)
19. [SoC-Specific](#19-soc-specific)
20. [Thunderbolt](#20-thunderbolt)
21. [MEI (Management Engine Interface)](#21-mei-management-engine-interface)
22. [Other Specialized Buffers](#22-other-specialized-buffers)
23. [Summary](#summary)

---

## 1. Core Kernel Infrastructure

### circ_buf - Generic Circular Buffer
- **Location**: `include/linux/circ_buf.h`
- **Purpose**: Simple, lightweight circular buffer implementation
- **Usage**: Widely used throughout kernel for basic ring buffer needs
- **Key Features**: Head/tail pointers, simple macros for space calculation
- **API**: `CIRC_CNT()`, `CIRC_SPACE()`, `CIRC_CNT_TO_END()`, etc.

### ptr_ring - Pointer Ring Buffer
- **Location**: `include/linux/ptr_ring.h`
- **Purpose**: Lock-free/lockless ring buffer for pointers
- **Usage**: Networking, virtio, high-performance scenarios
- **Key Features**:
  - Cache-optimized design
  - SPSC (Single Producer Single Consumer) and MPMC (Multi-Producer Multi-Consumer) support
  - Efficient for pointer-sized data
- **Notable Users**: TUN/TAP devices, packet scheduling

### skb_array - SKB Ring Buffer
- **Location**: `include/linux/skb_array.h`
- **Purpose**: Specialized ring for socket buffers (sk_buff)
- **Key Features**: Wraps ptr_ring with skb-specific operations
- **Usage**: Network device queuing

### kfifo - Kernel FIFO
- **Location**:
  - `include/linux/kfifo.h`
  - `lib/kfifo.c`
- **Purpose**: Generic FIFO implementation with ring buffer backing
- **Key Features**:
  - Type-safe macros
  - Record support (variable-length records)
  - DMA support
  - Dynamic and static allocation
- **API**: `kfifo_alloc()`, `kfifo_in()`, `kfifo_out()`, etc.
- **Usage**: Over 200 files use kfifo across various subsystems

### objpool - Object Pool with Ring Array
- **Location**: `include/linux/objpool.h`
- **Purpose**: Per-CPU ring-array based lockless MPMC queue
- **Key Features**:
  - Optimized for object allocation/free
  - Lock-free operation
  - Per-CPU design
- **Usage**: Kernel object pooling, kretprobe

---

## 2. Tracing & Debugging

### Ftrace Ring Buffer
- **Location**:
  - `kernel/trace/ring_buffer.c`
  - `include/linux/ring_buffer.h`
- **Purpose**: High-performance ring buffer for kernel tracing
- **Key Features**:
  - Per-CPU buffers to avoid cache line contention
  - Lock-free reader/writer implementation
  - Supports nested events
  - Overwrite and no-overwrite modes
  - Timestamping support
- **Size**: ~7000+ lines of sophisticated ring buffer implementation
- **API**: `ring_buffer_write()`, `ring_buffer_read()`, etc.
- **Usage**: Core infrastructure for ftrace, function tracer, event tracer

### Printk Ring Buffer
- **Location**:
  - `kernel/printk/printk_ringbuffer.c`
  - `kernel/printk/printk_ringbuffer.h`
- **Purpose**: Lock-free ring buffer for kernel log messages
- **Key Features**:
  - Completely lock-free design
  - Three separate ring buffers: descriptors, text data, metadata
  - Safe for use in any context (NMI, interrupt, etc.)
  - Supports variable-length records
- **History**: Redesigned in 2020 for better performance and reliability
- **Usage**: All kernel log messages (printk, pr_*, dev_*, etc.)

### Relay Buffer
- **Location**: `kernel/relay.c`
- **Purpose**: Efficient kernel-to-userspace data relay
- **Key Features**:
  - Per-CPU buffers
  - Exposed through debugfs
  - Supports both circular and non-circular modes
- **Usage**: High-volume kernel data streaming to userspace

### Coresight Buffers
- **Location**: `drivers/hwtracing/coresight/`
- **Purpose**: ARM CoreSight hardware tracing infrastructure
- **Key Features**: Hardware-assisted tracing with ring buffer management
- **Components**: ETR (Embedded Trace Router), TMC (Trace Memory Controller)
- **Usage**: ARM platform debugging and profiling

---

## 3. Hypervisor & Virtualization

### virtio_ring - Virtio Transport
- **Location**:
  - `include/linux/virtio_ring.h`
  - `drivers/virtio/virtio_ring.c`
- **Purpose**: Shared memory ring buffers for virtio devices
- **Key Features**:
  - Split virtqueues (separate avail/used rings)
  - Packed virtqueues (more efficient layout)
  - Supports indirect descriptors
  - Notification suppression
- **Components**: Available ring, descriptor ring, used ring
- **Usage**: All virtio devices (net, block, console, gpu, etc.)

### vringh - Host-Side Virtio Ring
- **Location**:
  - `include/linux/vringh.h`
  - `drivers/vhost/vringh.c`
- **Purpose**: Kernel access to virtio rings (host side)
- **Key Features**: Allows kernel to act as virtio device
- **Usage**: vhost drivers, kernel-based virtio implementations

### Xen Ring
- **Location**: `include/xen/interface/io/ring.h`
- **Purpose**: Producer-consumer rings for Xen paravirtualization
- **Key Features**:
  - Macro-based ring implementation
  - Shared between guest and hypervisor
  - Request/response pattern
- **Usage**: All Xen paravirt I/O (netfront, blkfront, etc.)

### Hyper-V Ring Buffer
- **Location**:
  - `drivers/hv/ring_buffer.c`
  - `include/linux/hyperv.h`
- **Purpose**: VMBus ring buffer for Hyper-V
- **Key Features**:
  - Bidirectional communication
  - Interrupt-driven notifications
  - Shared memory between guest and host
- **Usage**: All Hyper-V VSC/VSP devices

### KVM Dirty Ring
- **Location**: `include/linux/kvm_dirty_ring.h`
- **Purpose**: Track dirty (modified) guest memory pages
- **Key Features**:
  - More efficient than dirty bitmap for some workloads
  - Ring-based reporting of dirty pages
- **Usage**: KVM live migration optimization

### VMCI Queue Pairs
- **Location**: `drivers/misc/vmw_vmci/vmci_queue_pair.c`
- **Purpose**: VMware VMCI guest-host communication
- **Key Features**:
  - Bidirectional queues (produce/consume)
  - Shared memory transport
- **Usage**: VMware guest additions

---

## 4. Networking

### BPF Ring Buffer (Known)
- **Location**: `kernel/bpf/ringbuf.c`
- **Purpose**: Fast data passing from BPF programs to userspace
- **Key Features**: Lock-free, memory-efficient, supports epoll

### BPF User Ring Buffer (Known)
- **Location**: `kernel/bpf/ringbuf.c` (user ringbuf implementation)
- **Purpose**: Userspace to BPF program communication
- **Key Features**: Reverse direction of regular BPF ringbuf

### Perf Event Buffer (Known)
- **Location**: `kernel/events/ring_buffer.c`
- **Purpose**: Performance monitoring event delivery
- **Key Features**: Per-CPU buffers, supports AUX data

### XDP Socket Rings (AF_XDP)
- **Location**:
  - `net/xdp/xsk_queue.h`
  - `net/xdp/xsk_queue.c`
- **Purpose**: Zero-copy packet I/O for XDP
- **Key Rings**:
  - **Fill queue**: Userspace provides buffers to kernel
  - **Completion queue**: Kernel returns sent buffers
  - **TX ring**: Packet transmission
  - **RX ring**: Packet reception
- **Key Features**: True zero-copy, extremely high performance
- **Usage**: DPDK-like userspace packet processing

### AF_PACKET Ring
- **Location**:
  - `net/packet/af_packet.c`
  - `net/packet/internal.h`
- **Purpose**: High-performance packet capture and transmission
- **Ring Types**:
  - **RX_RING**: Packet reception (like libpcap)
  - **TX_RING**: Packet transmission
- **Versions**: V1, V2, V3 (TPACKET_V3 with block-based ring)
- **Key Features**: Zero-copy, memory-mapped I/O
- **Usage**: tcpdump, wireshark, custom packet processors

### RDS InfiniBand Ring
- **Location**: `net/rds/ib_ring.c`
- **Purpose**: Ring buffer for RDS (Reliable Datagram Socket) over IB
- **Usage**: Oracle's RDS protocol implementation

### mac80211 Aggregation Buffers
- **Location**:
  - `net/mac80211/agg-rx.c`
  - `net/mac80211/sta_info.h`
- **Purpose**: A-MPDU reordering for 802.11n/ac/ax
- **Key Features**:
  - Per-TID (Traffic Identifier) buffers
  - Reorder window for out-of-order frames
  - Block ACK bitmap management
- **Usage**: All WiFi devices with 802.11n+ support

### SCTP TSN Map
- **Location**: `net/sctp/tsnmap.c`
- **Purpose**: Track SCTP transmission sequence numbers
- **Key Features**: Circular buffer with GAP ACK support
- **Usage**: SCTP protocol implementation

### NIC Descriptor Rings (Known)
- **Location**: Throughout `drivers/net/ethernet/`
- **Purpose**: Hardware TX/RX descriptor rings for network cards
- **Examples**:
  - Intel: e1000, e1000e, igb, ixgbe, i40e, ice, iavf
  - Broadcom: bnxt, tg3, bnx2x
  - Mellanox: mlx4, mlx5
  - Realtek: r8169
  - AMD: xgbe
  - Marvell: mvneta, mvpp2
  - And 100+ more drivers
- **Key Features**: DMA-based, hardware-managed head/tail

---

## 5. GPU/DRM

### AMD GPU Rings
- **Location**:
  - `drivers/gpu/drm/amd/amdgpu/amdgpu_ring.c`
  - `drivers/gpu/drm/amd/amdgpu/amdgpu_ring_mux.c`
  - `drivers/gpu/drm/amd/amdgpu/vcn_sw_ring.c`
- **Ring Types**:
  - GFX ring (graphics commands)
  - Compute rings
  - DMA rings (SDMA)
  - VCN rings (video decode/encode)
  - UVD/VCE rings (older video)
  - JPEG rings
- **Key Features**:
  - Software ring buffer submitting to hardware
  - Fence/sync mechanism
  - Priority scheduling
  - Ring multiplexing for soft rings

### Intel GPU Rings
- **Location**: `drivers/gpu/drm/i915/gt/intel_ring.c`
- **Purpose**: Command submission for Intel integrated/discrete GPUs
- **Ring Types**: Render, compute, video, blitter
- **Key Features**: GuC (Graphics micro-Controller) submission

### Radeon Rings
- **Location**: `drivers/gpu/drm/radeon/radeon_ring.c`
- **Purpose**: Legacy AMD GPU command submission
- **Usage**: Older AMD/ATI graphics cards

### MSM (Qualcomm) Ringbuffer
- **Location**: `drivers/gpu/drm/msm/msm_ringbuffer.c`
- **Purpose**: Adreno GPU command submission
- **Usage**: Qualcomm SoCs

### Xe (Intel Xe) Ring Ops
- **Location**: `drivers/gpu/drm/xe/xe_ring_ops.c`
- **Purpose**: Next-gen Intel GPU driver ring operations
- **Usage**: Newer Intel discrete GPUs

### Nouveau Private Ring
- **Location**: `drivers/gpu/drm/nouveau/include/nvkm/subdev/privring.h`
- **Purpose**: NVIDIA GPU internal ring bus
- **Usage**: Open-source NVIDIA driver

---

## 6. Audio (ALSA/Sound)

### PCM Ring Buffer
- **Location**: `sound/core/pcm_lib.c`
- **Purpose**: Main audio playback and capture buffer
- **Key Features**:
  - Circular buffer for audio samples
  - Supports various period sizes
  - Hardware pointer tracking
  - Mmap support for zero-copy
- **Usage**: All ALSA audio devices (hundreds of drivers)

### ALSA Sequencer FIFO
- **Location**:
  - `sound/core/seq/seq_fifo.c`
  - `sound/core/seq/seq_fifo.h`
- **Purpose**: MIDI event queue
- **Key Features**: Cell-based FIFO for sequencer events
- **Usage**: ALSA sequencer API

### Compress Offload Ring Buffer
- **Location**: `sound/core/compress_offload.c`
- **Purpose**: Ring buffer for compressed audio data
- **Key Features**: Supports hardware decode/encode offload
- **Usage**: Mobile SoCs with audio DSPs

### Meson (Amlogic) Audio FIFOs
- **Location**:
  - `sound/soc/meson/axg-fifo.c`
  - `sound/soc/meson/aiu-fifo.c`
- **Purpose**: SoC-specific audio DMA FIFOs
- **Usage**: Amlogic SoCs

---

## 7. Media/Video

### DVB Ring Buffer
- **Location**:
  - `include/media/dvb_ringbuffer.h`
  - `drivers/media/dvb-core/dvb_ringbuffer.c`
- **Purpose**: Digital TV stream buffering
- **Key Features**:
  - Read/write operations for MPEG-TS data
  - Support for multiple readers
- **Usage**: All DVB (Digital Video Broadcasting) devices

### Videobuf2 (V4L2)
- **Location**: `drivers/media/common/videobuf2/videobuf2-core.c`
- **Purpose**: Video buffer queue management framework
- **Key Features**:
  - Manages queue of video buffers
  - Supports multiple memory models (mmap, userptr, dmabuf)
  - Streaming I/O
- **Usage**: 300+ V4L2 camera/video drivers

---

## 8. Block Devices & Storage

### io_uring (Known)
- **Location**: `io_uring/` directory
- **Components**:
  - **SQ (Submission Queue)**: Userspace submits I/O requests
  - **CQ (Completion Queue)**: Kernel reports completions
- **Purpose**: High-performance async I/O interface
- **Key Features**: Polling mode, registered buffers/files, linked operations

### ublk Ring
- **Location**: `drivers/block/ublk_drv.c`
- **Purpose**: Userspace block device implementation
- **Key Features**: Uses io_uring for communication
- **Usage**: Implement block devices in userspace (like NBD but faster)

### NVMe Queues
- **Location**: `drivers/nvme/host/pci.c`
- **Purpose**: NVMe command and completion queues
- **Components**:
  - Submission Queue (SQ)
  - Completion Queue (CQ)
- **Key Features**:
  - Circular queues
  - Doorbell registers
  - Multiple queue pairs for parallel I/O
- **Usage**: All NVMe SSDs

---

## 9. USB

### xHCI Ring
- **Location**: `drivers/usb/host/xhci-ring.c`
- **Purpose**: Transfer and event rings for xHCI (USB 3.x) controller
- **Ring Types**:
  - Transfer rings (for endpoints)
  - Event ring (for completions and errors)
  - Command ring
- **Key Features**: TRB (Transfer Request Block) based
- **Size**: ~4000 lines of ring management code

### cdnsp Ring
- **Location**: `drivers/usb/cdns3/cdnsp-ring.c`
- **Purpose**: Cadence USB device controller rings
- **Usage**: Similar to xHCI but for device mode

---

## 10. Serial/TTY

### Serial Circular Buffers
- **Location**: Various files in `drivers/tty/serial/`
- **Purpose**: UART TX/RX buffering
- **Implementation**: Uses circ_buf macros
- **Usage**: Virtually all serial port drivers (8250, amba-pl011, imx, etc.)

---

## 11. Input Devices

### evdev Buffer
- **Location**: `drivers/input/evdev.c`
- **Purpose**: Input event buffering for userspace
- **Key Features**:
  - Circular buffer of input_event structures
  - Per-client buffers
  - Supports poll/select/epoll
- **Usage**: /dev/input/eventX devices

---

## 12. IPC & File Systems

### Pipe Buffer
- **Location**: `fs/pipe.c`
- **Purpose**: Unix pipe implementation
- **Key Features**:
  - Ring buffer of pipe_buffer structures
  - Each pipe_buffer can point to a page of data
  - Supports splice operations
- **Usage**: All Unix pipes

### Watch Queue
- **Location**:
  - `kernel/watch_queue.c`
  - `include/linux/watch_queue.h`
- **Purpose**: Kernel event notification mechanism
- **Key Features**:
  - Ring buffer for notifications
  - Supports multiple event types
  - Integrates with fsnotify, mount notifications
- **Usage**: Modern Linux notification infrastructure

### FUSE io_uring Ring
- **Location**:
  - `fs/fuse/dev_uring.c`
  - `fs/fuse/dev_uring_i.h`
- **Purpose**: Ring-based FUSE communication
- **Key Features**: More efficient than traditional read/write
- **Usage**: FUSE filesystem drivers

---

## 13. IIO (Industrial I/O)

### IIO kfifo Buffer
- **Location**: `drivers/iio/buffer/kfifo_buf.c`
- **Purpose**: Software buffer for IIO sensor data
- **Key Features**: Uses kfifo internally
- **Usage**: 200+ IIO sensor drivers (ADCs, accelerometers, gyros, etc.)

### IIO DMA Buffer
- **Location**: `drivers/iio/buffer/industrialio-buffer-dma.c`
- **Purpose**: DMA-based IIO buffer
- **Key Features**:
  - Efficient for high-speed data acquisition
  - Zero-copy to userspace
- **Usage**: High-speed ADCs and DACs

---

## 14. Remote Processor & Messaging

### Remoteproc Vrings
- **Location**: `drivers/remoteproc/remoteproc_virtio.c`
- **Purpose**: Communication with remote processors (coprocessors)
- **Key Features**:
  - Uses virtio rings
  - Shared memory with Cortex-M, DSPs, PRUs, etc.
- **Usage**: ARM TI AM/DM SoCs, STM32MP, Qualcomm, NXP i.MX

### RPMSG
- **Purpose**: Message-based IPC over remoteproc vrings
- **Usage**: Linux <-> RTOS communication on heterogeneous SoCs

---

## 15. Modem/WWAN

### MHI (Modem Host Interface)
- **Location**:
  - `drivers/bus/mhi/host/ring.c` (implied)
  - `drivers/bus/mhi/ep/ring.c`
- **Purpose**: PCIe-based modem communication
- **Ring Types**:
  - Transfer rings
  - Event rings
- **Key Features**: Designed for high-speed cellular modems
- **Usage**: Qualcomm 5G modems, Intel modems

---

## 16. RDMA/InfiniBand

### RDMA Queue Pairs
- **Location**: `drivers/infiniband/hw/*/`
- **Components**:
  - **Send Queue (SQ)**: Work requests to send
  - **Receive Queue (RQ)**: Work requests to receive
  - **Completion Queue (CQ)**: Completed operations
- **Implementations**:
  - Mellanox mlx4/mlx5
  - Intel hfi1, irdma
  - Broadcom bnxt_re
  - Chelsio cxgb4
  - Marvell qedr
  - VMware pvrdma
  - Software: rxe, siw
- **Key Features**: RDMA zero-copy, kernel bypass (for userspace)
- **Usage**: High-performance computing, storage (NVMe-oF, iSER)

### VMware PVRDMA Ring
- **Location**: `drivers/infiniband/hw/vmw_pvrdma/pvrdma_ring.h`
- **Purpose**: Paravirtualized RDMA
- **Key Features**: Ring buffer for VM-to-host RDMA

---

## 17. Mailbox

### Mailbox Buffers
- **Purpose**: Hardware mailbox communication (typically with coprocessors)
- **Example**: BCM PDC mailbox
  - **Location**: `drivers/mailbox/bcm-pdc-mailbox.c`
  - **Purpose**: Broadcom PDC (Processor DMA Controller)
  - **Key Features**: Ring buffers for crypto offload

---

## 18. Crypto

### Inside-Secure SafeXcel Ring
- **Location**: `drivers/crypto/inside-secure/safexcel_ring.c`
- **Purpose**: Hardware crypto engine ring buffers
- **Components**: Command rings, result rings
- **Usage**: Inside-Secure crypto accelerators

---

## 19. SoC-Specific

### Texas Instruments K3 Ring Accelerator
- **Location**:
  - `drivers/soc/ti/k3-ringacc.c`
  - `include/linux/soc/ti/k3-ringacc.h`
- **Purpose**: Hardware ring accelerator
- **Key Features**:
  - Hardware-managed rings
  - DMA integration
  - Supports multiple modes (ring, message, credentials)
- **Usage**: TI K3 AM6x/J7x SoCs (DMA, networking, crypto)

### Broadcom Wireless Flow Rings
- **Location**:
  - `drivers/net/wireless/broadcom/brcm80211/brcmfmac/flowring.c`
  - `drivers/net/wireless/broadcom/brcm80211/brcmfmac/commonring.c`
- **Purpose**: WiFi packet flow control rings
- **Usage**: Broadcom FullMAC WiFi chips

---

## 20. Thunderbolt

### Thunderbolt Rings
- **Location**:
  - `drivers/thunderbolt/nhi.c`
  - `drivers/thunderbolt/ctl.c`
- **Purpose**: Thunderbolt protocol ring buffers
- **Ring Types**: TX rings, RX rings
- **Key Features**: PCIe-based DMA rings
- **Usage**: All Thunderbolt controllers

---

## 21. MEI (Management Engine Interface)

### MEI DMA Ring
- **Location**: `drivers/misc/mei/dma-ring.c`
- **Purpose**: DMA-based communication with Intel ME
- **Key Features**: Ring buffer for host-ME communication
- **Usage**: Intel Management Engine interface

---

## 22. Other Specialized Buffers

### CXL Event Buffers
- **Location**: `drivers/cxl/core/mbox.c`
- **Purpose**: Compute Express Link event logs
- **Key Features**: Ring-based event notification
- **Usage**: CXL devices (memory expansion, accelerators)

### Dynamic Queue Limits (DQL)
- **Location**:
  - `lib/dynamic_queue_limits.c`
  - `include/linux/dynamic_queue_limits.h`
- **Purpose**: Adaptive queue sizing algorithm
- **Key Features**: Prevents excessive queuing (bufferbloat)
- **Usage**: Network device TX queues

### LRU Cache Ring (DRBD)
- **Location**: `include/linux/lru_cache.h`
- **Purpose**: Ring-based LRU cache for DRBD
- **Usage**: Distributed Replicated Block Device

### Atomisp Circular Buffer
- **Location**: `drivers/staging/media/atomisp/pci/base/circbuf/`
- **Purpose**: Intel Atom ISP (Image Signal Processor)
- **Usage**: Staging driver for Intel camera ISP

### Ath11k/Ath12k Debug Ring
- **Location**:
  - `drivers/net/wireless/ath/ath11k/dbring.c`
  - `drivers/net/wireless/ath/ath12k/dbring.c`
- **Purpose**: Qualcomm WiFi debug/spectral scan data
- **Usage**: Qualcomm Atheros WiFi 6/7 chips

---

## Summary

### Total Count
**50+ distinct ring buffer implementations identified**

### Distribution by Subsystem

| Category | Count | Examples |
|----------|-------|----------|
| Core Infrastructure | 5 | circ_buf, ptr_ring, kfifo, objpool |
| Tracing/Debug | 4 | ftrace, printk, relay, coresight |
| Virtualization | 6 | virtio, Xen, Hyper-V, KVM, VMCI |
| Networking | 8+ | XDP, AF_PACKET, BPF, perf, RDS, mac80211 + all NIC rings |
| GPU/DRM | 6 | AMD, Intel, Radeon, MSM, Xe, Nouveau |
| Audio | 4+ | PCM, sequencer, compress, SoC-specific |
| Media | 2 | DVB, videobuf2 |
| Block I/O | 3 | io_uring, ublk, NVMe |
| USB | 2 | xHCI, cdnsp |
| IIO Sensors | 2+ | kfifo_buf, DMA buffer |
| IPC/RemoteProc | 5 | remoteproc, MHI, FUSE uring, pipe, watch_queue |
| RDMA | 10+ | Various vendor implementations |
| Other | 10+ | Serial, input, crypto, Thunderbolt, MEI, CXL, K3, etc. |

### Key Architectural Patterns

#### 1. **Lock-Free Designs**
Many modern ring buffers use lock-free algorithms for maximum performance:
- Ftrace ring buffer
- Printk ring buffer
- ptr_ring
- objpool

#### 2. **Per-CPU Buffers**
To avoid cache line contention:
- Ftrace ring buffer
- Relay buffers
- Perf event buffers

#### 3. **Shared Memory Rings**
For cross-domain communication:
- virtio rings (guest-host)
- Xen rings (guest-hypervisor)
- Hyper-V rings (guest-host)
- Remoteproc vrings (CPU-coprocessor)

#### 4. **Zero-Copy Rings**
For maximum efficiency:
- XDP sockets (AF_XDP)
- AF_PACKET (mmap rings)
- io_uring (registered buffers)
- RDMA queues

#### 5. **Hardware-Backed Rings**
Directly managed by hardware:
- NIC descriptor rings
- NVMe queues
- GPU command rings
- TI K3 Ring Accelerator

#### 6. **Power-of-2 Sizing**
Most implementations use power-of-2 sizes for efficient modulo operations using bit masking:
```c
index = (head + 1) & (size - 1);  // Fast modulo for power-of-2
```

#### 7. **Producer-Consumer Patterns**

**Single Producer Single Consumer (SPSC)**:
- Simplest, most efficient
- Used in many device drivers

**Multi-Producer Single Consumer (MPSC)**:
- Common in logging (printk)
- Networking (packet queues)

**Single Producer Multi-Consumer (SPMC)**:
- Less common
- Used in some broadcast scenarios

**Multi-Producer Multi-Consumer (MPMC)**:
- Most complex
- ptr_ring, objpool
- Requires careful synchronization

### Performance Characteristics

Different ring buffer implementations optimize for different characteristics:

| Implementation | Latency | Throughput | Memory | Complexity | Use Case |
|---------------|---------|------------|---------|------------|----------|
| circ_buf | Low | Medium | Low | Low | Simple UART buffers |
| kfifo | Low | Medium | Medium | Medium | General purpose |
| ptr_ring | Very Low | High | Low | Medium | Network fast path |
| ftrace ring | Low | Very High | Medium | High | High-freq tracing |
| printk ring | Very Low | High | Medium | High | NMI-safe logging |
| virtio ring | Medium | High | Low | High | Virtualized I/O |
| io_uring | Very Low | Very High | Medium | High | Async I/O |
| XDP ring | Minimal | Maximum | Low | Medium | Packet processing |

### Common APIs and Operations

Most ring buffers implement these core operations:

1. **Initialization**: `_init()`, `_alloc()`
2. **Producer**: `_write()`, `_enqueue()`, `_produce()`
3. **Consumer**: `_read()`, `_dequeue()`, `_consume()`
4. **Query**: `_count()`, `_space()`, `_empty()`, `_full()`
5. **Cleanup**: `_free()`, `_destroy()`

### Historical Evolution

1. **Early Linux (1990s)**: Simple circ_buf for serial ports
2. **2.6 era (2000s)**: kfifo, relay, specialized ring buffers
3. **Modern era (2010s+)**:
   - Lock-free designs (ftrace ring buffer ~2009)
   - Printk ring buffer redesign (2020)
   - io_uring (2019)
   - BPF ring buffer (2020)
   - Increasing use of per-CPU designs

### Conclusion

Ring buffers are fundamental to Linux kernel performance. They appear in virtually every high-performance subsystem, from networking to storage to graphics. The kernel contains a rich ecosystem of ring buffer implementations, each optimized for its specific use case:

- **General purpose**: circ_buf, kfifo
- **High performance**: ptr_ring, ftrace ring buffer
- **Kernel-user communication**: io_uring, BPF ringbuf, perf events
- **Virtualization**: virtio, Xen rings
- **Hardware interface**: NIC descriptors, NVMe queues, GPU rings
- **Real-time requirements**: printk ring buffer (NMI-safe)

Understanding these different implementations provides insight into how the Linux kernel achieves its performance and scalability across diverse hardware and workloads.

---

**Survey Date**: 2025-11-21
**Kernel Version**: Based on commit 23cb64fb76 (Linux 6.18-rc7 era)
**Files Analyzed**: 1000+ files across entire kernel tree
