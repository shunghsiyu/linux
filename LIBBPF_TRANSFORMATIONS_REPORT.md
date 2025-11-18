# LibBPF Transformations and Modifications to BPF Object Files

## Executive Summary

This report documents all operations and changes that libbpf (located in `tools/lib/bpf/`) performs on BPF object files during the loading process. This analysis is critical for understanding the implications of signing compiled BPF object files, as **libbpf makes extensive modifications to the BPF bytecode, BTF metadata, and ELF structures after the object file is compiled**.

**Key Finding**: BPF object files undergo substantial transformation between compilation and kernel loading, making naive signing of compiled `.o` files problematic without accounting for these changes.

---

## Table of Contents

1. [Loading Pipeline Overview](#loading-pipeline-overview)
2. [ELF Parsing and Initial Processing](#elf-parsing-and-initial-processing)
3. [BTF Modifications](#btf-modifications)
4. [Instruction-Level Modifications](#instruction-level-modifications)
5. [Relocation Operations](#relocation-operations)
6. [Map Modifications](#map-modifications)
7. [Program Sanitization](#program-sanitization)
8. [Implications for Signing](#implications-for-signing)

---

## Loading Pipeline Overview

The BPF object loading process follows this sequence:

### Phase 1: Opening (bpf_object__open)
Source: `tools/lib/bpf/libbpf.c:8038-8141`

```
1. bpf_object__new() - Create object structure
2. bpf_object__elf_init() - Initialize ELF parsing
3. bpf_object__elf_collect() - Collect ELF sections
4. bpf_object__collect_externs() - Collect external symbols
5. bpf_object_fixup_btf() - Fix up BTF
6. bpf_object__init_maps() - Initialize maps
7. bpf_object_init_progs() - Initialize programs
8. bpf_object__collect_relos() - Collect relocations
9. bpf_object__elf_finish() - Close ELF handle
```

### Phase 2: Preparation (bpf_object_prepare)
Source: `tools/lib/bpf/libbpf.c:8650-8680`

```
1. bpf_object_prepare_token() - Prepare BPF token
2. bpf_object__probe_loading() - Probe kernel features
3. bpf_object__load_vmlinux_btf() - Load kernel BTF
4. bpf_object__resolve_externs() - Resolve external variables
5. bpf_object__sanitize_maps() - Sanitize map definitions
6. bpf_object__init_kern_struct_ops_maps() - Initialize struct_ops
7. bpf_object_adjust_struct_ops_autoload() - Adjust struct_ops
8. bpf_object__relocate() - Perform all relocations ⚠️
9. bpf_object__sanitize_and_load_btf() - Sanitize and load BTF ⚠️
10. bpf_object__create_maps() - Create BPF maps
11. bpf_object_prepare_progs() - Prepare programs ⚠️
```

### Phase 3: Loading (bpf_object_load)
Source: `tools/lib/bpf/libbpf.c:8682-8732`

```
1. bpf_object__load_progs() - Load programs into kernel
2. bpf_object_init_prog_arrays() - Initialize program arrays
3. bpf_object_prepare_struct_ops() - Prepare struct_ops
```

---

## ELF Parsing and Initial Processing

### Endianness Conversion
**Source**: `tools/lib/bpf/libbpf.c:3988-3990`

**What**: If the BPF object file is not in native endianness, libbpf byte-swaps ALL BPF instructions.

**Function**: `bpf_object_bswap_progs()`

**Impact**: MODIFIES instruction encoding

```c
/* change BPF program insns to native endianness for introspection */
if (!is_native_endianness(obj))
    bpf_object_bswap_progs(obj);
```

### Section Processing
**Source**: `tools/lib/bpf/libbpf.c:3810-3999`

Parses and categorizes ELF sections:
- `.text`, `.data`, `.rodata`, `.bss` sections
- `.BTF` and `.BTF.ext` sections
- `.maps` section (legacy, now unsupported)
- Relocation sections (`.rel*`)
- Struct_ops sections

---

## BTF Modifications

### BTF Sanitization
**Source**: `tools/lib/bpf/libbpf.c:3112-3219`

Libbpf **extensively modifies BTF metadata** to ensure compatibility with the target kernel. This is performed by `bpf_object__sanitize_btf()`.

#### Modifications Applied:

1. **VAR/DECL_TAG → INT Conversion**
   - **When**: Kernel doesn't support BTF_KIND_VAR or BTF_KIND_DECL_TAG
   - **What**: Replaces VAR and DECL_TAG types with INT
   - **Location**: `libbpf.c:3129-3138`

2. **DATASEC → STRUCT Conversion**
   - **When**: Kernel doesn't support BTF_KIND_DATASEC
   - **What**: Converts DATASEC to STRUCT, renames sections (`.` → `_`)
   - **Location**: `libbpf.c:3139-3162`

3. **DATASEC Name Sanitization**
   - **When**: Kernel doesn't support `?` prefix in DATASEC names
   - **What**: Replaces `?` with `_`
   - **Location**: `libbpf.c:3163-3170`

4. **FUNC_PROTO → ENUM Conversion**
   - **When**: Kernel doesn't support BTF_KIND_FUNC
   - **What**: Replaces FUNC_PROTO with ENUM
   - **Location**: `libbpf.c:3171-3175`

5. **FUNC → TYPEDEF Conversion**
   - **When**: Kernel doesn't support BTF_KIND_FUNC
   - **What**: Replaces FUNC with TYPEDEF
   - **Location**: `libbpf.c:3176-3178`

6. **Global Function Linkage Modification**
   - **When**: Kernel doesn't support global functions OR user marks function as static
   - **What**: Changes BTF_FUNC_GLOBAL → BTF_FUNC_STATIC
   - **Location**: `libbpf.c:3179-3181` and `libbpf.c:3543-3565`

7. **FLOAT → STRUCT Conversion**
   - **When**: Kernel doesn't support BTF_KIND_FLOAT
   - **What**: Replaces FLOAT with anonymous STRUCT
   - **Location**: `libbpf.c:3182-3188`

8. **TYPE_TAG → CONST Conversion**
   - **When**: Kernel doesn't support BTF_KIND_TYPE_TAG
   - **What**: Replaces TYPE_TAG with CONST
   - **Location**: `libbpf.c:3189-3192`

9. **ENUM64 Modifications**
   - **When**: Kernel doesn't support BTF_KIND_ENUM64
   - **What**: Clears kflag for old-style enums, or replaces ENUM64 with UNION
   - **Location**: `libbpf.c:3193-3215`

10. **Pointer Size Enforcement**
    - **When**: Always for BPF-targeted BTFs
    - **What**: Enforces 8-byte pointer size
    - **Location**: `libbpf.c:3580`

---

## Instruction-Level Modifications

### 1. Endianness Byte-Swapping
Already covered in ELF section above.

### 2. Subprogram Call Relocations
**Source**: `tools/lib/bpf/libbpf.c:6468-6574`

**What**: Modifies call instruction immediate values to point to relocated subprogram offsets.

**Process**:
1. Subprograms are appended to main program's instruction array
2. Call instruction `imm` field is recalculated to new offset
3. Formula: `insn->imm = subprog->sub_insn_off - (prog->sub_insn_off + insn_idx) - 1`

**Location**: `bpf_object__reloc_code()`

**Modified Fields**: `insn->imm`

```c
// Line 6567
insn->imm = subprog->sub_insn_off - (prog->sub_insn_off + insn_idx) - 1;
```

### 3. Subprogram Address Marking
**Source**: `tools/lib/bpf/libbpf.c:7148-7158`

**What**: Marks instructions that reference subprogram addresses.

**Modified Fields**: `insn[0].src_reg`

```c
// Line 7155-7156
if (relo->type == RELO_SUBPROG_ADDR)
    insn[0].src_reg = BPF_PSEUDO_FUNC;
```

### 4. Data Relocations
**Source**: `tools/lib/bpf/libbpf.c:6153-6246`

Modifies instructions to reference maps, external variables, and kfuncs.

#### RELO_LD64 (Map FD References)
**Location**: `libbpf.c:6164-6176`

**Modified Fields**:
- `insn[0].src_reg` ← `BPF_PSEUDO_MAP_FD` or `BPF_PSEUDO_MAP_IDX`
- `insn[0].imm` ← map FD or map index

#### RELO_DATA (Map Data References)
**Location**: `libbpf.c:6177-6190`

**Modified Fields**:
- `insn[1].imm` ← data offset (original imm + symbol offset)
- `insn[0].src_reg` ← `BPF_PSEUDO_MAP_VALUE` or `BPF_PSEUDO_MAP_IDX_VALUE`
- `insn[0].imm` ← map FD or map index

#### RELO_EXTERN_LD64 (External Variables)
**Location**: `libbpf.c:6191-6212`

**Modified Fields**:
- For kconfig variables:
  - `insn[0].src_reg` ← `BPF_PSEUDO_MAP_VALUE` or `BPF_PSEUDO_MAP_IDX_VALUE`
  - `insn[0].imm` ← kconfig map FD or index
  - `insn[1].imm` ← kconfig data offset
- For ksyms:
  - `insn[0].src_reg` ← `BPF_PSEUDO_BTF_ID` (if typed)
  - `insn[0].imm` ← kernel BTF ID
  - `insn[1].imm` ← kernel BTF obj FD or address

#### RELO_EXTERN_CALL (Kfunc Calls)
**Location**: `libbpf.c:6213-6223`

**Modified Fields**:
- `insn[0].src_reg` ← `BPF_PSEUDO_KFUNC_CALL`
- `insn[0].imm` ← kernel BTF ID
- `insn[0].off` ← BTF FD index

---

## Relocation Operations

### CO-RE (Compile Once - Run Everywhere) Relocations
**Source**: `tools/lib/bpf/relo_core.c:1039-1165`

CO-RE relocations are one of the **most significant modifications** libbpf makes. They allow BPF programs to be portable across different kernel versions by adjusting field offsets, type IDs, and sizes at load time.

#### CO-RE Relocation Types

**Function**: `bpf_core_patch_insn()`

1. **ALU/ALU64 Instructions** (`relo_core.c:1063-1079`)
   - **Modified Field**: `insn->imm`
   - **Use Case**: Field sizes, type sizes, enumeration values
   - **Example**: `BPF_CORE_TYPE_SIZE`, `BPF_CORE_ENUMVAL_VALUE`

2. **LDX/ST/STX Instructions** (`relo_core.c:1080-1128`)
   - **Modified Fields**:
     - `insn->off` (field byte offset)
     - `insn->code` (memory access size)
   - **Use Case**: Field offset adjustments, field size adjustments
   - **Example**: `BPF_CORE_FIELD_BYTE_OFFSET`, `BPF_CORE_FIELD_BYTE_SIZE`

3. **LDIMM64 Instructions** (`relo_core.c:1129-1156`)
   - **Modified Fields**:
     - `insn[0].imm` (lower 32 bits)
     - `insn[1].imm` (upper 32 bits)
   - **Use Case**: Type IDs, addresses
   - **Example**: `BPF_CORE_TYPE_ID_LOCAL`, `BPF_CORE_TYPE_ID_TARGET`

#### CO-RE Modification Examples

```c
// Field offset relocation
insn->off = new_val;  // Adjusted to target kernel's field offset

// Field size relocation
insn->code = BPF_MODE(insn->code) | insn_bpf_sz | BPF_CLASS(insn->code);

// Immediate value relocation
insn->imm = new_val;
```

#### CO-RE Relocation Kinds

Based on `relo_core.c:85-104`, CO-RE supports:
- `BPF_CORE_FIELD_BYTE_OFFSET` - Field offset in bytes
- `BPF_CORE_FIELD_BYTE_SIZE` - Field size in bytes
- `BPF_CORE_FIELD_EXISTS` - Field existence check
- `BPF_CORE_FIELD_SIGNED` - Field signedness
- `BPF_CORE_FIELD_LSHIFT_U64` - Left shift for bitfield access
- `BPF_CORE_FIELD_RSHIFT_U64` - Right shift for bitfield access
- `BPF_CORE_TYPE_ID_LOCAL` - Local type ID
- `BPF_CORE_TYPE_ID_TARGET` - Target kernel type ID
- `BPF_CORE_TYPE_EXISTS` - Type existence check
- `BPF_CORE_TYPE_MATCHES` - Type matching check
- `BPF_CORE_TYPE_SIZE` - Type size
- `BPF_CORE_ENUMVAL_EXISTS` - Enum value existence
- `BPF_CORE_ENUMVAL_VALUE` - Enum value

---

## Map Modifications

### Map Sanitization
**Source**: `tools/lib/bpf/libbpf.c:8191-8203`

**What**: Modifies map flags based on kernel capabilities.

**Modified Fields**: `m->def.map_flags`

**Example**:
```c
// Remove BPF_F_MMAPABLE if kernel doesn't support it
if (!kernel_supports(obj, FEAT_ARRAY_MMAP))
    m->def.map_flags &= ~BPF_F_MMAPABLE;
```

---

## Program Sanitization

### Helper Function Call Modifications
**Source**: `tools/lib/bpf/libbpf.c:7422-7455`

**What**: Replaces newer helper function IDs with older equivalents for kernel compatibility.

**Modified Fields**: `insn->imm` (helper function ID)

**Function**: `bpf_object__sanitize_prog()`

**Examples**:
```c
// Replace bpf_probe_read_kernel/user with bpf_probe_read
case BPF_FUNC_probe_read_kernel:
case BPF_FUNC_probe_read_user:
    if (!kernel_supports(obj, FEAT_PROBE_READ_KERN))
        insn->imm = BPF_FUNC_probe_read;
    break;

// Replace bpf_probe_read_kernel_str/user_str with bpf_probe_read_str
case BPF_FUNC_probe_read_kernel_str:
case BPF_FUNC_probe_read_user_str:
    if (!kernel_supports(obj, FEAT_PROBE_READ_KERN))
        insn->imm = BPF_FUNC_probe_read_str;
    break;
```

---

## Implications for Signing

### Critical Challenges

1. **Bytecode is Modified After Compilation**
   - Instruction immediate values (`imm`)
   - Instruction offsets (`off`)
   - Instruction source registers (`src_reg`)
   - Instruction opcodes (`code`)
   - Entire instruction sequences (subprogram appending)

2. **BTF Metadata is Extensively Rewritten**
   - Type kinds are changed
   - Names are modified
   - Structure is reorganized
   - Content depends on target kernel features

3. **Modifications are Target-Dependent**
   - Same `.o` file produces different bytecode on different kernel versions
   - CO-RE relocations adapt to target kernel BTF
   - Feature detection changes behavior

### Potential Signing Strategies

#### Strategy 1: Sign Pre-Relocation Object
**Pros**: Can be done at build time
**Cons**:
- Signature becomes invalid after libbpf modifications
- Cannot verify what actually loads into kernel
- Doesn't prevent malicious libbpf modifications

#### Strategy 2: Sign Post-Relocation Bytecode
**Pros**: Verifies actual kernel-loaded code
**Cons**:
- Must happen at load time (runtime signing)
- Different signatures for different kernel versions
- Requires signing infrastructure on target system

#### Strategy 3: Hybrid Approach
**Concept**:
1. Sign the compiled object with metadata about allowed transformations
2. Libbpf records all transformations applied
3. Verify transformation log matches allowed operations
4. Sign final bytecode with derivation proof

**Pros**: Verifiable chain from source to kernel
**Cons**: Complex implementation, requires libbpf modifications

#### Strategy 4: Attestation-Based Approach
**Concept**:
1. Sign build metadata (compiler version, source hash, build flags)
2. Use reproducible builds to allow verification
3. Trust libbpf as part of TCB (Trusted Computing Base)
4. Optionally verify libbpf itself

**Pros**: Practical for many use cases
**Cons**: Requires trusting libbpf implementation

---

## Summary of Modified Components

### ELF Object File
- ✅ Sections parsed but not modified in file
- ❌ ELF handle closed after parsing (`bpf_object__elf_finish`)

### BPF Instructions
- ❌ **Endianness may be swapped**
- ❌ **Call instruction immediates modified** (subprogram calls)
- ❌ **Source registers modified** (map refs, subprog refs, kfunc calls)
- ❌ **Immediate values modified** (CO-RE, data relos, helper IDs)
- ❌ **Offset fields modified** (CO-RE field offsets)
- ❌ **Opcode modified** (CO-RE size adjustments)
- ❌ **Instructions appended** (subprograms merged into main program)

### BTF Metadata
- ❌ **Type kinds changed** (VAR→INT, DATASEC→STRUCT, FUNC→TYPEDEF, etc.)
- ❌ **Type properties modified** (GLOBAL→STATIC linkage)
- ❌ **Names changed** (DATASEC sanitization: `.`→`_`, `?`→`_`)
- ❌ **Structure reorganized** (DATASEC→STRUCT conversion)
- ❌ **Pointer size enforced** (always 8 bytes)

### Map Definitions
- ❌ **Flags modified** (BPF_F_MMAPABLE removal)

---

## Key Source File References

| Component | File | Line Range | Function |
|-----------|------|------------|----------|
| Main loading pipeline | `libbpf.c` | 8038-8742 | `bpf_object_open`, `bpf_object_prepare`, `bpf_object_load` |
| ELF collection | `libbpf.c` | 3810-3999 | `bpf_object__elf_collect` |
| BTF sanitization | `libbpf.c` | 3112-3219 | `bpf_object__sanitize_btf` |
| BTF loading | `libbpf.c` | 3517-3620 | `bpf_object__sanitize_and_load_btf` |
| Code relocation | `libbpf.c` | 6468-6574 | `bpf_object__reloc_code` |
| Data relocation | `libbpf.c` | 6153-6246 | `bpf_object__relocate_data` |
| CO-RE relocation | `libbpf.c` | 5975-6080 | `bpf_object__relocate_core` |
| CO-RE patching | `relo_core.c` | 1039-1165 | `bpf_core_patch_insn` |
| Program sanitization | `libbpf.c` | 7422-7455 | `bpf_object__sanitize_prog` |
| Map sanitization | `libbpf.c` | 8191-8203 | `bpf_object__sanitize_maps` |

---

## Conclusion

Libbpf performs **extensive transformations** on BPF object files between compilation and kernel loading. These modifications are:

1. **Pervasive** - Affect bytecode, BTF, and metadata
2. **Target-Dependent** - Vary based on kernel version and features
3. **Runtime-Determined** - Cannot be fully predicted at build time
4. **Essential** - Required for portability and compatibility

Any signing mechanism for BPF programs must account for these transformations, either by:
- Signing after transformation (runtime signing)
- Defining and verifying allowed transformation rules
- Trusting the transformation mechanism itself
- Using reproducible builds with build-time attestation

**The compiled `.o` file is NOT what gets loaded into the kernel.**

---

Report generated by analyzing Linux kernel source tree at commit: 6a23ae0a9 (Linux 6.18-rc6)
Source directory: `/home/user/linux/tools/lib/bpf/`
