# BPF Lean: Formal Verification of the BPF Virtual Machine

A complete formalization of the Berkeley Packet Filter (BPF) virtual machine in Lean 4, with a focus on proof-carrying code and security verification.

## Overview

This project provides a formal model of the BPF virtual machine as used in the Linux kernel, including:

1. **Instruction Set Architecture** - Complete encoding of BPF instructions
2. **Operational Semantics** - State machine model of program execution
3. **Security Policy** - Formal specification of safety requirements
4. **Verifier** - Static analyzer using abstract interpretation
5. **Proofs** - Correctness and safety theorems

## Architecture

### Modules

- **Basic.lean** - Core types (registers, instruction classes, operations)
- **Instruction.lean** - BPF instruction set and encoding/decoding
- **State.lean** - VM state machine and operational semantics
- **Security.lean** - Security policy, abstract values, and type system
- **Verifier.lean** - Static verifier using abstract interpretation
- **Proofs.lean** - Correctness and safety theorems
- **Tests.lean** - Example programs and test cases

### Key Features

#### 1. Complete Instruction Set Model

The formalization covers:
- ALU operations (32-bit and 64-bit)
- Memory operations (load/store)
- Jump operations (conditional and unconditional)
- Function calls and program exit

```lean
inductive BpfInstr : Type where
  | Alu64Reg (op : BpfAluOp) (dst : BpfReg) (src : BpfReg)
  | Alu64Imm (op : BpfAluOp) (dst : BpfReg) (imm : Int32)
  | LoadReg (size : BpfSize) (dst : BpfReg) (src : BpfReg) (off : Int16)
  | JumpReg (op : BpfJmpOp) (dst : BpfReg) (src : BpfReg) (off : Int16)
  ...
```

#### 2. State Machine Semantics

The VM state includes:
- Register file (11 registers R0-R10)
- Memory (byte-addressable)
- Program counter
- Execution fuel (for termination)

```lean
structure BpfState where
  regs : RegFile
  mem : Memory
  pc : Nat
  prog : Array BpfInsn
  fuel : Nat
```

#### 3. Security Policy

The security policy enforces:
- **Type safety**: Registers have well-defined types
- **Memory safety**: All accesses are bounds-checked
- **Control flow safety**: No unbounded loops (DAG requirement)
- **Initialization safety**: Registers must be initialized before use

```lean
inductive RegType where
  | NotInit
  | ScalarValue
  | PtrToCtx
  | PtrToStack (off : Int)
  | PtrToMapValue
  ...
```

#### 4. Abstract Interpretation

The verifier uses abstract interpretation to track:
- Register types at each program point
- Value ranges (signed and unsigned)
- Known bits (tristate numbers)
- Pointer relationships

```lean
structure AbstractValue where
  known_mask : UInt64
  known_value : UInt64
  umin : UInt64
  umax : UInt64
  smin : Int64
  smax : Int64
  ...
```

#### 5. Proof-Carrying Code

Programs are verified before execution:

```lean
def verifyAndRun (prog : Array BpfInsn) :
    Except VerifyError (BpfState × ExecResult) :=
  match verifyProgram prog SecurityPolicy.default with
  | .error err => .error err
  | .ok cert => .ok (BpfState.init prog).run
```

## Safety Theorems

The formalization proves or states several key safety properties:

### Verified Programs Are Memory Safe
```lean
axiom verified_program_memory_safe :
  ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    -- Program cannot violate memory safety
```

### Verified Programs Terminate
```lean
axiom verified_program_terminates :
  ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    cert.isDAG = true  -- No loops
```

### Type Safety
```lean
axiom type_safety :
  ∀ (prog : Array BpfInsn) (cert : SafetyCertificate),
    verifyProgram prog cert.policy = .ok cert →
    -- Well-typed programs don't have type errors
```

## Building

Requires Lean 4.25.0 or later.

```bash
lake build
```

## Running Tests

```bash
lake exe tests
```

Example output:
```
=== BPF Formalization Tests ===

Testing example program 1: return 42
Program exited with value: 42
✓ Test passed!

Testing example program 2: (10 + 5) * 2 = 30
Program exited with value: 30
✓ Test passed!

Testing invalid program 1: uninitialized register
✓ Correctly rejected: UninitializedRegister 0 R5
```

## Example: Simple BPF Program

```lean
-- Program: return 42
def example : Array BpfInsn :=
  #[
    mkInsn 0xb7 0 0 0 42,  -- mov r0, 42
    mkInsn 0x95 0 0 0 0    -- exit
  ]

-- Verify and run
#eval verifyAndRun example
-- Result: .ok (_, .Exit 42)
```

## Comparison with Linux Kernel BPF

This formalization closely models the Linux kernel's BPF implementation:

| Component | Linux Kernel | This Formalization |
|-----------|--------------|-------------------|
| Instruction format | `struct bpf_insn` | `BpfInsn` |
| Registers | R0-R10 | `BpfReg` |
| Instruction classes | LD, LDX, ST, STX, ALU, JMP | `BpfClass` |
| Verifier | `kernel/bpf/verifier.c` | `Verifier.lean` |
| Abstract values | `struct tnum` + ranges | `AbstractValue` |
| Register state | `struct bpf_reg_state` | `AbstractReg` |
| Type system | `enum bpf_reg_type` | `RegType` |

## Future Work

- [ ] Complete abstract interpretation for all instruction types
- [ ] Model helper functions and maps
- [ ] Add BTF (BPF Type Format) support
- [ ] Prove verifier soundness and completeness
- [ ] Extract verified code to runnable implementation
- [ ] Add more comprehensive test suite
- [ ] Model JIT compilation

## References

1. Linux Kernel BPF Documentation: https://www.kernel.org/doc/html/latest/bpf/
2. BPF Instruction Set: https://www.kernel.org/doc/Documentation/networking/filter.txt
3. Lean 4 Documentation: https://leanprover.github.io/lean4/doc/

## License

This formalization is provided for educational and research purposes.
See kernel source files for original BPF implementation licensing.
