/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Verification in Lean 4

This is the main entry point for the BPF verification library.

## Overview

This library provides a complete formal model of the BPF (Berkeley Packet Filter)
virtual machine in Lean 4, including:

1. **Core Definitions** (`BPF.Core`): Instructions, registers, and basic types
2. **State Machine** (`BPF.State`): Execution semantics and state transitions
3. **Security Policy** (`BPF.Security`): Formalization of proof-carrying code policies
4. **Verifier** (`BPF.Verifier`): Static analysis and verification
5. **Proofs** (`BPF.Proofs`): Correctness and security properties
6. **Tests** (`BPF.Tests`): Comprehensive test suite

## Usage

```lean
import BPF

-- Create a simple BPF program
def myProgram : Array BPF.Insn :=
  #[BPF.Insn.movImm BPF.Reg.R0 42,
    BPF.Insn.exit]

-- Verify the program
def verifyResult := BPF.verifyProgram myProgram

-- Certify and execute
def runProgram : Option BPF.ExecState :=
  match BPF.certifyProgram myProgram with
  | some cp => some (cp.execute 100)
  | none => none
```

## Key Concepts

### Proof-Carrying Code

This implementation follows the proof-carrying code (PCC) paradigm:
- Programs come with security proofs
- The verifier checks these proofs statically
- Only verified programs can execute
- No runtime checks needed (zero-cost abstractions)

### Abstract Interpretation

The verifier uses abstract interpretation to track:
- Register types (scalar, pointer, etc.)
- Value ranges (signed and unsigned bounds)
- Tri-state numbers (tracking known/unknown bits)
- Memory safety properties

### Security Policy

The security policy ensures:
- **Memory Safety**: No out-of-bounds memory access
- **Type Safety**: Operations respect type system
- **Termination**: Programs are DAGs (no infinite loops)
- **Resource Bounds**: Limited instruction count and stack size

## References

Based on the Linux kernel BPF implementation:
- `kernel/bpf/verifier.c`: BPF verifier implementation
- `include/linux/bpf.h`: BPF types and structures
- `include/uapi/linux/bpf.h`: BPF instruction encoding

-/

-- Export all public modules
import BPF.Core
import BPF.State
import BPF.Security
import BPF.Verifier
import BPF.Proofs
import BPF.Tests

namespace BPF

/-- Version information -/
def version : String := "0.1.0"

/-- Quick verification function -/
def verify (prog : Array Insn) : String :=
  formatVerifyResult (verifyProgram prog)

/-- Quick certification function -/
def certify (prog : Array Insn) : Option CertifiedProgram :=
  certifyProgram prog

end BPF
