/-
  BPF Lean: A Formal Verification Framework for BPF

  This is the main entry point for the BPF formalization in Lean 4.

  Modules:
  - Basic: Core types (registers, instruction classes, operations)
  - Instruction: BPF instruction set and encoding
  - State: VM state machine and operational semantics
  - Security: Security policy and abstract interpretation
  - Verifier: Static analyzer (proof checker)
  - Proofs: Correctness and safety theorems
  - Tests: Example programs and test cases

  This formalization models the Berkeley Packet Filter (BPF) virtual machine
  as used in the Linux kernel, with a focus on proof-carrying code.
-/

import BpfLean.Basic
import BpfLean.Instruction
import BpfLean.State
import BpfLean.Security
import BpfLean.Verifier
import BpfLean.Proofs
import BpfLean.Tests

-- Re-export key types and functions
export BpfLean.Basic (BpfReg BpfClass BpfSize BpfAluOp BpfJmpOp)
export BpfLean.Instruction (BpfInsn BpfInstr decodeBpfInsn)
export BpfLean.State (BpfState RegFile Memory ExecResult)
export BpfLean.Security (SecurityPolicy SafetyCertificate VerifyError verify)
export BpfLean.Verifier (verifyProgram verifyAndRun)
