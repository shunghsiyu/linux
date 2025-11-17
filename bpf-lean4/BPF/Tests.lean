/-
Copyright (c) 2025 BPF Verification Project. All rights reserved.
Released under Apache 2.0 license.

# BPF Tests and Examples

This module contains comprehensive tests and examples demonstrating
the BPF virtual machine, verifier, and security policy.
-/

import BPF.Core
import BPF.State
import BPF.Security
import BPF.Verifier
import BPF.Proofs

namespace BPF

/-! ## Basic Instruction Tests -/

/-- Test: MOV immediate creates correct instruction -/
def test_mov_imm : Bool :=
  let insn := Insn.movImm Reg.R0 42
  insn.dst_reg == Reg.R0 && insn.imm == 42

/-- Test: EXIT instruction is correctly formed -/
def test_exit : Bool :=
  let insn := Insn.exit
  insn.opcode == 0x95

/-- Test: ADD instruction is correctly formed -/
def test_add : Bool :=
  let insn := Insn.add Reg.R0 Reg.R1
  insn.dst_reg == Reg.R0 && insn.src_reg == Reg.R1

/-! ## Register State Tests -/

/-- Test: notInit register is not initialized -/
def test_notInit : Bool :=
  ¬RegState.notInit.isInit

/-- Test: scalar register is initialized -/
def test_scalar_init : Bool :=
  (RegState.scalar 42).isInit

/-- Test: scalar register has correct value -/
def test_scalar_value : Bool :=
  (RegState.scalar 42).value == 42

/-- Test: scalar register is scalar type -/
def test_scalar_type : Bool :=
  (RegState.scalar 42).isScalar

/-- Test: pointer to stack is a pointer -/
def test_ptr_to_stack : Bool :=
  (RegState.ptrToStack (-8)).isPtr

/-- Test: Constant value detection -/
def test_regstate_is_const : Bool :=
  let r := RegState.scalar 42
  r.isConst && r.getConst? == some 42

/-- Test: mayBeZero function -/
def test_regstate_may_be_zero : Bool :=
  let r1 := RegState.scalar 0
  let r2 := RegState.scalar 5
  let r3 := { RegState.scalar 10 with umin := 0, umax := 20 }
  r1.mayBeZero && !r2.mayBeZero && r3.mayBeZero

/-- Test: isNonZero function -/
def test_regstate_is_nonzero : Bool :=
  let r1 := RegState.scalar 5
  let r2 := { RegState.scalar 10 with umin := 1, umax := 20 }
  let r3 := { RegState.scalar 10 with umin := 0, umax := 20 }
  r1.isNonZero && r2.isNonZero && !r3.isNonZero

/-! ## TNum Tests -/

/-- Test: constant TNum is constant -/
def test_tnum_const : Bool :=
  (TNum.const 42).isConst

/-- Test: unknown TNum is not constant -/
def test_tnum_unknown : Bool :=
  ¬TNum.unknown.isConst

/-- Test: getConst works for constant -/
def test_tnum_get_const : Bool :=
  (TNum.const 42).getConst? == some 42

/-- Test: AND of constants -/
def test_tnum_and : Bool :=
  let a := TNum.const 0xFF
  let b := TNum.const 0x0F
  let c := a.and b
  c.getConst? == some 0x0F

/-- Test: OR of constants -/
def test_tnum_or : Bool :=
  let a := TNum.const 0xF0
  let b := TNum.const 0x0F
  let c := a.or b
  c.getConst? == some 0xFF

/-! ## Policy Tests -/

/-- Test: Safe policy is safe -/
def test_policy_safe : Bool :=
  PolicyResult.Safe.isSafe

/-- Test: Unsafe policy is unsafe -/
def test_policy_unsafe : Bool :=
  (PolicyResult.Unsafe SecurityViolation.StackOverflow).isUnsafe

/-- Test: Safe AND Safe is Safe -/
def test_policy_and_safe : Bool :=
  (PolicyResult.Safe.and PolicyResult.Safe) == PolicyResult.Safe

/-- Test: checkRegInit detects uninitialized register -/
def test_check_reg_init : Bool :=
  let s := ExecState.init #[]
  let result := checkRegInit s Reg.R0
  result.isUnsafe

/-- Test: checkStackBounds detects overflow -/
def test_stack_overflow : Bool :=
  let result := checkStackBounds 1000
  result.isUnsafe

/-- Test: checkStackBounds allows valid access -/
def test_stack_valid : Bool :=
  let result := checkStackBounds 256
  result.isSafe

/-! ## Execution Tests -/

/-- Test program: MOV R0, 42; EXIT -/
def simple_program : Array Insn :=
  #[Insn.movImm Reg.R0 42, Insn.exit]

/-- Test: Simple program initializes correctly -/
def test_simple_init : Bool :=
  let s := ExecState.init simple_program
  s.pc == 0 && ¬s.halted

/-- Test: Halt sets halted flag -/
def test_halt : Bool :=
  let s := ExecState.init simple_program
  s.halt.halted

/-! ## Verifier Tests -/

/-- Test: Simple valid program verifies -/
def test_verify_simple : Bool :=
  match verifyProgram simple_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program with uninitialized read -/
def uninit_read_program : Array Insn :=
  #[Insn.add Reg.R0 Reg.R2,  -- R0, R2 not initialized
    Insn.exit]

/-- Test: Uninitialized read is detected -/
def test_verify_uninit : Bool :=
  match verifyProgram uninit_read_program with
  | VerifyResult.Invalid (SecurityViolation.UninitializedRead _) _ => true
  | _ => false

/-- Test: Too large program is rejected -/
def test_verify_size : Bool :=
  let large_prog := Array.mkArray (MAX_INSNS + 1) Insn.exit
  match verifyProgram large_prog with
  | VerifyResult.Invalid SecurityViolation.InvalidInstruction _ => true
  | _ => false

/-- Test: Verifier initial state has R1 initialized (context pointer) -/
def test_verifier_init_r1 : Bool :=
  let s := VerifierState.init
  (s.getReg Reg.R1).isInit

/-- Test: Verifier initial state has R10 as frame pointer -/
def test_verifier_init_r10 : Bool :=
  let s := VerifierState.init
  let r10 := s.getReg Reg.R10
  r10.regType == RegType.PtrToStack

/-! ## Abstract Interpretation Tests -/

/-- Test: Abstract add of constants -/
def test_abstract_add : Bool :=
  let dst := RegState.scalar 10
  let src := RegState.scalar 32
  let result := abstractAdd dst src
  result.value == 42 && result.isScalar

/-- Test: Abstract sub of constants -/
def test_abstract_sub : Bool :=
  let dst := RegState.scalar 50
  let src := RegState.scalar 8
  let result := abstractSub dst src
  result.value == 42 && result.isScalar

/-- Test: Abstract AND of constants -/
def test_abstract_and : Bool :=
  let dst := RegState.scalar 0xFF
  let src := RegState.scalar 0x0F
  let result := abstractAnd dst src
  result.value == 0x0F && result.isScalar

/-- Test: Abstract move preserves value -/
def test_abstract_mov : Bool :=
  let src := RegState.scalar 42
  let result := abstractMov src
  result.value == 42 && result.isScalar

/-- Test: Abstract multiplication -/
def test_abstract_mul : Bool :=
  let dst := RegState.scalar 6
  let src := RegState.scalar 7
  let result := abstractMul dst src
  result.value == 42 && result.isScalar

/-- Test: Abstract division -/
def test_abstract_div : Bool :=
  let dst := RegState.scalar 84
  let src := RegState.scalar 2
  let result := abstractDiv dst src
  result.value == 42 && result.isScalar

/-- Test: Abstract XOR -/
def test_abstract_xor : Bool :=
  let dst := RegState.scalar 0xF0
  let src := RegState.scalar 0x0F
  let result := abstractXor dst src
  result.value == 0xFF && result.isScalar

/-- Test: Abstract left shift -/
def test_abstract_lsh : Bool :=
  let dst := RegState.scalar 21
  let src := RegState.scalar 1  -- Shift left by 1 = multiply by 2
  let result := abstractLsh dst src
  result.value == 42 && result.isScalar

/-- Test: Abstract right shift -/
def test_abstract_rsh : Bool :=
  let dst := RegState.scalar 84
  let src := RegState.scalar 1  -- Shift right by 1 = divide by 2
  let result := abstractRsh dst src
  result.value == 42 && result.isScalar

/-- Test: Abstract MOD -/
def test_abstract_mod : Bool :=
  let dst := RegState.scalar 100
  let src := RegState.scalar 58
  let result := abstractAluOp AluOp.MOD dst src
  result.value == 42 && result.isScalar &&
  result.umax < 58  -- Result should be less than modulus

/-! ## Complex Program Tests -/

/-- Test program: Add two registers
    R1 = ctx (initialized)
    R0 = R1
    R0 += R1
    EXIT
-/
def add_program : Array Insn :=
  #[Insn.mov Reg.R0 Reg.R1,
    Insn.add Reg.R0 Reg.R1,
    Insn.exit]

/-- Test: Add program verifies (R1 is initialized as context) -/
def test_verify_add : Bool :=
  match verifyProgram add_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program: Arithmetic operations
    R0 = 100
    R2 = 7
    R0 -= R2  // R0 = 93
    R0 *= R2  // R0 = 651
    R0 /= R2  // R0 = 93
    EXIT
-/
def arithmetic_program : Array Insn :=
  #[Insn.movImm Reg.R0 100,
    Insn.movImm Reg.R2 7,
    Insn.sub Reg.R0 Reg.R2,
    Insn.mul Reg.R0 Reg.R2,
    Insn.div Reg.R0 Reg.R2,
    Insn.exit]

/-- Test: Arithmetic program verifies -/
def test_verify_arithmetic : Bool :=
  match verifyProgram arithmetic_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program: Bitwise operations
    R0 = 0xFF
    R1 = 0x0F
    R2 = R0 & R1  // Should be 0x0F
    R3 = R0 | R1  // Should be 0xFF
    R4 = R0 ^ R1  // Should be 0xF0
    EXIT
-/
def bitwise_program : Array Insn :=
  #[Insn.movImm Reg.R0 0xFF,
    Insn.movImm Reg.R1 0x0F,
    Insn.mov Reg.R2 Reg.R0,
    Insn.and Reg.R2 Reg.R1,
    Insn.mov Reg.R3 Reg.R0,
    Insn.or Reg.R3 Reg.R1,
    Insn.mov Reg.R4 Reg.R0,
    Insn.xor Reg.R4 Reg.R1,
    Insn.exit]

/-- Test: Bitwise program verifies -/
def test_verify_bitwise : Bool :=
  match verifyProgram bitwise_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program: Immediate arithmetic
    R0 = 10
    R0 += 32
    EXIT
    (Should result in R0 = 42)
-/
def imm_arithmetic_program : Array Insn :=
  #[Insn.movImm Reg.R0 10,
    Insn.addImm Reg.R0 32,
    Insn.exit]

/-- Test: Immediate arithmetic verifies -/
def test_verify_imm_arithmetic : Bool :=
  match verifyProgram imm_arithmetic_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program: Stack operations
    R2 = R10        // Get frame pointer
    R2 += -8        // Point to stack slot
    *(u64*)(R2) = R1  // Store R1 to stack
    R0 = *(u64*)(R2)  // Load from stack
    EXIT
-/
def stack_program : Array Insn :=
  #[Insn.mov Reg.R2 Reg.R10,
    Insn.addImm Reg.R2 (-8),
    Insn.stx MemSize.DW Reg.R2 Reg.R1 0,
    Insn.ldx MemSize.DW Reg.R0 Reg.R2 0,
    Insn.exit]

/-- Test: Stack operations program verifies -/
def test_verify_stack : Bool :=
  match verifyProgram stack_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program: Conditional branch
    R0 = 42
    R1 = 42
    if R0 == R1 goto +2
    R0 = 0  // Skip this
    exit
    R0 = 1  // Jump here
    EXIT
-/
def branch_program : Array Insn :=
  #[Insn.movImm Reg.R0 42,
    Insn.movImm Reg.R1 42,
    Insn.jeq Reg.R0 Reg.R1 2,
    Insn.movImm Reg.R0 0,
    Insn.exit,
    Insn.movImm Reg.R0 1,
    Insn.exit]

/-- Test: Branch program verifies -/
def test_verify_branch : Bool :=
  match verifyProgram branch_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program: Division by zero detection
    R0 = 100
    R1 = 0
    R0 /= R1  // Should be detected as unsafe
    EXIT
-/
def div_zero_program : Array Insn :=
  #[Insn.movImm Reg.R0 100,
    Insn.movImm Reg.R1 0,
    Insn.div Reg.R0 Reg.R1,
    Insn.exit]

/-- Test: Division by zero is detected -/
def test_detect_div_zero : Bool :=
  match verifyProgram div_zero_program with
  | VerifyResult.Invalid SecurityViolation.DivisionByZero _ => true
  | _ => false

/-- Test program: Range refinement allows safe division
    R0 = <unknown value from context>
    if R0 <= 0 goto exit_zero
    R1 = 100
    R1 /= R0   // Safe! We know R0 > 0 in this branch
    R0 = R1
    exit
    exit_zero:
    R0 = 0
    EXIT
-/
def range_refinement_program : Array Insn :=
  #[-- R0 already initialized (context)
    -- Check if R0 <= 0
    Insn.movImm Reg.R2 0,
    Insn.jeq Reg.R0 Reg.R2 3,  -- if R0 == 0, jump to exit_zero

    -- Safe division path (R0 != 0)
    Insn.movImm Reg.R1 100,
    Insn.div Reg.R1 Reg.R0,  -- This should verify! R0 != 0 here
    Insn.mov Reg.R0 Reg.R1,
    Insn.exit,

    -- exit_zero:
    Insn.movImm Reg.R0 0,
    Insn.exit
  ]

/-- Test: Range refinement enables safe division -/
def test_range_refinement : Bool :=
  match verifyProgram range_refinement_program with
  | VerifyResult.Valid => true
  | _ => false

/-! ## State Merging Tests -/

/-- Test: Merging TNum with itself is idempotent -/
def test_merge_tnum_idem : Bool :=
  let t := TNum.const 42
  mergeTNum t t == t

/-- Test: Merging two different constants produces unknown -/
def test_merge_tnum_diff : Bool :=
  let t1 := TNum.const 10
  let t2 := TNum.const 20
  let merged := mergeTNum t1 t2
  merged.mask == UInt64.max  -- All bits unknown

/-- Test: Merging register states with same type preserves type -/
def test_merge_regstate_same_type : Bool :=
  let r1 := RegState.scalar 10
  let r2 := RegState.scalar 20
  let merged := mergeRegState r1 r2
  merged.regType == RegType.ScalarValue &&
  merged.umin == 10 &&  -- min of both
  merged.umax == 20     -- max of both

/-- Test: Merging register states with different types produces scalar -/
def test_merge_regstate_diff_type : Bool :=
  let r1 := RegState.scalar 10
  let r2 := RegState.ptrToStack 0
  let merged := mergeRegState r1 r2
  merged.regType == RegType.ScalarValue

/-- Program with control flow merge -/
def merge_test_program : Array Insn :=
  #[
    -- if R1 > 10
    Insn.movImm Reg.R2 10,
    Insn.jgt Reg.R1 Reg.R2 2,

    -- False branch: R0 = 100
    Insn.movImm Reg.R0 100,
    Insn.exit,

    -- True branch: R0 = 200
    Insn.movImm Reg.R0 200,
    Insn.exit
  ]

/-- Test: Program with merge point verifies -/
def test_merge_program : Bool :=
  match verifyProgram merge_test_program with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Loop Detection Tests -/

/-- Program with a simple loop (back-edge) -/
def loop_program : Array Insn :=
  #[
    -- Loop: R0++, jump back
    Insn.movImm Reg.R0 0,
    Insn.addImm Reg.R0 1,  -- R0 += 1
    Insn.ja (-2),          -- Jump back to addImm (creates loop)
    Insn.exit
  ]

/-- Test: Loop detection rejects infinite loops -/
def test_loop_detection : Bool :=
  match verifyProgram loop_program with
  | VerifyResult.Invalid SecurityViolation.InfiniteLoop _ => true
  | _ => false

/-- Program with forward jump only (no loop) -/
def no_loop_program : Array Insn :=
  #[
    Insn.movImm Reg.R0 0,
    Insn.jgt Reg.R0 Reg.R1 2,  -- Forward jump only
    Insn.movImm Reg.R0 1,
    Insn.exit,
    Insn.movImm Reg.R0 2,
    Insn.exit
  ]

/-- Test: Forward jumps are allowed -/
def test_no_loop : Bool :=
  match verifyProgram no_loop_program with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Subprogram (BPF-to-BPF Call) Tests -/

/-- Program with BPF-to-BPF function call -/
def bpf_to_bpf_call_program : Array Insn :=
  #[
    -- Main function
    Insn.movImm Reg.R1 10,
    -- Call subprogram at offset +3 (src_reg = 1 indicates BPF-to-BPF call)
    { opcode := 0x85, dst_reg := Reg.R0, src_reg := Reg.R1, off := 0, imm := 2 },
    Insn.exit,

    -- Subprogram: R0 = R1 * 2
    Insn.mov Reg.R0 Reg.R1,
    Insn.add Reg.R0 Reg.R1,  -- R0 = R1 + R1 (i.e., R1 * 2)
    Insn.exit
  ]

/-- Test: BPF-to-BPF calls verify -/
def test_bpf_to_bpf_call : Bool :=
  match verifyProgram bpf_to_bpf_call_program with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Map Operation Tests -/

/-- Test: Sample hash map has correct properties -/
def test_map_hash : Bool :=
  sampleHashMap.mapType == MapType.Hash &&
  sampleHashMap.keySize == 4 &&
  sampleHashMap.valueSize == 8

/-- Test: Sample array map has correct properties -/
def test_map_array : Bool :=
  sampleArrayMap.mapType == MapType.Array &&
  sampleArrayMap.keySize == 4 &&
  sampleArrayMap.maxEntries == 256

/-- Test: Map key size validation -/
def test_map_key_valid : Bool :=
  sampleHashMap.isKeyValid 4 &&
  !sampleHashMap.isKeyValid 8

/-- Program that performs map lookup -/
def map_lookup_program : Array Insn :=
  #[
    -- Assume R1 = map_ptr, R2 = key_ptr (from context)
    -- Call bpf_map_lookup_elem(R1, R2)
    -- R1 and R2 are already set up by caller
    Insn.call HelperFunc.MapLookupElem,

    -- R0 now contains pointer to map value (or NULL)
    -- Check if lookup succeeded
    Insn.movImm Reg.R1 0,
    Insn.jeq Reg.R0 Reg.R1 2,  -- if R0 == NULL, return 0

    -- Lookup succeeded, load value from map
    Insn.ldx MemSize.DW Reg.R0 Reg.R0 0,
    Insn.exit,

    -- NULL case: return 0
    Insn.movImm Reg.R0 0,
    Insn.exit
  ]

/-- Test: Map lookup program verifies -/
def test_map_lookup : Bool :=
  match verifyProgram map_lookup_program with
  | VerifyResult.Valid => true
  | _ => false

/-! ## Helper Function Test Programs -/

/-- Program that calls bpf_ktime_get_ns helper -/
def helper_ktime_program : Array Insn :=
  #[
    -- Call bpf_ktime_get_ns() - returns current time in R0
    Insn.call HelperFunc.KtimeGetNs,

    -- R0 now contains timestamp, return it
    Insn.exit
  ]

/-- Test: Helper function call verifies -/
def test_helper_ktime : Bool :=
  match verifyProgram helper_ktime_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Program that calls bpf_get_prandom_u32 helper -/
def helper_random_program : Array Insn :=
  #[
    -- Call bpf_get_prandom_u32() - returns random u32
    Insn.call HelperFunc.GetPrandomU32,

    -- Check if random number is even
    Insn.movImm Reg.R1 1,
    Insn.and Reg.R0 Reg.R1,  -- R0 & 1

    -- Return result (0 = even, 1 = odd)
    Insn.exit
  ]

/-- Test: Helper with subsequent operations verifies -/
def test_helper_random : Bool :=
  match verifyProgram helper_random_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Program that calls GetSmpProcessorId -/
def helper_cpu_id_program : Array Insn :=
  #[
    -- Get current CPU ID
    Insn.call HelperFunc.GetSmpProcessorId,

    -- CPU ID should be < 4096, return it
    Insn.exit
  ]

/-- Test: CPU ID helper verifies -/
def test_helper_cpu_id : Bool :=
  match verifyProgram helper_cpu_id_program with
  | VerifyResult.Valid => true
  | _ => false

/-- Test program: Stack operations
    R2 = R10 (frame pointer)
    R2 += -8 (stack offset)
    *(u64 *)(R2 + 0) = R1
    R0 = *(u64 *)(R2 + 0)
    EXIT
-/
-- Note: This would require more complex instruction encoding

/-! ## Certification Tests -/

/-- Test: Valid program can be certified -/
def test_certify_valid : Bool :=
  match certifyProgram simple_program with
  | some _ => true
  | none => false

/-- Test: Invalid program cannot be certified -/
def test_certify_invalid : Bool :=
  match certifyProgram uninit_read_program with
  | some _ => false
  | none => true

/-- Test: Certified program can be loaded -/
def test_certified_load : Bool :=
  match certifyProgram simple_program with
  | some cp => cp.canLoad
  | none => false

/-! ## Regression Tests -/

/-- Test: Ensure R0-R5 are caller-saved -/
def test_caller_saved : Bool :=
  let s := VerifierState.init
  let s' := s.invalidateCallerSaved
  ¬(s'.getReg Reg.R0).isInit &&
  ¬(s'.getReg Reg.R1).isInit &&
  (s'.getReg Reg.R10).isInit  -- R10 should remain initialized

/-- Test: Setting register updates state -/
def test_set_reg : Bool :=
  let s := VerifierState.init
  let newReg := RegState.scalar 42
  let s' := s.setReg Reg.R0 newReg
  (s'.getReg Reg.R0).value == 42

/-- Test: Worklist operations -/
def test_worklist : Bool :=
  let wl := Worklist.empty
  let s := VerifierState.init
  let wl' := wl.add s
  ¬wl'.isEmpty

/-! ## Integration Tests -/

/-- Integration test: Full pipeline from program to execution -/
def test_full_pipeline : Bool :=
  let prog := simple_program
  match certifyProgram prog with
  | some cp =>
    let result := cp.execute 10
    result.halted || result.pc < prog.size
  | none => false

/-! ## Run All Tests -/

/-- List of all test cases with names -/
def all_tests : List (String × Bool) := [
  -- Basic instruction tests
  ("mov_imm", test_mov_imm),
  ("exit", test_exit),
  ("add", test_add),

  -- Register state tests
  ("notInit", test_notInit),
  ("scalar_init", test_scalar_init),
  ("scalar_value", test_scalar_value),
  ("scalar_type", test_scalar_type),
  ("ptr_to_stack", test_ptr_to_stack),
  ("regstate_is_const", test_regstate_is_const),
  ("regstate_may_be_zero", test_regstate_may_be_zero),
  ("regstate_is_nonzero", test_regstate_is_nonzero),

  -- TNum tests
  ("tnum_const", test_tnum_const),
  ("tnum_unknown", test_tnum_unknown),
  ("tnum_get_const", test_tnum_get_const),
  ("tnum_and", test_tnum_and),
  ("tnum_or", test_tnum_or),

  -- Policy tests
  ("policy_safe", test_policy_safe),
  ("policy_unsafe", test_policy_unsafe),
  ("policy_and_safe", test_policy_and_safe),
  ("check_reg_init", test_check_reg_init),
  ("stack_overflow", test_stack_overflow),
  ("stack_valid", test_stack_valid),

  -- Execution tests
  ("simple_init", test_simple_init),
  ("halt", test_halt),

  -- Verifier tests
  ("verify_simple", test_verify_simple),
  ("verify_uninit", test_verify_uninit),
  ("verify_size", test_verify_size),
  ("verifier_init_r1", test_verifier_init_r1),
  ("verifier_init_r10", test_verifier_init_r10),

  -- Abstract interpretation tests
  ("abstract_add", test_abstract_add),
  ("abstract_sub", test_abstract_sub),
  ("abstract_mul", test_abstract_mul),
  ("abstract_div", test_abstract_div),
  ("abstract_and", test_abstract_and),
  ("abstract_xor", test_abstract_xor),
  ("abstract_lsh", test_abstract_lsh),
  ("abstract_rsh", test_abstract_rsh),
  ("abstract_mod", test_abstract_mod),
  ("abstract_mov", test_abstract_mov),

  -- Program verification tests
  ("verify_add", test_verify_add),
  ("verify_arithmetic", test_verify_arithmetic),
  ("verify_bitwise", test_verify_bitwise),
  ("verify_imm_arithmetic", test_verify_imm_arithmetic),
  ("verify_stack", test_verify_stack),
  ("verify_branch", test_verify_branch),
  ("detect_div_zero", test_detect_div_zero),
  ("range_refinement", test_range_refinement),

  -- State merging tests
  ("merge_tnum_idem", test_merge_tnum_idem),
  ("merge_tnum_diff", test_merge_tnum_diff),
  ("merge_regstate_same_type", test_merge_regstate_same_type),
  ("merge_regstate_diff_type", test_merge_regstate_diff_type),
  ("merge_program", test_merge_program),

  -- Loop detection tests
  ("loop_detection", test_loop_detection),
  ("no_loop", test_no_loop),

  -- Subprogram tests
  ("bpf_to_bpf_call", test_bpf_to_bpf_call),

  -- Map operation tests
  ("map_hash", test_map_hash),
  ("map_array", test_map_array),
  ("map_key_valid", test_map_key_valid),
  ("map_lookup", test_map_lookup),

  -- Helper function tests
  ("helper_ktime", test_helper_ktime),
  ("helper_random", test_helper_random),
  ("helper_cpu_id", test_helper_cpu_id),

  -- Certification tests
  ("certify_valid", test_certify_valid),
  ("certify_invalid", test_certify_invalid),
  ("certified_load", test_certified_load),

  -- Misc tests
  ("caller_saved", test_caller_saved),
  ("set_reg", test_set_reg),
  ("worklist", test_worklist),
  ("full_pipeline", test_full_pipeline)
]

/-- Run all tests and report results -/
def run_tests : IO Unit := do
  IO.println "Running BPF tests..."
  let mut passed := 0
  let mut failed := 0

  for (name, test) in all_tests do
    if test then
      IO.println s!"  ✓ {name}"
      passed := passed + 1
    else
      IO.println s!"  ✗ {name}"
      failed := failed + 1

  IO.println ""
  IO.println s!"Results: {passed} passed, {failed} failed out of {all_tests.length} tests"

  if failed > 0 then
    IO.Process.exit 1

/-! ## Example Usage -/

/-- Example: Verify and execute a simple program -/
def example_usage : IO Unit := do
  IO.println "Example: Verifying and executing a simple BPF program"
  IO.println ""

  let prog := simple_program
  IO.println "Program:"
  IO.println "  MOV R0, 42"
  IO.println "  EXIT"
  IO.println ""

  -- Verify the program
  let verifyResult := verifyProgram prog
  IO.println s!"Verification result: {formatVerifyResult verifyResult}"
  IO.println ""

  -- Certify the program
  match certifyProgram prog with
  | some cp => do
    IO.println "✓ Program certified successfully"
    IO.println ""

    -- Execute the program
    let finalState := cp.execute 100
    IO.println s!"Execution completed: halted = {finalState.halted}"
    IO.println s!"Final R0 value: {(finalState.getReg Reg.R0).value}"

  | none =>
    IO.println "✗ Program certification failed"

-- To run tests: lake build && lake env lean --run BPF/Tests.lean

end BPF
