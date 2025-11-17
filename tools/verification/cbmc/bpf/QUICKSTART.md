# CBMC BPF Verifier - Quick Start Guide

This guide will get you up and running with CBMC verification of BPF verifier functions in under 10 minutes.

## What You'll Need

1. **CBMC installed** - The C Bounded Model Checker
2. **Linux kernel source** - You're already in it!
3. **5-10 minutes** - For setup and first verification

## Installation

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y cbmc
```

### Fedora/RHEL
```bash
sudo dnf install -y cbmc
```

### Verify Installation
```bash
goto-cc --version
cbmc --version
```

Both commands should output version information. If not, see the main [README.md](README.md) for alternative installation methods.

## Your First Verification

### Step 1: Navigate to the verification directory

```bash
cd tools/verification/cbmc/bpf
```

### Step 2: See what's available

```bash
make help
```

You should see a list of available verification targets.

### Step 3: Run your first verification

Let's verify that the sign-extension tracking function works correctly:

```bash
make coerce_reg_to_size_sx_verify
```

**What's happening:**
1. `goto-cc` compiles the BPF verifier to a special format (this takes ~30 seconds)
2. CBMC symbolically executes all possible inputs (this takes 2-5 minutes)
3. You'll see either `VERIFICATION SUCCESSFUL` or a failure message

**Expected output:**
```
Compiling BPF verifier to goto-binary...
Building verification harness...
Running CBMC verification for coerce_reg_to_size_sx...
This may take several minutes depending on complexity...
...
** 0 of 2 failed (2 iterations)
VERIFICATION SUCCESSFUL
```

🎉 **Success!** You've just formally verified that `coerce_reg_to_size_sx()` correctly tracks all possible register values after sign extension!

### Step 4: Try a binary operation

Now let's verify addition tracking:

```bash
make scalar_min_max_add_verify
```

This verifies that when the BPF verifier sees an addition instruction, it correctly computes the possible range of the result.

## What Just Happened?

CBMC just checked **billions** of possible inputs to these functions and verified that they satisfy their safety properties. Specifically:

### For `coerce_reg_to_size_sx()`
✅ For **every** possible input register state
✅ Containing **any** value `x`
✅ After sign-extending to 1, 2, or 4 bytes
✅ The output register state **always** contains the correct sign-extended value

### For `scalar_min_max_add()`
✅ For **every** possible pair of input register states
✅ Containing **any** values `a` and `b`
✅ After adding them together
✅ The output register state **always** contains `a + b` (accounting for overflow)

This is **much stronger** than testing - we've proven correctness for all inputs, not just a few test cases!

## Exploring the Code

### Look at a verification harness

```bash
cat coerce_reg_to_size_sx_verify.c
```

You'll see three main sections:

1. **Setup**: Create symbolic inputs
   ```c
   struct bpf_reg_state reg = __bpf_reg_state_input();
   u64 x = __CPROVER_unsigned_long_long_input();
   ```

2. **Operation**: Call the function
   ```c
   coerce_reg_to_size_sx(&reg, size);
   ```

3. **Verification**: Check the property
   ```c
   assert(val_in_reg(&reg, sign_extended_x));
   ```

### Understanding the helper functions

- `__bpf_reg_state_input()`: Creates a symbolic register state (any possible state)
- `valid_bpf_reg_state()`: Ensures the state satisfies all invariants
- `val_in_reg()`: Checks if a specific value is within the tracked ranges

## Next Steps

### If verification fails

Don't panic! Here's what to do:

#### 1. Get a counterexample
```bash
make coerce_reg_to_size_sx_trace
```

This shows you the specific input that causes the property to fail.

#### 2. Simplify the counterexample
```bash
make coerce_reg_to_size_sx_simple
```

This uses smaller input ranges to give you a simpler counterexample that's easier to understand.

#### 3. Analyze the trace

Look for:
- **Initial values**: What were the inputs?
- **Intermediate steps**: What happened during execution?
- **Failed assertion**: Which property was violated?

### Create your own verification harness

Use the helper script:

```bash
./new_verify_harness.sh my_function
```

This creates a template `my_function_verify.c` that you can fill in.

### Examples to try

The directory contains these examples:

1. **coerce_reg_to_size_sx_verify.c** - Unary operation (single input)
2. **scalar_min_max_add_verify.c** - Binary operation (two inputs)

Use these as templates for your own functions!

## Common Use Cases

### Before submitting a patch

Verify your changes don't break correctness:

```bash
make <your_function>_verify
```

### When refactoring

Verify the refactored version is equivalent to the original:

```bash
# Test before refactoring
git stash
make my_function_verify   # Should pass

# Test after refactoring
git stash pop
make my_function_verify   # Should still pass
```

### Finding bugs

CBMC can find subtle bugs that are hard to catch with testing. If verification fails, you may have found a real bug!

## Performance Tips

Verification can be slow for complex functions. To speed things up:

1. **Add simplified constraints** (see examples in `*_verify.c` files)
2. **Test incrementally** - Verify small pieces first
3. **Use `_simple` targets** during development
4. **Be patient** - Initial runs take longer, but it's worth it!

## Troubleshooting

### "goto-cc: command not found"

CBMC isn't installed or not in PATH. See installation instructions above.

### Verification takes forever

1. Try the `_simple` target: `make my_function_simple`
2. Add more constraints in `#ifdef CBMC_SIMPLE_CONSTRAINTS`
3. Verify smaller pieces of the function

### "No rule to make target"

Make sure you're in the right directory:
```bash
pwd  # Should end in tools/verification/cbmc/bpf
```

## Getting Help

- **README.md** - Comprehensive documentation
- **Examples** - Look at existing `*_verify.c` files
- **Makefile** - See the template for adding new targets
- **CBMC docs** - https://www.cprover.org/cbmc/

## What's Next?

You now have a working CBMC setup! You can:

1. ✅ Verify existing BPF verifier functions
2. ✅ Create verification harnesses for new functions
3. ✅ Find and fix bugs using formal methods
4. ✅ Prove correctness properties about your code

Happy verifying! 🚀

---

**Pro tip:** Start small! Verify simple functions first, then work your way up to more complex ones. The skills you learn on simple functions will help you tackle the complex ones.
