import Lake
open Lake DSL

package «bpf-lean4» where
  version := v!"0.1.0"
  keywords := #["bpf", "verification", "proof-carrying-code"]
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «BPF» where
  -- add library configuration options here
