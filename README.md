# ckb-cobuild-testvector

This repo helps generate testvector for CKB cobuild protocols.

```
$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/ckb-cobuild-testvector`
Seed: 1702964543625138242
Sighash all example written to sighash_all1.data
  skeleton hash: 0x32efd92df0a62a1209ab39782b18ed47492bee86afc1c64fad2a5a40e8bb7cd2
  signing message hash: 0xa23bd632fd1352822e4be89509e149f723da63be24c9bb10d40a016cd6703650
  Message is kept in witness #0
Otx example written to otx1.data
  skeleton hash: 0x067ba0f8ae7bc23460c2793c4a280f3864fa1958ee147f89bbfacb6f9c3e53d1
  signing message hash: 0x1c6030f40d10ed85781ecf8060ad64a8bc0764305e94c985f4c473ec37e979c1
  Message is kept in witness #0
Otx example written to otx2.data
  skeleton hash: 0x8323277fd8a1ef4916636582145a79c13a3282b26cf8f419bb0456d88d85988a
  signing message hash: 0xab9be11126e57dd99ad132aaa2a2b5d54586547066ad1865a3c7525bfae66300
  Message is kept in witness #0
```

The `SEED` environment variable can be used for deterministic generation:

```
$ SEED=3 cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.02s
     Running `target/debug/ckb-cobuild-testvector`
Seed: 3
Sighash all example written to sighash_all1.data
  skeleton hash: 0xd1220ae957b7d4aef33b394eb92538bbf5eec0f762ae44567aed94c8e9de1706
  signing message hash: 0xda4480089eff52313fe7681a0c8bc51a62a31c1494d74279a498e39acff992bb
  Message is kept in witness #0
Otx example written to otx1.data
  skeleton hash: 0x2f55feac43c959a55444af95249d6e805fae6d88c9fe743d8d1ac927aee42299
  signing message hash: 0x4f5d66976bb4d5c13eb5a380ddfafab41995bdaca85e2963b2c8e137f784f949
  Message is kept in witness #0
Otx example written to otx2.data
  skeleton hash: 0xbbfb3c1dd6cd589b3a0b94788ec4b539b7a56977694036caded53c380c3c1a06
  signing message hash: 0xc9b3a0229f1d53f954b19d723b32b5d0f7b0fb92754cb33f88cf11bf3e8ca945
  Message is kept in witness #0
```

One can also tweak the main function to generate different test cases.
