# ckb-cobuild-testvector

This repo helps generate testvector for CKB cobuild protocols.

```
$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.02s
     Running `target/debug/ckb-cobuild-testvector`
Seed: 1703206565541293524
Sighash all example written to sighash_all1.data as BuildingPacket
  signing message hash: 0x909b4ef94116b26e43e89eea1fbc5ccd21fd717903f908b7511ab3e35a619d54
  Message is kept in witness #0
Sighash all example written to sighash_all2.data as BuildingPacket
  signing message hash: 0xb9f238446eac60b18cda23050b7430aa0a974b44c3f0ffe44f52bede2089fdfd
  Message is kept in witness #0
Sighash all only example(i.e., tx without Message) written to sighash_all_only1.data as BuildingPacket
  signing message hash: 0x1422f11f433b1326a39fa1df8d467739c3f6ad4828ae5ae8a568bc8cf22b6716
Otx example written to otx1.data as BuildingPacket
  signing message hash: 0xedc2e5cc2b92840c8408c69ca1fc065c05a5d9381e9ff1e5ed7bcfa8b778bb70
Otx example written to otx2.data as BuildingPacket
  signing message hash: 0x1c7bc125511918c440dad4083028f49253f90d7b02c4c5ce636869412ecf83bd
```

The `SEED` environment variable can be used for deterministic generation:

```
$ SEED=3 cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/ckb-cobuild-testvector`
Seed: 3
Sighash all example written to sighash_all1.data as BuildingPacket
  signing message hash: 0x7d7aed24acb6c226a692b708659920fefce1cd834edaaa8a84d556dc1ed68ee4
  Message is kept in witness #0
Sighash all example written to sighash_all2.data as BuildingPacket
  signing message hash: 0x0d468090afd1bfdfbf2d0b1ae820325c051f8c727ba32acea5b71a448446dbe7
  Message is kept in witness #0
Sighash all only example(i.e., tx without Message) written to sighash_all_only1.data as BuildingPacket
  signing message hash: 0x992a888fbf78dd3a1c2858252470bf3e6fe80e2b6beec0043c45c41ba8957b14
Otx example written to otx1.data as BuildingPacket
  signing message hash: 0x5fc915b0291e8916c28c46e2d48a4c7787117212f9e0fc674297b2795d866954
Otx example written to otx2.data as BuildingPacket
  signing message hash: 0x9279baf5fa1d5b9204e64d250762f4b54153aa71ad9ce2957a9476e9380c7e6b
```

One can also tweak the main function to generate different test cases.
