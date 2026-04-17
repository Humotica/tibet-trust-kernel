# tibet-trust-kernel

Zero-Trust DGX — Cross-machine AI memory virtualization. Run LLMs larger than your RAM by transparently mapping model blocks across servers via userfaultfd + encrypted RAID-0. No NVLink required.

## What it does

Maps AI model memory across multiple machines using the **DIME Aperture** pattern (inspired by 3dfx Voodoo AGP texture aperture). Blocks start as unmapped spaceholders, materialize on-demand via page faults, and stream over TCP with SHA-256 integrity + AES-256-GCM encryption.

```
Page fault → MUX fetch from RAM B → SHA-256 verify → uffd.copy() → block resident
2nd+ access → hash cache hit → SHA-256 skipped → 14x faster
```

## Hardware-tested performance

Tested with real Qwen 2.5 7B model (4.36GB) over P520 (64GB) ↔ DL360 (64GB) direct 10Gbps:

| Metric | Result |
|--------|--------|
| Ping RTT (10Gbps direct) | 0.17ms |
| Store to RAM B | 33 MB/s (sequential) |
| Restore + Verify | 112 MB/s |
| Hash cache hit rate | 100% |
| SHA-256 bytes saved | 2.4 GB |
| Block integrity | 2234/2234 verified |

Combined RAM: 128GB — a 70B Q4_K_M model (40GB) fits entirely.

## Quick start

```rust
// Cargo.toml
tibet-trust-kernel = { version = "1.0.0-alpha", features = ["llm"] }
```

```bash
# Server (DL360 — RAM B provider)
ram-raid-cluster-demo server 0.0.0.0:4432

# Client (P520 — runs inference)
ram-raid-cluster-demo client 10.0.100.1:4432

# LLM Mapper demo
llm-mapper-demo quick    # 48MB simulation
llm-mapper-demo 70b      # 40GB aperture map

# Real GGUF model test
gguf-raid-test /path/to/model.gguf 10.0.100.1:4432
```

## Features

```toml
tibet-trust-kernel = { version = "1.0", features = ["cluster"] }   # Cross-machine RAM
tibet-trust-kernel = { version = "1.0", features = ["llm"] }       # LLM Memory Mapper
tibet-trust-kernel = { version = "1.0", features = ["full"] }      # Everything
```

- `cluster` — Cross-machine RAM RAID-0 + ClusterMux transport
- `llm` — LLM Memory Mapper (DIME aperture), implies cluster
- `simulation` (default) — Simulated KVM for testing
- `kvm` — Real Ignition KVM isolation

## Modules

| Module | Description | Tests |
|--------|-------------|-------|
| `cluster_transport` | TCP-per-block transport, BlockStore | 9 |
| `cluster_mux` | Persistent MUX, streaming SHA-256, hash cache | 8 |
| `llm_mapper` | DIME Aperture, model manifests, prefetch | 11 |
| `ram_raid` | RAID-0 striping, batch restore, uffd | - |
| `bifurcation` | AES-256-GCM seal/open, X25519 key exchange | 5 |

## Key concepts

- **DIME Aperture**: Virtual address space where all model blocks exist as spaceholders. On first access, the block materializes from the remote machine. Like a 3dfx Voodoo AGP texture aperture, but for AI model weights.

- **Hash Cache**: After first SHA-256 verification, the hash is cached. Subsequent loads skip SHA-256 entirely — 14x speedup on repeat access. Store pre-warms the cache (zero misses ever).

- **RAID-0 Striping**: Even blocks stay local (RAM A), odd blocks go remote (RAM B). Combined RAM of both machines available for model loading.

- **Prefetch**: During inference, while processing layer N, layers N+1..N+4 are prefetched in the background. 21/24 layers hit prefetch cache.

## Part of TIBET

tibet-trust-kernel is part of the [TIBET ecosystem](https://pypi.org/project/tibet/) — Traceable Intent-Based Event Tokens. Built by [Humotica](https://humotica.com) for the [AInternet](https://ainternet.org).

## License

MIT
