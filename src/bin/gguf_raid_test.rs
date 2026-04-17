// ═══════════════════════════════════════════════════════════════
// GGUF RAID Test — Real Model File Over Cross-Machine RAID-0
//
// Loads an actual GGUF model file (e.g. Qwen 7B, 4.4GB) into
// the RAM RAID-0 pipeline:
//   1. Read GGUF in 2MB blocks
//   2. Odd blocks → RAM B (DL360) via ClusterMux
//   3. Read all blocks back, verify SHA-256
//
// Usage:
//   gguf-raid-test <gguf-path> <mux-endpoint>
//   gguf-raid-test /path/to/model.gguf 10.0.100.1:4432
// ═══════════════════════════════════════════════════════════════

use tibet_trust_kernel::cluster_mux::*;
use tibet_trust_kernel::cluster_transport::{BlockStore, sha256_hex};
use tibet_trust_kernel::ram_raid::RAID_BLOCK_SIZE;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::io::Read;

const BLOCK_SIZE: usize = RAID_BLOCK_SIZE; // 2MB

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: gguf-raid-test <gguf-path> <mux-endpoint>");
        eprintln!("  e.g. gguf-raid-test /path/to/qwen7b.gguf 10.0.100.1:4432");
        std::process::exit(1);
    }
    let gguf_path = &args[1];
    let endpoint = &args[2];

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  GGUF RAID Test — Real Model Over Cross-Machine RAID-0  ║");
    println!("║  P520 (RAM A) ↔ DL360 (RAM B) via 10Gbps Direct Link   ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    // ─── Read GGUF file ───
    let file_size = std::fs::metadata(gguf_path)
        .unwrap_or_else(|e| { eprintln!("Cannot read {}: {}", gguf_path, e); std::process::exit(1); })
        .len() as usize;
    let num_blocks = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    let local_blocks = (num_blocks + 1) / 2;  // even indices
    let remote_blocks = num_blocks / 2;        // odd indices

    println!("  File:    {}", gguf_path);
    println!("  Size:    {:.2} GB ({} bytes)", file_size as f64 / (1024.0 * 1024.0 * 1024.0), file_size);
    println!("  Blocks:  {} × 2MB", num_blocks);
    println!("  Local:   {} blocks ({:.2} GB) → RAM A (P520)", local_blocks, local_blocks as f64 * 2.0 / 1024.0);
    println!("  Remote:  {} blocks ({:.2} GB) → RAM B (DL360)", remote_blocks, remote_blocks as f64 * 2.0 / 1024.0);
    println!("  Endpoint: {}", endpoint);
    println!();

    // ─── Connect to RAM B ───
    let client = Arc::new(ClusterMuxClient::new(endpoint, "p520.aint"));
    let rtt = client.ping().await.unwrap();
    println!("  RAM B RTT: {}µs", rtt);
    println!();

    // ─── Phase 1: Read file and store blocks ───
    println!("═══ Phase 1: Loading GGUF into RAID-0 ═══\n");

    let mut file = std::fs::File::open(gguf_path).unwrap();
    let mut block_hashes: Vec<String> = Vec::with_capacity(num_blocks);
    let mut local_store: Vec<Vec<u8>> = Vec::new(); // Local blocks (even)
    let t0 = Instant::now();
    let mut bytes_to_remote = 0u64;
    let mut blocks_sent = 0u32;

    for block_idx in 0..num_blocks {
        let mut buf = vec![0u8; BLOCK_SIZE];
        let bytes_read = file.read(&mut buf).unwrap();
        buf.truncate(bytes_read);

        let hash = sha256_hex(&buf);
        block_hashes.push(hash.clone());

        if block_idx % 2 == 0 {
            // Even → local (RAM A)
            local_store.push(buf);
        } else {
            // Odd → remote (RAM B) via MUX
            client.store_block(
                block_idx,
                &buf,
                &hash,
                "gguf-raid-test",
                bytes_read,
                block_idx as u64,
            ).await.unwrap();
            bytes_to_remote += bytes_read as u64;
            blocks_sent += 1;
        }

        // Progress every 100 blocks
        if (block_idx + 1) % 100 == 0 || block_idx == num_blocks - 1 {
            let elapsed = t0.elapsed().as_millis();
            let pct = (block_idx + 1) as f64 / num_blocks as f64 * 100.0;
            let throughput = bytes_to_remote as f64 / 1_000_000.0 / (elapsed as f64 / 1000.0).max(0.001);
            print!("\r  [{:>5.1}%] Block {}/{}, {} sent to RAM B ({:.0} MB/s)    ",
                pct, block_idx + 1, num_blocks, blocks_sent, throughput);
        }
    }
    let store_time = t0.elapsed();
    println!("\n");
    println!("  Store complete: {:.2}s", store_time.as_secs_f64());
    println!("  Sent to RAM B: {:.2} GB ({} blocks)", bytes_to_remote as f64 / (1024.0 * 1024.0 * 1024.0), blocks_sent);
    println!("  Throughput:     {:.0} MB/s", bytes_to_remote as f64 / 1_000_000.0 / store_time.as_secs_f64().max(0.001));
    println!();

    // ─── Phase 2: Read all blocks back, verify SHA-256 ───
    println!("═══ Phase 2: Restore + Verify (all blocks) ═══\n");

    let t1 = Instant::now();
    let mut verify_ok = 0u32;
    let mut verify_fail = 0u32;
    let mut bytes_from_remote = 0u64;
    let mut local_idx = 0usize;

    for block_idx in 0..num_blocks {
        let data = if block_idx % 2 == 0 {
            // Even → local
            let d = local_store[local_idx].clone();
            local_idx += 1;
            d
        } else {
            // Odd → fetch from RAM B
            let (d, _us) = client.fetch_block(block_idx, Some(&block_hashes[block_idx]), block_idx as u64).await.unwrap();
            bytes_from_remote += d.len() as u64;
            d
        };

        let hash = sha256_hex(&data);
        if hash == block_hashes[block_idx] {
            verify_ok += 1;
        } else {
            verify_fail += 1;
            eprintln!("  FAIL block {}: expected {} got {}", block_idx, &block_hashes[block_idx][..16], &hash[..16]);
        }

        if (block_idx + 1) % 100 == 0 || block_idx == num_blocks - 1 {
            let pct = (block_idx + 1) as f64 / num_blocks as f64 * 100.0;
            print!("\r  [{:>5.1}%] Verified {}/{}, {} OK    ", pct, block_idx + 1, num_blocks, verify_ok);
        }
    }
    let verify_time = t1.elapsed();
    println!("\n");

    // ─── Phase 3: Repeat fetch (hash cache test) ───
    println!("═══ Phase 3: Cached Re-fetch (hash cache speedup) ═══\n");

    let t2 = Instant::now();
    let mut cached_ok = 0u32;
    // Only re-fetch remote blocks (odd indices), first 50 or all if less
    let refetch_count = remote_blocks.min(50);
    for i in 0..refetch_count {
        let block_idx = (i * 2 + 1) as u32; // odd indices
        let (data, _us) = client.fetch_block(block_idx as usize, Some(&block_hashes[block_idx as usize]), block_idx as u64).await.unwrap();
        let hash = sha256_hex(&data);
        if hash == block_hashes[block_idx as usize] {
            cached_ok += 1;
        }
    }
    let cache_time = t2.elapsed();

    // ─── Results ───
    let (hits, misses, ratio, saved) = client.hash_cache.stats();

    println!("  Re-fetched {} blocks in {:.2}s", refetch_count, cache_time.as_secs_f64());
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  GGUF RAID-0 Test Results                               ║");
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║  Model:       {:>42} ║", gguf_path.split('/').last().unwrap_or(gguf_path));
    println!("║  Size:        {:>38.2} GB ║", file_size as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("║  Blocks:      {:>38} × 2MB ║", num_blocks);
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║  STORE                                                  ║");
    println!("║    Time:      {:>38.2}s ║", store_time.as_secs_f64());
    println!("║    To RAM B:  {:>34.2} GB ║", bytes_to_remote as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("║    Throughput:{:>35.0} MB/s ║", bytes_to_remote as f64 / 1_000_000.0 / store_time.as_secs_f64().max(0.001));
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║  VERIFY                                                 ║");
    println!("║    Time:      {:>38.2}s ║", verify_time.as_secs_f64());
    println!("║    From RAM B:{:>34.2} GB ║", bytes_from_remote as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("║    Throughput:{:>35.0} MB/s ║", bytes_from_remote as f64 / 1_000_000.0 / verify_time.as_secs_f64().max(0.001));
    println!("║    OK:        {:>38} ║", verify_ok);
    println!("║    FAIL:      {:>38} ║", verify_fail);
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║  HASH CACHE                                             ║");
    println!("║    Hits:      {:>38} ║", hits);
    println!("║    Misses:    {:>38} ║", misses);
    println!("║    Ratio:     {:>37.0}% ║", ratio * 100.0);
    println!("║    SHA-256 saved: {:>30.1} MB ║", saved as f64 / 1_000_000.0);
    println!("╠═══════════════════════════════════════════════════════════╣");
    if verify_fail == 0 {
        println!("║  RESULT: ALL {} BLOCKS VERIFIED ✓{:>21} ║", num_blocks, "");
    } else {
        println!("║  RESULT: {} FAILURES — DATA CORRUPTION{:>16} ║", verify_fail, "");
    }
    println!("╚═══════════════════════════════════════════════════════════╝");
}
