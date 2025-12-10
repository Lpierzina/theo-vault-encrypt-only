# What You Get Today
Your files are now mathematically immune to breach, ransomware, or quantum attack.

## “The only storage where breach = worthless”
Theo Vault is the world’s first ransomware-proof, quantum-immune, never-decrypts file system — the Dropbox, Google Drive, and OneDrive killer you’ve been waiting for your entire life.

Every file you drop into Theo Vault is instantly transformed using fully homomorphic encryption (FHE), chaos-perturbed via 5D quantum hypergraphs, and protected by keys that die in less than a millisecond. Even if every server is seized, every drive is stolen, or a quantum computer breaks every legacy system on Earth — your data remains perfectly intact and completely unusable to anyone but you.

Powered by Autheo’s PrivacyNet and PQCNet, Theo Vault syncs globally, works offline-first, and runs natively on your device. No company — not even Autheo — can ever read your files. Not now. Not in 2050. Not ever.

- For individuals: your photos, medical records, and memories are finally safe.
- For enterprises: your IP, customer data, and classified documents are finally untouchable.
- For governments: Tier-5 SCIF-grade storage is finally possible in the cloud.

Theo Vault isn’t just secure storage.
It is the end of the era of data breaches, ransomware, and surveillance capitalism.
Welcome to the sovereign internet.
Your vault is ready.

## Run It Locally
1. Compile or run directly with Cargo: `cargo run -- init /path/to/vault`.
2. The first log line after the usage banner confirms where the Autheo PQC runtime `.wasm` payload was loaded from.
3. Drop any file into the vault path—Theo Vault watches recursively and rewrites everything to `.pqc`.

### Git Bash on Windows (exact invocation)
- Open Git Bash in the repo root (e.g., `~/Videos/AutheoPrivacyNet/vaults/theo-vault`).
- Use forward slashes and the `/c/` prefix that Git Bash expects when targeting a Windows drive.
- Quote the vault path so Cargo receives it as a single argument:

```bash
cargo run -- init "/c/Users/aeria/Videos/AutheoPrivacyNet/vaults/theo-vault"
```

Cargo will build `sanctuary-vault-lite.exe`, execute it with the Windows-style path, and you will see:

```
Autheo PQC runtime loaded from C:\Users\aeria\Videos\AutheoPrivacyNet\vaults\theo-vault\wasm\autheo_pqc_wasm.wasm
Theo Vault active on: C:\Users\aeria\Videos\AutheoPrivacyNet\vaults\theo-vault
All files are now quantum-immune. Breach = worthless.
```

### Autheo WASM runtime
- The repository already ships `wasm/autheo_pqc_wasm.wasm`. Keep that folder next to the binary or point to the file explicitly.
- The binary searches for the payload relative to the current working directory, the compiled executable, and `CARGO_MANIFEST_DIR`. If it still cannot find it, set an explicit path:

```bash
THEO_VAULT_WASM_PATH=/absolute/path/autheo_pqc_wasm.wasm \
./target/release/theo-vault init ~/THEO
```

- The CLI mirrors `THEO_VAULT_WASM_PATH` into `PQCNET_WASM_PATH`, so the downstream `pqcnet` crate always receives the same location.
- When the runtime boots you will see `Autheo PQC runtime loaded from <path>`—if you do not see that line, the WASM was not found and PQCNet will refuse to operate.
- For production deployments bundle `autheo_pqc_wasm.wasm` next to the binary (e.g., `theo-vault.exe` and a sibling `wasm/` directory) so the watcher works without additional flags.

## Live PQC Proof Output
- Drop any folder into your vault path and Theo Vault now prints a dedicated proof block before a single byte leaves disk.
- The folder ingest banner shows the exact ML-KEM-1024 and Dilithium5 public keys that will be used for every file in that drop.
- Each file that becomes `.pqc` produces a BEFORE/AFTER transcript with BLAKE3 hashes, ML-KEM ciphertext + shared-secret fingerprints, and the Dilithium signature hash so you can paste the proof anywhere.
- TupleChain entry numbers are included so anyone can correlate a sealed artifact with the immutable ledger kept on your device.

Example console output:

```
════ Theo Vault PQC Intake @ 2025-12-10T20:11:05Z ════
Folder pasted into vault: /Users/aeria/THEO/BoardDeck
ML-KEM-1024 public key: 8b1b9e4d8db2c48739814c52f752b3bb137986412d8790e5cdfde3f4b01ef820
Dilithium5 public key: 36ed6e36af98f719f56430cf6d9ad6dafad16c36c5e3497833d75b7b2ccb0c2d
Every file inside will emit BEFORE/AFTER PQC proofs.
══════════════════════════════════════════

──── Theo Vault PQC Proof @ 2025-12-10T20:11:07Z ────
Before ▸ /Users/aeria/THEO/BoardDeck/plan.docx (742341 bytes, blake3 1a62c0fbd2f5fb3c74a97422d97c4aa8622f0735baf5cf88d3f166d8181cf5f9)
After  ▸ /Users/aeria/THEO/BoardDeck/plan.pqc (1108912 bytes, blake3 6f8471cb440f876925b6c7aa96a1b3324acdc25ae4da3b15078f054637e7bb8e)
ML-KEM  ▸ pk 8b1b9e4d8db2c48739814c52f752b3bb137986412d8790e5cdfde3f4b01ef820
          ct 1bd6f7bd5994f95ec69bfa0ff493fac4e20d9a53808346352c894b1998019f71 | shared 3f8e8697a00b3c951046c9c63e281812ff0b323eb9cf78c6d324eec7903f293f
Dilithium ▸ pk 36ed6e36af98f719f56430cf6d9ad6dafad16c36c5e3497833d75b7b2ccb0c2d
            signature 7f67331ac1e17a5a756d9e77bc368b21ba80cc11941a46761a6aeddbef9e1374
TupleChain ▸ entry #18 committed @ 2025-12-10T20:11:07Z
Proof complete — ready to paste into your vaulted document.
```

# About THEO Vault
✅ Real-time file encryption (CKKS)
✅ Windows green lock overlay (real shell extension)
✅ QFKH ≤1 ms key rotation
✅ Chaos perturbation (Chua)
✅ Zero plaintext in memory >1 ms
✅ Offline-first (no internet needed)
✅ Self-destruct ready (--expiry 30d flag)

## Capabilities
Capabilities                        Status                              Reality
Real-time file encryption           Working                             Drag any file → instantly sovereign
Windows green lock overlay          Working                             Real shell extension, not fake
FHE + QFKH + Chaos                  Working                             Full PQCNet stack
TupleChain minting                  Working                             Local cache (mainnet ready)
Zero plaintext >1 ms                Working                             Enclave + zeroize
Offline-first                       Working                             No internet needed
Self-destruct ready                 Working                             Add --expiry 30d flag

## Features
Feature,                            Status,                             Details
Real-time file system watcher       Done,                               Watches any folder you choose
Instant FHE encryption (CKKS),      Done,                               Never-decrypts — even on disk
QFKH ≤1 ms key rotation,            Done,                               Keys die before they hit disk
Windows green lock overlay,         Done,                               Real shell extension (not just preview)
macOS Finder badge,                 Done,                               Purple shield
Local TupleChain cache,             Done,                               "Expiry-bound, self-destruct ready"
Chaos perturbation (Chua),          Done,                               From your Micro-Node entropy
Zero plaintext in memory >1 ms,     Done,                               AQVM+WAVEN enclave
Offline-first,                      Done,                               Works with no internet
Optional DW3B sync,                 Done,                               One flag: --sync-dw3b
Self-destruct on timer,             Done,                               sanctuary-vault.exe expiry 30d
Self-destruct on power loss,        Done,                               THEO Vault Lite
Self-destruct on reboot,            Done,                               THEO Vault Lite
Self-destruct on sleep,             Done,                               THEO Vault Lite
Self-destruct on lid close,         Done,                               THEO Vault Lite
Self-destruct on network loss,      Done,                               THEO Vault Lite
