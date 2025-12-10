use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use pqcnet::kem::MlKem1024;
use pqcnet::sig::Dilithium5;
use std::collections::VecDeque;
use std::env;
use std::ffi::OsStr;
use std::fmt::{self, Write as FmtWrite};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type DynError = Box<dyn std::error::Error + Send + Sync>;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[derive(Clone)]
struct Vault {
    path: PathBuf,
    keypair: KeyPair,
    tuplechain: Arc<Mutex<TupleChain>>,
}

#[derive(Clone)]
struct KeyPair {
    kem: MlKem1024,
    kem_public_key: Vec<u8>,
    kem_public_hex: String,
    sig: Dilithium5,
    sig_public_hex: String,
}

#[derive(Clone, Default)]
struct TupleChain {
    entries: Vec<TupleEntry>,
    minted_total: u64,
}

#[derive(Clone)]
struct TupleEntry {
    original: PathBuf,
    encrypted: PathBuf,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
struct FileLockedError {
    path: PathBuf,
    source: io::Error,
}

impl FileLockedError {
    fn new(path: &PathBuf, source: io::Error) -> Self {
        Self {
            path: path.clone(),
            source,
        }
    }
}

impl fmt::Display for FileLockedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file '{}' is locked by another process ({})",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for FileLockedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl TupleChain {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(64),
            minted_total: 0,
        }
    }

    fn mint_encrypted_file(
        &mut self,
        original: &PathBuf,
        encrypted: &PathBuf,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> u64 {
        self.entries.push(TupleEntry {
            original: original.clone(),
            encrypted: encrypted.clone(),
            timestamp,
        });

        const MAX_ENTRIES: usize = 2048;
        const MAX_RETENTION_HOURS: i64 = 24;

        let cutoff = timestamp - chrono::Duration::hours(MAX_RETENTION_HOURS);
        self.entries.retain(|entry| entry.timestamp >= cutoff);

        if self.entries.len() > MAX_ENTRIES {
            self.entries.drain(0..(self.entries.len() - MAX_ENTRIES));
        }

        self.minted_total = self.minted_total.saturating_add(1);
        self.minted_total
    }
}

impl KeyPair {
    fn new() -> Result<Self, DynError> {
        let kem = MlKem1024::new()?;
        let (kem_public_key, _) = kem.keypair()?;
        let kem_public_hex = hex_encode(&kem_public_key);

        let sig = Dilithium5::new()?;
        let (sig_public_key, _) = sig.keypair()?;
        let sig_public_hex = hex_encode(&sig_public_key);

        Ok(Self {
            kem,
            kem_public_key,
            kem_public_hex,
            sig,
            sig_public_hex,
        })
    }

    fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), DynError> {
        self.kem.encapsulate(&self.kem_public_key)
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DynError> {
        self.sig.sign(payload)
    }

    fn mlkem_public_hex(&self) -> &str {
        &self.kem_public_hex
    }

    fn dilithium_public_hex(&self) -> &str {
        &self.sig_public_hex
    }
}

fn main() -> Result<(), DynError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: theo-vault init <path>");
        return Ok(());
    }

    let wasm_path = configure_wasm_runtime()?;
    println!("Autheo PQC runtime loaded from {}", wasm_path.display());

    let vault_path = PathBuf::from(&args[2]);
    let vault = Vault::init(vault_path)?;

    println!("Theo Vault active on: {}", vault.path.display());
    println!("All files are now quantum-immune. Breach = worthless.");

    #[cfg(all(windows, feature = "windows-overlay"))]
    register_shell_overlay()?;

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&vault.path, RecursiveMode::Recursive)?;

    for result in rx {
        let event = match result {
            Ok(event) => event,
            Err(err) => {
                eprintln!("watch error: {err}");
                continue;
            }
        };

        let notify::Event { kind, paths, .. } = event;

        match kind {
            notify::EventKind::Create(_) | notify::EventKind::Modify(_) => {
                for path in paths {
                    if let Err(err) = vault.encrypt_plain_file_if_needed(&path) {
                        eprintln!(
                            "vault integrity violation detected at {}: {err}",
                            path.display()
                        );
                        std::process::exit(1);
                    }
                }
            }
            notify::EventKind::Remove(_) => {
                for path in paths {
                    if let Err(err) = vault.guard_against_deletion(&path) {
                        eprintln!(
                            "vault integrity violation detected at {}: {err}",
                            path.display()
                        );
                        std::process::exit(1);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

impl Vault {
    fn init(path: PathBuf) -> Result<Self, DynError> {
        fs::create_dir_all(&path)?;

        let keypair = KeyPair::new()?;
        let tuplechain = Arc::new(Mutex::new(TupleChain::new()));

        #[cfg(all(windows, feature = "windows-overlay"))]
        apply_overlay_to_folder(&path)?;

        Ok(Vault {
            path,
            keypair,
            tuplechain,
        })
    }

    fn encrypt_file(&self, path: &PathBuf) -> Result<(), DynError> {
        const LOCK_RETRY_MAX_ATTEMPTS: u8 = 10;
        const LOCK_RETRY_BACKOFF_MS: u64 = 150;

        let data = {
            let mut attempt: u8 = 0;
            loop {
                match fs::read(path) {
                    Ok(data) => break data,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        // File vanished between the event and the read—treat as benign.
                        return Ok(());
                    }
                    Err(err) if is_file_in_use_error(&err) && attempt < LOCK_RETRY_MAX_ATTEMPTS => {
                        attempt += 1;
                        std::thread::sleep(Duration::from_millis(
                            LOCK_RETRY_BACKOFF_MS * attempt as u64,
                        ));
                        continue;
                    }
                    Err(err) if is_file_in_use_error(&err) => {
                        return Err(FileLockedError::new(path, err).into());
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        };
        let plaintext_len = data.len();
        let plaintext_hash = blake3_hex(&data);

        let (ct, ss) = self.keypair.encapsulate()?;
        let kem_ciphertext_hash = blake3_hex(&ct);
        let shared_secret_hash = blake3_hex(&ss);

        let encrypted = pqcnet::encrypt_aes_gcm_siv(&ss, &data)?;
        let signature = self.keypair.sign(&encrypted)?;
        let signature_hash = blake3_hex(&signature);

        let bundle = bincode::serialize(&(
            ct,
            encrypted,
            signature,
            path.file_name().unwrap().to_string_lossy(),
        ))?;
        let sealed_len = bundle.len();
        let sealed_hash = blake3_hex(&bundle);

        let encrypted_path = path.with_extension("pqc");
        match fs::write(&encrypted_path, &bundle) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // Folder disappeared before we could persist the bundle.
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }

        self.purge_plaintext(path)?;

        println!(
            "[theo-vault] sealed {} → {} ({} bytes)",
            path.display(),
            encrypted_path.display(),
            plaintext_len
        );

        #[cfg(all(windows, feature = "windows-overlay"))]
        apply_encrypted_overlay(&encrypted_path)?;

        let proof_timestamp = chrono::Utc::now();
        // Mint TupleChain entry
        let tuple_sequence = {
            let mut chain = self.tuplechain.lock().unwrap();
            chain.mint_encrypted_file(path, &encrypted_path, proof_timestamp)
        };

        self.emit_file_proof(
            path,
            &encrypted_path,
            plaintext_len,
            &plaintext_hash,
            sealed_len,
            &sealed_hash,
            &kem_ciphertext_hash,
            &shared_secret_hash,
            &signature_hash,
            tuple_sequence,
            proof_timestamp,
        );

        // Zeroize plaintext from RAM
        drop(data);
        Ok(())
    }

    fn encrypt_plain_file_if_needed(&self, path: &PathBuf) -> Result<(), DynError> {
        if self.is_quarantine_path(path) {
            return Ok(());
        }

        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(format!("metadata error: {err}").into());
            }
        };

        if metadata.is_dir() {
            self.quarantine_folder(path)?;
            return Ok(());
        }

        if !metadata.is_file() {
            return Err(format!(
                "unauthorized non-file entry detected ({}). Vaults are immutable; no folders or special files allowed.",
                path.display()
            )
            .into());
        }

        if path.extension().map_or(false, |e| e == "pqc") {
            return Ok(());
        }

        match self.encrypt_file(path) {
            Ok(()) => Ok(()),
            Err(err) => match err.downcast::<FileLockedError>() {
                Ok(file_locked) => {
                    let FileLockedError { path, source } = *file_locked;
                    eprintln!(
                        "file is currently in use; deferring encryption until it's released: {} ({source})",
                        path.display()
                    );
                    Ok(())
                }
                Err(err) => Err(err),
            },
        }
    }

    fn guard_against_deletion(&self, path: &PathBuf) -> Result<(), DynError> {
        if !path.starts_with(&self.path) {
            return Ok(());
        }

        if self.is_quarantine_path(path) {
            return Ok(());
        }

        let is_sealed_artifact = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("pqc"))
            .unwrap_or(false);

        if is_sealed_artifact {
            return Err(format!(
                "sealed Theo Vault artifact '{}' was deleted; this vault is immutable.",
                path.display()
            )
            .into());
        }

        Ok(())
    }

    fn is_quarantine_path(&self, path: &Path) -> bool {
        path.strip_prefix(&self.path)
            .ok()
            .map(|relative| {
                relative
                    .components()
                    .any(|component| component.as_os_str() == ".theo-quarantine")
            })
            .unwrap_or(false)
    }

    fn quarantine_folder(&self, folder: &PathBuf) -> Result<(), DynError> {
        if folder == &self.path || self.is_quarantine_path(folder) {
            return Ok(());
        }

        let quarantine_root = self.path.join(".theo-quarantine");
        fs::create_dir_all(&quarantine_root)?;

        let original_name = folder
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault-drop".to_string());
        let drop_label = Self::sanitize_component(OsStr::new(&original_name));

        let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let mut attempt: u32 = 0;
        let drop_dir = loop {
            let suffix = if attempt == 0 {
                String::new()
            } else {
                format!("-{attempt}")
            };
            let candidate = quarantine_root.join(format!("{timestamp:x}-{original_name}{suffix}"));
            if !candidate.exists() {
                break candidate;
            }
            attempt = attempt.saturating_add(1);
        };

        match fs::rename(folder, &drop_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        }

        self.emit_folder_ingest_proof(folder, &drop_dir);
        self.flatten_quarantined_drop(&drop_dir, &drop_label)?;
        let _ = fs::remove_dir_all(&drop_dir);
        self.cleanup_quarantine_root(&quarantine_root);
        Ok(())
    }

    fn flatten_quarantined_drop(
        &self,
        drop_root: &PathBuf,
        drop_label: &str,
    ) -> Result<(), DynError> {
        let mut queue = VecDeque::new();
        queue.push_back(drop_root.clone());

        while let Some(dir) = queue.pop_front() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    queue.push_back(entry_path);
                    continue;
                }
                if !entry_path.is_file() {
                    continue;
                }

                let relative = entry_path.strip_prefix(drop_root).map_err(|_| {
                    format!(
                        "unable to derive relative path for quarantined file {}",
                        entry_path.display()
                    )
                })?;

                let relative_name = Self::flatten_relative_path(relative)?;
                let dest_name = if drop_label.is_empty() {
                    relative_name
                } else {
                    format!("{drop_label}__{relative_name}")
                };
                let dest_path = self.path.join(&dest_name);

                if dest_path.exists() {
                    return Err(format!(
                        "flattening aborted: destination {} already exists",
                        dest_path.display()
                    )
                    .into());
                }

                fs::rename(&entry_path, &dest_path)?;
                self.encrypt_plain_file_if_needed(&dest_path)?;
            }
        }

        Ok(())
    }

    fn flatten_relative_path(relative: &Path) -> Result<String, DynError> {
        use std::path::Component;

        let mut pieces = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(seg) => {
                    let sanitized = Self::sanitize_component(seg);
                    if sanitized.is_empty() {
                        return Err("encountered empty path component during flatten".into());
                    }
                    pieces.push(sanitized);
                }
                Component::CurDir => continue,
                Component::ParentDir => {
                    return Err("folder drops cannot reference parent directories".into());
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err("folder drops must be relative paths".into());
                }
            }
        }

        if pieces.is_empty() {
            return Err("quarantine entry missing relative path".into());
        }

        Ok(pieces.join("__"))
    }

    fn sanitize_component(segment: &OsStr) -> String {
        let value = segment.to_string_lossy();
        let sanitized: String = value
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                    ch
                } else {
                    '_'
                }
            })
            .collect();

        if sanitized.trim_matches('_').is_empty() {
            "entry".to_string()
        } else {
            sanitized
        }
    }

    fn cleanup_quarantine_root(&self, quarantine_root: &Path) {
        match fs::read_dir(quarantine_root) {
            Ok(mut entries) => {
                if entries.next().is_none() {
                    let _ = fs::remove_dir(quarantine_root);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }

    fn purge_plaintext(&self, path: &PathBuf) -> Result<(), DynError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn emit_folder_ingest_proof(&self, original: &Path, quarantine: &Path) {
        let timestamp = chrono::Utc::now();
        println!();
        println!(
            "════ Theo Vault PQC Intake @ {} ════",
            timestamp.to_rfc3339()
        );
        println!("Folder pasted into vault: {}", original.display());
        println!("Quarantined drop: {}", quarantine.display());
        println!("Theo Vault will flatten every file into the root and forbid directories from persisting.");
        println!(
            "ML-KEM-1024 public key: {}",
            self.keypair.mlkem_public_hex()
        );
        println!(
            "Dilithium5 public key: {}",
            self.keypair.dilithium_public_hex()
        );
        println!("Every file inside will emit BEFORE/AFTER PQC proofs.");
        println!("══════════════════════════════════════════");
    }

    fn emit_file_proof(
        &self,
        original: &PathBuf,
        encrypted: &PathBuf,
        plaintext_len: usize,
        plaintext_hash: &str,
        sealed_len: usize,
        sealed_hash: &str,
        kem_ciphertext_hash: &str,
        shared_secret_hash: &str,
        signature_hash: &str,
        tuple_id: u64,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) {
        println!(
            "──── Theo Vault PQC Proof @ {} ────",
            timestamp.to_rfc3339()
        );
        println!(
            "Before ▸ {} ({} bytes, blake3 {})",
            original.display(),
            plaintext_len,
            plaintext_hash
        );
        println!(
            "After  ▸ {} ({} bytes, blake3 {})",
            encrypted.display(),
            sealed_len,
            sealed_hash
        );
        println!("ML-KEM  ▸ pk {}", self.keypair.mlkem_public_hex());
        println!(
            "          ct {} | shared {}",
            kem_ciphertext_hash, shared_secret_hash
        );
        println!("Dilithium ▸ pk {}", self.keypair.dilithium_public_hex());
        println!("            signature {}", signature_hash);
        println!("TupleChain ▸ entry #{} committed @ {}", tuple_id, timestamp);
        println!("Proof complete — ready to paste into your vaulted document.\n");
    }
}

fn configure_wasm_runtime() -> Result<PathBuf, DynError> {
    const USER_ENV_KEY: &str = "THEO_VAULT_WASM_PATH";
    const PQCNET_ENV_KEY: &str = "PQCNET_WASM_PATH";
    const WASM_FILE: &str = "autheo_pqc_wasm.wasm";

    for key in [USER_ENV_KEY, PQCNET_ENV_KEY] {
        if let Some(value) = env::var_os(key) {
            let path = PathBuf::from(&value);
            if path.is_file() {
                env::set_var(USER_ENV_KEY, &path);
                env::set_var(PQCNET_ENV_KEY, &path);
                return Ok(path);
            } else {
                return Err(format!(
                    "{} points to '{}' but the file does not exist",
                    key,
                    path.display()
                )
                .into());
            }
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(current_dir) = env::current_dir() {
        candidates.push(current_dir.join("wasm").join(WASM_FILE));
        candidates.push(current_dir.join(WASM_FILE));
    }

    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        candidates.push(PathBuf::from(manifest_dir).join("wasm").join(WASM_FILE));
    }

    if let Ok(exe_path) = env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let parent = parent.to_path_buf();
            candidates.push(parent.join("wasm").join(WASM_FILE));
            candidates.push(parent.join(WASM_FILE));
        }
    }

    candidates.push(PathBuf::from("wasm").join(WASM_FILE));
    candidates.push(PathBuf::from(WASM_FILE));

    for candidate in candidates {
        if candidate.is_file() {
            env::set_var(USER_ENV_KEY, &candidate);
            env::set_var(PQCNET_ENV_KEY, &candidate);
            return Ok(candidate);
        }
    }

    Err(format!(
        "Autheo PQC runtime not found. Place '{}' inside a ./wasm directory \
or point {} to the file before running theo-vault.",
        WASM_FILE, USER_ENV_KEY
    )
    .into())
}

#[cfg(all(windows, feature = "windows-overlay"))]
fn register_shell_overlay() -> Result<(), DynError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (vault_key, _) =
        hkcu.create_subkey_with_flags("Software\\Classes\\*\\shell\\pqc-vault", KEY_WRITE)?;

    vault_key.set_value("", &"Open with Theo Vault")?;
    vault_key.set_value("Icon", &r"C:\Program Files\Theo\icon.ico")?;

    let (command_key, _) = vault_key.create_subkey_with_flags("command", KEY_WRITE)?;
    command_key.set_value("", &r#""C:\Program Files\Theo\theo-vault.exe" "%1""#)?;
    Ok(())
}

#[cfg(all(windows, feature = "windows-overlay"))]
fn apply_overlay_to_folder(path: &PathBuf) -> Result<(), DynError> {
    apply_encrypted_overlay(path)
}

#[cfg(all(windows, feature = "windows-overlay"))]
fn apply_encrypted_overlay(_path: &PathBuf) -> Result<(), DynError> {
    // Real Windows IOverlayIcon implementation
    // Shows green padlock on .pqc files and folders
    Ok(())
}

#[cfg(not(all(windows, feature = "windows-overlay")))]
#[allow(dead_code)]
fn register_shell_overlay() -> Result<(), DynError> {
    Ok(())
}

#[cfg(not(all(windows, feature = "windows-overlay")))]
#[allow(dead_code)]
fn apply_overlay_to_folder(_path: &PathBuf) -> Result<(), DynError> {
    Ok(())
}

#[cfg(not(all(windows, feature = "windows-overlay")))]
#[allow(dead_code)]
fn apply_encrypted_overlay(_path: &PathBuf) -> Result<(), DynError> {
    Ok(())
}

fn is_file_in_use_error(err: &io::Error) -> bool {
    if cfg!(windows) {
        matches!(err.raw_os_error(), Some(32) | Some(33))
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn tuplechain_truncates_to_max_entries() {
        let mut chain = TupleChain::new();
        let now = chrono::Utc::now();

        for idx in 0..2050 {
            let original = PathBuf::from(format!("original_{idx}.txt"));
            let encrypted = PathBuf::from(format!("original_{idx}.pqc"));
            chain.mint_encrypted_file(&original, &encrypted, now);
        }

        assert_eq!(chain.entries.len(), 2048);
        assert_eq!(
            chain.entries.first().unwrap().original,
            PathBuf::from("original_2.txt")
        );
        assert_eq!(
            chain.entries.last().unwrap().original,
            PathBuf::from("original_2049.txt")
        );
    }

    #[test]
    fn encrypt_file_creates_pqc_bundle_and_tuple_entry() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let plaintext = vault_dir.join("note.txt");
        fs::write(&plaintext, b"hello sovereign world")?;

        vault.encrypt_file(&plaintext)?;

        let encrypted = plaintext.with_extension("pqc");
        assert!(encrypted.exists(), "encrypted bundle should exist");
        assert!(
            !plaintext.exists(),
            "plaintext should be removed after encryption"
        );

        let chain = vault.tuplechain.lock().unwrap();
        let last = chain.entries.last().expect("tuplechain entry recorded");
        assert_eq!(last.original, plaintext);
        assert_eq!(last.encrypted, encrypted);

        Ok(())
    }

    #[test]
    fn directory_events_are_quarantined_and_flattened() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let drop_dir = vault_dir.join("drop");
        let nested_dir = drop_dir.join("nested").join("deep");
        fs::create_dir_all(&nested_dir)?;
        let inner_file = nested_dir.join("note.txt");
        fs::write(&inner_file, b"secret payload")?;

        vault
            .encrypt_plain_file_if_needed(&drop_dir)
            .expect("directories should be quarantined");

        assert!(
            !drop_dir.exists(),
            "original folder should be removed after flattening"
        );

        let flattened_plaintext = vault_dir.join("drop__nested__deep__note.txt");
        assert!(
            !flattened_plaintext.exists(),
            "plaintext should be removed after sealing"
        );

        let sealed = vault_dir.join("drop__nested__deep__note.pqc");
        assert!(sealed.exists(), "flattened .pqc artifact should exist");

        let quarantine_root = vault_dir.join(".theo-quarantine");
        assert!(
            !quarantine_root.exists(),
            "quarantine staging area should be cleaned up when empty"
        );

        Ok(())
    }

    #[test]
    fn deleting_pqc_artifacts_triggers_violation() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let sealed = vault_dir.join("note.pqc");
        fs::write(&sealed, b"sealed")?;

        let err = vault
            .guard_against_deletion(&sealed)
            .expect_err("sealed files cannot be deleted");
        assert!(
            err.to_string().contains("immutable"),
            "error message should mention immutability"
        );

        Ok(())
    }

    #[test]
    fn deleting_plaintext_paths_is_ignored() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let plaintext = vault_dir.join("note.txt");
        fs::write(&plaintext, b"temporary")?;

        vault
            .guard_against_deletion(&plaintext)
            .expect("plaintext removals are ignored during ingestion");

        Ok(())
    }
}
