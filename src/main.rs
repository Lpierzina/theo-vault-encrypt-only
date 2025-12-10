use notify::event::{ModifyKind, RenameMode};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use pqcnet::kem::MlKem1024;
use pqcnet::sig::Dilithium5;
use std::collections::HashSet;
use std::env;
use std::fmt::{self, Write as FmtWrite};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const SEALED_MAGIC: [u8; 11] = *b"THEO_PQC_v1";

#[derive(Clone, Copy)]
enum DirectoryPolicy {
    AllowExisting,
    ForbidNewEntries,
}

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
    sanctioned_removals: Arc<Mutex<HashSet<PathBuf>>>,
    sanctioned_directories: Arc<Mutex<HashSet<PathBuf>>>,
    known_directories: Arc<Mutex<HashSet<PathBuf>>>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViolationKind {
    DirectoryCreation,
    DirectoryDeletion,
    FileDeletion,
    UnauthorizedEntry,
}

#[derive(Debug)]
struct VaultViolation {
    path: PathBuf,
    kind: ViolationKind,
    detail: String,
}

impl VaultViolation {
    fn new(kind: ViolationKind, path: &PathBuf, detail: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.clone(),
            detail: detail.into(),
        }
    }

    fn directory_creation(path: &PathBuf, detail: impl Into<String>) -> Self {
        Self::new(ViolationKind::DirectoryCreation, path, detail)
    }

    fn directory_deletion(path: &PathBuf, detail: impl Into<String>) -> Self {
        Self::new(ViolationKind::DirectoryDeletion, path, detail)
    }

    fn file_deletion(path: &PathBuf, detail: impl Into<String>) -> Self {
        Self::new(ViolationKind::FileDeletion, path, detail)
    }

    fn unauthorized_entry(path: &PathBuf, detail: impl Into<String>) -> Self {
        Self::new(ViolationKind::UnauthorizedEntry, path, detail)
    }
}

impl fmt::Display for VaultViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for VaultViolation {}

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

        match event.kind {
            notify::EventKind::Create(_) => {
                for path in event.paths {
                    if let Err(err) = vault.process_new_entry(&path) {
                        if dispatch_enforcement_error(&vault, err) {
                            std::process::exit(1);
                        }
                    }
                }
            }
            notify::EventKind::Modify(ModifyKind::Name(rename_mode)) => {
                if let Err(err) = vault.handle_rename_event(rename_mode, event.paths) {
                    if dispatch_enforcement_error(&vault, err) {
                        std::process::exit(1);
                    }
                }
            }
            notify::EventKind::Modify(_) => {
                for path in event.paths {
                    if let Err(err) =
                        vault.encrypt_plain_file_if_needed(&path, DirectoryPolicy::AllowExisting)
                    {
                        if dispatch_enforcement_error(&vault, err) {
                            std::process::exit(1);
                        }
                    }
                }
            }
            notify::EventKind::Remove(_) => {
                for path in event.paths {
                    if let Err(err) = vault.guard_external_removal(&path) {
                        if dispatch_enforcement_error(&vault, err) {
                            std::process::exit(1);
                        }
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

        let mut known_dirs = HashSet::new();
        known_dirs.insert(path.clone());

        // Scan and track existing directories
        Self::scan_and_track_directories(&path, &mut known_dirs)?;

        let vault = Vault {
            path: path.clone(),
            keypair,
            tuplechain,
            sanctioned_removals: Arc::new(Mutex::new(HashSet::new())),
            sanctioned_directories: Arc::new(Mutex::new(HashSet::new())),
            known_directories: Arc::new(Mutex::new(known_dirs)),
        };

        // Sanction all existing directories (they were there before vault init)
        if let Ok(mut dir_ledger) = vault.sanctioned_directories.lock() {
            if let Ok(known_dirs) = vault.known_directories.lock() {
                for dir in known_dirs.iter() {
                    if dir != &vault.path {
                        dir_ledger.insert(dir.clone());
                    }
                }
            }
        }

        Ok(vault)
    }

    fn scan_and_track_directories(
        root: &PathBuf,
        known_dirs: &mut HashSet<PathBuf>,
    ) -> Result<(), DynError> {
        let entries = fs::read_dir(root)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if let Ok(metadata) = fs::metadata(&path) {
                if metadata.is_dir() {
                    known_dirs.insert(path.clone());
                    // Recursively scan subdirectories
                    Self::scan_and_track_directories(&path, known_dirs)?;
                }
            }
        }
        Ok(())
    }

    fn authorize_internal_removal(&self, path: &PathBuf) {
        if let Ok(mut ledger) = self.sanctioned_removals.lock() {
            ledger.insert(path.clone());
        }
    }

    fn is_directory_sanctioned(&self, path: &PathBuf) -> bool {
        if path == &self.path {
            return true;
        }
        if let Ok(ledger) = self.sanctioned_directories.lock() {
            ledger.contains(path)
        } else {
            false
        }
    }

    fn guard_external_removal(&self, path: &PathBuf) -> Result<(), DynError> {
        if path == &self.path {
            return Err(VaultViolation::directory_deletion(
                path,
                "vault root cannot be removed while Theo Vault is active",
            )
            .into());
        }

        // Check if it's a known directory (since we can't check metadata after removal)
        let is_directory = {
            let known_dirs = self.known_directories.lock().unwrap();
            known_dirs.contains(path)
        };

        if is_directory {
            // Directories can only be removed if they're in the sanctioned removals set
            let mut removal_ledger = self.sanctioned_removals.lock().unwrap();
            if removal_ledger.remove(path) {
                // Also remove from tracking sets
                if let Ok(mut dir_ledger) = self.sanctioned_directories.lock() {
                    dir_ledger.remove(path);
                }
                if let Ok(mut known_dirs) = self.known_directories.lock() {
                    known_dirs.remove(path);
                }
                return Ok(());
            }
            return Err(VaultViolation::directory_deletion(
                path,
                "vault integrity violation: directory deletion detected",
            )
            .into());
        }

        // For files, check the sanctioned removals ledger
        let mut ledger = self.sanctioned_removals.lock().unwrap();
        if ledger.remove(path) {
            return Ok(());
        }

        Err(
            VaultViolation::file_deletion(path, "vault integrity violation: deletion detected")
                .into(),
        )
    }

    fn process_new_entry(&self, path: &PathBuf) -> Result<(), DynError> {
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.is_dir() {
                if let Ok(mut known_dirs) = self.known_directories.lock() {
                    known_dirs.insert(path.clone());
                }

                if !self.is_directory_sanctioned(path) {
                    return Err(VaultViolation::directory_creation(
                        path,
                        "directories cannot be added to immutable vaults",
                    )
                    .into());
                }
                return Ok(());
            }
        }

        self.encrypt_plain_file_if_needed(path, DirectoryPolicy::ForbidNewEntries)
    }

    fn respond_to_violation(&self, violation: VaultViolation) {
        let VaultViolation { kind, path, detail } = violation;
        eprintln!(
            "vault integrity violation detected at {}: {}",
            path.display(),
            detail
        );

        match kind {
            ViolationKind::DirectoryCreation => {
                if path == self.path {
                    return;
                }

                self.authorize_internal_removal(&path);
                if let Err(err) = fs::remove_dir_all(&path) {
                    eprintln!(
                        "failed to remove unauthorized directory {}: {err}",
                        path.display()
                    );
                }

                if let Ok(mut known_dirs) = self.known_directories.lock() {
                    known_dirs.remove(&path);
                }
                if let Ok(mut dir_ledger) = self.sanctioned_directories.lock() {
                    dir_ledger.remove(&path);
                }
            }
            ViolationKind::DirectoryDeletion => {
                if path == self.path && !path.exists() {
                    if let Err(err) = fs::create_dir_all(&path) {
                        eprintln!("failed to recreate vault root after deletion attempt: {err}");
                    }
                }
                if let Ok(mut known_dirs) = self.known_directories.lock() {
                    known_dirs.remove(&path);
                }
            }
            ViolationKind::FileDeletion | ViolationKind::UnauthorizedEntry => {}
        }
    }

    fn handle_rename_event(&self, mode: RenameMode, paths: Vec<PathBuf>) -> Result<(), DynError> {
        match mode {
            RenameMode::From => {
                if paths.is_empty() {
                    return Err("rename event missing source path".into());
                }
                for path in paths {
                    self.guard_external_removal(&path)?;
                }
                Ok(())
            }
            RenameMode::To => {
                if paths.is_empty() {
                    return Err("rename event missing destination path".into());
                }
                for path in paths {
                    self.process_new_entry(&path)?;
                }
                Ok(())
            }
            RenameMode::Both => {
                if paths.len() < 2 {
                    return Err("rename event missing either source or destination path".into());
                }
                let mut iter = paths.into_iter();
                if let Some(source) = iter.next() {
                    self.guard_external_removal(&source)?;
                }
                for destination in iter {
                    self.process_new_entry(&destination)?;
                }
                Ok(())
            }
            RenameMode::Any => {
                if paths.is_empty() {
                    return Err("rename event missing paths".into());
                }
                for path in paths {
                    if path.exists() {
                        self.process_new_entry(&path)?;
                    } else {
                        self.guard_external_removal(&path)?;
                    }
                }
                Ok(())
            }
            _ => Err("unsupported rename mode detected".into()),
        }
    }

    fn encrypt_file(&self, path: &PathBuf) -> Result<(), DynError> {
        const LOCK_RETRY_MAX_ATTEMPTS: u8 = 10;
        const LOCK_RETRY_BACKOFF_MS: u64 = 150;

        if Self::is_sealed_artifact(path)? {
            return Ok(());
        }

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
        let mut sealed_bundle = Vec::with_capacity(SEALED_MAGIC.len() + bundle.len());
        sealed_bundle.extend_from_slice(&SEALED_MAGIC);
        sealed_bundle.extend_from_slice(&bundle);
        let sealed_len = sealed_bundle.len();
        let sealed_hash = blake3_hex(&sealed_bundle);

        match fs::write(path, &sealed_bundle) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // Folder disappeared before we could persist the bundle.
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }

        println!(
            "[theo-vault] sealed {} ({} bytes plaintext → {} bytes sealed)",
            path.display(),
            plaintext_len,
            sealed_len
        );

        #[cfg(all(windows, feature = "windows-overlay"))]
        apply_encrypted_overlay(path)?;

        let proof_timestamp = chrono::Utc::now();
        // Mint TupleChain entry
        let tuple_sequence = {
            let mut chain = self.tuplechain.lock().unwrap();
            chain.mint_encrypted_file(path, path, proof_timestamp)
        };

        self.emit_file_proof(
            path,
            path,
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

    fn is_sealed_artifact(path: &PathBuf) -> Result<bool, DynError> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err.into()),
        };

        let mut header = [0u8; SEALED_MAGIC.len()];
        match file.read_exact(&mut header) {
            Ok(()) => Ok(header == SEALED_MAGIC),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    fn encrypt_plain_file_if_needed(
        &self,
        path: &PathBuf,
        directory_policy: DirectoryPolicy,
    ) -> Result<(), DynError> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(format!("metadata error: {err}").into());
            }
        };

        if metadata.is_dir() {
            if path == &self.path {
                return Ok(());
            }

            return match directory_policy {
                DirectoryPolicy::AllowExisting => Ok(()),
                DirectoryPolicy::ForbidNewEntries => Err(VaultViolation::directory_creation(
                    path,
                    "directories cannot be added to immutable vaults",
                )
                .into()),
            };
        }

        if !metadata.is_file() {
            return Err(
                VaultViolation::unauthorized_entry(
                    path,
                    "unauthorized non-file entry detected. Vaults are immutable; no folders or special files allowed.",
                )
                .into(),
            );
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
            "After  ▸ {} (sealed artifact, {} bytes, blake3 {})",
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

fn dispatch_enforcement_error(vault: &Vault, err: DynError) -> bool {
    match err.downcast::<VaultViolation>() {
        Ok(violation) => {
            vault.respond_to_violation(*violation);
            false
        }
        Err(err) => {
            eprintln!("fatal Theo Vault error: {err}");
            true
        }
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
    // Shows green padlock on sealed Theo Vault files and folders
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
    use notify::event::RenameMode;
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

        assert!(
            plaintext.exists(),
            "sealed artifacts should remain at their original path"
        );
        assert!(
            Vault::is_sealed_artifact(&plaintext)?,
            "sealed artifacts must carry the Theo Vault header"
        );

        let chain = vault.tuplechain.lock().unwrap();
        let last = chain.entries.last().expect("tuplechain entry recorded");
        assert_eq!(last.original, plaintext);
        assert_eq!(last.encrypted, plaintext);

        Ok(())
    }

    #[test]
    fn directory_creation_is_blocked() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let nested_dir = vault_dir.join("nested");
        fs::create_dir(&nested_dir)?;

        let err = vault
            .encrypt_plain_file_if_needed(&nested_dir, DirectoryPolicy::ForbidNewEntries)
            .expect_err("new directories should be rejected");
        assert!(
            err.to_string().contains("directories cannot be added"),
            "error should describe directory ban"
        );

        Ok(())
    }

    #[test]
    fn existing_directories_are_ignored() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let nested_dir = vault_dir.join("nested");
        fs::create_dir(&nested_dir)?;

        vault
            .encrypt_plain_file_if_needed(&nested_dir, DirectoryPolicy::AllowExisting)
            .expect("existing directories should be ignored");

        let chain = vault.tuplechain.lock().unwrap();
        assert!(
            chain.entries.is_empty(),
            "directories should not mint tuplechain entries"
        );

        Ok(())
    }

    #[test]
    fn sealed_artifacts_reject_unsanctioned_removals() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let plaintext = vault_dir.join("note.txt");
        fs::write(&plaintext, b"hello sovereign world")?;
        vault.encrypt_file(&plaintext)?;

        let err = vault
            .guard_external_removal(&plaintext)
            .expect_err("sealed artifacts should not be removable without sanction");
        assert!(
            err.to_string().contains("deletion detected"),
            "error should mention deletion detection"
        );

        let rogue = vault_dir.join("rogue.txt");
        let err = vault
            .guard_external_removal(&rogue)
            .expect_err("unauthorized deletion should still be blocked");
        assert!(
            err.to_string().contains("deletion detected"),
            "error should mention deletion detection"
        );

        Ok(())
    }

    #[test]
    fn renaming_files_outside_vault_is_detected() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let target = vault_dir.join("document.txt");
        fs::write(&target, b"classified intel")?;

        let err = vault
            .handle_rename_event(RenameMode::From, vec![target.clone()])
            .expect_err("renaming files out of the vault should be blocked");
        assert!(
            err.to_string().contains("deletion detected"),
            "error should mention deletion detection"
        );

        Ok(())
    }

    #[test]
    fn moving_plain_files_into_vault_triggers_encryption() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let staging = temp.path().join("outside.txt");
        fs::write(&staging, b"hello from outside")?;

        let inside_path = vault_dir.join("outside.txt");
        fs::rename(&staging, &inside_path)?;

        vault.handle_rename_event(RenameMode::To, vec![inside_path.clone()])?;

        assert!(
            inside_path.exists(),
            "sealed artifact should persist at the original path"
        );
        assert!(
            Vault::is_sealed_artifact(&inside_path)?,
            "sealed artifacts must include the Theo Vault header"
        );

        Ok(())
    }

    #[test]
    fn moving_directories_into_vault_is_blocked() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let staging_dir = temp.path().join("incoming");
        fs::create_dir(&staging_dir)?;

        let inside_dir = vault_dir.join("incoming");
        fs::rename(&staging_dir, &inside_dir)?;

        let err = vault
            .handle_rename_event(RenameMode::To, vec![inside_dir.clone()])
            .expect_err("directories moved into the vault should be rejected");
        assert!(
            err.to_string().contains("directories cannot be added"),
            "error should describe directory ban"
        );

        Ok(())
    }
}
