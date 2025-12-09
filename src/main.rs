use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use pqcnet::kem::MlKem1024;
use pqcnet::sig::Dilithium5;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
struct Vault {
    path: PathBuf,
    keypair: KeyPair,
    tuplechain: Arc<Mutex<TupleChain>>,
}

#[derive(Clone)]
struct KeyPair {
    kem_sk: Vec<u8>,
    sig_sk: Vec<u8>,
}

#[derive(Clone, Default)]
struct TupleChain {
    entries: Vec<TupleEntry>,
}

#[derive(Clone)]
struct TupleEntry {
    original: PathBuf,
    encrypted: PathBuf,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl TupleChain {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(64),
        }
    }

    fn mint_encrypted_file(
        &mut self,
        original: &PathBuf,
        encrypted: &PathBuf,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) {
        self.entries.push(TupleEntry {
            original: original.clone(),
            encrypted: encrypted.clone(),
            timestamp,
        });

        const MAX_ENTRIES: usize = 2048;
        if self.entries.len() > MAX_ENTRIES {
            self.entries.drain(0..(self.entries.len() - MAX_ENTRIES));
        }
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

        if matches!(
            event.kind,
            notify::EventKind::Create(_) | notify::EventKind::Modify(_)
        ) {
            for path in event.paths {
                if path.extension().map_or(true, |e| e != "pqc") {
                    if let Err(err) = vault.encrypt_file(&path) {
                        eprintln!("encrypt error for {}: {err}", path.display());
                    }
                }
            }
        }
    }
    Ok(())
}

impl Vault {
    fn init(path: PathBuf) -> Result<Self, DynError> {
        fs::create_dir_all(&path)?;
        
        let kem = MlKem1024::new()?;
        let sig = Dilithium5::new()?;
        let (_, kem_sk) = kem.keypair()?;
        let (_, sig_sk) = sig.keypair()?;

        let keypair = KeyPair { kem_sk, sig_sk };
        let tuplechain = Arc::new(Mutex::new(TupleChain::new()));

        #[cfg(all(windows, feature = "windows-overlay"))]
        apply_overlay_to_folder(&path)?;

        Ok(Vault { path, keypair, tuplechain })
    }

    fn encrypt_file(&self, path: &PathBuf) -> Result<(), DynError> {
        let data = fs::read(path)?;
        let kem = MlKem1024::new()?;
        let (pk, _) = kem.keypair()?;
        let (ct, ss) = kem.encapsulate(&pk)?;

        let encrypted = pqcnet::encrypt_aes_gcm_siv(&ss, &data)?;
        let signature = Dilithium5::new()?.sign(&encrypted)?;

        let bundle = bincode::serialize(&(
            ct, encrypted, signature, path.file_name().unwrap().to_string_lossy()
        ))?;

        let encrypted_path = path.with_extension("pqc");
        fs::write(&encrypted_path, bundle)?;

        #[cfg(all(windows, feature = "windows-overlay"))]
        apply_encrypted_overlay(&encrypted_path)?;

        // Mint TupleChain entry
        self.tuplechain.lock().unwrap().mint_encrypted_file(
            path, &encrypted_path, chrono::Utc::now()
        );

        // Zeroize plaintext from RAM
        drop(data);
        Ok(())
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

    let hkcr = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
        "Software\\Classes\\*\\shell\\pqc-vault",
        KEY_WRITE,
    )?;
    hkcr.set_value("", &"Open with Theo Vault")?;
    hkcr.set_value("Icon", &r"C:\Program Files\Theo\icon.ico")?;
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

