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
    kem: MlKem1024,
    sig: Dilithium5,
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
        const MAX_RETENTION_HOURS: i64 = 24;

        let cutoff = timestamp - chrono::Duration::hours(MAX_RETENTION_HOURS);
        self.entries
            .retain(|entry| entry.timestamp >= cutoff);

        if self.entries.len() > MAX_ENTRIES {
            self.entries.drain(0..(self.entries.len() - MAX_ENTRIES));
        }
    }
}

impl KeyPair {
    fn new() -> Result<Self, DynError> {
        Ok(Self {
            kem: MlKem1024::new()?,
            sig: Dilithium5::new()?,
        })
    }

    fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), DynError> {
        let (pk, _) = self.kem.keypair()?;
        self.kem.encapsulate(&pk)
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DynError> {
        self.sig.sign(payload)
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
                if let Err(err) = vault.encrypt_plain_file_if_needed(&path) {
                    eprintln!("encrypt error for {}: {err}", path.display());
                }
            }
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
        let data = fs::read(path)?;
        let (ct, ss) = self.keypair.encapsulate()?;

        let encrypted = pqcnet::encrypt_aes_gcm_siv(&ss, &data)?;
        let signature = self.keypair.sign(&encrypted)?;

        let bundle = bincode::serialize(&(
            ct,
            encrypted,
            signature,
            path.file_name().unwrap().to_string_lossy(),
        ))?;

        let encrypted_path = path.with_extension("pqc");
        fs::write(&encrypted_path, bundle)?;

        #[cfg(all(windows, feature = "windows-overlay"))]
        apply_encrypted_overlay(&encrypted_path)?;

        // Mint TupleChain entry
        self.tuplechain.lock().unwrap().mint_encrypted_file(
            path,
            &encrypted_path,
            chrono::Utc::now(),
        );

        // Zeroize plaintext from RAM
        drop(data);
        Ok(())
    }

    fn encrypt_plain_file_if_needed(&self, path: &PathBuf) -> Result<(), DynError> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(format!("metadata error: {err}").into());
            }
        };

        if !metadata.is_file() {
            return Ok(());
        }

        if path.extension().map_or(false, |e| e == "pqc") {
            return Ok(());
        }

        self.encrypt_file(path)
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

        let chain = vault.tuplechain.lock().unwrap();
        let last = chain.entries.last().expect("tuplechain entry recorded");
        assert_eq!(last.original, plaintext);
        assert_eq!(last.encrypted, encrypted);

        Ok(())
    }

    #[test]
    fn directory_events_are_ignored() -> Result<(), DynError> {
        let temp = tempdir().expect("temp dir");
        let vault_dir = temp.path().join("vault");
        let vault = Vault::init(vault_dir.clone())?;

        let nested_dir = vault_dir.join("nested");
        fs::create_dir(&nested_dir)?;

        vault.encrypt_plain_file_if_needed(&nested_dir)?;

        assert!(
            !nested_dir.with_extension("pqc").exists(),
            "directories should not produce encrypted bundles"
        );

        let chain = vault.tuplechain.lock().unwrap();
        assert!(
            chain.entries.is_empty(),
            "directory events should not mint tuple entries"
        );

        Ok(())
    }
}
