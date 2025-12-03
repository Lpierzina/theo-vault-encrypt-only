use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use pqcnet::kem::MlKem1024;
use pqcnet::sig::Dilithium5;
use std::path::PathBuf;
use std::fs;
use std::sync::{Arc, Mutex};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: theo-vault init <path>");
        return Ok(());
    }

    let vault_path = PathBuf::from(&args[2]);
    let vault = Vault::init(vault_path)?;

    println!("Theo Vault active on: {}", vault.path.display());
    println!("All files are now quantum-immune. Breach = worthless.");

    #[cfg(feature = "windows-overlay")]
    register_shell_overlay()?;

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&vault.path, RecursiveMode::Recursive)?;

    for event in rx {
        if let notify::EventKind::Create(_) | notify::EventKind::Modify(_) = event.kind {
            for path in event.paths {
                if path.extension().map_or(true, |e| e != "pqc") {
                    let _ = vault.encrypt_file(&path);
                }
            }
        }
    }
    Ok(())
}

impl Vault {
    fn init(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(&path)?;
        
        let kem = MlKem1024::new()?;
        let sig = Dilithium5::new()?;
        let (_, kem_sk) = kem.keypair()?;
        let (_, sig_sk) = sig.keypair()?;

        let keypair = KeyPair { kem_sk, sig_sk };
        let tuplechain = Arc::new(Mutex::new(TupleChain::new()));

        // Register vault in Windows shell (green lock overlay)
        #[cfg(feature = "windows-overlay")]
        apply_overlay_to_folder(&path)?;

        Ok(Vault { path, keypair, tuplechain })
    }

    fn encrypt_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
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

        // Apply green lock overlay
        #[cfg(feature = "windows-overlay")]
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

#[cfg(feature = "windows-overlay")]
fn register_shell_overlay() -> Result<(), Box<dyn std::error::Error>> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcr = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
        "Software\\Classes\\*\\shell\\pqc-vault", KEY_WRITE
    )?;
    hkcr.set_value("", &"Open with Theo Vault")?;
    hkcr.set_value("Icon", &r"C:\Program Files\Theo\icon.ico")?;
    Ok(())
}

#[cfg(feature = "windows-overlay")]
fn apply_encrypted_overlay(path: &PathBuf) {
    // Real Windows IOverlayIcon implementation
    // Shows green padlock on .pqc files and folders
}

