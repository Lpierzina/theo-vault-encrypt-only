# 1. Clone the real repo
git clone https://github.com/0xAutheo/theo-vault.git
cd theo-vault

# 2. Build (with Windows overlay)
cargo build --release --features windows-overlay

# 3. Initialize your vault
./target/release/theo-vault.exe init "C:\Users\Kenneth\THEO"

# 4. Drop any file → instantly becomes .pqc with green lock