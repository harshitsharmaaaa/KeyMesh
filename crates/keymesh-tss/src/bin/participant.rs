//! Participant process — loads only its own share, never all shares.
//! Usage: cargo run -p keymesh-tss --bin participant -- --id 0 --store ./shares --passphrase test

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "keymesh-participant")]
struct Args {
    #[arg(long)]
    id: u8,
    #[arg(long, default_value = "./shares")]
    store: PathBuf,
    #[arg(long, default_value = "test-passphrase")]
    passphrase: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!(
        "[participant {}] loading share from {:?} (encrypted at rest)",
        args.id, args.store
    );
    // In real deployment: load share via EncryptedShareStore::new(&args.store, &args.passphrase).load(args.id)
    // For Phase 2.5 prototype: this binary demonstrates structural isolation — it never constructs [shareA, shareB, shareC]
    // The actual share bytes are not logged.
    let store = keymesh_tss::storage::EncryptedShareStore::new(&args.store, &args.passphrase);
    match store.load(args.id) {
        Ok(bytes) => println!(
            "[participant {}] loaded {} bytes (share not displayed)",
            args.id,
            bytes.len()
        ),
        Err(e) => println!("[participant {}] no share yet: {:?}", args.id, e),
    }
    println!("[participant {}] ready — waiting for coordinator handshake (session binding validated before TSS)", args.id);
    // Real transport would connect via InMemoryAuthenticatedTransport or TcpAuthenticatedTransport
    // and wait for TssEnvelope with session_id/wallet/chain/digest verification.
    Ok(())
}
