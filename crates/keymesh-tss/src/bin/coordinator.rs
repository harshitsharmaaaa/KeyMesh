//! Coordinator — untrusted for signing authority, coordinates sessions.

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "3")]
    participants: usize,
    #[arg(long, default_value = "2")]
    threshold: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!(
        "[coordinator] threshold {}/{} — authenticated transport, session handshake before TSS",
        args.threshold, args.participants
    );
    println!("[coordinator] responsibilities: participant discovery, session creation (SessionBinding), message relay, timeout, signature aggregation");
    println!("[coordinator] MUST NOT: know private key, sign alone, change digest/nonce, bypass threshold/policy");
    // Real implementation would use TssTransport::connect/authenticate/send/receive and synedrion InteractiveSigning
    Ok(())
}
