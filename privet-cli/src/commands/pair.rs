use clap::Args;

use privet_core::PrivetConfig;

#[derive(Args)]
pub struct PairArgs {
    /// Show pairing code for a peer fingerprint
    #[arg(long)]
    pub code: Option<String>,

    /// Trust a peer by fingerprint
    #[arg(long)]
    pub trust: Option<String>,

    /// Trust a peer AND auto-accept all future transfers from them
    #[arg(long)]
    pub trust_and_accept: Option<String>,

    /// Verification code (when set, --trust/--trust-and-accept requires the code to match)
    #[arg(long)]
    pub verify_code: Option<String>,

    /// Remove trust from a peer by fingerprint
    #[arg(long)]
    pub untrust: Option<String>,

    /// Reject a pending pairing request
    #[arg(long)]
    pub reject_pairing: Option<String>,

    /// Remove a peer from auto-accept list (keeps trust)
    #[arg(long)]
    pub unaccept: Option<String>,

    /// List all trusted peers
    #[arg(long)]
    pub list: bool,

    /// List all auto-accept (accepted) peers
    #[arg(long)]
    pub list_accepted: bool,
}

pub async fn run(args: PairArgs, config: PrivetConfig) -> privet_core::Result<()> {
    // --trust and --trust-and-accept are mutually exclusive
    if args.trust.is_some() && args.trust_and_accept.is_some() {
        eprintln!("ERROR: --trust and --trust-and-accept are mutually exclusive");
        std::process::exit(1);
    }

    let engine = privet_core::PrivetEngine::new(config).await?;
    let local_fp = engine.identity().fingerprint.clone();

    if args.list {
        let trusted = engine.trusted_fingerprints().await;
        if trusted.is_empty() {
            println!("No trusted peers");
        } else {
            println!("Trusted peers ({}):", trusted.len());
            for (i, fp) in trusted.iter().enumerate() {
                let code = privet_core::security::trust::TrustStore::pairing_code(&local_fp, fp);
                let short = if fp.len() > 16 { &fp[..16] } else { fp.as_str() };
                println!("  {}. {}...  (code: {})", i + 1, short, code);
            }
        }
        return Ok(());
    }

    if args.list_accepted {
        let accepted = engine.accepted_fingerprints().await;
        if accepted.is_empty() {
            println!("No auto-accept peers");
        } else {
            println!("Auto-accept peers ({}):", accepted.len());
            for (i, fp) in accepted.iter().enumerate() {
                let code = privet_core::security::trust::TrustStore::pairing_code(&local_fp, fp);
                let short = if fp.len() > 16 { &fp[..16] } else { fp.as_str() };
                println!("  {}. {}...  (code: {})", i + 1, short, code);
            }
        }
        return Ok(());
    }

    if let Some(fp) = &args.trust {
        if let Some(expected) = &args.verify_code {
            let computed = privet_core::security::trust::TrustStore::pairing_code(&local_fp, fp);
            if &computed != expected {
                eprintln!("ERROR: Pairing code mismatch");
                eprintln!("  Expected: {expected}");
                eprintln!("  Computed: {computed}");
                eprintln!("The pairing code must match on both devices.");
                eprintln!("Use `privet pair --code <fp>` to see the current code.");
                std::process::exit(1);
            }
            println!("Pairing code verified: {computed}");
        }
        engine.trust_peer(fp).await?;
        println!("Trusted fingerprint: {fp}");
        return Ok(());
    }

    if let Some(fp) = &args.trust_and_accept {
        if let Some(expected) = &args.verify_code {
            let computed = privet_core::security::trust::TrustStore::pairing_code(&local_fp, fp);
            if &computed != expected {
                eprintln!("ERROR: Pairing code mismatch");
                eprintln!("  Expected: {expected}");
                eprintln!("  Computed: {computed}");
                eprintln!("The pairing code must match on both devices.");
                eprintln!("Use `privet pair --code <fp>` to see the current code.");
                std::process::exit(1);
            }
            println!("Pairing code verified: {computed}");
        }
        engine.trust_and_accept_peer(fp).await?;
        println!("Trusted and auto-accepted fingerprint: {fp}");
        return Ok(());
    }

    if let Some(fp) = &args.untrust {
        engine.untrust_peer(fp).await?;
        println!("Removed trust for fingerprint: {fp}");
        return Ok(());
    }

    if let Some(fp) = &args.reject_pairing {
        engine.reject_pairing(fp).await?;
        println!("Rejected pairing for fingerprint: {fp}");
        return Ok(());
    }

    if let Some(fp) = &args.unaccept {
        engine.unaccept_peer(fp).await?;
        println!("Removed auto-accept for fingerprint: {fp}");
        return Ok(());
    }

    if let Some(fp) = &args.code {
        let code = privet_core::security::trust::TrustStore::pairing_code(&local_fp, fp);
        let short = if fp.len() > 16 { &fp[..16] } else { fp.as_str() };
        println!("Local fingerprint: {}...", &local_fp[..16]);
        println!("Peer fingerprint: {short}...");
        println!("Pairing code: {code}");
        println!("Verify this code matches on the other device.");
        return Ok(());
    }

    // Default: show help
    println!("Usage:");
    println!("  privet pair --trust <fp> [--verify-code <code>]");
    println!("  privet pair --trust-and-accept <fp> [--verify-code <code>]");
    println!("  privet pair --untrust <fp>");
    println!("  privet pair --reject-pairing <fp>");
    println!("  privet pair --unaccept <fp>");
    println!("  privet pair --code <fp>");
    println!("  privet pair --list");
    println!("  privet pair --list-accepted");
    println!();
    println!("Pairing flow:");
    println!("  1. Both devices run `privet pair --code <peer-fingerprint>`");
    println!("  2. Verify the 6-digit code matches on both devices");
    println!("  3. Run `privet pair --trust <fp> --verify-code <code>`");
    println!("     or `privet pair --trust-and-accept <fp> --verify-code <code>`");
    println!();
    println!("Trust vs Accept:");
    println!("  --trust:            Verify device identity only");
    println!("  --trust-and-accept: Verify identity AND auto-accept future transfers");
    println!("  --unaccept:         Remove auto-accept (keeps trust)");
    Ok(())
}
