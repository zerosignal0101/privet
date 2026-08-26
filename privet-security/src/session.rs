use privet_crypto::pake::{PakeOutput, PakeScheme};
use privet_crypto::transcript::{transcript_hash, verify_transcript};
use privet_crypto::{gen_nonce, identity::Identity};
use privet_protocol::control_frame::Payload;
use privet_protocol::{ControlFrame, PairingConfirm, PairingInit, PairingResult, PairingResultAck};

use crate::channel::{PairingChannel, PairingClock};
use crate::constants::EXPORTER_LEN;
use crate::transcript::{assert_identity_binding, build_transcript_parts, Role};
use crate::trust::{PeerTrust, TrustStore};
use crate::PairingError;
use privet_crypto::CryptoError;

pub struct SessionInputs {
    pub code: String,
    pub peer_device_fingerprint: String,
    pub peer_device_name: String,
    pub peer_spki: Vec<u8>,
    pub exporter: [u8; EXPORTER_LEN],
}

#[derive(Debug)]
pub enum PairingOutcome {
    Paired {
        peer_device_fingerprint: String,
        peer_spki: Vec<u8>,
    },
    Failed { reason: PairingError },
}

fn wrap(payload: Payload) -> ControlFrame {
    ControlFrame {
        payload: Some(payload),
    }
}

pub async fn run_initiator(
    local: &Identity,
    inputs: &SessionInputs,
    channel: &mut dyn PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    pake: &dyn PakeScheme,
    store: &dyn crate::commit::ProofStore,
) -> Result<PairingOutcome, PairingError> {
    run_initiator_with_config(
        local,
        inputs,
        channel,
        clock,
        trust,
        pake,
        store,
        &crate::PairingConfig::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_initiator_with_config(
    local: &Identity,
    inputs: &SessionInputs,
    channel: &mut dyn PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    pake: &dyn PakeScheme,
    store: &dyn crate::commit::ProofStore,
    config: &crate::PairingConfig,
) -> Result<PairingOutcome, PairingError> {
    let nonce_i = gen_nonce()?;
    let (mut state_i, spake_msg_i) = pake.start_initiator(
        inputs.code.as_bytes(),
        local.fingerprint().as_bytes(),
        inputs.peer_device_fingerprint.as_bytes(), // id_b = R
    )?;
    let msg_i = spake_msg_i.clone();
    channel
        .send(wrap(Payload::PairingInit(PairingInit {
            device_fingerprint: local.fingerprint(),
            identity_pubkey: local.spki_der().to_vec(),
            spake2_msg: spake_msg_i,
            nonce: nonce_i.to_vec(),
        })))
        .await?;

    let confirm = match channel.recv().await?.payload {
        Some(Payload::PairingConfirm(c)) => c,
        _ => return Err(PairingError::Protocol("expected PairingConfirm".into())),
    };
    let out: PakeOutput = state_i.finish(&confirm.spake2_msg)?;
    let nonce_r = confirm.nonce.clone();

    let local_fingerprint = local.fingerprint();
    let parts = build_transcript_parts(
        Role::Initiator,
        &local_fingerprint,
        local.spki_der(),
        &inputs.peer_device_fingerprint,
        &inputs.peer_spki,
        &msg_i,
        &confirm.spake2_msg,
        &nonce_i,
        &nonce_r,
        &inputs.exporter,
        &out.confirmation_tag,
    );
    let hash = transcript_hash(&parts);

    let sig_r = ed25519_dalek::Signature::from_slice(&confirm.transcript_sig)
        .map_err(|e| PairingError::TranscriptInvalid(format!("sig decode: {e}")))?;
    verify_transcript(&inputs.peer_spki, &hash, &sig_r).map_err(|e| {
        if matches!(e, CryptoError::InvalidKey(_)) {
            PairingError::CodeMismatch
        } else {
            PairingError::Crypto(e)
        }
    })?;

    let sig_i = local.sign(&hash);
    channel
        .send(wrap(Payload::PairingResult(PairingResult {
            success: true,
            error: String::new(),
            identity_pubkey: local.spki_der().to_vec(),
            transcript_sig: sig_i.to_vec(),
        })))
        .await?;

    let proof = crate::commit::PendingProof {
        transcript_hash: hash,
        transcript_sig_i: sig_i.to_vec(),
        peer_device_fingerprint: inputs.peer_device_fingerprint.clone(),
        peer_device_name: inputs.peer_device_name.clone(),
        peer_spki: inputs.peer_spki.clone(),
        local_spki: local.spki_der().to_vec(),
    };
    crate::commit::wait_for_ack_with_retries(
        channel,
        clock,
        trust,
        &proof,
        store,
        std::time::Duration::from_secs(config.pairing_ack_timeout_secs),
        config.pairing_max_retries,
    )
    .await
}

pub async fn run_responder(
    local: &Identity,
    inputs: &SessionInputs,
    channel: &mut dyn PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    pake: &dyn PakeScheme,
) -> Result<PairingOutcome, PairingError> {
    let init = match channel.recv().await?.payload {
        Some(Payload::PairingInit(i)) => i,
        _ => return Err(PairingError::Protocol("expected PairingInit".into())),
    };
    assert_identity_binding(&init.identity_pubkey, &inputs.peer_spki)?;

    let (mut state_r, spake_msg_r) = pake.start_responder(
        inputs.code.as_bytes(),
        inputs.peer_device_fingerprint.as_bytes(),
        local.fingerprint().as_bytes(), // id_b = R
    )?;
    let out = state_r.finish(&init.spake2_msg)?;
    let nonce_r = gen_nonce()?;

    let local_fingerprint = local.fingerprint();
    let parts = build_transcript_parts(
        Role::Responder,
        &local_fingerprint,
        local.spki_der(),
        &inputs.peer_device_fingerprint,
        &inputs.peer_spki,
        &init.spake2_msg,
        &spake_msg_r,
        &init.nonce,
        &nonce_r,
        &inputs.exporter,
        &out.confirmation_tag,
    );
    let hash = transcript_hash(&parts);
    let sig_r = local.sign(&hash);
    channel
        .send(wrap(Payload::PairingConfirm(PairingConfirm {
            device_fingerprint: local_fingerprint,
            spake2_msg: spake_msg_r,
            transcript_sig: sig_r.to_vec(),
            nonce: nonce_r.to_vec(),
        })))
        .await?;

    let result = match channel.recv().await?.payload {
        Some(Payload::PairingResult(r)) => r,
        _ => return Err(PairingError::Protocol("expected PairingResult".into())),
    };
    if !result.success {
        return Ok(PairingOutcome::Failed {
            reason: PairingError::CodeMismatch,
        });
    }
    assert_identity_binding(&result.identity_pubkey, &inputs.peer_spki)?;
    let sig_i = ed25519_dalek::Signature::from_slice(&result.transcript_sig)
        .map_err(|e| PairingError::TranscriptInvalid(format!("sig decode: {e}")))?;
    verify_transcript(&result.identity_pubkey, &hash, &sig_i).map_err(|e| {
        if matches!(e, CryptoError::InvalidKey(_)) {
            PairingError::CodeMismatch
        } else {
            PairingError::Crypto(e)
        }
    })?;

    let now = clock.now_ms();
    if crate::commit::should_commit(trust, &inputs.peer_device_fingerprint, &inputs.peer_spki)? {
        trust.commit_peer(PeerTrust {
            device_fingerprint: inputs.peer_device_fingerprint.clone(),
            peer_spki: inputs.peer_spki.clone(),
            peer_device_name: inputs.peer_device_name.clone(),
            share_with_peers: false,
            first_paired_ts: now,
            last_seen_ts: now,
        })?;
    }
    channel
        .send(wrap(Payload::PairingResultAck(PairingResultAck {
            transcript_hash: hash.to_vec(),
        })))
        .await?;
    Ok(PairingOutcome::Paired {
        peer_device_fingerprint: inputs.peer_device_fingerprint.clone(),
        peer_spki: inputs.peer_spki.clone(),
    })
}

use crate::code::PairingCode;

#[allow(clippy::too_many_arguments)]
pub async fn run_initiator_checked(
    local: &Identity,
    inputs: &SessionInputs,
    code: &mut PairingCode,
    channel: &mut dyn PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    pake: &dyn PakeScheme,
    store: &dyn crate::commit::ProofStore,
) -> Result<PairingOutcome, PairingError> {
    code.check_valid(clock.now_ms())?;
    let outcome = run_initiator(local, inputs, channel, clock, trust, pake, store).await;
    match &outcome {
        Ok(PairingOutcome::Paired { .. }) => {
            let _ = code.consume();
        }
        Ok(PairingOutcome::Failed { reason }) => {
            if is_spake2_failure(reason) {
                code.record_failure();
            }
        }
        Err(e) => {
            if is_spake2_failure(e) {
                code.record_failure();
            }
        }
    }
    outcome
}

fn is_spake2_failure(e: &PairingError) -> bool {
    matches!(
        e,
        PairingError::CodeMismatch
            | PairingError::TranscriptInvalid(_)
            | PairingError::Crypto(CryptoError::InvalidKey(_))
    )
}

pub async fn run_responder_checked(
    local: &Identity,
    inputs: &SessionInputs,
    code: &mut PairingCode,
    channel: &mut dyn PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    pake: &dyn PakeScheme,
) -> Result<PairingOutcome, PairingError> {
    code.check_valid(clock.now_ms())?;
    let outcome = run_responder(local, inputs, channel, clock, trust, pake).await;
    match &outcome {
        Ok(PairingOutcome::Paired { .. }) => {
            let _ = code.consume();
        }
        Ok(PairingOutcome::Failed { reason }) => {
            if is_spake2_failure(reason) {
                code.record_failure();
            }
        }
        Err(e) => {
            if is_spake2_failure(e) {
                code.record_failure();
            }
        }
    }
    outcome
}
