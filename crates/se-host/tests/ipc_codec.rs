use se_host::{
    client::{auth, endpoint, wire},
    *,
};
use se_types::{Generation, Secret};
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;

/// Protects: 40 §7.1 — opaque operation keys remain independent of transport correlation IDs.
#[test]
fn operation_roundtrip_retains_key_authority_and_exact_envelope() -> Check {
    let mut input = call()?;
    input.authority = Some(PresentedAuthority::Session(secret(3)?));
    let frame = wire::encode_call(&input)?;
    let output = wire::decode_call(&payload(&frame)?)?;
    assert_eq!(output.request_id, 9);
    assert_eq!(output.generation, input.generation);
    assert_eq!(output.version, input.version);
    let Some(PresentedAuthority::Session(token)) = &output.authority else {
        return Err("session authority lost".into());
    };
    assert_eq!(token.expose(), secret(3)?.expose());
    let IpcRequest::Operation(output) = output.request else {
        return Err("operation changed family".into());
    };
    assert_eq!(
        output.key.ok_or("missing durable key")?.as_str(),
        "opaque/key:9-vs-transport-9"
    );
    assert_eq!(output.name, "working-state.set");
    let mut input = call()?;
    input.request_id = 10;
    let output = wire::decode_call(&payload(&wire::encode_call(&input)?)?)?;
    let IpcRequest::Operation(output) = output.request else {
        return Err("operation changed family".into());
    };
    assert_eq!(
        output.key.ok_or("missing durable key")?.as_str(),
        "opaque/key:9-vs-transport-9"
    );
    Ok(())
}

/// Protects: 40 §7.1 — malformed and open envelopes refuse before any dispatch.
#[test]
fn closed_decoder_refuses_duplicates_unknowns_utf8_depth_and_trailing_values() -> Check {
    let valid = String::from_utf8(payload(&wire::encode_call(&call()?)?)?)?;
    let mut variants = vec![
        valid.replacen("\"request_id\":9", "\"request_id\":9,\"request_id\":10", 1),
        valid.replacen("\"request_id\":9", "\"extra\":true,\"request_id\":9", 1),
        valid.replacen("\"name\":", "\"extra\":true,\"name\":", 1),
        format!("{valid}{{}}"),
        valid.replacen("\"request_id\":9", "\"request_id\":0", 1),
    ];
    let mut nested = serde_json::Value::Null;
    for _ in 0..65 {
        nested = serde_json::json!([nested]);
    }
    let mut object: serde_json::Value = serde_json::from_str(&valid)?;
    object["request"]["input"]["arguments"] = nested;
    variants.push(object.to_string());
    for bytes in variants {
        assert!(
            wire::decode_call(bytes.as_bytes()).is_err(),
            "accepted malformed closed envelope"
        );
    }
    assert!(wire::decode_call(&[0xff]).is_err());
    assert!(wire::decode_call(b"").is_err());
    let duplicate = valid.replacen("\"text\":", "\"text\":\"first\",\"text\":", 1);
    assert!(wire::decode_call(duplicate.as_bytes()).is_err());
    Ok(())
}

/// Protects: 40 §7.1 — zero/oversize and incomplete frames never become empty successful messages.
#[test]
fn frame_boundaries_and_incomplete_eof_remain_errors() -> Check {
    assert!(wire::frame_length([0; 4], wire::MAX_FRAME_BYTES).is_err());
    assert!(
        wire::frame_length(
            ((wire::MAX_FRAME_BYTES + 1) as u32).to_be_bytes(),
            wire::MAX_FRAME_BYTES
        )
        .is_err()
    );
    let frame = wire::encode_call(&call()?)?;
    for n in [0, 1, 3, 4, frame.as_bytes().len() - 1] {
        assert!(
            wire::read_payload(
                &mut std::io::Cursor::new(&frame.as_bytes()[..n]),
                wire::MAX_FRAME_BYTES
            )
            .is_err()
        );
    }
    let complete = wire::read_payload(
        &mut std::io::Cursor::new(frame.as_bytes()),
        wire::MAX_FRAME_BYTES,
    )?;
    assert!(wire::decode_call(complete.as_bytes()).is_ok());
    let json = wire::encode_json(&serde_json::json!({"not":"a frame"}), 1024)?;
    let mut output = Vec::new();
    assert!(wire::write_frame(&mut output, &json).is_err());
    assert!(output.is_empty());
    Ok(())
}

/// Protects: 40 §7.1 — reply budgets include metadata, with exact ID/API/G correlation.
#[test]
fn responses_refuse_small_budget_and_wrong_correlation() -> Check {
    let input = response()?;
    assert!(wire::encode_response(&input, 32).is_err());
    let frame = wire::encode_response(&input, 4096)?;
    let body = payload(&frame)?;
    assert!(wire::decode_response(&body, input.version, input.generation, 9, 4096).is_ok());
    assert!(wire::decode_response(&body, input.version, input.generation, 10, 4096).is_err());
    assert!(wire::decode_response(&body, input.version, Generation::new(12)?, 9, 4096).is_err());
    let mut version = input.version;
    version.minor += 1;
    assert!(wire::decode_response(&body, version, input.generation, 9, 4096).is_err());
    assert!(
        wire::decode_response(&body, input.version, input.generation, 9, body.len() - 1).is_err()
    );
    Ok(())
}

/// Protects: 40 §7.1 — owner MAC binds both nonces, native peer, epoch/image/API and its protocol domain.
#[test]
fn owner_proof_fields_and_one_use_challenge_are_bound() -> Check {
    let home = Home::new()?;
    let endpoint = home.record()?;
    let key = secret(1)?;
    let peer = se_proc::native_ipc::observe_ipc_self()?.binding();
    let nonce = [2; 32];
    let mut state = auth::OwnerChallenge::begin(&endpoint, auth::ProofDomain::Owner)?;
    let challenge = state.challenge()?.clone();
    let mac = auth::create_owner_mac(&key, auth::ProofDomain::Owner, &challenge, &nonce, &peer)?;
    auth::verify_owner_mac(
        &key,
        auth::ProofDomain::Owner,
        &challenge,
        &nonce,
        &peer,
        &mac,
    )?;
    assert!(
        auth::verify_owner_mac(
            &key,
            auth::ProofDomain::RuntimeStop,
            &challenge,
            &nonce,
            &peer,
            &mac
        )
        .is_err()
    );
    assert!(
        auth::verify_owner_mac(
            &key,
            auth::ProofDomain::Owner,
            &challenge,
            &[3; 32],
            &peer,
            &mac
        )
        .is_err()
    );
    let mut different = peer.clone();
    different.push(0);
    assert!(
        auth::verify_owner_mac(
            &key,
            auth::ProofDomain::Owner,
            &challenge,
            &nonce,
            &different,
            &mac
        )
        .is_err()
    );
    for field in 0..4 {
        let mut changed = challenge.clone();
        match field {
            0 => changed.nonce[0] ^= 1,
            1 => changed.version.minor += 1,
            2 => changed.image_sha256 = se_types::Sha256::from_bytes([8; 32]),
            _ => changed.epoch.generation = se_types::HostGeneration::new(8)?,
        };
        assert!(
            auth::verify_owner_mac(
                &key,
                auth::ProofDomain::Owner,
                &changed,
                &nonce,
                &peer,
                &mac
            )
            .is_err()
        );
    }
    state.verify(&key, &nonce, &peer, &mac)?;
    assert!(state.verify(&key, &nonce, &peer, &mac).is_err());
    let mut failed = auth::OwnerChallenge::begin(&endpoint, auth::ProofDomain::Owner)?;
    let mac = auth::create_owner_mac(
        &key,
        auth::ProofDomain::Owner,
        failed.challenge()?,
        &nonce,
        &peer,
    )?;
    assert!(failed.verify(&secret(9)?, &nonce, &peer, &mac).is_err());
    assert!(failed.verify(&key, &nonce, &peer, &mac).is_err());
    Ok(())
}

/// Protects: 40 §7.1.1 — stop control stays closed, keyed and independent from the operation API.
#[test]
fn fixed_stop_control_refuses_operations_and_wrong_reply_identity() -> Check {
    let home = Home::new()?;
    let endpoint = home.record()?;
    let request = endpoint::RuntimeStopRequest {
        expected_epoch: endpoint.epoch.clone(),
        generation: endpoint.generation,
        key: se_types::IdempotencyKey::new("original-stop-key")?,
        deadline_at: se_types::UnixMicros::new(1_700_000_000_000_000)?,
        nonce: [1; 32],
        mac: Secret::new(vec![2; 32])?,
    };
    let encoded = endpoint::encode_stop(&request)?;
    let decoded = endpoint::decode_stop(&payload(&encoded)?)?;
    assert_eq!(decoded.key, request.key);
    assert!(wire::decode_call(&payload(&encoded)?).is_err());
    assert!(endpoint::decode_stop(&payload(&wire::encode_call(&call()?)?)?).is_err());
    let mut reply = endpoint::RuntimeStopReply {
        epoch: endpoint.epoch,
        generation: endpoint.generation,
        key: request.key.clone(),
        outcome: endpoint::RuntimeStopOutcome::Facts {
            achieved: vec![],
            retained_resume: vec![],
            pending: vec!["writer not joined".into()],
        },
    };
    assert!(
        endpoint::decode_stop_reply(
            &payload(&endpoint::encode_stop_reply(&reply, 4096)?)?,
            &request,
            4096
        )
        .is_ok()
    );
    reply.key = se_types::IdempotencyKey::new("different")?;
    assert!(
        endpoint::decode_stop_reply(
            &payload(&endpoint::encode_stop_reply(&reply, 4096)?)?,
            &request,
            4096
        )
        .is_err()
    );
    Ok(())
}

/// Protects: CLI route metadata stays outside closed operation arguments and cannot be attached to hook ingress.
#[test]
fn cli_selections_are_preserved_only_for_operations() -> Check {
    let mut operation = call()?;
    operation.cli_selections =
        Some(serde_json::json!({"project":"raw selector","agent":"chosen agent"}));
    let decoded = wire::decode_call(&payload(&wire::encode_call(&operation)?)?)?;
    assert_eq!(decoded.cli_selections, operation.cli_selections);
    let IpcRequest::Operation(raw) = decoded.request else {
        return Err("wrong request family".into());
    };
    assert_eq!(
        raw.arguments,
        serde_json::json!({"text":"a visible effect"})
    );
    operation.cli_selections = Some(serde_json::json!("not an object"));
    assert!(wire::encode_call(&operation).is_err());
    let home = Home::new()?;
    operation.request = IpcRequest::Hook(ClaudeHookInput {
        kind: ClaudeHookKind::Stop,
        conversation: se_types::ProviderSessionId::new("provider-session")?,
        claimed_transcript: se_types::NativePath::from_local(home.0.join("transcript"))?,
        payload: serde_json::json!({}),
    });
    operation.cli_selections = Some(serde_json::json!({}));
    assert!(wire::encode_call(&operation).is_err());
    operation.cli_selections = None;
    let mut body: serde_json::Value =
        serde_json::from_slice(&payload(&wire::encode_call(&operation)?)?)?;
    body["cli_selections"] = serde_json::json!({});
    assert!(wire::decode_call(&serde_json::to_vec(&body)?).is_err());
    Ok(())
}
