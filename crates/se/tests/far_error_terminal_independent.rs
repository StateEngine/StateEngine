#[path = "../src/render/error.rs"]
mod render_error;

use se_types::{ErrorBody, RenderCx, SeError};
type Check = Result<(), Box<dyn std::error::Error>>;

fn hostile(far: bool) -> Result<SeError, serde_json::Error> {
    let mut body = serde_json::json!({
        "code": "listener-unavailable",
        "detail": {"subject": "peer\u{1b}", "reason": "[2J\nforged\rline", "next_step": "repair\t\u{009b}31m"},
        "recovery": {"text": "remedy\u{1b}]52;c;synthetic\u{7}\nforged\rline", "command": null}
    });
    if far {
        body["far"] = true.into();
    }
    serde_json::from_value::<ErrorBody>(body).map(SeError::from)
}

#[test]
fn far_message_and_remedy_cannot_inject_terminal_records() -> Check {
    let error = hostile(true)?;
    for json in [false, true] {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            render_error::write(&error, &RenderCx::default(), json, &mut out, &mut err)?,
            1
        );
        let diagnostic = String::from_utf8(err)?;
        assert_eq!(
            diagnostic,
            "error[listener-unavailable]: Listener peer\\u{1b}: [2J\\nforged\\rline\n  fix: remedy\\u{1b}]52;c;synthetic\\u{7}\\nforged\\rline\n"
        );
        if json {
            let v: serde_json::Value = serde_json::from_slice(&out)?;
            assert_eq!(v["message"], "Listener peer\\u{1b}: [2J\\nforged\\rline");
            assert_eq!(
                v["remedy"]["text"],
                "remedy\\u{1b}]52;c;synthetic\\u{7}\\nforged\\rline"
            );
            assert_eq!(v["detail"]["subject"], "peer\u{1b}");
            assert_eq!(v["detail"]["reason"], "[2J\nforged\rline");
            assert_eq!(
                v["recovery"]["text"],
                "remedy\u{1b}]52;c;synthetic\u{7}\nforged\rline"
            );
            assert_eq!(out.iter().filter(|b| **b == b'\n').count(), 1);
        } else {
            assert!(out.is_empty());
        }
    }
    Ok(())
}

#[test]
fn a_far_default_remedy_escapes_tabs_and_c1_controls() -> Check {
    let body: ErrorBody = serde_json::from_value(serde_json::json!({
        "code": "listener-unavailable", "detail": {"subject": "peer", "reason": "reason", "next_step": "repair\t\u{009b}31m"}, "far": true
    }))?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    render_error::write(
        &body.into(),
        &RenderCx::default(),
        false,
        &mut out,
        &mut err,
    )?;
    assert_eq!(
        String::from_utf8(err)?,
        "error[listener-unavailable]: Listener peer: reason\n  fix: repair\\t\\u{9b}31m\n"
    );
    Ok(())
}

#[test]
fn local_messages_and_remedies_keep_their_exact_bytes() -> Check {
    let error = hostile(false)?;
    for json in [false, true] {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        render_error::write(&error, &RenderCx::default(), json, &mut out, &mut err)?;
        assert_eq!(
            String::from_utf8(err)?,
            "error[listener-unavailable]: Listener peer\u{1b}: [2J\nforged\rline\n  fix: remedy\u{1b}]52;c;synthetic\u{7}\nforged\rline\n"
        );
        if json {
            let v: serde_json::Value = serde_json::from_slice(&out)?;
            assert_eq!(v["message"], "Listener peer\u{1b}: [2J\nforged\rline");
            assert_eq!(
                v["remedy"]["text"],
                "remedy\u{1b}]52;c;synthetic\u{7}\nforged\rline"
            );
            assert!(v.get("far").is_none());
        }
    }
    Ok(())
}
