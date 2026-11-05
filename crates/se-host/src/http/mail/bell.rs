//! Per-launch mail-only authentication. No bearer crosses the mod's HTTP API.
//! A nonce binds both directions to this exact origin, path and session; a
//! redirect cannot gain a reusable credential or forge an accepted mail page.
use hmac::{Hmac, Mac};
use se_types::{AgentId, Result, SeError, Secret, SessionId};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(crate) struct Bells {
    maximum: usize,
    entries: Mutex<BTreeMap<SessionId, Entry>>,
}
struct Entry {
    bearer: Arc<Secret>,
    key: [u8; 32],
    agent: AgentId,
    origin: String,
    hold: PathBuf,
    nonces: VecDeque<(String, Instant)>,
}
pub(crate) struct Authenticated {
    pub bearer: Arc<Secret>,
    pub session: SessionId,
    pub nonce: String,
    pub hold: PathBuf,
    key: [u8; 32],
}
fn invalid(why: &str) -> SeError {
    SeError::invalid("Claude mail bell", why)
}
fn mac(key: &[u8], text: &str) -> Result<[u8; 32]> {
    let mut value = Hmac::<Sha256>::new_from_slice(key).map_err(|_| invalid("a valid mail key"))?;
    value.update(text.as_bytes());
    Ok(value.finalize().into_bytes().into())
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    se_types::hex_lower(bytes)
}
impl Bells {
    pub(crate) fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            entries: Mutex::new(BTreeMap::new()),
        })
    }
    pub(crate) fn register(
        &self,
        session: SessionId,
        agent: AgentId,
        bearer: &Secret,
        origin: String,
        hold: PathBuf,
    ) -> Result<String> {
        let key = mac(bearer.expose(), "se.claude.mail.key/v1")?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| invalid("unpoisoned bell bindings"))?;
        if !entries.contains_key(&session) && entries.len() >= self.maximum {
            return Err(invalid("available bounded bell capacity"));
        }
        if let Some(found) = entries.get(&session) {
            if found.key != key
                || found.agent != agent
                || found.origin != origin
                || found.hold != hold
            {
                return Err(invalid("the original protected launch binding"));
            }
        } else {
            entries.insert(
                session,
                Entry {
                    bearer: Arc::new(Secret::new(bearer.expose().to_vec())?),
                    key,
                    agent,
                    origin,
                    hold,
                    nonces: VecDeque::new(),
                },
            );
        }
        Ok(hex(&key))
    }
    pub(crate) fn revoke(&self, session: &SessionId) -> Result<()> {
        let hold = self
            .entries
            .lock()
            .map_err(|_| invalid("unpoisoned bell bindings"))?
            .get(session)
            .map(|entry| entry.hold.clone());
        if let Some(hold) = hold {
            set_hold(&hold, true, Some("revocation"))?;
        }
        self.retire(session)
    }
    pub(crate) fn retire(&self, session: &SessionId) -> Result<()> {
        self.entries
            .lock()
            .map_err(|_| invalid("unpoisoned bell bindings"))?
            .remove(session);
        Ok(())
    }
    pub(crate) fn held(&self, session: &SessionId) -> Result<bool> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| invalid("unpoisoned bell bindings"))?;
        match entries.get(session) {
            Some(entry) => held(&entry.hold),
            None => Ok(false),
        }
    }
    pub(crate) fn authenticate(
        &self,
        session: SessionId,
        nonce: String,
        issued: &str,
        proof: &str,
        method: &str,
        body: &str,
    ) -> Result<Authenticated> {
        if uuid::Uuid::parse_str(&nonce).is_err()
            || nonce.len() != 36
            || proof.len() != 64
            || body.len() > 64
        {
            return Err(invalid("bounded canonical nonce, proof and action"));
        }
        let issued_ms = issued
            .parse::<u128>()
            .map_err(|_| invalid("a bounded request time"))?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid("a readable clock"))?
            .as_millis();
        if now_ms.abs_diff(issued_ms) > 30_000 {
            return Err(invalid(
                "a request within the thirty-second authentication window",
            ));
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| invalid("unpoisoned bell bindings"))?;
        let entry = entries
            .get_mut(&session)
            .ok_or_else(|| invalid("a current installed bell binding; relaunch this agent"))?;
        let text = format!(
            "se.claude.mail.request/v1\n{method}\n{}/stateengine/mail/next_change\n{session}\n{issued}\n{nonce}\n{body}",
            entry.origin
        );
        let bytes = decode(proof)?;
        let mut verifier =
            Hmac::<Sha256>::new_from_slice(&entry.key).map_err(|_| invalid("a valid mail key"))?;
        verifier.update(text.as_bytes());
        verifier
            .verify_slice(&bytes)
            .map_err(|_| invalid("authenticated original local host and mail request"))?;
        let now = Instant::now();
        entry
            .nonces
            .retain(|(_, at)| now.duration_since(*at) < Duration::from_secs(60));
        if entry.nonces.iter().any(|(value, _)| value == &nonce) || entry.nonces.len() >= 128 {
            return Err(invalid(
                "a fresh nonce within the per-session request budget",
            ));
        }
        entry.nonces.push_back((nonce.clone(), now));
        Ok(Authenticated {
            bearer: Arc::clone(&entry.bearer),
            session,
            nonce,
            hold: entry.hold.clone(),
            key: entry.key,
        })
    }
}
fn held(path: &std::path::Path) -> Result<bool> {
    let mut file = se_proc::OwnedFile::open(path)
        .map_err(|e| invalid(&e.to_string()))?
        .ok_or_else(|| invalid("the original protected durable mail hold"))?;
    let value: serde_json::Value = serde_json::from_slice(
        &file.read(1024).map_err(|e| invalid(&e.to_string()))?,
    )
    .map_err(|_| invalid("readable durable mail hold; an unreadable hold never enables wake"))?;
    value
        .get("held")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| invalid("an explicit durable hold state"))
}
fn set_hold(path: &std::path::Path, held: bool, reason: Option<&str>) -> Result<()> {
    let mut file = se_proc::OwnedFile::open(path)
        .map_err(|e| invalid(&e.to_string()))?
        .ok_or_else(|| invalid("the original protected durable mail hold"))?;
    let prior = file.read(1024).map_err(|e| invalid(&e.to_string()))?;
    let value = serde_json::to_vec(&serde_json::json!({"held":held,"reason":reason}))
        .map_err(|_| invalid("an encodable durable hold"))?;
    file.replace(Sha256::digest(&prior).into(), &value)
        .map_err(|e| invalid(&e.to_string()))
}

/// Only this mail endpoint accepts a mail-only signature. It cannot be used as
/// an MCP capability or carry a raw secret through a redirecting fetch API.
pub(crate) async fn respond(
    router: &crate::HostedRouter,
    request: hyper::Request<hyper::body::Incoming>,
    active: Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    use http_body_util::BodyExt;
    use hyper::{StatusCode, header};
    type Reply = hyper::Response<http_body_util::Full<hyper::body::Bytes>>;
    fn response(status: StatusCode, text: String, proof: Option<String>) -> Reply {
        let mut reply =
            hyper::Response::new(http_body_util::Full::new(hyper::body::Bytes::from(text)));
        *reply.status_mut() = status;
        reply.headers_mut().insert(
            header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        if let Some(proof) = proof.and_then(|p| hyper::header::HeaderValue::from_str(&p).ok()) {
            reply.headers_mut().insert("x-se-mail-proof", proof);
        }
        reply
    }
    let method = request.method().as_str().to_owned();
    let one = |name: &str| -> Result<String> {
        let mut values = request.headers().get_all(name).iter();
        let value = values
            .next()
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| invalid("one bounded mail authentication header"))?;
        if values.next().is_some() || value.len() > 128 {
            return Err(invalid("one bounded mail authentication header"));
        }
        Ok(value.to_owned())
    };
    let fields = (|| -> Result<_> {
        if request.headers().contains_key(header::AUTHORIZATION) {
            return Err(invalid("one mail authentication scheme"));
        }
        Ok((
            one("x-se-mail-session")?.parse::<SessionId>()?,
            one("x-se-mail-nonce")?,
            one("x-se-mail-time")?,
            one("x-se-mail-proof")?,
        ))
    })();
    let (session, nonce, issued, proof) = match fields {
        Ok(fields) => fields,
        Err(_) => return response(StatusCode::UNAUTHORIZED, "{}".into(), None),
    };
    let after = match request.headers().get("last-event-id") {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|s| se_types::Cursor::new(s).ok())
        {
            Some(cursor) => Some(cursor.as_str().to_owned()),
            None => return response(StatusCode::BAD_REQUEST, "{}".into(), None),
        },
        None => None,
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(10),
        http_body_util::Limited::new(request.into_body(), 64).collect(),
    )
    .await
    {
        Ok(Ok(body)) => match String::from_utf8(body.to_bytes().to_vec()) {
            Ok(body) => body,
            Err(_) => return response(StatusCode::BAD_REQUEST, "{}".into(), None),
        },
        _ => return response(StatusCode::BAD_REQUEST, "{}".into(), None),
    };
    let auth = match router
        .execution
        .mail_waits
        .bells
        .authenticate(session, nonce, &issued, &proof, &method, &body)
    {
        Ok(auth) => auth,
        Err(_) => return response(StatusCode::UNAUTHORIZED, "{}".into(), None),
    };
    let result = async {
        let deadline =
            crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                expected_generation: None,
                timeout: Duration::from_secs(30),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })?;
        if method == "GET" && body.is_empty() {
            return serde_json::to_value(
                router
                    .next_mail(auth.bearer.clone(), after, active, &deadline)
                    .await?,
            )
            .map_err(|_| invalid("encodable bounded mail page"));
        }
        if method != "POST" {
            return Err(invalid("GET wait or POST hold transition"));
        }
        let page = router.mail_page(auth.bearer.clone(), &deadline).await?;
        if page.session != auth.session {
            return Err(invalid("the exact authenticated recipient session"));
        }
        let action: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| invalid("one bounded hold transition"))?;
        let reason = action.get("hold").and_then(|v| v.as_str());
        let is_hold = matches!(reason, Some("human-stop" | "session-end" | "revocation"));
        let resume = action == serde_json::json!({"resume":true});
        if (!is_hold && !resume) || (is_hold && action != serde_json::json!({"hold":reason})) {
            return Err(invalid("one explicit hold or resume transition"));
        }
        set_hold(&auth.hold, is_hold, reason)?;
        router.execution.mail_waits.interrupt(&auth.session)?;
        Ok(serde_json::json!({"held":is_hold}))
    }
    .await;
    let (status, value) = match result {
        Ok(value) => (StatusCode::OK, value),
        Err(error) => (
            StatusCode::CONFLICT,
            serde_json::json!({"error":error.body}),
        ),
    };
    let text = match serde_json::to_string(&value) {
        Ok(text) => text,
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "{}".into(), None),
    };
    let signed = auth.response_mac(status.as_u16(), &text).ok();
    response(status, text, signed)
}
impl Authenticated {
    pub(crate) fn response_mac(&self, status: u16, body: &str) -> Result<String> {
        mac(
            &self.key,
            &format!(
                "se.claude.mail.response/v1\n{}\n{}\n{status}\n{body}",
                self.session, self.nonce
            ),
        )
        .map(|value| hex(&value))
    }
}
fn decode(text: &str) -> Result<Vec<u8>> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("a 32-byte hexadecimal proof"));
    }
    (0..32)
        .map(|n| {
            u8::from_str_radix(&text[n * 2..n * 2 + 2], 16)
                .map_err(|_| invalid("a hexadecimal proof"))
        })
        .collect()
}
