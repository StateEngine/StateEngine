use super::{
    Acceptance, CapabilityRepair, NoticeBinding, ServiceIdentity, registration_fields, unreadable,
};
use crate::client::lease::Deadline;
use reqwest::{Method, Url};
use se_types::{Result, Secret};
use serde_json::Value;
use std::{collections::BTreeSet, io::Read, path::Path, sync::Arc};

fn transport_reason(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut reason = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        reason.push_str(": ");
        reason.push_str(&cause.to_string());
        source = cause.source();
    }
    reason
}

fn private_reason(reason: impl AsRef<str>, secret: &str, body: Option<&Value>) -> String {
    let mut reason = reason.as_ref().replace(secret, "[credential]");
    if let Some(capability) = body
        .and_then(|body| body.get("capability"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        reason = reason.replace(capability, "[capability]");
    }
    reason
}

/// Authenticated loopback-only reader/control. No ambient proxies, redirects,
/// credential-bearing URLs, implicit retries or alternate endpoints are used.
pub struct Control {
    endpoint: Url,
    credential: Arc<Secret>,
    client: reqwest::Client,
}
impl Control {
    pub fn open(profile: &Path, endpoint: &str) -> Result<Self> {
        let endpoint = Url::parse(endpoint).map_err(|e| unreadable("SE Code endpoint", e))?;
        let loopback = endpoint
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|address| address.is_loopback());
        if !loopback
            || endpoint.scheme() != "http"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || endpoint
                .port_or_known_default()
                .is_none_or(|port| port == 0)
        {
            return Err(unreadable(
                "SE Code endpoint",
                "an exact loopback HTTP origin without credentials or routing suffixes is required",
            ));
        }
        let files = se_proc::NativeProfileFiles::open(profile)
            .map_err(|e| unreadable("SE Code private profile", e))?;
        let mut file = files
            .readback(&profile.join("basic.credential"))
            .map_err(|e| unreadable("SE Code credential", e))?
            .ok_or_else(|| {
                unreadable("SE Code credential", "private service credential is absent")
            })?;
        let mut credential = zeroize::Zeroizing::new(Vec::new());
        Read::by_ref(&mut file)
            .take(513)
            .read_to_end(&mut credential)
            .map_err(|e| unreadable("SE Code credential", e))?;
        if credential.last() == Some(&b'\n') {
            credential.pop();
        }
        if credential.is_empty()
            || credential.len() > 512
            || credential.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(unreadable(
                "SE Code credential",
                "invalid bounded private credential",
            ));
        }
        let text = std::str::from_utf8(&credential)
            .map_err(|_| unreadable("SE Code credential", "credential is not UTF-8"))?;
        if text
            .split_once(':')
            .is_none_or(|(user, secret)| user.is_empty() || secret.is_empty())
        {
            return Err(unreadable(
                "SE Code credential",
                "credential has no username or secret",
            ));
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            // The private service spends a finite request budget per connection.
            // Start each operation on a fresh connection rather than exhausting
            // a retained socket or retrying an unconfirmed write.
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|e| unreadable("SE Code HTTP control", e))?;
        Ok(Self {
            endpoint,
            credential: Arc::new(Secret::new(std::mem::take(&mut *credential))?),
            client,
        })
    }
    pub async fn read(&self, segments: &[&str], deadline: &Deadline) -> Result<Value> {
        self.request(Method::GET, segments, None, deadline).await
    }
    pub async fn request(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<&Value>,
        deadline: &Deadline,
    ) -> Result<Value> {
        self.request_query(method, segments, body, &[], deadline)
            .await
    }
    pub async fn messages(
        &self,
        session: &str,
        cursor: Option<&str>,
        deadline: &Deadline,
    ) -> Result<Value> {
        let mut query = vec![("limit", "100")];
        if let Some(cursor) = cursor {
            if cursor.len() > 1024 {
                return Err(unreadable(
                    "SE Code message cursor",
                    "cursor exceeds one KiB",
                ));
            }
            query.push(("cursor", cursor));
        } else {
            query.push(("order", "asc"));
        }
        self.request_query(
            Method::GET,
            &["api", "session", session, "message"],
            None,
            &query,
            deadline,
        )
        .await
    }
    async fn request_query(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<&Value>,
        query: &[(&str, &str)],
        deadline: &Deadline,
    ) -> Result<Value> {
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .map_err(|_| unreadable("SE Code route", "origin cannot accept a route"))?
            .clear()
            .extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let credential = std::str::from_utf8(self.credential.expose())
            .map_err(|_| unreadable("SE Code credential", "invalid retained encoding"))?;
        let (username, secret) = credential
            .split_once(':')
            .ok_or_else(|| unreadable("SE Code credential", "invalid retained fields"))?;
        let operation = format!("{method} {}", url.path());
        let mut request = self
            .client
            .request(method, url)
            .basic_auth(username, Some(secret))
            .timeout(deadline.remaining()?);
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request.send().await.map_err(|e| {
            // Display omits the transport cause. Keep it without a credential-
            // bearing URL so a timeout and a refused connection remain distinct.
            unreadable(
                "SE Code authenticated control",
                private_reason(
                    format!("{operation}: {}", transport_reason(e)),
                    secret,
                    body,
                ),
            )
        })?;
        let status = response.status();
        let limit: usize = if status.is_success() {
            8 * 1024 * 1024
        } else {
            65536
        };
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| unreadable("SE Code control read", e))?
        {
            deadline.remaining()?;
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                return Err(unreadable(
                    "SE Code control read",
                    format!(
                        "HTTP {status} response exceeds its {limit}-byte bound; no prefix is accepted"
                    ),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        deadline.remaining()?;
        if !status.is_success() {
            let value = serde_json::from_slice::<Value>(&bytes).map_err(|error| unreadable("SE Code control error response",format!("HTTP {status}; structured error unreadable: {error}; retain the original operation identity")))?;
            let reason = value
                .get("message")
                .or_else(|| value.get("reason"))
                .and_then(Value::as_str)
                .filter(|reason| reason.len() <= 2048 && !reason.chars().any(char::is_control));
            let reason = private_reason(
                reason.unwrap_or("The service supplied no bounded public reason"),
                secret,
                body,
            );
            return Err(unreadable(
                "SE Code authenticated control",
                format!(
                    "{operation}: HTTP {status}: {reason}; the original operation remains unconfirmed; retain its identity for readback"
                ),
            ));
        }
        if status == reqwest::StatusCode::NO_CONTENT && bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|e| unreadable("SE Code control JSON", e))
    }
    pub async fn binding(&self, session: &str, deadline: &Deadline) -> Result<NoticeBinding> {
        let value = self
            .read(
                &["api", "session", session, "stateengine", "notice"],
                deadline,
            )
            .await?;
        let binding: NoticeBinding =
            serde_json::from_value(value).map_err(|e| unreadable("SE Code notice binding", e))?;
        binding.service.validate()?;
        if binding.session_id != session {
            return Err(unreadable(
                "SE Code notice binding",
                "the authenticated response names another session",
            ));
        }
        Ok(binding)
    }
    /// Release one retained stop exactly once. The caller persists the original
    /// coordinates first and reconciles uncertain responses through binding().
    pub async fn release_hold(&self, held: &NoticeBinding, deadline: &Deadline) -> Result<()> {
        let (target, binding, hold) = held.require_held()?;
        let value = self.request(Method::POST,
            &["api", "session", &held.session_id, "stateengine", "resume"],
            Some(&serde_json::json!({"holdID":hold,"targetID":target,"binding":binding,"service":held.service})),
            deadline).await?;
        let released: NoticeBinding =
            serde_json::from_value(value).map_err(|e| unreadable("SE Code hold release", e))?;
        released.require_released(held)
    }
    pub async fn acceptance(
        &self,
        service: &ServiceIdentity,
        session: &str,
        input: &str,
        deadline: &Deadline,
    ) -> Result<Acceptance> {
        let value = self
            .read(&["api", "session", session, "input", input], deadline)
            .await?;
        let receipt: Acceptance =
            serde_json::from_value(value).map_err(|e| unreadable("SE Code input readback", e))?;
        service.require_same(&receipt.service)?;
        Ok(receipt)
    }
    /// Offer exactly once. Callers retain an uncertain flight and query its
    /// original key; this method contains no write retry or replacement key.
    pub async fn offer_notice(
        &self,
        binding: &NoticeBinding,
        input: &str,
        messages: &[String],
        deadline: &Deadline,
    ) -> Result<Acceptance> {
        let (target, fingerprint) = binding.require_ready()?;
        let unique: BTreeSet<_> = messages.iter().collect();
        if messages.is_empty()
            || messages.len() > 32
            || unique.len() != messages.len()
            || messages
                .iter()
                .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(unreadable(
                "SE Code notice",
                "one to thirty-two distinct bounded committed source IDs are required",
            ));
        }
        let body = serde_json::json!({
            "id":input,"targetID":target,"binding":fingerprint,"messages":messages,
            "incarnation":binding.service.incarnation,"serviceInstance":binding.service.service_instance,
            "generation":binding.service.generation,"registrationVersion":binding.service.registration_version,
        });
        let value = self
            .request(
                Method::POST,
                &[
                    "api",
                    "session",
                    &binding.session_id,
                    "stateengine",
                    "notice",
                ],
                Some(&body),
                deadline,
            )
            .await?;
        let receipt: Acceptance = serde_json::from_value(value)
            .map_err(|e| unreadable("SE Code notice acceptance", e))?;
        binding.service.require_same(&receipt.service)?;
        Ok(receipt)
    }
}

pub(crate) fn service_registration(profile: &std::path::Path) -> Result<Option<Vec<u8>>> {
    let path = profile.join("registration");
    let Some(mut pin) = se_proc::NativeSourcePin::open(&path)
        .map_err(|e| unreadable("SE Code registration read", e))?
    else {
        return Ok(None);
    };
    let raw = pin
        .read_at(0, 8513)
        .map_err(|e| unreadable("SE Code registration read", e))?;
    if !raw.end_of_file || raw.bytes.len() > 8512 {
        return Err(unreadable(
            "SE Code registration read",
            "registration exceeds its complete-read bound",
        ));
    }
    pin.validate_path(&path)
        .map_err(|e| unreadable("SE Code registration custody", e))?;
    registration_fields(&raw.bytes)?;
    Ok(Some(raw.bytes))
}

impl CapabilityRepair {
    pub(crate) async fn apply(
        mut self,
        control: &Control,
        credential: &Secret,
        config: &Path,
        deadline: &Deadline,
    ) -> Result<Self> {
        let session = self.before.session_id.as_str();
        let sent: Result<()> = async {
            let capability = std::str::from_utf8(credential.expose())
                .map_err(|cause| unreadable("SE Code capability", cause))?;
            let config = config.to_str().ok_or_else(|| {
                unreadable(
                    "SE Code policy binding",
                    "the control API requires a UTF-8 path",
                )
            })?;
            control
                .request(
                    Method::PUT,
                    &["api", "session", session, "stateengine", "capability"],
                    Some(&serde_json::json!({"capability":capability,"configPath":config})),
                    deadline,
                )
                .await
                .map(drop)
        }
        .await;
        let observed = control.binding(session, deadline).await.and_then(|after| {
            self.before.service.require_same(&after.service)?;
            after.require_bound()?;
            Ok(after)
        });
        self.after = Some(match (sent, observed) {
            (Ok(()), Ok(after)) => after,
            (Err(write), Ok(after)) => {
                self.write_failure = Some(write.body);
                after
            }
            (Err(write), Err(read)) => return Err(read.with_cause(write)),
            (Ok(_), Err(read)) => return Err(read),
        });
        Ok(self)
    }
}
