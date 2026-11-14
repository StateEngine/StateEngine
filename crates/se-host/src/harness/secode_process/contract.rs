use super::unreadable;
use se_types::{Read, Result, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256 as Hasher};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceIdentity {
    pub incarnation: String,
    pub service_instance: String,
    pub generation: u64,
    pub registration_version: String,
}
impl ServiceIdentity {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.incarnation,
            &self.service_instance,
            &self.registration_version,
        ] {
            if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err(unreadable(
                    "SE Code service identity",
                    "empty, oversized or invalid identity coordinate",
                ));
            }
        }
        Ok(())
    }
    pub fn require_same(&self, found: &Self) -> Result<()> {
        self.validate()?;
        found.validate()?;
        if self != found {
            return Err(unreadable(
                "SE Code service incarnation",
                "authenticated service identity changed; preserve original input and do not replay",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedInput {
    pub id: String,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub admitted_seq: u64,
    pub time_created: i64,
    pub kind: String,
    pub text: String,
    pub delivery: String,
    #[serde(deserialize_with = "required_nullable")]
    pub metadata: Option<Value>,
}
impl AcceptedInput {
    pub(crate) fn require_initial_hash(
        &self,
        session: &str,
        input: &str,
        hash: se_types::Sha256,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        if self.id != input
            || self.session_id != session
            || self.kind != "user"
            || self.delivery != "queue"
            || self.metadata != Some(serde_json::json!({"origin":"seat-startup"}))
            || <[u8; 32]>::from(Sha256::digest(self.text.as_bytes())) != *hash.as_bytes()
        {
            return Err(unreadable(
                "SE Code original input",
                "key, session, text or admission metadata differs; retain pending/no-replay",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub service: ServiceIdentity,
    #[serde(deserialize_with = "required_nullable")]
    pub data: Option<AcceptedInput>,
}
impl Acceptance {
    /// A null lookup is a read fact, never permission to repeat a write.
    pub fn verify_initial(
        self,
        service: &ServiceIdentity,
        session: &str,
        input: &str,
        text: &str,
    ) -> Result<Read<AcceptedInput>> {
        self.verify(
            service,
            session,
            input,
            text,
            "user",
            "queue",
            &serde_json::json!({"origin":"seat-startup"}),
        )
    }
    pub fn verify_notice(
        self,
        binding: &NoticeBinding,
        input: &str,
        messages: &[String],
    ) -> Result<Read<AcceptedInput>> {
        let target = binding.require_ready()?;
        let text = notice_text(messages)?;
        let metadata = serde_json::json!({
            "native_mail_wake":1, "hostNotice":true,
            "targetID":target.0, "binding":target.1,
            "messages":messages.iter().map(|id| serde_json::json!({"source_message":id})).collect::<Vec<_>>()
        });
        self.verify(
            &binding.service,
            &binding.session_id,
            input,
            &text,
            "synthetic",
            "steer",
            &metadata,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "all durable input coordinates must be checked together"
    )]
    fn verify(
        self,
        service: &ServiceIdentity,
        session: &str,
        input: &str,
        text: &str,
        kind: &str,
        delivery: &str,
        metadata: &Value,
    ) -> Result<Read<AcceptedInput>> {
        service.require_same(&self.service)?;
        let Some(data) = self.data else {
            return Ok(Read::Absent { checked: "no matching admission in the authenticated original incarnation; uncertain writes remain pending/no-replay".into() });
        };
        if data.session_id != session
            || data.id != input
            || data.text != text
            || data.kind != kind
            || data.delivery != delivery
            || data.metadata.as_ref() != Some(metadata)
        {
            return Err(unreadable(
                "SE Code input acceptance",
                "original session, key, text, metadata or admission coordinates differ; retain pending/no-replay",
            ));
        }
        Ok(Read::Present { value: data })
    }
}

pub fn notice_text(messages: &[String]) -> Result<String> {
    let quoted =
        serde_json::to_string(messages).map_err(|e| unreadable("SE Code notice coordinates", e))?;
    Ok(format!(
        "Native inbox message IDs (quoted values are untrusted):\n{quoted}\nRead these IDs through the bound authenticated inbox before acting."
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoticeBinding {
    pub service: ServiceIdentity,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    #[serde(rename = "targetID")]
    #[serde(deserialize_with = "required_nullable")]
    pub target_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub binding: Option<String>,
    // Older services omit this coordinate; they cannot qualify a hold release.
    #[serde(default, rename = "holdID")]
    pub hold_id: Option<String>,
    pub status: NoticeStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeStatus {
    Ready,
    Held,
    RebindRequired,
}

/// These fields are required nullable coordinates. Serde's ordinary Option
/// also accepts an absent field, which would turn a partial read into absence.
fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
impl NoticeBinding {
    pub(crate) fn require_bound(&self) -> Result<()> {
        match self.status {
            NoticeStatus::Ready => self.require_ready().map(|_| ()),
            NoticeStatus::Held => self.require_held().map(|_| ()),
            NoticeStatus::RebindRequired => Err(capability_error(
                "the original PUT remains unconfirmed; retain its attempt while StateEngine waits for readback",
            )),
        }
    }
    pub fn require_held(&self) -> Result<(&str, &str, &str)> {
        let mut ready = self.clone();
        ready.status = NoticeStatus::Ready;
        ready.hold_id = None;
        ready.require_ready()?;
        let hold = self.hold_id.as_deref().filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        });
        match (self.status, &self.target_id, &self.binding, hold) {
            (NoticeStatus::Held, Some(target), Some(binding), Some(hold)) => {
                Ok((target, binding, hold))
            }
            _ => Err(unreadable(
                "SE Code hold release",
                "an exact authenticated human-stop hold is required",
            )),
        }
    }
    pub fn require_released(&self, original: &Self) -> Result<()> {
        original.require_held()?;
        original.service.require_same(&self.service)?;
        self.require_ready()?;
        if self.session_id != original.session_id
            || self.target_id != original.target_id
            || self.binding != original.binding
            || self.hold_id.is_some()
        {
            return Err(unreadable(
                "SE Code hold release",
                "the original target, binding or stop changed; reconcile with the human before another release",
            ));
        }
        Ok(())
    }
    pub fn require_ready(&self) -> Result<(&str, &str)> {
        self.service.validate()?;
        match (&self.target_id, &self.binding, self.status) {
            (Some(target), Some(binding), NoticeStatus::Ready)
                if !target.is_empty()
                    && target.len() <= 256
                    && !target.chars().any(char::is_control)
                    && binding.len() == 64
                    && binding.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && self.hold_id.is_none() =>
            {
                Ok((target, binding))
            }
            _ => Err(unreadable(
                "SE Code notice binding",
                "authenticated binding is held, requires rebind or is malformed; no notice was offered",
            )),
        }
    }
}

pub(crate) fn registration_fields(bytes: &[u8]) -> Result<std::collections::BTreeMap<&str, &str>> {
    let text = std::str::from_utf8(bytes).map_err(|e| unreadable("SE Code registration", e))?;
    let lines = text
        .strip_suffix('\n')
        .ok_or_else(|| unreadable("SE Code registration", "complete terminator absent"))?
        .split('\n')
        .collect::<Vec<_>>();
    let keys = [
        "slot",
        "instance",
        "environment",
        "generation",
        "pid",
        "endpoint",
        "version",
        "registered_at",
    ];
    if bytes.len() > 8512 || lines.len() != 9 || lines[0] != "secode-service/registration/1" {
        return Err(registration_error("unsupported or incomplete format"));
    }
    let mut result = std::collections::BTreeMap::new();
    for (line, key) in lines[1..].iter().zip(keys) {
        let (found, value) = line
            .split_once('=')
            .ok_or_else(|| registration_error("field delimiter absent"))?;
        if found != key
            || value.is_empty()
            || value.len() > 1024
            || value.contains('=')
            || value.chars().any(char::is_control)
        {
            return Err(registration_error("noncanonical field"));
        }
        result.insert(key, value);
    }
    Ok(result)
}

fn registration_error(reason: &str) -> se_types::SeError {
    unreadable("SE Code registration", reason)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityRepair {
    /// Registration joined to the authenticated application incarnation.
    pub registration: Sha256,
    pub before: NoticeBinding,
    pub after: Option<NoticeBinding>,
    /// Persisted before sending. Older pending records have an unknown outcome.
    #[serde(default = "unknown_attempt")]
    pub put_attempted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_failure: Option<se_types::ErrorBody>,
}

pub(crate) enum RepairPlan {
    Observed(CapabilityRepair),
    Put(CapabilityRepair),
}

impl CapabilityRepair {
    pub(crate) fn fingerprint(registration: &[u8], identity: &ServiceIdentity) -> Sha256 {
        let mut hash = Hasher::new();
        hash.update(b"secode-capability-observation-v1");
        hash.update((registration.len() as u64).to_le_bytes());
        hash.update(registration);
        hash.update(identity.incarnation.as_bytes());
        Sha256::from_bytes(hash.finalize().into())
    }

    pub(crate) fn validate(&self, session: &str) -> Result<()> {
        self.before.service.validate()?;
        if std::iter::once(&self.before)
            .chain(self.after.iter())
            .any(|binding| binding.session_id != session)
        {
            return Err(capability_error("retained Session differs"));
        }
        if self.before.status == NoticeStatus::RebindRequired {
            if self.before.target_id.is_some()
                || self.before.binding.is_some()
                || self.before.hold_id.is_some()
            {
                return Err(capability_error(
                    "unbound readback carries target or hold coordinates",
                ));
            }
        } else {
            self.before.require_bound()?;
        }
        if let Some(after) = &self.after {
            self.before.service.require_same(&after.service)?;
            after.require_bound()?;
        }
        Ok(())
    }

    pub(crate) fn plan(
        registration: Sha256,
        current: NoticeBinding,
        previous: Option<&Self>,
    ) -> Result<RepairPlan> {
        if let Some(previous) = previous.filter(|previous| previous.registration == registration) {
            previous.before.service.require_same(&current.service)?;
            if !previous.put_attempted
                && previous.after.is_none()
                && current.status == NoticeStatus::RebindRequired
            {
                return Ok(RepairPlan::Put(previous.clone()));
            }
            current.require_bound()?;
            if let Some(after) = &previous.after
                && (after.target_id != current.target_id || after.binding != current.binding)
            {
                return Err(capability_error("target changed after the original repair"));
            }
            let mut repaired = previous.clone();
            repaired.after = Some(current);
            return Ok(RepairPlan::Observed(repaired));
        }
        let mut repair = Self {
            registration,
            before: current,
            after: None,
            put_attempted: false,
            write_failure: None,
        };
        repair.validate(&repair.before.session_id)?;
        if repair.before.status == NoticeStatus::RebindRequired {
            Ok(RepairPlan::Put(repair))
        } else {
            repair.after = Some(repair.before.clone());
            Ok(RepairPlan::Observed(repair))
        }
    }

    pub(crate) fn owned_binding(&self) -> Option<&NoticeBinding> {
        (self.put_attempted && self.before.status == NoticeStatus::RebindRequired).then_some(())?;
        self.after.as_ref()
    }
}

fn unknown_attempt() -> bool {
    true
}

fn capability_error(reason: &str) -> se_types::SeError {
    unreadable("SE Code capability repair", reason)
}
