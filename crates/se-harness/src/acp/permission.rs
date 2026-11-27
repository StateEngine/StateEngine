//! Permission choices stay attached to their original request. An uncertain
//! response is never retried as another approval.
use super::failure;
use se_types::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Whether the ACP client advertises and answers `fs/write_text_file` inside
/// the session's workspace. Derived from the saved profile's sandbox, never
/// from a protocol suggestion. This bounds only StateEngine's client callbacks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WorkspaceAccess {
    #[default]
    ReadOnly,
    ReadWrite,
}
impl WorkspaceAccess {
    pub fn from_saved_sandbox(sandbox: se_config::config_policy::EffectiveSandbox) -> Self {
        match sandbox {
            se_config::config_policy::EffectiveSandbox::ReadOnly => Self::ReadOnly,
            se_config::config_policy::EffectiveSandbox::WorkspaceWrite
            | se_config::config_policy::EffectiveSandbox::Bypass => Self::ReadWrite,
        }
    }
    pub fn allows_write(self) -> bool {
        matches!(self, Self::ReadWrite)
    }
}

/// Answers permission RPCs; this does not establish a filesystem or network
/// sandbox. Construct this from the saved profile, never a protocol suggestion.
#[derive(Clone, Copy)]
pub enum PermissionPolicy {
    NeverAsk,
    Refuse,
}
impl PermissionPolicy {
    pub fn from_saved_approval(approval: se_config::config_policy::Approval) -> Self {
        match approval {
            se_config::config_policy::Approval::Never => Self::NeverAsk,
            _ => Self::Refuse,
        }
    }
    /// Surface at launch and in status; protocol permissions are not containment.
    pub fn notice(self) -> &'static str {
        match self {
            Self::NeverAsk => {
                "StateEngine adds no execution sandbox. The selected harness owns permissions and sandboxing. The saved never-ask profile allows its protocol permission requests."
            }
            Self::Refuse => {
                "StateEngine adds no execution sandbox. The selected harness owns permissions and sandboxing. Protocol permission requests are refused because this headless session cannot collect approval."
            }
        }
    }
}
#[derive(Clone, Serialize)]
pub struct PermissionRefusal {
    pub request: u64,
    pub reason: &'static str,
}
#[derive(Clone, Serialize)]
pub struct PermissionOption {
    pub id: String,
    pub name: String,
    pub kind: String,
}
#[derive(Clone, Serialize)]
pub struct PermissionView {
    pub request: u64,
    pub tool: Value,
    pub options: Vec<PermissionOption>,
    pub response_uncertain: bool,
}
pub(super) struct Permission {
    pub id: Value,
    pub view: PermissionView,
}
impl Permission {
    pub fn parse(number: u64, id: Value, params: &Value) -> Result<Self> {
        let tool = params
            .get("toolCall")
            .filter(|v| v.is_object())
            .ok_or_else(|| failure("ACP permission", "original tool call is absent"))?
            .clone();
        let encoded =
            serde_json::to_vec(params).map_err(|_| failure("ACP permission", "invalid request"))?;
        if encoded.len() > 64 * 1024 {
            return Err(failure(
                "ACP permission",
                "request exceeds 64 KiB; no truncated choice accepted",
            ));
        }
        let values = params
            .get("options")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty() && v.len() <= 32)
            .ok_or_else(|| failure("ACP permission", "one to 32 original options required"))?;
        let mut ids = BTreeSet::new();
        let mut options = Vec::new();
        for value in values {
            let id = bounded(value, "optionId", 512)?;
            let name = bounded(value, "name", 4096)?;
            let kind = bounded(value, "kind", 64)?;
            if !ids.insert(id.clone())
                || !matches!(
                    kind.as_str(),
                    "allow_once" | "allow_always" | "reject_once" | "reject_always"
                )
            {
                return Err(failure("ACP permission", "duplicate or unknown option"));
            }
            options.push(PermissionOption { id, name, kind });
        }
        Ok(Self {
            id,
            view: PermissionView {
                request: number,
                tool,
                options,
                response_uncertain: false,
            },
        })
    }
    pub fn automatic(&self, policy: PermissionPolicy) -> (Value, Option<&'static str>) {
        let (kinds, reason): (&[&str], _) = match policy {
            // A never-ask profile approves this one call. A persistent allow
            // would change the harness's own future policy, so it is not chosen.
            PermissionPolicy::NeverAsk => (&["allow_once"], None),
            PermissionPolicy::Refuse => (
                &["reject_once", "reject_always"],
                Some(
                    "The saved profile requires approval; no approval path is available. This tool call was refused.",
                ),
            ),
        };
        for kind in kinds {
            if let Some(option) = self.view.options.iter().find(|v| v.kind == *kind) {
                return (selected(&option.id), reason);
            }
        }
        let persistent_only = self.view.options.iter().any(|v| v.kind == "allow_always");
        (
            cancelled(),
            reason.or(Some(if persistent_only {
                "The harness offered only a persistent allow, which would change its own future policy; this tool call was refused. Set the harness's native permission level instead."
            } else {
                "The harness offered no allow option; this tool call was refused."
            })),
        )
    }
    pub fn select(&mut self, option: Option<&str>) -> Result<Value> {
        if self.view.response_uncertain {
            return Err(failure(
                "ACP permission",
                "original response remains uncertain; do not replay",
            ));
        }
        let response = match option {
            Some(option) if self.view.options.iter().any(|v| v.id == option) => selected(option),
            Some(_) => {
                return Err(failure(
                    "ACP permission",
                    "choice is not an original offered option",
                ));
            }
            None => cancelled(),
        };
        self.view.response_uncertain = true;
        Ok(response)
    }
}
fn bounded(value: &Value, field: &str, cap: usize) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= cap)
        .map(str::to_owned)
        .ok_or_else(|| failure("ACP permission", "bounded option fields required"))
}
fn selected(id: &str) -> Value {
    json!({"outcome":{"outcome":"selected","optionId":id}})
}
fn cancelled() -> Value {
    json!({"outcome":{"outcome":"cancelled"}})
}
