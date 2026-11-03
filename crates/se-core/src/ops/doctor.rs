//! Diagnosis and one-check repair policy. Native observations and effects belong to adapters.
use super::{Named, inputs::Validate};
use schemars::JsonSchema;
use se_types::{Detail, ProjectId, Result, SeError, details};
use serde::{Deserialize, Serialize};
mod plan;
pub use plan::*;

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorInspect {}
impl Validate for DoctorInspect {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorRepair {
    pub check_id: String,
}
impl Validate for DoctorRepair {
    fn validate(&self) -> Result<()> {
        super::inputs::bounded("check_id", &self.check_id, 1024, false)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CheckState {
    Ok,
    Failed,
    Warning,
    Unmeasured,
    Skipped,
    NotApplicable,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CheckFix {
    pub text: String,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosisCheck {
    pub id: String,
    pub title: String,
    pub state: CheckState,
    pub measured_at: Option<String>,
    pub observed: Option<String>,
    pub expected: Option<String>,
    pub reason: Option<String>,
    pub code: Option<String>,
    pub fix: Option<CheckFix>,
    pub repairable: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosisSummary {
    pub ok: u32,
    pub failed: u32,
    pub warning: u32,
    pub unmeasured: u32,
    pub skipped: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosisScope {
    pub home: String,
    pub project: Option<Named<ProjectId>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Diagnosis {
    pub generated_at: String,
    pub scope: DiagnosisScope,
    pub outcome: String,
    pub summary: DiagnosisSummary,
    pub checks: Vec<DiagnosisCheck>,
}
impl Diagnosis {
    pub fn new(
        generated_at: String,
        scope: DiagnosisScope,
        checks: Vec<DiagnosisCheck>,
    ) -> Result<Self> {
        let mut ids = std::collections::BTreeSet::new();
        let mut summary = DiagnosisSummary::default();
        for check in &checks {
            if !ids.insert(&check.id) || check.id.is_empty() {
                return Err(SeError::invalid(
                    "doctor checks",
                    "unique nonempty check IDs",
                ));
            }
            match check.state {
                CheckState::Ok => summary.ok += 1,
                CheckState::Failed => summary.failed += 1,
                CheckState::Warning => summary.warning += 1,
                CheckState::Unmeasured => summary.unmeasured += 1,
                CheckState::Skipped => summary.skipped += 1,
                CheckState::NotApplicable => (),
            }
        }
        let outcome = if summary.failed > 0 {
            "problems"
        } else if summary.unmeasured > 0 {
            "incomplete"
        } else if summary.warning > 0 {
            "warnings"
        } else {
            "healthy"
        };
        Ok(Self {
            generated_at,
            scope,
            outcome: outcome.into(),
            summary,
            checks,
        })
    }
    pub fn exit_code(&self) -> u8 {
        if self.summary.failed > 0 {
            1
        } else if self.summary.unmeasured > 0 {
            2
        } else {
            0
        }
    }
    pub fn repair_check(&self, id: &str) -> Result<&DiagnosisCheck> {
        let check = self
            .checks
            .iter()
            .find(|check| check.id == id)
            .ok_or_else(|| refused(id, "this ID is not in the current diagnosis"))?;
        if !check.repairable || !matches!(check.state, CheckState::Failed | CheckState::Warning) {
            return Err(refused(
                id,
                "the current check has no supported repair to apply",
            ));
        }
        Ok(check)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RepairFact {
    pub subject: String,
    pub outcome: String,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RepairOutput {
    pub check_id: String,
    pub plan: RepairPlan,
    pub complete: bool,
    pub applied: Vec<RepairFact>,
    pub skipped: Vec<RepairFact>,
    pub readbacks: Vec<RepairFact>,
    pub remaining_checks: Vec<DiagnosisCheck>,
}
pub fn refused(id: &str, reason: &str) -> SeError {
    SeError::new(Detail::RepairRefused(details::RepairRefused {
        subject:id.into(),reason:reason.into(),
        next_step:"Run se doctor for this same data home and select one currently diagnosed repairable CHECK-ID; restore and credential rotation are separate owner actions".into(),
    }))
}
