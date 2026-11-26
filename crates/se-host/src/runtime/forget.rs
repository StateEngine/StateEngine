//! Owner erasure: plan first, then erase on the authoritative writer only after
//! the owner confirms the printed plan. The CLI already proved human presence.
use super::{ExecutionContext, executor};
use crate::client::lease::Deadline;
use se_core::{
    ops::{
        AnyOutput, ErasureReceipt, StoreForget,
        store_forget::{
            BoundCopy, ForgetNext, ForgetResidual, ForgetTarget, confirm, exact_path, plan_digest,
        },
    },
    scope,
    store_error::store_error,
};
use se_store::*;
use se_types::Result;

/// A plan's receipt, or a completed one with what the erasure actually committed.
fn receipt(input: &StoreForget, plan: &ErasurePlan, outcome: &str) -> Result<ErasureReceipt> {
    let targets: Vec<ForgetTarget> = plan
        .targets
        .iter()
        .map(|t| ForgetTarget {
            event: t.event.clone(),
            revision: t.expected.value.get(),
        })
        .collect();
    let shown: Vec<String> = plan
        .residuals
        .iter()
        .map(|r| Ok(r.location.to_local()?.display().to_string()))
        .collect::<Result<_>>()?;
    // A path shown like a different one also names its exact form, so the owner
    // can tell apart the copies the digest binds.
    let residuals: Vec<ForgetResidual> = plan
        .residuals
        .iter()
        .zip(&shown)
        .map(|(r, text)| {
            let alike = plan
                .residuals
                .iter()
                .zip(&shown)
                .any(|(other, other_text)| other_text == text && other.location != r.location);
            ForgetResidual {
                custodian: r.custodian.clone(),
                location: if alike {
                    format!("{text} (exact path {})", exact_path(&r.location))
                } else {
                    text.clone()
                },
                reason: r.reason.clone(),
            }
        })
        .collect();
    let bound: Vec<BoundCopy<'_>> = plan
        .residuals
        .iter()
        .map(|r| BoundCopy {
            custodian: &r.custodian,
            location: &r.location,
            reason: &r.reason,
        })
        .collect();
    Ok(ErasureReceipt {
        idempotency_key: input.idempotency_key.clone(),
        outcome: outcome.into(),
        erasure: se_types::hex_lower(plan.id.as_bytes()),
        plan: plan_digest(&targets, &bound),
        targets,
        backups_replaced: plan.owned_generations.len(),
        required_bytes: plan.required_bytes,
        unlisted: se_core::ops::store_forget::UNLISTED.into(),
        residuals,
        completed_event: None,
        next: None,
    })
}
async fn fresh_plan(context: &ExecutionContext, input: &StoreForget) -> Result<ErasurePlan> {
    let planning = context.writer.erasure_plan(input.events.clone());
    planning
        .map_err(|e| store_error(&e))?
        .await
        .map_err(|e| store_error(&e))
}
pub(super) async fn execute(
    context: ExecutionContext,
    input: StoreForget,
    admission: Admission,
    deadline: &Deadline,
) -> Result<AnyOutput> {
    let owner = match (&admission.actor, admission.session.is_none()) {
        (Actor::Human(owner), true) => owner.clone(),
        _ => {
            return Err(scope::unreadable(
                "forget",
                "the verified owner at a human terminal is required",
            ));
        }
    };
    let incarnation = context
        .run_foreground(deadline, |context| {
            executor::check_generation(&context.reader, context.generation)?;
            Ok(context
                .reader
                .info()
                .map_err(|e| store_error(&e))?
                .incarnation)
        })
        .await?;
    let plan = fresh_plan(&context, &input).await?;
    let mut planned = receipt(&input, &plan, "planned")?;
    // `--yes` confirms the plan the owner saw, by its digest; any other plan is shown instead.
    if !input.yes || input.plan.as_deref() != Some(planned.plan.as_str()) {
        let next = confirm(&input, &planned.plan);
        planned.next = Some(match (input.yes, &input.plan) {
            (false, _) => next,
            (true, None) => ForgetNext {
                text: "Nothing was erased: --yes confirms a printed plan by its digest. Review this plan, then confirm".into(),
                argv: next.argv,
            },
            (true, Some(_)) => ForgetNext {
                text: "Nothing was erased: the plan changed since the one you confirmed. Review it, then confirm".into(),
                argv: next.argv,
            },
        });
        return Ok(planned.into());
    }
    let approval = ErasureApproval {
        erasure: plan.id,
        owner,
        expected_incarnation: incarnation,
        // No delivery buffer reports a readback witness; residuals are named instead.
        buffer_witnesses: Vec::new(),
        accept_named_residuals: true,
    };
    let erasing = context
        .writer
        .erase(plan.clone(), approval)
        .map_err(|e| store_error(&e))?;
    let report = match erasing.await {
        Ok(report) => report,
        // Nothing was erased: show the changed copies and ask again.
        Err(error) if error.code == StoreErrorCode::ErasurePlanChanged => {
            let mut planned = receipt(&input, &fresh_plan(&context, &input).await?, "planned")?;
            planned.next = Some(ForgetNext {
                text: "Nothing was erased: the copies StateEngine cannot erase changed since planning. Review them above, then confirm".into(),
                argv: confirm(&input, &planned.plan).argv,
            });
            return Ok(planned.into());
        }
        Err(error) => return Err(store_error(&error)),
    };
    // Report what the erasure committed and observed, not the plan's estimate.
    let committed = ErasurePlan {
        residuals: report.residuals.clone(),
        ..plan
    };
    let mut done = receipt(
        &input,
        &committed,
        if report.cleanup_complete {
            "forgotten"
        } else {
            "incomplete"
        },
    )?;
    done.backups_replaced = report.backups_replaced;
    done.completed_event = report.completed_event;
    if !report.cleanup_complete {
        let cause = report
            .cleanup_failure
            .map_or_else(String::new, |cause| format!(" ({cause})"));
        done.next = Some(ForgetNext {
            text: format!(
                "The bodies are erased, but a database or backup copy could not be replaced yet{cause}; repeat this command to finish"
            ),
            argv: confirm(&input, &done.plan).argv,
        });
    }
    Ok(done.into())
}
