//! Owner erasure: plan first, then erase on the authoritative writer only after
//! the owner confirms the printed plan. The CLI already proved human presence.
use super::{ExecutionContext, executor};
use crate::client::lease::Deadline;
use se_core::{
    ops::{
        AnyOutput, ErasureReceipt, StoreForget,
        store_forget::{ForgetNext, ForgetResidual, ForgetTarget, confirm},
    },
    scope,
    store_error::store_error,
};
use se_store::*;
use se_types::Result;

fn receipt(input: &StoreForget, plan: &ErasurePlan, outcome: &str) -> Result<ErasureReceipt> {
    Ok(ErasureReceipt {
        idempotency_key: input.idempotency_key.clone(),
        outcome: outcome.into(),
        erasure: se_types::hex_lower(plan.id.as_bytes()),
        targets: plan
            .targets
            .iter()
            .map(|t| ForgetTarget {
                event: t.event.clone(),
                revision: t.expected.value.get(),
            })
            .collect(),
        backups_replaced: plan.owned_generations.len(),
        required_bytes: plan.required_bytes,
        unlisted: se_core::ops::store_forget::UNLISTED.into(),
        residuals: plan
            .residuals
            .iter()
            .map(|r| {
                Ok(ForgetResidual {
                    custodian: r.custodian.clone(),
                    location: r.location.to_local()?.display().to_string(),
                    reason: r.reason.clone(),
                })
            })
            .collect::<Result<_>>()?,
        completed_event: None,
        next: None,
    })
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
    let planning = context
        .writer
        .erasure_plan(input.events.clone())
        .map_err(|e| store_error(&e))?;
    let plan = planning.await.map_err(|e| store_error(&e))?;
    if !input.yes {
        let mut planned = receipt(&input, &plan, "planned")?;
        planned.next = Some(confirm(&input));
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
    let report = erasing.await.map_err(|e| store_error(&e))?;
    let mut done = receipt(
        &input,
        &plan,
        if report.cleanup_complete {
            "forgotten"
        } else {
            "incomplete"
        },
    )?;
    done.completed_event = report.completed_event;
    if !report.cleanup_complete {
        done.next = Some(ForgetNext {
            text: "The bodies are erased, but a database or backup copy could not be replaced yet; repeat this command to finish".into(),
            argv: confirm(&input).argv,
        });
    }
    Ok(done.into())
}
