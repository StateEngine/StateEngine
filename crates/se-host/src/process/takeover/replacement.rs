//! Stop the original selection, retain achieved effects, then launch once.
use super::*;
impl LaunchCoordinator {
    pub(super) async fn replace_selected(
        self: &Arc<Self>,
        plan: LaunchPlan,
        admission: Admission,
        deadline: &Deadline,
        stopped: Stopped,
    ) -> Result<AnyOutput> {
        let mut reports = stopped.lock().await;
        let mut failures = Vec::new();
        let embedded = self
            .retire_embedded_bindings(
                &plan.control,
                &plan.agent.id,
                &plan.input.idempotency_key,
                &admission,
                deadline,
            )
            .await?;
        let mut records = plan.control.processes.clone();
        // A terminal native record can still need session/capture
        // cleanup after a previous host stopped between barriers.
        if records.is_empty()
            && embedded.is_empty()
            && let se_types::Read::Present { value } = &plan.control.latest_process
        {
            records.push(value.clone());
        }
        for record in records {
            let lifecycle = process_identity(&record)?.record.clone();
            if reports.contains_key(&lifecycle) {
                continue;
            }
            let mut selected = plan.clone();
            selected.control.processes = vec![record.clone()];
            selected.control.latest_process = se_types::Read::Present { value: record };
            match self
                .inspect_takeover(&selected, &admission, deadline, true)
                .await
            {
                Ok(report) => {
                    reports.insert(lifecycle, report);
                }
                Err(failure) => failures.push(format!("{lifecycle}: {failure}")),
            }
        }
        if !failures.is_empty() {
            return Err(error(
                "takeover incomplete",
                format!(
                    "{} original lifecycles closed; unresolved: {}. No successor launched; retry this same --force request and key.",
                    reports.len(),
                    failures.join("; ")
                ),
            ));
        }
        let report = combine_reports(
            reports
                .values()
                .cloned()
                .chain(embedded.iter().map(|binding| binding.report()))
                .collect(),
        )?;
        let input = plan.input.clone();
        let seed = plan.seed.clone();
        let configuration = self.options.configuration.clone();
        let mut next = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                let mut facts = crate::runtime::start::allocate_facts()?;
                facts.event = seed;
                se_core::ops::process_plan::launch(
                    &se_core::dispatch::Kernel::new(facts)?,
                    input,
                    &configuration,
                    cx,
                )
            })
            .await
            .map_err(|failure| successor_failure(&report, failure))?;
        if report.new_conversation {
            next.start_new_conversation("Forced relaunch preserved the previous history and starts a new conversation because the previous service was forcibly retired or final capture remained unavailable.".into());
        }
        self.preflight_relaunch(&mut next, &admission, deadline)
            .await
            .map_err(|failure| successor_failure(&report, failure))?;
        // This is continuation of the already admitted self launch,
        // scoped to its newly allocated session, never owner authority.
        // Old credentials remain revoked; no later request can reuse them.
        let mut successor_admission = admission;
        if matches!(&successor_admission.actor, se_store::Actor::Agent(agent) if agent == &next.agent.id)
        {
            successor_admission.session = Some(next.session.clone());
        }
        self.launch_prepared(next, successor_admission, deadline, Some(report.clone()))
            .await
            .map_err(|failure| successor_failure(&report, failure))
            .map(AnyOutput::from)
    }
}
