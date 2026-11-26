//! Stop the original selection, retain achieved effects, then launch once.
use super::*;
impl LaunchCoordinator {
    pub(super) async fn replace_selected(
        self: &Arc<Self>,
        plan: LaunchPlan,
        admission: Admission,
        deadline: &Deadline,
        stopped: Stopped,
        fallback: Option<se_types::Read<se_types::ProviderSessionId>>,
    ) -> Result<AnyOutput> {
        let agent_guard = self
            .lock_agent_launch(&plan.project.id, &plan.agent.id, deadline)
            .await?;
        let mut reports = stopped.lock().await;
        let mut checked = self.replan_launch(&plan, &admission, deadline).await?;
        checked.prepare_replacement(&plan, None, false)?;
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
        let mut next = self
            .replan_launch(&plan, &admission, deadline)
            .await
            .map_err(|failure| successor_failure(&report, failure))?;
        if !next.control.processes.is_empty() || !next.control.sessions.is_empty() {
            return Err(successor_failure(
                &report,
                error(
                    "takeover race",
                    "another lifecycle or session appeared while stopping the original selection; inspect and retry",
                ),
            ));
        }
        next.prepare_replacement(&plan, fallback, report.new_conversation)
            .map_err(|failure| successor_failure(&report, failure))?;
        let successor_admission = next.successor_admission(admission);
        self.launch_prepared(
            next,
            successor_admission,
            deadline,
            Some(report.clone()),
            Some(agent_guard),
            #[cfg(feature = "remote")]
            None,
        )
        .await
        .map_err(|failure| successor_failure(&report, failure))
        .map(AnyOutput::from)
    }
    pub(crate) async fn replan_launch(
        &self,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<LaunchPlan> {
        let input = plan.input.clone();
        let seed = plan.seed.clone();
        let configuration = self.options.configuration.clone();
        self.store
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
    }
}
