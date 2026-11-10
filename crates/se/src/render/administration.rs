use se_core::ops::outputs::*;
use std::io::{self, Write};

pub fn agent(value: &AgentReceipt, out: &mut impl Write) -> io::Result<()> {
    let outcome = match value.outcome {
        AgentOutcome::Created => "created",
        AgentOutcome::Existing => "already exists",
        AgentOutcome::Renamed => "renamed",
        AgentOutcome::Unchanged => "unchanged",
    };
    writeln!(out, "Agent {}: {outcome}", value.agent.name)?;
    if matches!(value.commit.state, se_types::CommitState::Replayed) {
        writeln!(
            out,
            "Original receipt replayed; identity details reflect that recorded change."
        )?;
    }
    if let Some(previous) = &value.previous_name {
        writeln!(out, "Previous name: {previous}")?;
    }
    let provider = super::labels::provider(value.agent.provider);
    writeln!(
        out,
        "Provider: {provider}; permission profile: {}",
        value.agent.profile
    )?;
    if let Some(model) = &value.agent.model {
        writeln!(out, "Model: {model}")?;
    }
    writeln!(out, "No process started.")?;
    writeln!(
        out,
        "Event: {}; request key: {}",
        value.commit.event_id, value.commit.idempotency_key
    )
}

pub fn decision(value: &DecisionReceipt, out: &mut impl Write) -> io::Result<()> {
    let action = match value.action {
        DecisionAction::Propose => "proposed",
        DecisionAction::Ratify => "approved",
        DecisionAction::Reject => "rejected",
        DecisionAction::Retract => "withdrawn",
        DecisionAction::Supersede => "replaced",
    };
    writeln!(out, "Decision {}: {action}", value.decision.key)?;
    if matches!(value.commit.state, se_types::CommitState::Replayed) {
        writeln!(
            out,
            "Original receipt replayed; the recorded state may have changed since this event."
        )?;
    }
    writeln!(out, "{}", value.decision.statement.text)?;
    if !value.decision.statement.complete {
        if let Some(command) = &value.decision.statement.command {
            writeln!(out, "Read the full statement: {command}")?;
        } else {
            writeln!(
                out,
                "Statement preview; full text is not included in this receipt."
            )?;
        }
    }
    if let Some(reason) = &value.decision.reason {
        writeln!(out, "Reason: {reason}")?;
    }
    if let Some(previous) = &value.replaced {
        writeln!(out, "Replaced decision: {} ({})", previous.key, previous.id)?;
    }
    writeln!(
        out,
        "Decision: {}; recorded revision {}",
        value.decision.id, value.decision.revision
    )?;
    writeln!(
        out,
        "Event: {}; request key: {}",
        value.commit.event_id, value.commit.idempotency_key
    )
}

pub fn config(value: &AgentConfigReceipt, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{} for {}", value.key, value.agent.name)?;
    writeln!(out, "Value: {}", value.value)?;
    writeln!(out, "Previous: {}", value.previous.value)?;
    let source = match value.previous.source {
        se_types::ConfigPreviousSource::Stored => "stored",
        se_types::ConfigPreviousSource::Default => "default",
    };
    writeln!(out, "Previous source: {source}")?;
    writeln!(
        out,
        "Recorded revision {}; current revision {}",
        value.revision, value.current_revision
    )?;
    if matches!(value.commit.state, se_types::CommitState::Replayed) {
        writeln!(
            out,
            "Original receipt replayed; the value above belongs to that recorded change."
        )?;
    }
    writeln!(
        out,
        "Event: {}; request key: {}",
        value.commit.event_id, value.commit.idempotency_key
    )
}
pub fn config_value(value: &ConfigValueOutput, out: &mut impl Write) -> io::Result<()> {
    match &value.value {
        se_types::Read::Present { value: setting } => writeln!(out, "{}: {setting}", value.key)?,
        se_types::Read::Absent { checked } => writeln!(out, "{}: absent ({checked})", value.key)?,
        se_types::Read::Unreadable { source, reason, .. } => {
            writeln!(out, "{}: unreadable at {source}: {reason}", value.key)?
        }
        se_types::Read::Unknown { what } => writeln!(out, "{}: unknown ({what})", value.key)?,
    }
    if let Some(origin) = &value.origin {
        writeln!(out, "Source: {origin}")?;
    }
    Ok(())
}
pub fn config_page(value: &ConfigPageOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Effective configuration:")?;
    let mut source = None;
    for row in value.page.items() {
        source = source.or_else(|| row.origin.clone());
        match &row.value {
            se_types::Read::Present { value: setting } => writeln!(out, "{}: {setting}", row.key)?,
            se_types::Read::Absent { checked } => writeln!(out, "{}: absent ({checked})", row.key)?,
            se_types::Read::Unreadable { source, reason, .. } => {
                writeln!(out, "{}: unreadable at {source}: {reason}", row.key)?
            }
            se_types::Read::Unknown { what } => writeln!(out, "{}: unknown ({what})", row.key)?,
        }
    }
    if let Some(source) = source {
        writeln!(out, "Source: {source}")?;
    }
    if let Some(next) = value.page.next() {
        writeln!(out, "Continue the same command with --cursor {next}")?;
    }
    if !value.page.window().complete() {
        writeln!(
            out,
            "This page is incomplete; its JSON window describes the remaining omissions."
        )?;
    }
    Ok(())
}
pub fn agent_status(value: &AgentStatusOutput, out: &mut impl Write) -> io::Result<()> {
    match &value.agent {
        se_types::Read::Present { value } => {
            writeln!(out, "Agent {} ({})", value.name, value.id)?;
            writeln!(out, "Permission profile: {}", value.profile)?;
            super::transcript::render(&value.session.transcript, out)?;
            if let Some(model) = &value.model {
                writeln!(out, "Model: {model}")?;
            }
            writeln!(out, "Session: {}", value.session.state)?;
            if let Some(session) = &value.session.session_id {
                writeln!(out, "Session ID: {session}")?;
            }
            if let Some(surface) = &value.session.surface {
                writeln!(out, "Surface: {surface}")?;
            }
            if let Some(containment) = &value.session.containment {
                writeln!(out, "Recorded containment: {containment}")?;
            }
            if let Some(reason) = &value.session.containment_cause {
                writeln!(
                    out,
                    "Containment reason: {}",
                    se_core::ops::containment_cause_description(reason)
                )?;
            }
            if let Some(notice) = &value.harness_policy_notice {
                writeln!(out, "{notice}")?;
            }
            if let Some(runtime) = &value.acp_runtime {
                super::acp::runtime(runtime, "", out)?;
            }
            writeln!(out, "Conversation: {}", value.conversation.state)?;
            if let Some(conversation) = &value.conversation.id {
                writeln!(out, "Conversation ID: {conversation}")?;
            }
            if let Some(unread) = value.unread {
                writeln!(out, "Unread messages: {unread}")?;
            }
            if let Some(runtime) = &value.secode_runtime {
                super::read::secode::runtime(runtime, "", out)?;
            }
            super::read::resume_advice(&value.resume, "", out)?;
        }
        se_types::Read::Absent { checked } => writeln!(out, "Agent absent: {checked}")?,
        se_types::Read::Unreadable { source, reason, .. } => {
            writeln!(out, "Agent unreadable at {source}: {reason}")?
        }
        se_types::Read::Unknown { what } => writeln!(out, "Agent unknown: {what}")?,
    }
    Ok(())
}

pub(super) fn agents(
    value: &se_core::ops::AgentPage,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(out, "Agents in {}", value.project.name)?;
    for agent in value.page.items() {
        writeln!(
            out,
            "{} ({}) — {}; saved profile {}",
            agent.name,
            agent.id,
            super::labels::provider(agent.provider),
            agent.profile
        )?;
        writeln!(out, "  Session: {}", agent.session.state)?;
        if let Some(runtime) = &agent.secode_runtime {
            super::read::secode::runtime(runtime, "  ", out)?;
        }
        if let Some(session) = &agent.session.session_id {
            writeln!(out, "  Session ID: {session}")?;
        }
        if let Some(reason) = &agent.resume.reason {
            writeln!(out, "  Resume: {reason}")?;
        }
    }
    if value.page.items().is_empty() {
        writeln!(out, "No agents in this page.")?;
    }
    if let Some(next) = value.page.next() {
        writeln!(out, "Continue the same command with --cursor {next}")?;
    }
    if !value.page.window().complete() {
        writeln!(
            out,
            "This page is incomplete; its JSON window describes the remaining omissions."
        )?;
    }
    Ok(())
}
