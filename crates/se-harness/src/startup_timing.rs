//! Monotonic, fixed-label timing for one Codex readiness attempt.
use se_types::{AgentId, ErrorBody, ProviderSessionId, Read, Remedy, RenderCx};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub enum Phase {
    Setup,
    Transport,
    Initialize,
    Thread,
    Publication,
}

const PHASES: [Phase; 5] = [
    Phase::Setup,
    Phase::Transport,
    Phase::Initialize,
    Phase::Thread,
    Phase::Publication,
];

pub struct Timing {
    current: Phase,
    resuming: bool,
    started: Instant,
    completed: [Option<Duration>; PHASES.len()],
    failed_at: Option<Instant>,
}

impl Timing {
    pub fn new(resume: &Read<ProviderSessionId>) -> Self {
        Self {
            current: Phase::Setup,
            resuming: matches!(resume, Read::Present { .. }),
            started: Instant::now(),
            completed: [None; PHASES.len()],
            failed_at: None,
        }
    }

    pub fn advance(&mut self, phase: Phase) {
        let now = Instant::now();
        self.completed[self.current as usize] = Some(now.duration_since(self.started));
        self.current = phase;
        self.started = now;
    }

    pub fn freeze(&mut self) {
        self.failed_at.get_or_insert_with(Instant::now);
    }

    fn label(&self, phase: Phase) -> &'static str {
        match phase {
            Phase::Setup => "setup",
            Phase::Transport => "transport",
            Phase::Initialize => "initialize",
            Phase::Thread if self.resuming => "thread resume",
            Phase::Thread => "thread start",
            Phase::Publication => "publication",
        }
    }

    fn summary(&self) -> String {
        let last = PHASES
            .iter()
            .rfind(|phase| self.completed[**phase as usize].is_some())
            .map_or("none", |phase| self.label(*phase));
        let current = self.current as usize;
        let active = self
            .failed_at
            .unwrap_or_else(Instant::now)
            .duration_since(self.started);
        let times = PHASES.map(|phase| {
            let label = self.label(phase);
            if phase as usize == current {
                format!("{label} {} ms (incomplete)", active.as_millis())
            } else if let Some(elapsed) = self.completed[phase as usize] {
                format!("{label} {} ms", elapsed.as_millis())
            } else {
                format!("{label} not started")
            }
        });
        format!(
            "Codex readiness last completed phase: {last}. Phase times: {}.",
            times.join(", ")
        )
    }

    pub fn report(&self, failure: ErrorBody, agent: &AgentId) -> ErrorBody {
        let recovery = failure.remedy(&RenderCx::default()).ok();
        let next = format!(
            "Run `se agent show {agent}` with the same home and project to check the saved lifecycle before retrying."
        );
        // The actionable fix leads; phase times are diagnosis for whoever reads further.
        let text = match &recovery {
            Some(remedy) => format!("{} {next} {}", remedy.text, self.summary()),
            None => format!("{next} {}", self.summary()),
        };
        failure.with_remedy(Remedy {
            text,
            command: recovery.and_then(|remedy| remedy.command),
        })
    }
}
