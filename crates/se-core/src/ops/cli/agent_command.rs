//! CLI receipt commands use the same positional selectors as the live grammar.
use se_types::{AgentId, ProjectId};

pub struct AgentCommand {
    pub command: String,
    pub argv: Vec<String>,
}
impl AgentCommand {
    /// On Windows, the readable command uses PowerShell quoting. Literal argv
    /// remains shell-independent for programmatic consumers.
    pub fn instruction(text: &str) -> String {
        if cfg!(windows) {
            format!("Open PowerShell, then {}", text.to_lowercase())
        } else {
            text.into()
        }
    }
    pub const HOME_UNAVAILABLE: &str =
        "The data home is not UTF-8; no portable CLI command can name it exactly.";
    pub fn launch_in_home(
        agent: &AgentId,
        home: &std::path::Path,
        project: &ProjectId,
        new: bool,
    ) -> Option<Self> {
        Some(Self::launch(
            agent,
            Some(home.to_str()?),
            Some(project),
            new,
        ))
    }
    pub fn stop_in_home(
        agent: &AgentId,
        home: &std::path::Path,
        project: &ProjectId,
    ) -> Option<Self> {
        Some(Self::stop(agent, Some(home.to_str()?), Some(project)))
    }
    pub fn launch(
        agent: &AgentId,
        home: Option<&str>,
        project: Option<&ProjectId>,
        new: bool,
    ) -> Self {
        let mut argv = Self::arguments("launch", agent, home, project);
        argv.push("--detach".into());
        if new {
            argv.push("--new".into());
        }
        Self::from_argv(argv)
    }
    pub fn stop(agent: &AgentId, home: Option<&str>, project: Option<&ProjectId>) -> Self {
        Self::from_argv(Self::arguments("stop", agent, home, project))
    }
    fn arguments(
        verb: &str,
        agent: &AgentId,
        home: Option<&str>,
        project: Option<&ProjectId>,
    ) -> Vec<String> {
        let mut argv = vec!["se".into()];
        if let Some(home) = home {
            argv.extend(["--home".into(), home.into()]);
        }
        if let Some(project) = project {
            argv.extend(["--project".into(), project.to_string()]);
        }
        argv.extend([verb.into(), agent.to_string()]);
        argv
    }
    /// cmd.exe expands percent/exclamation variables even inside double quotes.
    /// Such arguments require the explicitly named PowerShell form instead.
    pub fn for_cmd(&self) -> Option<Self> {
        let words: Option<Vec<_>> = self
            .argv
            .iter()
            .map(|word| {
                if word.contains(['%', '!', '"', '\r', '\n']) {
                    return None;
                }
                if !word.is_empty()
                    && word
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.:'\\/".contains(&b))
                {
                    Some(word.clone())
                } else {
                    let trailing = word.chars().rev().take_while(|c| *c == '\\').count();
                    Some(format!("\"{}{}\"", word, "\\".repeat(trailing)))
                }
            })
            .collect();
        Some(Self {
            command: words?.join(" "),
            argv: self.argv.clone(),
        })
    }
    pub fn from_argv(argv: Vec<String>) -> Self {
        let command = argv
            .iter()
            .map(|word| {
                if !word.is_empty()
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/".contains(&byte))
                {
                    word.clone()
                } else if cfg!(windows) {
                    format!("'{}'", word.replace('\'', "''"))
                } else {
                    format!("'{}'", word.replace('\'', "'\"'\"'"))
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        Self { command, argv }
    }
}
