//! CLI receipt commands use the same positional selectors as the live grammar.
use se_types::{AgentId, ProjectId};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AgentCommand {
    pub command: String,
    pub argv: Vec<String>,
}
impl AgentCommand {
    pub fn history_in_home(
        agent: &AgentId,
        home: &std::path::Path,
        project: &ProjectId,
    ) -> Option<Self> {
        Self::from_argv(vec![
            "se".into(),
            "--home".into(),
            Self::home_argument(home)?.into(),
            "--project".into(),
            project.to_string(),
            "history".into(),
            "--agent".into(),
            agent.to_string(),
            "--kind".into(),
            "session.turn".into(),
        ])
    }
    /// On Windows, the readable command uses PowerShell quoting. Literal argv
    /// remains shell-independent for programmatic consumers.
    pub fn instruction(text: &str) -> String {
        if cfg!(windows) {
            format!("Open PowerShell, then {}", text.to_lowercase())
        } else {
            text.into()
        }
    }
    pub const HOME_UNAVAILABLE: &str = "The data home is not UTF-8 or contains a line break; no portable CLI command can name it exactly.";
    pub const SECODE_RESUME_UNAVAILABLE: &str = "Managed resume requires the original live service, a fenced input-free release of its exact human-stop hold, and proved client closure and capture. Reconcile the retained service before resuming, or explicitly launch with --new for a different conversation.";
    pub fn home_argument(home: &std::path::Path) -> Option<&str> {
        home.to_str().filter(|value| !value.contains(['\r', '\n']))
    }
    /// Preserve the selected launch surface and re-render its existing words.
    pub fn with_detach(self, detach: bool) -> Self {
        let mut argv = self.argv;
        argv.retain(|value| value != "--detach");
        if detach {
            argv.push("--detach".into());
        }
        // No caller-supplied word is introduced by changing this fixed flag.
        Self::render(argv)
    }
    /// A literal shell word, including in assignments and compound remedies.
    pub fn quoted_word(word: &str) -> Option<String> {
        (!word.contains(['\r', '\n'])).then(|| shell_word(word))
    }
    pub fn launch_in_home(
        agent: &AgentId,
        home: &std::path::Path,
        project: &ProjectId,
        new: bool,
    ) -> Option<Self> {
        Some(Self::launch(
            agent,
            Some(Self::home_argument(home)?),
            Some(project),
            new,
        ))
    }
    pub fn stop_in_home(
        agent: &AgentId,
        home: &std::path::Path,
        project: &ProjectId,
    ) -> Option<Self> {
        Some(Self::stop(
            agent,
            Some(Self::home_argument(home)?),
            Some(project),
        ))
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
        Self::render(argv)
    }
    pub fn stop(agent: &AgentId, home: Option<&str>, project: Option<&ProjectId>) -> Self {
        Self::render(Self::arguments("stop", agent, home, project))
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
    pub fn from_argv(argv: Vec<String>) -> Option<Self> {
        if argv.iter().any(|word| word.contains(['\r', '\n'])) {
            return None;
        }
        Some(Self::render(argv))
    }
    fn render(argv: Vec<String>) -> Self {
        let command = argv
            .iter()
            .map(|word| {
                if !word.is_empty()
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/".contains(&byte))
                {
                    word.clone()
                } else {
                    shell_word(word)
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        Self { command, argv }
    }
}

impl se_types::OperationCommand for AgentCommand {
    fn cli_argv(&self) -> Vec<String> {
        self.argv.clone()
    }
}

fn shell_word(word: &str) -> String {
    if cfg!(windows) {
        powershell_word(word)
    } else {
        format!("'{}'", word.replace('\'', "'\"'\"'"))
    }
}

fn powershell_word(word: &str) -> String {
    let mut quoted = String::from("'");
    for character in word.chars() {
        quoted.push(character);
        if matches!(
            character,
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}'
        ) {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cmd_form_preserves_spaces_apostrophes_and_trailing_backslashes()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let original = AgentCommand::from_argv(vec![
            "se".into(),
            "--home".into(),
            "C:\\state home's\\".into(),
        ])
        .ok_or("ordinary command refused")?;
        let cmd = original.for_cmd().ok_or("ordinary cmd form refused")?;
        assert_eq!(cmd.argv, original.argv);
        assert_eq!(cmd.command, "se --home \"C:\\state home's\\\\\"");
        Ok(())
    }
    #[test]
    fn cmd_form_refuses_variable_expansion_and_embedded_quotes() {
        for word in ["%TEMP%", "!private!", "line\nnext", "embedded\"quote"] {
            assert!(
                AgentCommand::from_argv(vec![word.into()])
                    .and_then(|command| command.for_cmd())
                    .is_none()
            );
        }
    }
    #[test]
    fn powershell_quotes_every_single_quote_delimiter() {
        for character in ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
            let word = format!("C:\\O{character}Brien; Write-Output injected");
            assert_eq!(
                powershell_word(&word),
                format!(
                    "'{}'",
                    word.replace(character, &format!("{character}{character}"))
                )
            );
        }
    }
    #[test]
    fn command_and_home_refuse_line_breaks() {
        for word in ["C:\\line\rnext", "C:\\line\nnext"] {
            assert!(AgentCommand::from_argv(vec![word.into()]).is_none());
            assert!(AgentCommand::quoted_word(word).is_none());
            assert!(AgentCommand::home_argument(std::path::Path::new(word)).is_none());
        }
    }
}
