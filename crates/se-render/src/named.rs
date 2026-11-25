//! Status hints read better with names. A name replaces an ID only when it selects the same
//! row: an agent name must be unique on a complete page, and neither may look like an ID.
//! JSON keeps the exact IDs; an ambiguous project name is refused by the selector, naming
//! its matches.
use se_core::ops::{AgentCommand, outputs::StatusOutput};
use se_types::Read;
use std::collections::BTreeMap;

pub(crate) struct Names(BTreeMap<String, String>);

impl Names {
    pub(crate) fn of(value: &StatusOutput) -> Self {
        let mut names = BTreeMap::new();
        if let Read::Present { value: project } = &value.project
            && plain(&project.name)
        {
            names.insert(project.id.to_string(), project.name.clone());
        }
        if let Some(page) = value
            .agents
            .as_ref()
            .filter(|page| page.window().complete())
        {
            let rows = page.items();
            for row in rows {
                let unique = rows.iter().filter(|other| other.name == row.name).count() == 1;
                if unique && plain(&row.name) {
                    names.insert(row.id.to_string(), row.name.clone());
                }
            }
        }
        Self(names)
    }

    /// The same argv with known IDs replaced, quoted for the same shell as the original.
    pub(crate) fn command(&self, argv: &[String], original: &str, cmd: bool) -> String {
        let renamed: Vec<String> = argv
            .iter()
            .map(|word| self.0.get(word).unwrap_or(word).clone())
            .collect();
        if renamed == argv {
            return original.to_owned();
        }
        let command = AgentCommand::from_argv(renamed);
        let command = if cmd {
            command.and_then(|command| command.for_cmd())
        } else {
            command
        };
        command.map_or_else(|| original.to_owned(), |command| command.command)
    }
}

fn plain(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with("prj_")
        && !name.starts_with("ag_")
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}
