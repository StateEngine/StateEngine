//! A startup timeout precedes submission. Retain the parsed invocation and key
//! instead of asking the user to invent a new launch or a new request identity.
use crate::bootstrap::Bootstrap;
use se_core::ops::{AgentCommand, AnyOp, CommonArgs};
use se_types::{Argv, Cmd, Code, OperationCommand, Remedy, SeError};
use std::ffi::OsString;

#[derive(Debug)]
pub(crate) struct Invocation {
    arguments: Vec<OsString>,
    home_missing: bool,
    project_missing: bool,
    key_missing: bool,
}
impl Invocation {
    pub(crate) fn new(arguments: Vec<OsString>, common: &CommonArgs) -> Self {
        Self {
            arguments,
            home_missing: common.home.is_none(),
            project_missing: common.project.is_none(),
            key_missing: common.key.is_none(),
        }
    }
}
struct Words(Vec<String>);
impl OperationCommand for Words {
    fn cli_argv(&self) -> Vec<String> {
        self.0.clone()
    }
}
pub(super) struct Retry {
    command: Option<std::result::Result<Cmd, String>>,
    cwd: std::path::PathBuf,
}
impl Retry {
    pub(super) fn capture(cx: &Bootstrap, admission: &se_store::Admission, op: &AnyOp) -> Self {
        let command =
            cx.retry_invocation
                .as_ref()
                .zip(op.idempotency_key())
                .map(|(invocation, key)| {
                    let build = || -> se_types::Result<Cmd> {
                        let mut words = vec!["se".into()];
                        if invocation.home_missing {
                            let home = cx.home.to_str().ok_or_else(|| {
                                SeError::invalid("retry home", "an exact UTF-8 path")
                            })?;
                            words.extend(["--home".into(), home.into()]);
                        }
                        if invocation.project_missing {
                            if let se_store::Scope::Project(project) = &admission.scope {
                                words.extend(["--project".into(), project.to_string()]);
                            }
                        }
                        if invocation.key_missing {
                            words.extend(["--key".into(), key.to_string()]);
                        }
                        for word in invocation.arguments.iter().skip(1) {
                            words.push(
                                word.to_str()
                                    .ok_or_else(|| {
                                        SeError::invalid("retry argument", "exact UTF-8 argv")
                                    })?
                                    .into(),
                            );
                        }
                        Ok(Cmd::Se {
                            argv: Argv::from_op(&Words(words))?,
                        })
                    };
                    build().map_err(|error| error.to_string())
                });
        Self {
            command,
            cwd: cx.cwd.clone(),
        }
    }
    pub(super) fn attach(self, mut error: SeError) -> SeError {
        if error.code() != Code::RuntimeStartPending {
            return error;
        }
        let mut remedy = match error.body.remedy(&se_types::RenderCx::default()) {
            Ok(remedy) => remedy,
            Err(reason) => Remedy {
                text: format!("Startup recovery could not be rendered: {reason}"),
                command: None,
            },
        };
        match self.command {
            Some(Ok(command)) => {
                let cwd = self.cwd.to_str().and_then(AgentCommand::quoted_word);
                remedy.text.push_str(&match cwd {
                    Some(cwd) => format!(" Retry from {cwd} using the same key."),
                    None => " Retry from the original working directory using the same key.".into(),
                });
                remedy.command = Some(command);
            }
            Some(Err(reason)) => remedy.text.push_str(&format!(" Exact retry argv could not be represented: {reason}; retain the original command and key.")),
            None => (),
        }
        error.body = error
            .body
            .with_retry(se_types::Retry::WhenRuntimeReady)
            .with_remedy(remedy);
        error
    }
}
