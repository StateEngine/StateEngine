//! Shared explicit and fallback foreground CLI lifetime and output handling.
use crate::{bootstrap::Bootstrap, render, route};
use se_types::RenderCx;
use std::io::{self, Write};

pub(crate) fn run(context: &Bootstrap, json: bool, quiet: bool) -> io::Result<u8> {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let result = route::foreground(context, &mut |output| {
        render::output(&output, json, quiet, &mut stdout)
            .map(|_| ())
            .map_err(|error| {
                se_core::scope::unreadable("foreground startup output", &error.to_string())
                    .with_cause(error)
            })?;
        stdout.flush().map_err(|error| {
            se_core::scope::unreadable("foreground startup output", &error.to_string())
                .with_cause(error)
        })
    });
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            render::error::write(&error, &RenderCx::default(), json, &mut stdout, &mut stderr)
        }
    }
}
