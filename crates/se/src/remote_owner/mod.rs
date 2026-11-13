//! Native Owner execution and shared CLI formatting adapt the remote command crate.
use clap::Command;
use se_core::ops::{AnyOp, AnyOutput};
pub(crate) use se_remote_cli::Input;
use se_types::{RenderCx, Result, SeError};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
};
struct Host;
mod pair;

impl se_remote_cli::OwnerCommands for Host {
    type Context = crate::bootstrap::Bootstrap;
    fn resolve_owner(
        &self,
        home: Option<PathBuf>,
        no_color: bool,
        json: bool,
    ) -> Result<Self::Context> {
        crate::bootstrap::Bootstrap::resolve_remote_owner(home, no_color, json)
    }
    fn execute_owner(
        &self,
        context: &Self::Context,
        input: Input,
        progress: &mut dyn FnMut(se_host::remote::ssh::ImageProgress) -> Result<()>,
    ) -> Result<se_host::OperationOutput> {
        pair::execute(context, input, progress)
    }
}
impl se_remote_cli::Presentation for Host {
    fn help_grammar(&self, command: Command) -> Command {
        crate::grammar::help_grammar(command)
    }
    fn usage_error(&self, error: clap::Error, args: &[OsString]) -> SeError {
        crate::grammar::usage_error(error, args)
    }
    fn json_requested(&self, args: &[OsString]) -> bool {
        crate::grammar::json_requested(args)
    }
    fn write_error<O: Write, E: Write>(
        &self,
        error: &SeError,
        context: &RenderCx<'_>,
        json: bool,
        stdout: &mut O,
        stderr: &mut E,
    ) -> io::Result<u8> {
        crate::render::error::write(error, context, json, stdout, stderr)
    }
    fn write_output<O: Write>(
        &self,
        value: &AnyOutput,
        json: bool,
        quiet: bool,
        stdout: &mut O,
    ) -> io::Result<u8> {
        crate::render::output(value, json, quiet, stdout)
    }
}
pub(crate) fn entry(args: &[OsString]) -> Option<io::Result<u8>> {
    se_remote_cli::entry(args, &Host)
}
pub(crate) fn help(operation: &AnyOp) -> Option<AnyOutput> {
    se_remote_cli::help(operation)
}
