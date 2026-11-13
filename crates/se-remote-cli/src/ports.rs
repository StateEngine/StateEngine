//! Native execution and common CLI presentation remain owned by the caller.
use crate::Input;
use clap::Command;
use se_core::ops::AnyOutput;
use se_types::{RenderCx, Result, SeError};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
};

pub trait OwnerCommands {
    type Context;
    fn resolve_owner(
        &self,
        home: Option<PathBuf>,
        no_color: bool,
        json: bool,
    ) -> Result<Self::Context>;
    fn execute_owner(
        &self,
        context: &Self::Context,
        input: Input,
    ) -> Result<se_host::OperationOutput>;
}

pub trait Presentation {
    fn help_grammar(&self, command: Command) -> Command;
    fn usage_error(&self, error: clap::Error, args: &[OsString]) -> SeError;
    fn json_requested(&self, args: &[OsString]) -> bool;
    fn write_error<O: Write, E: Write>(
        &self,
        error: &SeError,
        context: &RenderCx<'_>,
        json: bool,
        stdout: &mut O,
        stderr: &mut E,
    ) -> io::Result<u8>;
    fn write_output<O: Write>(
        &self,
        value: &AnyOutput,
        json: bool,
        quiet: bool,
        stdout: &mut O,
    ) -> io::Result<u8>;
}
