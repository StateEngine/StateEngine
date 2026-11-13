//! Launch consent is available from pairing and the native Owner menu.
use super::*;
use std::io::{BufRead, IsTerminal};
pub(super) fn command<H: OwnerCommands + Presentation>(
    m: &ArgMatches,
    json: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    host: &H,
) -> io::Result<u8> {
    if text(m, "name").is_none()
        || json
        || !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || m.get_flag("version")
        || m.get_one::<String>("project").is_some()
        || text(m, "key").is_some()
    {
        return host.write_error(
            &invalid(
                "launch permission review requires a native Owner terminal: run se remote permissions --name <saved-alias> --launch; omit --json, --project, --version and --key",
            ),
            &se_types::RenderCx::default(),
            json,
            stdout,
            stderr,
        );
    }
    super::launch_permissions::review(m, stdout, &mut io::stdin().lock(), host)?;
    Ok(0)
}
pub(super) fn review<H: OwnerCommands>(
    m: &ArgMatches,
    stdout: &mut impl Write,
    host: &H,
) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        writeln!(
            stdout,
            "Launch permission review requires a native Owner terminal. Run se remote permissions --name <saved-alias> --launch in a terminal."
        )?;
        return Ok(());
    }
    writeln!(
        stdout,
        "Review which existing destination agents this paired machine may launch? [launch/Enter to finish]"
    )?;
    stdout.flush()?;
    let mut input = io::stdin().lock();
    if line(&mut input)? == "launch" {
        super::launch_permissions::review(m, stdout, &mut input, host)?;
    }
    Ok(())
}
pub(super) fn line(input: &mut impl BufRead) -> io::Result<String> {
    let mut bytes = Vec::new();
    let count = std::io::Read::take(input, 257).read_until(b'\n', &mut bytes)?;
    if count > 256 || (count > 0 && bytes.last() != Some(&b'\n')) {
        return Err(io::Error::other("pairing choice exceeds 256 bytes"));
    }
    String::from_utf8(bytes)
        .map(|s| s.trim().to_owned())
        .map_err(io::Error::other)
}
