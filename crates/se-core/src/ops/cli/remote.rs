use super::*;
use se_types::remote::*;
pub(super) fn command(name: &str, c: Command) -> Command {
    let c =
        if name.starts_with("remote.") {
            c.arg(value("host").required(true).help(
                "Saved nonsecret remote host alias configured by the Owner; never a URL or key",
            ))
        } else {
            c
        };
    if name == "remote.send" {
        c.arg(
            value("expected_host")
                .long("expected-host")
                .requires("expected_grant")
                .help("Pinned host ID from an earlier send; preserve for an uncertain retry"),
        )
        .arg(
            value("expected_grant")
                .long("expected-grant")
                .requires("expected_host")
                .help("Grant ID from the original pending/send receipt"),
        )
        .arg(
            value("target")
                .required(true)
                .help("Exact remote project-ID/agent-ID; never a local project selector"),
        )
        .arg(
            value("session")
                .required(true)
                .help("Expected current remote session ID"),
        )
        .arg(
            positional("body", 1, true)
                .help("Direct message UTF-8 text (1..32768 bytes); - reads stdin"),
        )
    } else {
        let c = c
            .arg(value("target").action(ArgAction::Append).help(
                "Exact remote project-ID/agent-ID; repeat, or omit for the grant's exact set",
            ))
            .arg(
                value("budget")
                    .default_value("32768")
                    .help("Maximum encoded response bytes (1024..65536)"),
            );
        if name == "remote.list" {
            c.arg(
                value("limit")
                    .default_value("20")
                    .help("Maximum whole rows (1..100)"),
            )
            .arg(value("cursor").help("Opaque continuation from this same remote grant"))
        } else {
            c.arg(
                toggle("measure")
                    .help("Include host observation ages for matched terminal timing comparisons"),
            )
            .arg(
                toggle("once")
                    .help("Return one page and exit; otherwise follow with bounded waits"),
            )
            .arg(
                value("wait_ms")
                    .long("wait-ms")
                    .default_value("29000")
                    .help("Bounded wait for this page (0..30000 milliseconds)"),
            )
            .arg(value("cursors").help("JSON cursor set returned by the preceding watch page"))
            .arg(value("visible").help("Exact project-ID/agent-ID currently visible"))
        }
    }
}
pub fn parse_remote_target(text: &str) -> Result<RemoteTarget> {
    let (project, agent) = text
        .split_once('/')
        .ok_or_else(|| SeError::invalid("remote target", "an exact project-ID/agent-ID"))?;
    Ok(RemoteTarget {
        project: se_types::ProjectId::from_legacy(project)?,
        agent: se_types::AgentId::from_legacy(agent)?,
    })
}
pub(super) fn decode(
    name: &str,
    m: &ArgMatches,
    key: impl FnOnce() -> Result<IdempotencyKey>,
) -> Result<AnyOp> {
    let host = if name.starts_with("remote.") {
        required(m, "host")?
    } else {
        String::new()
    };
    let number = |id| {
        required(m, id)?
            .parse::<u32>()
            .map_err(|_| SeError::invalid(id, "a bounded unsigned integer"))
    };
    Ok(match name {
        "remote.list" => AnyOp::RemoteList(RemoteListCall {
            host,
            request: RemoteList {
                targets: many(m, "target")
                    .iter()
                    .map(|s| parse_remote_target(s))
                    .collect::<Result<_>>()?,
                cursor: text(m, "cursor").map(Cursor::new).transpose()?,
                limit: super::number(m, "limit")?,
                budget: number("budget")?,
            },
        }),
        "remote.watch" | "client.watch" => {
            let input = RemoteWatchCall {
                host,
                reader_id: None,
                request: RemoteWatch {
                    measure: flag(m, "measure"),
                    targets: many(m, "target")
                        .iter()
                        .map(|s| parse_remote_target(s))
                        .collect::<Result<_>>()?,
                    cursors: text(m, "cursors")
                        .map(|s| {
                            serde_json::from_str(&s).map_err(|_| {
                                SeError::invalid(
                                    "remote cursors",
                                    "the preceding typed watch cursor set",
                                )
                            })
                        })
                        .transpose()?
                        .unwrap_or_default(),
                    visible: text(m, "visible")
                        .map(|s| parse_remote_target(&s))
                        .transpose()?,
                    budget: number("budget")?,
                },
                follow: !flag(m, "once"),
                wait_ms: number("wait_ms")?,
            };
            if name == "client.watch" {
                AnyOp::ClientWatch(ClientWatchCall {
                    request: input.request,
                    reader_id: input.reader_id,
                    wait_ms: input.wait_ms,
                    follow: input.follow,
                })
            } else {
                AnyOp::RemoteWatch(input)
            }
        }
        "remote.send" => AnyOp::RemoteSend(RemoteSendCall {
            expected_binding: text(m, "expected_host")
                .map(|host| {
                    Ok::<_, SeError>(Box::new(crate::ops::remote::RemoteBindingSelection {
                        host: RemoteHostId(se_types::Sha256::parse_hex(&host)?),
                        grant: required(m, "expected_grant")?.parse()?,
                    }))
                })
                .transpose()?,
            host,
            request: RemoteSend {
                target: parse_remote_target(&required(m, "target")?)?,
                session: se_types::SessionId::from_legacy(required(m, "session")?)?,
                body: se_types::Body::new(required(m, "body")?)?,
                idempotency_key: key()?,
            },
        }),
        _ => return Err(SeError::invalid("remote command", "list, watch or send")),
    })
}
