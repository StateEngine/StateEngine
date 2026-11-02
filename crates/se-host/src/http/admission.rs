//! Request-head admission for the loopback HTTP surface (section 40 §7.3).
//! Order: origin-form target -> exact Host/port -> Origin/Sec-Fetch-Site ->
//! framing -> method/media -> credential. Nothing here performs I/O; a refusal
//! carries only its status and a fixed nonsecret reason.
use hyper::{
    Method, Request, StatusCode,
    header::{self, HeaderMap, HeaderValue},
};
use se_types::Secret;

/// The fixed routes. Every other target is 404, never a fallback route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Route {
    Mcp,
    Livez,
}
#[derive(Debug)]
pub(crate) struct Refusal {
    pub status: StatusCode,
    pub reason: &'static str,
    /// Only a wrong method on a known route names its single legal method.
    pub allow: Option<&'static str>,
}
impl Refusal {
    const fn new(status: StatusCode, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            allow: None,
        }
    }
}
pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Admit everything except the credential. Livez is anonymous; /mcp still
/// needs `bearer` after this returns.
pub(crate) fn admit<B>(request: &Request<B>, port: u16) -> Result<Route, Refusal> {
    let uri = request.uri();
    // Origin-form only: no scheme/authority, no query, exact path.
    if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "origin-form target without query required",
        ));
    }
    let route = match uri.path() {
        "/mcp" => Route::Mcp,
        "/stateengine/livez" => Route::Livez,
        _ => return Err(Refusal::new(StatusCode::NOT_FOUND, "no such route")),
    };
    let headers = request.headers();
    exact_host(headers, port)?;
    exact_origin(headers, port)?;
    fetch_site(headers)?;
    framing(headers)?;
    let method = request.method();
    match route {
        Route::Mcp if method == Method::POST => json_media(headers)?,
        Route::Livez if method == Method::GET => {
            // An exact zero declares no body; `framing` has already refused
            // duplicate, unreadable or oversized lengths.
            if single(headers, &header::CONTENT_LENGTH)?.is_some_and(|length| length != "0") {
                return Err(Refusal::new(StatusCode::BAD_REQUEST, "GET carries no body"));
            }
        }
        Route::Mcp => {
            return Err(Refusal {
                status: StatusCode::METHOD_NOT_ALLOWED,
                reason: "POST only",
                allow: Some("POST"),
            });
        }
        Route::Livez => {
            return Err(Refusal {
                status: StatusCode::METHOD_NOT_ALLOWED,
                reason: "GET only",
                allow: Some("GET"),
            });
        }
    }
    Ok(route)
}

fn single<'a>(
    headers: &'a HeaderMap,
    name: &header::HeaderName,
) -> Result<Option<&'a HeaderValue>, Refusal> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "duplicate security header",
        ));
    }
    Ok(first)
}

fn exact_host(headers: &HeaderMap, port: u16) -> Result<(), Refusal> {
    let host = single(headers, &header::HOST)?
        .and_then(|value| value.to_str().ok())
        .ok_or(Refusal::new(
            StatusCode::BAD_REQUEST,
            "Host header required",
        ))?;
    if host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}") {
        Ok(())
    } else {
        Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "Host must be this loopback listener",
        ))
    }
}

fn exact_origin(headers: &HeaderMap, port: u16) -> Result<(), Refusal> {
    let Some(origin) = single(headers, &header::ORIGIN)? else {
        return Ok(());
    };
    let origin = origin
        .to_str()
        .map_err(|_| Refusal::new(StatusCode::FORBIDDEN, "unreadable Origin"))?;
    // Never "null", suffix matches, alternate IP spellings or reflected CORS.
    if origin == format!("http://127.0.0.1:{port}") || origin == format!("http://localhost:{port}")
    {
        Ok(())
    } else {
        Err(Refusal::new(StatusCode::FORBIDDEN, "cross-origin request"))
    }
}

fn fetch_site(headers: &HeaderMap) -> Result<(), Refusal> {
    // A missing Origin cannot erase a cross-site fetch signal.
    match single(headers, &header::HeaderName::from_static("sec-fetch-site"))? {
        None => Ok(()),
        Some(value) if value == "same-origin" || value == "none" => Ok(()),
        Some(_) => Err(Refusal::new(StatusCode::FORBIDDEN, "cross-site request")),
    }
}

fn framing(headers: &HeaderMap) -> Result<(), Refusal> {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "chunked or encoded framing is refused; send Content-Length",
        ));
    }
    if headers.contains_key(header::UPGRADE)
        || headers.get_all(header::CONNECTION).iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|v| v.to_ascii_lowercase().contains("upgrade"))
        })
    {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "protocol upgrades are refused",
        ));
    }
    if let Some(coding) = single(headers, &header::CONTENT_ENCODING)?
        && coding != "identity"
    {
        return Err(Refusal::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content coding refused",
        ));
    }
    if let Some(length) = single(headers, &header::CONTENT_LENGTH)? {
        let length: usize = length
            .to_str()
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(Refusal::new(
                StatusCode::BAD_REQUEST,
                "unreadable Content-Length",
            ))?;
        if length > MAX_BODY_BYTES {
            return Err(Refusal::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body exceeds 1 MiB",
            ));
        }
    }
    Ok(())
}

fn json_media(headers: &HeaderMap) -> Result<(), Refusal> {
    let media = single(headers, &header::CONTENT_TYPE)?
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
    if media.as_deref() == Some("application/json") {
        Ok(())
    } else {
        Err(Refusal::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type application/json required",
        ))
    }
}

/// The session capability a launched provider received in its protected MCP
/// configuration; never logged, echoed or read from a query. Absent is legal
/// for the anonymous lifecycle methods; a malformed header is reported so the
/// MCP consumer refuses tool methods while initialize and ping still answer.
pub(crate) fn bearer(headers: &HeaderMap) -> Result<Option<Secret>, Refusal> {
    let malformed = || Refusal::new(StatusCode::UNAUTHORIZED, "malformed session bearer");
    let Some(value) = single(headers, &header::AUTHORIZATION)? else {
        return Ok(None);
    };
    let token = value
        .as_bytes()
        .strip_prefix(b"Bearer ")
        .filter(|token| !token.is_empty() && token.iter().all(|byte| byte.is_ascii_graphic()))
        .ok_or_else(malformed)?;
    Secret::new(token.to_vec())
        .map(Some)
        .map_err(|_| malformed())
}
