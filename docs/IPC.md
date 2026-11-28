# StateEngine Local IPC Wire Specification (v1)

This document specifies the local-IPC wire protocol (`api: { "major": 1, "minor": 0 }`) used by the `se` CLI and supported for external local clients (desktop applications, editors, and custom tools) without any Cargo crate coupling.

---

## 1. Endpoint Discovery (`endpoint.json`)

A running StateEngine host publishes its local transport address and process identity to `<state_home>/endpoint.json`:

- **Unix (Linux & macOS):** State directory permissions `0700`, `endpoint.json` permissions `0600`, Unix domain socket inside the protected state directory.
- **Windows:** State directory and `endpoint.json` protected by an owner-only DACL; local Named Pipe (`\\.\pipe\<name>`) created with an owner-only DACL.

### `endpoint.json` Schema (v1)

All fields are closed (`deny_unknown_fields`); `schema` must be `1` and `package_version` must be non-empty.

```json
{
  "schema": 1,
  "address": {
    "kind": "unix_socket",
    "path": { "encoding": "unix_bytes", "units": [47, 118, 97, 114, 47, 114, 117, 110, 47, 115, 101, 46, 115, 111, 99, 107] }
  },
  "epoch": {
    "owner": {
      "machine": "machine-id",
      "boot": "boot-id",
      "pid": 12345,
      "started": { "os": "linux", "start_ticks": 987654321 },
      "executable": { "encoding": "unix_bytes", "units": [47, 117, 115, 114, 47, 108, 111, 99, 97, 108, 47, 98, 105, 110, 47, 115, 101] },
      "argv_sha256": "<64-hex-chars>"
    },
    "generation": 1
  },
  "generation": 1,
  "kind": "standalone",
  "listener_port": 49152,
  "api": { "major": 1, "minor": 0 },
  "package_version": "0.1.3",
  "image_sha256": "<64-hex-chars>"
}
```

- `address.kind`:
  - `"unix_socket"` with `path` encoded as a `NativePath` (`{ "encoding": "unix_bytes", "units": [u8...] }`).
  - `"windows_pipe"` with `name` matching `\\.\pipe\<segment>` (`<segment>` non-empty, not `.` or `..`, no NUL or `/` / `\` separators; full `name` at most 1024 UTF-16 code units).
- `epoch.owner.started.os`:
  - `"linux"`: `{ "os": "linux", "start_ticks": u64 }`
  - `"macos"`: `{ "os": "macos", "start_seconds": u64, "start_micros": u32 }`
  - `"windows"`: `{ "os": "windows", "creation_filetime": u64 }`
- `kind`: `"standalone"` or `"embedded_secode"`.
- `listener_port`: Loopback HTTP port for managed MCP sessions (`null` if absent; never `0`).

### Native Server Verification

Before sending credentials, a client SHOULD verify the connected OS peer matches `endpoint.json`:

1. Same OS user/principal as the client.
2. Connected server PID, process start time, and executable SHA-256 match `epoch.owner` and `image_sha256`.

---

## 2. Framing & Bounds

Every message on the local IPC stream is framed as:

```text
+-----------------------+-----------------------------------+
| length (4 bytes, BE)  | UTF-8 JSON payload (length bytes) |
+-----------------------+-----------------------------------+
```

- **Length prefix:** Unsigned 32-bit big-endian integer (`u32::to_be_bytes`).
- **Bounds:**
  - `MAX_FRAME_BYTES = 1,048,576` (1 MiB) — absolute upper bound for any frame.
  - `DEFAULT_REPLY_BYTES = 262,144` (256 KiB) — default negotiated `maximum_reply_bytes`.
  - `MAX_ENDPOINT_BYTES = 16,384` (16 KiB) — maximum size for `endpoint.json` and all handshake frames (`ServerChallenge`, `ClientHello`, `ServerHello`, and handshake refusals).
  - `MAX_JSON_DEPTH = 64` — maximum nesting depth for JSON objects/arrays.
- **Rejection before allocation:** Zero-length (`0`) and oversized (`> limit`) length prefixes are rejected immediately before allocating the payload buffer.
- **Strict parsing:** All wire envelopes use closed schemas (`deny_unknown_fields`). Unknown or duplicate keys are rejected.

---

## 3. Three-Step Mutual-Auth Handshake

All three handshake frames are bounded by `MAX_ENDPOINT_BYTES` (16 KiB) and a 5-second handshake timeout (`HELLO_TIMEOUT`).

### Step 1: Host -> Client (`ServerChallenge`)

Immediately after accepting a connection and observing the client's native OS peer identity, the host sends either a `ServerChallenge` or a refusal (`{ "error": ErrorEnvelope }`):

```json
{
  "version": { "major": 1, "minor": 0 },
  "epoch": { "owner": { "...": "same HostEpoch as endpoint.json" }, "generation": 1 },
  "nonce": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
  "image_sha256": "<64-hex-chars>"
}
```

(`nonce` is a 32-byte random `u8` array.)

The client MUST verify that `version`, `epoch`, and `image_sha256` match the verified `endpoint.json` before proceeding.

### Step 2: Client -> Host (`ClientHello`)

The client replies with a `ClientHello`:

```json
{
  "version": { "major": 1, "minor": 0 },
  "expected_generation": 1,
  "maximum_reply_bytes": 262144,
  "authority": {
    "kind": "owner_proof",
    "proof": {
      "nonce": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
      "mac": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    }
  },
  "client_capabilities": ["ipc.capabilities"]
}
```

- `expected_generation`: Optional `u64` (`null` to accept any live generation). If present and different from the host's current generation, the host refuses with a stale-generation error.
- `maximum_reply_bytes`: Non-zero `u32`, at most `1,048,576` (1 MiB).
- `authority`: Tagged union (`kind` + `proof`), supporting:
  - `owner_proof`: `{ "nonce": [u8; 32], "mac": [u8; 32] }` — HMAC-SHA256 using the owner's local machine credential (`<state_home>/credential`, exact 32 bytes) over the following `u32`-big-endian length-prefixed fields in order:
    1. Domain tag: `b"se.ipc.owner/v1"`
    2. API version: `major` (`u16` BE) concatenated with `minor` (`u16` BE) (4 bytes)
    3. Canonical `challenge.epoch` JSON with object keys sorted lexicographically and no extra whitespace
    4. `challenge.image_sha256` raw bytes (32 bytes)
    5. `challenge.nonce` (32 bytes)
    6. Client `nonce` (32 bytes)
    7. Canonical native OS peer binding bytes observed on the channel: the unprefixed header `b"se.native.peer/v1"` followed by these components, where **every component (including each platform tag and each value) is individually `u32`-big-endian length-prefixed**:
       - Principal tag: `b"unix"` or `b"windows"`
       - Principal value: `uid` (`u32` BE, 4 bytes) for Unix, or UTF-8 `sid` bytes for Windows
       - Process ID: `pid` (`u32` BE, 4 bytes)
       - Start-identity OS tag: `b"linux"`, `b"windows"`, or `b"macos"`
       - Start-identity value(s): `start_ticks` (`u64` BE, 8 bytes) on Linux; `creation_filetime` (`u64` BE, 8 bytes) on Windows; `start_seconds` (`u64` BE, 8 bytes) followed by a separate length-prefixed `start_micros` (`u32` BE, 4 bytes) on macOS
       - Executable digest: `image_sha256` raw bytes (32 bytes)
  - `external_session`: `[u8; N]` — UTF-8 bytes of an owner-approved external seat capability (`sext1.<hex>`), held in transport memory only.
  - `external_claim`: `ExternalClaimBootstrap` (`{ "project": ProjectId | null, "cwd": NativePath, "agent": String, "connection_nonce": [u8; 32] }`) — opens a pending external seat claim awaiting out-of-band `se external approve <claim_id>`.
  - `session` / `launch` / `guest_bootstrap` / `session_bootstrap` / `lease`: Managed session and read-only guest bootstrap credentials used by `se` itself.
- `client_capabilities` *(optional, `Call` handshakes only)*: Array of ASCII capability names indicating that the client supports capability negotiation. Rejected on `Stop` and `Rebind` handshakes.
  - Semantics: omitted or `null` means no opt-in (legacy behavior); `[]` (empty array) opts in to receiving host metadata and capability lists.
  - Bounds: at most `32` entries, each `1..=64` ASCII bytes matching `[A-Za-z0-9._-]`.
  - **Rolling-upgrade rule:** Omit `client_capabilities` when connecting to a host that does not support capability negotiation (for example, `v0.1.2` hosts whose `ClientHello` decoder rejects unknown fields).

### Step 3: Host -> Client (`ServerHello`)

If authentication and admission succeed, the host replies with `ServerHello` (or `{ "error": ErrorEnvelope }` on refusal):

```json
{
  "version": { "major": 1, "minor": 0 },
  "epoch": { "owner": { "...": "same HostEpoch as endpoint.json" }, "generation": 1 },
  "generation": 1,
  "maximum_reply_bytes": 262144,
  "package_version": "0.1.3",
  "store_id": "store_01...",
  "capabilities": ["ipc.capabilities"]
}
```

- `maximum_reply_bytes`: `min(client.maximum_reply_bytes, server_cap, 1_048_576)`.
- `lease` *(optional)*: Present only for `guest_bootstrap` / `session_bootstrap` handshakes (`ConnectionTicket`).
- **Rolling-upgrade capability fields:** `package_version`, `store_id`, and `capabilities` are **only** serialized when the client sent a non-null `client_capabilities` array (`Some(...)`, including `[]`) in `ClientHello`. When a client omits `client_capabilities` (or sends `null`), the host omits all three fields so older clients enforcing `deny_unknown_fields` never reject the response.
  - `package_version`: The host's semantic version string (`1..=128` UTF-8 bytes, same as `endpoint.json`).
  - `store_id`: The host's persistent SQLite store identifier (`store_...`, `1..=128` UTF-8 bytes), stable across host restarts. Omitted if unavailable.
  - `capabilities`: Exact list of optional capabilities supported by this host binary. Hosts never advertise unimplemented capabilities.
    - `"ipc.capabilities"`: Capability negotiation handshake is supported.
    - `"events.subscribe"`: Cursor-resumable push event stream (`IpcRequest::Subscribe`) is supported.

---

## 4. Request / Response Exchange

After `ServerHello`, the connection enters a sequential request/response loop (one outstanding request per connection; idle connections time out after 300 seconds, except parked external bridge witnesses and streaming `mail_follow` connections).

### Request (`IpcEnvelope`)

```json
{
  "version": { "major": 1, "minor": 0 },
  "request_id": 1,
  "generation": 1,
  "authority": null,
  "request": {
    "kind": "operation",
    "input": {
      "name": "project.status",
      "arguments": {},
      "key": null
    }
  }
}
```

- `request_id`: Strictly positive `u64` (`>= 1`). Echoed back in `IpcResponse`.
- `generation`: Must equal `ServerHello.generation`.
- `authority`: Optional per-request authority override. `null` inherits the connection's authenticated authority for `owner_proof`, `session`, and `external_session` connections (external seat connections forbid per-request overrides). Bootstrapped guest connections (`guest_bootstrap` / `session_bootstrap`) MUST present their channel-bound `lease` ticket (`ConnectionTicket`) on each request.
- `presence` *(optional)*: Omitted when `null`. Owner terminal presence attestation for destructive or privilege-changing actions.
- `cli_selections` *(optional)*: Omitted when `null`. CLI routing metadata (never widens authority).
- `request`: Tagged union (`kind` + `input`):
  - `"operation"`: `{ "name": "<op>", "arguments": { ... }, "key": "<idempotency-key>" | null }`
  - `"external"`: External seat lifecycle and blocking mail wait (`claim_open`, `claim_wait`, `list`, `approve`, `revoke`, `mail_wait`).
  - `"subscribe"`: Cursor-resumable push event stream (`SubscribeRequest`, see Section 5).
  - `"adopt"` / `"hook"` / `"remote_owner"`: Specialized CLI/hook/remote control requests.

### Idempotency Keys

Every mutating operation requires a caller-supplied `key` (`IdempotencyKey`) in `request.input.key` (and/or inside `arguments` per the operation's schema). If a network/IPC failure leaves a commit outcome uncertain, retry with the **exact same `key`** and arguments after rediscovering the endpoint—never mint a new key for an uncertain write.

### Response (`IpcResponse`)

Success (`state: "output"`):

```json
{
  "version": { "major": 1, "minor": 0 },
  "request_id": 1,
  "generation": 1,
  "result": {
    "state": "output",
    "value": {
      "schema": "se.status/v1",
      "value": { "...": "operation output payload" },
      "window": null
    }
  }
}
```

Error (`state: "error"`):

```json
{
  "version": { "major": 1, "minor": 0 },
  "request_id": 1,
  "generation": 1,
  "result": {
    "state": "error",
    "value": {
      "schema": "se.error/v1",
      "code": "owner-required",
      "detail": { "op": "project.init" },
      "retry": { "kind": "never" },
      "class": "unauthorized",
      "exit": 1,
      "message": "`project.init` is an owner command; agent sessions can't run it",
      "remedy": {
        "text": "Use an owner terminal; unsetting SE_SESSION alone does not establish authority",
        "command": null
      }
    }
  }
}
```

(`ErrorEnvelope` flattens `ErrorBody` into the envelope root, so `"code"`, `"detail"` (the typed per-code payload object), `"retry"`, and optional `"recovery"` / `"far"` appear alongside `"schema"`, `"class"`, `"exit"`, `"message"`, and `"remedy"`.)

---

## 5. Push Event Stream (`events.subscribe`)

When `ServerHello.capabilities` includes `"events.subscribe"`, an authenticated Owner, managed session, or external seat connection may open a long-lived, cursor-resumable push stream on a dedicated connection with `request.kind = "subscribe"`:

```json
{
  "version": { "major": 1, "minor": 0 },
  "request_id": 1,
  "generation": 1,
  "authority": null,
  "request": {
    "kind": "subscribe",
    "input": {
      "project_id": "prj_01...",
      "agent_id": null,
      "after_cursor": null,
      "filter": ["mail.notice", "agent.state"],
      "max_batch_bytes": 65536
    }
  }
}
```

- **Authorization & scope:** Owner connections may filter by `project_id` / `agent_id` or subscribe across all registered projects (`project_id: null`). Managed and external session connections are pinned to their authenticated `(project_id, agent_id, session_id)` and refuse cross-project or cross-agent selectors; session-owned events (`agent.state`, `session.hold`, `session.revoke`) are gated to that exact session/credential.
- **Effective byte cap:** `min(max_batch_bytes, ServerHello.maximum_reply_bytes)` must be at least `4096` bytes (`MIN_BATCH_BYTES`) and at most `1,048,576` bytes (`MAX_FRAME_BYTES`). Every streamed frame and terminal error stays within this effective cap; an oversized event emits a terminal `input-too-large` error carrying the exact serialized byte count.
- **Streamed frames:** Each pushed `IpcResponse` carries `result.state = "output"` with `schema = "se.event-stream/v1"`. Clients MUST verify `schema == "se.event-stream/v1"` before parsing `value`, which is one of:
  - **Event frame:** `{ "cursor": "evcur_v1_...", "event_id": "ev_...", "kind": "<kind>", "occurred_at_us": i64, "payload": { ... } }`, where `kind` is one of `"mail.notice"`, `"agent.state"`, `"assignment"`, `"decision"`, `"session.hold"`, or `"session.revoke"`.
    - **Erasure invariant:** `"mail.notice"` and `"decision"` payloads carry IDs, routing metadata, and body-free dedupe digests only—never message or decision text bodies.
  - **Heartbeat control frame:** `{ "kind": "heartbeat", "head_cursor": "evcur_v1_..." }` emitted immediately when subscribing without `after_cursor` and periodically (default 10s) for liveness, never advancing `head_cursor` ahead of covered/delivered replay.
  - **Lagged control frame (terminal):** `{ "kind": "lagged", "missed_through_cursor": "evcur_v1_..." }` emitted when the per-subscriber queue (256 frames) overflows, after which the host closes the stream.
- **Cursor verification & termination:** Cursors (`evcur_v1_...`) are bound to `(store_id, incarnation, generation, event_seq)`. Malformed, reset/restored, or ahead-of-head cursors refuse with `code = "cursor-invalid"`; host generation changes refuse with `code = "runtime-incompatible"`. Session/seat revocation fences queued frames and terminates with `code = "capability-invalid"` (or closes the connection cleanly if a frame write was interrupted mid-frame).

---

## 6. Operation Schemas

Exact JSON Schemas for every registered operation's input and output are exported directly by the installed `se` binary (offline, without a running host):

```sh
se schema                          # list all registered operations and their schemas
se schema project.status --json    # exact input/output JSON schema for one operation
```

See [docs/OPS.md](OPS.md) for the complete operation inventory and [docs/USING.md](USING.md) for external seat workflows (`se agent add <name> --external`, `se external approve`, `se msg wait`).
