# Miner REST API — contract v1

**Status: implemented in part.** The GPU miner serves the read and write routes below and answers
`501` for the rest; the CPU miner does not implement it yet. Call `GET /api/v1/` and read the
capability list rather than assuming — that is what it is for, and section 10 lists the differences.

This document is the contract both implementations are built against, and it was written before
either grew handlers: it is the interface an external manager, dashboard or monitoring agent codes
against, so it had to be agreed first.

This file is duplicated verbatim in both miner trees. If you change one copy, change both in the
same session — a checked-in hash of this file plus `openapi.yaml` is compared by the test suite,
and a divergence fails the run.

Examples below are normative for shape and field names. They are **real captured output** from a
running miner against a live pool, reformatted for width, with the operator's wallet replaced by
`wallet.worker`. Values are a snapshot, not a promise; field names and nullability are the contract.

---

## 1. Scope and versioning

Two miners implement one API:

| Miner | `miner.kind` | Devices | Pools |
|---|---|---|---|
| GPU miner | `gpu` | N CUDA GPUs, full NVML/NVAPI telemetry | pool array with failover |
| CPU miner | `cpu` | one CPU, temp/fan/clock | single pool |

**This document names no implementation.** Everything below is keyed on `miner.kind`, which is the
only value a client may branch on. `miner.name` is a free-form identifier for logs and dashboards;
it is never part of a capability decision.

**Identical paths, verbs, field names and error model on both.** Where one miner cannot serve a
resource it answers `501 not_implemented` on the same path rather than `404`, so a client never sees
a route appear or disappear — only a capability flip. Section 10 lists every such difference.

Versioning: base path `/api/v1`. **Adding** a field, an endpoint or an enum value is not a breaking
change and does not bump the version — clients must ignore unknown fields. Removing or retyping
anything bumps to `/api/v2`, and both versions would then be served during a deprecation window.
`miner.api_version` reports the contract revision (`"1.0"`), not the miner version.

## 2. Enabling it

| Option | Config key | Values | Default | Meaning |
|---|---|---|---|---|
| `--api-mode=MODE` | `"api-mode"` | `binary` · `http` · `both` | `binary` | protocol served on the API port |
| `--api-token=TOKEN` | `"api-token"` | string | none | require `Authorization: Bearer TOKEN` on **every** route |
| `--api-cors=ORIGIN` | `"api-cors"` | string | none | value for `Access-Control-Allow-Origin`; enables `OPTIONS` preflight |
| `--api-http-port=PORT` | `"api-http-port"` | int | `0` | with `both`: serve HTTP on a second port instead of sniffing one |
| `--api-control` | `"api-control"` | flag | off | enable `/api/v1/control/*`; without it those routes answer `403` |
| `--api-control-min-interval=S` | `"api-control-min-interval"` | int | `15` | minimum seconds between accepted control mutations |
| `--api-control-park-timeout=MS` | `"api-control-park-timeout"` | int | `10000` | how long a control call waits for mining threads to idle |

Modes:

- **`binary`** — the historical `command|params` → `KEY=value;…|` protocol only. Default, so an
  upgrade changes nothing.
- **`http`** — the port speaks HTTP/JSON only. A binary command gets `400`. **This is the mode to
  use for remote control:** the legacy write verbs are unreachable and every route is token-gated.
- **`both`** — one port, protocol decided from the first bytes of the connection. An uppercase
  ASCII token followed by a space is HTTP; anything else is a binary command. WebSocket upgrade
  requests keep working. Misdetection in either direction fails closed (no command executes).

Bind address and IP allowlisting are unchanged from each miner's binary API (`--api-bind` plus
whatever allowlist/permission flags it already has).

There is **no TLS in-process**. For anything beyond a trusted LAN, terminate TLS in nginx/caddy or
keep the rigs on WireGuard.

## 3. Conventions

- `Content-Type: application/json; charset=utf-8`, UTF-8, no BOM. Compact by default; `?pretty=1`
  indents.
- Every response body is a JSON **object**, never a bare array, so fields can be added later.
- Field names are `snake_case` with a **mandatory unit suffix**: `_hs` (hashes/second), `_khs`,
  `_mhz`, `_mw`, `_c` (Celsius), `_pct`, `_rpm`, `_ms`, `_s`, `_bytes`. Counters carry no suffix.
- **Unavailable values are `null`, never `0` and never omitted.** `0` means measured zero.
- Timestamps are unix seconds (integer). Durations end in `_s`.
- Trailing slashes are tolerated; unknown query parameters are ignored.
- `HEAD` is accepted wherever `GET` is. `OPTIONS` returns `204` + `Allow` when `--api-cors` is set.
  Another verb on a known path is `405` + `Allow`; an unknown path is `404`.
- Every response carries a `miner` object (section 5).
- ⚠️ **Units differ from the binary API on purpose:** JSON reports **H/s**, the binary API reported
  kH/s. The suffix makes it explicit; section 12 maps the old keys.

## 4. Authentication and privilege

Three privilege levels:

| Level | Requirement | Routes |
|---|---|---|
| `read` | source passes the IP allowlist; token if one is set | all `GET`, plus `/metrics` |
| `write` | `read` **plus** a privileged source (the miner's existing remote/admin permission flag) | `POST /pools/switch`, `/pools/url`, `/quit` |
| `control` | `write` **plus** `--api-control` | everything under `/control/` except `GET /control/state`, which is `read` |

**When `--api-token` is set it is required on every route, reads and `/metrics` included** — there
is no exemption, because hashrate and pool identity are exactly what an intruder would want.
Missing or wrong token is `401` with `WWW-Authenticate: Bearer`, evaluated before routing or
privilege. Correct token from an unprivileged source is `403`.

```
Authorization: Bearer <token>
```

Status codes, and the stable `error.code` that goes with each:

| Status | `code` | When |
|---|---|---|
| 400 | `bad_request` | malformed path, query or body; wrong JSON type; missing required field |
| 401 | `unauthorized` | missing/incorrect token |
| 403 | `forbidden` | unprivileged source, or `/control/*` without `--api-control` |
| 404 | `not_found` | unknown route, or index out of range |
| 405 | `method_not_allowed` | known path, wrong verb |
| 409 | `conflict` | a control mutation is already in progress, or one could not complete — including a switch refused because the target algorithm's per-thread workspace does not fit in RAM (§7.5) |
| 413 | `payload_too_large` | body over 8 KiB |
| 429 | `too_many_requests` | control mutation inside `--api-control-min-interval` |
| 501 | `not_implemented` | this miner cannot serve this route |
| 500 | `internal_error` | handler failure |

Clients branch on `code`, never on the prose in `message`.

Limits: request line ≤ 2 KiB, headers ≤ 8 KiB and ≤ 32 lines, body ≤ 8 KiB, socket timeout 5 s.
Responses are always `Connection: close` — one request per connection, no keep-alive, no chunked
bodies, no compression.

## 5. Capability discovery — call this first

`GET /api/v1/` is the only endpoint a client should hardcode. It reports which miner it is and
exactly which capabilities that build serves, so a manager negotiates once instead of probing for
`501`s.

```json
{
  "miner": { "name": "ccminer-tpfuemp", "version": "2026.07.2", "api_version": "1.0", "kind": "gpu" },
  "index": {
    "capabilities": ["summary", "threads", "devices", "system", "pools", "health",
                     "config", "algos", "history", "scanlog", "meminfo",
                     "pools.switch", "pools.url", "quit"],
    "links": { "summary": "/api/v1/summary", "devices": "/api/v1/devices" }
  }
}
```

⚠️ **That capability list is one build's, not the contract's.** This build does not serve the
`control.*` group or `metrics`, so they are absent and those paths answer `501`. A client must read
the list rather than assume the full set — that is the whole point of calling this endpoint first.

The list is derived from the server's route table and the `--api-control` gate, so it cannot drift
from actual behaviour. A capability absent here answers `501` (or `403` for control) if called.

`miner` is present on **every** response, including errors:

```json
{ "miner": { "name": "cpu-miner", "version": "3.2.1", "api_version": "1.0", "kind": "cpu" },
  "error": { "code": "not_implemented", "message": "scanlog is not available on this miner",
             "status": 501 } }
```

## 6. Endpoint reference

Availability by `miner.kind`: ✔ served · `501` answered but not implemented · `403` gated by an option.

| Method | Path | Priv | `gpu` | `cpu` |
|---|---|---|---|---|
| GET | `/api/v1/` | read | ✔ | ✔ |
| GET | `/api/v1/summary` | read | ✔ | ✔ |
| GET | `/api/v1/threads` | read | ✔ | ✔ |
| GET | `/api/v1/devices` · `/devices/{id}` | read | ✔ | ✔ (1 item) |
| GET | `/api/v1/system` | read | ✔ | ✔ |
| GET | `/api/v1/pools` · `/pools/{n}` | read | ✔ | ✔ (index `0` only) |
| GET | `/api/v1/health` | read | ✔ | ✔ |
| GET | `/api/v1/history` | read | ✔ | `501` |
| GET | `/api/v1/scanlog` | read | ✔ | `501` |
| GET | `/api/v1/meminfo` | read | ✔ | `501` |
| GET | `/api/v1/config` | read | ✔ | ✔ |
| GET | `/api/v1/algos` | read | ✔ | ✔ |
| POST | `/api/v1/pools/switch` | write | ✔ | `501` by design (section 10) |
| POST | `/api/v1/pools/url` | write | ✔ | ✔ |
| POST | `/api/v1/quit` | write | ✔ | ✔ |
| GET | `/api/v1/control/state` | read | ✔ | ✔ |
| POST | `/api/v1/control/start` · `/pause` · `/stop` | control | ✔ | ✔ |
| POST | `/api/v1/control/profile` | control | ✔ | ✔ |
| GET | `/metrics` | read | ✔ | ✔ |

Query parameters: `/threads?id=N` · `/history?thread=N&limit=50` (capped at 50) ·
`/pools?index=N` (alias for `/pools/{n}`) · `?pretty=1` everywhere.

### 6.1 `GET /api/v1/summary`

```json
{ "miner": { "…": "" },
  "summary": {
    "algo": "sha3t",
    "uptime_s": 40,
    "timestamp": 1786735914,
    "hashrate_hs": 269024983.0,
    "hashrate_avg_hs": null,
    "devices": 1,
    "threads": 1,
    "shares": { "accepted": 5, "rejected": 0, "stale": null, "solved": 0, "accepted_per_min": 7.5 },
    "difficulty": { "pool": 1.0, "network": 372.6308775514737, "best_share": 8.176620023103917 },
    "network": { "hashrate_hs": null },
    "pools": { "count": 1, "active": 0, "wait_time_s": 1 } } }
```

`hashrate_avg_hs` is `null` because this build does not track a rolling average yet, and
`shares.stale` is `null` because stale counts are per pool — see `/pools`. Both are the `null`
convention doing its job: the value is unavailable, not zero.

`devices` is the GPU count when `kind` is `gpu`, the CPU count when it is `cpu`. Errors: `401`, `403`, `500`.

### 6.2 `GET /api/v1/threads`

`{"threads":[…]}`, one entry per mining thread:

```json
{ "id": 0, "device_id": 0, "hashrate_hs": 269024982.6536372,
  "accepted": 5, "rejected": 0, "hw_errors": 0,
  "intensity": 25.0, "throughput": 33554432 }
```

`intensity` and `throughput` are `null` on a `cpu` miner, as are `accepted`/`rejected` until it
grows per-thread accounting. `device_id` indexes into `/devices`.

### 6.3 `GET /api/v1/devices`, `GET /api/v1/devices/{id}`

`{"devices":[…]}` — a common shell plus exactly one typed sub-object:

```json
{ "id": 0, "type": "gpu", "name": "NVIDIA GeForce RTX 3060",
  "temp_c": 74.0, "fan_pct": 46, "fan_rpm": null,
  "clock_mhz": null, "mem_clock_mhz": null,
  "power_mw": 145470, "power_limit_mw": 170000,
  "hashrate_hs": 269024982.6536372, "hashrate_per_watt_khs": null,
  "gpu": { "bus_id": 1, "sm": 860, "mem_bytes": 12884901888, "pstate": "P2",
           "base_clock_mhz": 1777, "base_mem_clock_mhz": 7501,
           "vendor_id": "0x103c", "device_id": "0x8903",
           "serial": "C445A31728", "bios": "94.06.2f.00.ed",
           "nvml_id": 0, "nvapi_id": 0, "monitoring": true } }
```

⚠️ `clock_mhz`, `mem_clock_mhz`, `fan_rpm` and `hashrate_per_watt_khs` are `null` above because they
come from the optional monitoring sampler, which was not running in that capture. `sm` is the compute
capability ×10 (860 = 8.6), not ×1.

A `cpu` miner emits one `"type": "cpu"` entry with a `cpu` sub-object (`cores`, `threads`,
`features`) and no `gpu` key. **Clients must tolerate either sub-object being absent.**

This is the **expensive** route — it queries the vendor telemetry libraries. Poll `/summary` or
`/health` instead if you only need rates. `404` for an unknown `{id}`.

### 6.4 `GET /api/v1/system`

```json
{ "os": "windows", "driver": "595.95", "cpus": 16, "cpu_temp_c": null,
  "cpu_clock_mhz": null, "cpu_fan_pct": null }
```

`driver` is the GPU driver version on a `gpu` miner, `null` on a `cpu` miner.

### 6.5 `GET /api/v1/pools`, `GET /api/v1/pools/{n}`

```json
{ "index": 0, "active": true, "name": "pool1",
  "url": "stratum+tcp://host:3333", "user": "wallet.worker",
  "algo": "x16r", "type": "stratum", "status": "connected",
  "shares": { "accepted": 41, "rejected": 1, "stale": 0, "solved": 0 },
  "difficulty": 0.5, "best_share": 3.21,
  "job": { "id": "6a1f", "height": 812345, "extranonce2_size": 4, "extranonce2": "0x00000000" },
  "ping_ms": 42, "disconnects": 0, "wait_time_s": 12, "uptime_s": 3600, "last_share_age_s": 8 }
```

`user` is exposed as the binary API already exposes it (stratum only); the **password is never
returned by any endpoint**. `stale` is `null` on a `cpu` miner, whose array always has
length 1 so that only index `0` exists.

### 6.6 `GET /api/v1/health`

Cheap enough to poll every 5 s — no vendor telemetry calls.

```json
{ "status": "ok", "mining": true, "pool_connected": true, "devices_ok": 1 }
```

`200` when healthy; `503` with `"status": "degraded"` and `"reasons": ["pool_disconnected"]`
otherwise. **A deliberately stopped miner is `200 ok` with `"mining": false`** — a manager-initiated
stop is not a fault. Ask `/control/state` for *why* mining is off.

### 6.7 `GET /api/v1/history`, `/scanlog`, `/meminfo`

`gpu`-only for now (`501` on a `cpu` miner). `history` returns the last 50 scan records per thread;
`scanlog` is available only in debug builds / with `-D`; `meminfo` reports the
miner's own bookkeeping allocations.

### 6.8 `GET /api/v1/config`

Effective options after config file + command line, **with credentials masked** (`user`, `pass`, and
any userinfo inside a URL). Use it to confirm what a rig is actually running.

### 6.9 `GET /api/v1/algos`

The authoritative, machine-readable list of algorithms this build can switch to, and which
parameters each one accepts:

```json
{ "algos": [
  { "name": "x16r", "params": [] },
  { "name": "yescrypt", "params": [
      { "name": "n",   "type": "int",    "tier": "fast" },
      { "name": "r",   "type": "int",    "tier": "fast" },
      { "name": "key", "type": "string", "tier": "fast" } ] },
  { "name": "verthash", "params": [
      { "name": "data_file", "type": "string", "tier": "slow" } ] } ] }
```

**Do not hardcode this list.** It differs between the two miners and between builds; section 9
explains the parameter tiers.

### 6.10 Write endpoints

All take a JSON body and answer `200 {"result":{…}}`.

- **`POST /api/v1/pools/switch`** — `{"index": 1}` or `{"next": true}` → `{"ok":true,"active":1}`.
  Out-of-range index → `404`. `501` on a `cpu` miner by design (section 10).
- **`POST /api/v1/pools/url`** — `{"url":"stratum+tcp://host:port","user":"…","pass":"x"}`;
  `user`/`pass` optional. The handler assembles whatever internal form the miner needs, so clients
  never build a packed string.
- **`POST /api/v1/quit`** — terminates the **process**. The `200 {"ok":true}` is flushed before the
  shutdown flag is acted on. This is not a stop verb: nothing can restart the miner afterwards. Use
  `/control/stop` for a reversible stop.

## 7. Control API

Off unless `--api-control` is given. Designed for a profit-switching manager: it can stop, start and
re-target the miner without restarting the process.

### 7.1 State machine

Four states. Every mutation passes through `switching` and lands in exactly one of the other three.

| from ↓ / verb → | `start` | `pause` | `stop` | `profile` |
|---|---|---|---|---|
| `running` | no-op `200` | → `paused` | → `stopped` | → the profile's `run` target |
| `paused` | → `running` | no-op `200` | → `stopped` (drops connection) | applies, then honours `run` (default: stay `paused`) |
| `stopped` | → `running` (reconnects first) | → `paused` (reconnects, stays parked) | no-op `200` | applies, then honours `run` (default: stay `stopped`) |
| `switching` | `409 conflict` | `409 conflict` | `409 conflict` | `409 conflict` |

- **No-ops return `200` and do not advance `epoch`.** A manager can therefore be crash-safe by
  simply re-asserting the state it wants instead of tracking what it last sent.
- **`pause` vs `stop`** differ in exactly one respect: `stop` also drops the pool connection.
  Both release device resources and keep the process and API alive.

| | process | API answers | device resources | pool connection | counted as a pool disconnect |
|---|---|---|---|---|---|
| `pause` | alive | yes | freed | **kept alive** | no |
| `stop` | alive | yes | freed | **dropped** | **no** (deliberate stops are not pool faults) |
| `quit` | exits | no | freed | dropped | n/a |

- Mutations are serialised. A second one arriving during `switching` gets `409`, never a queue.
- Mutations are throttled to one per `--api-control-min-interval` (default 15 s); a faster call gets
  `429`. `start`/`pause`/`stop` are **not** throttled, only re-targeting is.

Internally a mutation parks every mining thread first and only then changes anything, so an algo
switch can never race a running kernel. If a thread does not park within
`--api-control-park-timeout`, the mutation is **abandoned and rolled back** (`409`, with the reason
in `last_error`) rather than forced.

### 7.2 `GET /api/v1/control/state`

Read privilege — a manager is expected to poll this.

```json
{ "control": {
    "state": "running",
    "epoch": 42,
    "since_s": 118,
    "algo": "x16rv2",
    "params": { "n": null, "r": null, "key": null },
    "pool": { "index": 0, "url": "stratum+tcp://host:3333", "user": "wallet.worker" },
    "pool_connected": true,
    "threads_total": 3, "threads_parked": 0,
    "switch_count": 7, "last_switch_age_s": 118,
    "min_interval_s": 15, "ready_for_switch": true,
    "last_error": null } }
```

`epoch` increments once per accepted mutation and is the reliable way to tell "my change took
effect" from "the state happens to look right". `pool_connected` is `null` for getwork/GBT.
`ready_for_switch` is `false` while the anti-flap interval is unexpired — check it to avoid a `429`.

### 7.3 `POST /api/v1/control/pause`, `/stop`, `/start`

Body `{"wait_ms": 10000}`, optional. Responses carry the resulting state:

```json
{ "result": { "state": "paused", "epoch": 43, "parked": 3 } }
```

`start` from `stopped` reconnects, re-subscribes and re-authorises, so it takes seconds and **can
fail** — the state returns to `stopped`, `last_error` is set and `epoch` does not advance. All three
verbs return when the state flag is set, **not** when hashing has ramped up; confirm throughput via
`/summary.hashrate_hs`.

### 7.4 `POST /api/v1/control/profile` — the endpoint a manager should use

One atomic change of algorithm, parameters, pool and run state:

```json
{ "algo": "x16rv2",
  "params": { "n": 2048, "key": "Client Key" },
  "pool": { "url": "stratum+tcp://host:port", "user": "wallet.worker", "pass": "x" },
  "run": true,
  "wait_ms": 10000 }
```

Sequence: park once → apply algo and params → apply pool → set run state → one `epoch++` → respond
with the resulting `/control/state` body. **If any step fails, all of them are rolled back** to the
pre-call algo/params/pool and the response is `409` with `last_error`. A half-switched miner is never
a possible outcome.

**`algo` and `pool` must be sent together.** An `algo` without a `pool` is `400`, not a best-effort
switch: mining algorithm X against a pool expecting Y produces 100 % rejected shares while every
other metric looks healthy. That is also why there is no `/control/algo` endpoint — the invariant is
structural rather than merely validated.

Legal bodies: `algo`+`pool` (± `params`, `run`) for a full switch; `pool` alone to re-target the
same algorithm; `params` alone to retune the current algorithm; `run` alone as a synonym for
`start`/`pause`.

### 7.5 Memory-hungry algorithms are refused, not attempted

A switch whose target needs more memory than the machine has free is rejected with `409` and a
`last_error` naming the arithmetic:

```
equihash144 needs 24.3 GB for 8 threads (3106 MB each) but only 14.0 GB is free
-- 3 thread(s) would fit. Restart with -t 3 to mine it here.
```

The check runs after the target algorithm registers (its workspace is sized from the params read
at registration, so it is not knowable earlier) and before any thread allocates, keeping the same
20 % margin the startup thread-cap uses. Threads are parked and the previous algorithm is restored,
so a refusal costs a brief pause and nothing else.

The thread count cannot be lowered to fit: threads are parked for a switch, not destroyed, so
mining N threads is a property of the process. **A manager that wants a high-memory algorithm on a
small machine must start the miner with a suitable `-t`** — or run one miner process per algorithm
class. The refusal exists because the alternative is not a failed allocation but an OOM kill: the
workspaces are touched, so overcommit cannot absorb them, and the kernel takes the whole process
down along with its session stats and any queued shares.

NOTE: this is the one control-path failure a manager cannot retry its way out of. Treat a `409`
mentioning `needs … GB` as permanent for that `(algo, params, -t)` combination.

### 7.6 Worked profit-switch sequence

```
GET  /api/v1/                     → capabilities; confirm "control.profile" is present
GET  /api/v1/summary              → current algo + hashrate for the profitability model
POST /api/v1/control/profile      → {"algo":"…","pool":{…},"params":{…},"run":true}
GET  /api/v1/control/state        → poll until state == "running" and epoch has advanced
GET  /api/v1/summary              → confirm hashrate recovered for the new algo
GET  /api/v1/pools/0              → confirm shares are being ACCEPTED, not just submitted
```

The last step matters: a `200` from `/control/profile` proves the switch was applied, not that the
pool agrees with your algorithm choice.

**Slow parameters** (section 9) cannot complete inside a request. If the change needs longer than
`wait_ms`, the response is `202 Accepted` with the current state; poll `/control/state` until
`epoch` advances (success) or `last_error` is populated (failure, previous configuration still
running). Setting `wait_ms: 0` always takes this path.

## 8. Field dictionary

One alphabetical table so a name cannot mean two things in two places. `n` = nullable.

| Field | Type | Unit | n | Meaning |
|---|---|---|---|---|
| `accepted` | int | — | ✔ | accepted shares (scope: summary, thread, pool) |
| `accepted_per_min` | float | 1/min | | accepted shares per minute, process lifetime |
| `active` | bool | — | | this pool is the one currently mined |
| `algo` | string | — | | algorithm name as accepted by `--algo` |
| `api_version` | string | — | | contract revision, `"1.0"` |
| `base_clock_mhz` | int | MHz | ✔ | stock core clock |
| `best_share` | float | difficulty | ✔ | best share difficulty seen |
| `bios` | string | — | ✔ | GPU VBIOS version |
| `bus_id` | int | — | ✔ | PCI bus id |
| `capabilities` | array | — | | capability strings served by this build |
| `clock_mhz` | int | MHz | ✔ | current core clock |
| `code` | string | — | | stable machine-readable error code |
| `cores` | int | — | ✔ | physical CPU cores |
| `cpu_clock_mhz` | int | MHz | ✔ | CPU clock |
| `cpu_temp_c` | float | °C | ✔ | CPU temperature |
| `cpus` | int | — | ✔ | logical CPUs |
| `device_id` | int/string | — | ✔ | thread→device index; in `gpu` sub-object, the PCI device id |
| `devices` | int/array | — | | count in `summary`, array at `/devices` |
| `devices_ok` | int | — | | devices reporting healthy |
| `difficulty` | float/object | difficulty | | pool difficulty (pool scope) or `{pool,network,best_share}` |
| `disconnects` | int | — | | **unintentional** pool disconnects only |
| `driver` | string | — | ✔ | GPU driver version |
| `epoch` | int | — | | increments once per accepted control mutation |
| `extranonce2` / `extranonce2_size` | string/int | — | ✔ | stratum job fields |
| `fan_pct` / `fan_rpm` | int | % / rpm | ✔ | fan speed |
| `features` | array | — | ✔ | CPU instruction-set features |
| `hashrate_avg_hs` | float | H/s | | session-average hashrate |
| `hashrate_hs` | float | H/s | | current hashrate |
| `hashrate_per_watt_khs` | float | kH/s/W | ✔ | efficiency |
| `health.status` | string | — | | `ok` \| `degraded` |
| `height` | int | — | ✔ | block height of the current job |
| `hw_errors` | int | — | ✔ | hardware/validation errors on this thread |
| `id` | int | — | | device or thread index |
| `index` | int | — | | pool index |
| `intensity` | float | — | ✔ | GPU launch intensity |
| `job.id` | string | — | ✔ | stratum job id |
| `kind` | string | — | | `gpu` \| `cpu` |
| `last_error` | string | — | ✔ | reason the last control mutation failed |
| `last_share_age_s` | int | s | ✔ | seconds since the last accepted share |
| `last_switch_age_s` | int | s | ✔ | seconds since the last control mutation |
| `mem_bytes` | int | bytes | ✔ | device memory |
| `mem_clock_mhz` | int | MHz | ✔ | memory clock |
| `min_interval_s` | int | s | | configured anti-flap interval |
| `mining` | bool | — | | is the miner hashing right now |
| `monitoring` | bool | — | | telemetry available for this device |
| `name` | string | — | | miner name, device name or pool name by scope |
| `network.hashrate_hs` | float | H/s | ✔ | network hashrate |
| `params` | object | — | ✔ | algorithm parameters in effect; `null` members = not set |
| `parked` / `threads_parked` | int | — | | mining threads currently idle |
| `ping_ms` | int | ms | ✔ | pool round-trip time |
| `pool_connected` | bool | — | ✔ | `null` for getwork/GBT |
| `power_mw` / `power_limit_mw` | int | mW | ✔ | power draw and cap |
| `pstate` | string | — | ✔ | performance state |
| `ready_for_switch` | bool | — | | anti-flap interval has expired |
| `reasons` | array | — | ✔ | why health is `degraded` |
| `rejected` | int | — | ✔ | rejected shares |
| `serial` | string | — | ✔ | device serial |
| `shares` | object | — | | `{accepted,rejected,stale,solved[,accepted_per_min]}` |
| `since_s` | int | s | | seconds in the current control state |
| `sm` | int | — | ✔ | CUDA compute capability ×10 |
| `solved` | int | — | | blocks solved |
| `stale` | int | — | ✔ | stale shares |
| `state` | string | — | | `running` \| `paused` \| `stopped` \| `switching` |
| `status` | string | — | | pool connection status |
| `switch_count` | int | — | | accepted control mutations this session |
| `temp_c` | float | °C | ✔ | device temperature |
| `threads` | int/array | — | | count in `summary`, array at `/threads` |
| `threads_total` | int | — | | configured mining threads |
| `throughput` | int | — | ✔ | nonces per launch |
| `timestamp` | int | unix s | | when the response was generated |
| `type` | string | — | | `gpu` \| `cpu` (device), `stratum` \| `getwork` (pool) |
| `uptime_s` | int | s | | process uptime, or pool session length by scope |
| `url` | string | — | | pool URL, never containing a password |
| `user` | string | — | ✔ | pool username/wallet |
| `vendor_id` | string | — | ✔ | PCI vendor id |
| `version` | string | — | | miner version |
| `wait_time_s` | int | s | ✔ | time spent waiting for work |

## 9. Algorithm parameters

Some algorithms take parameters beyond their name (`n`, `r`, `key`, a data file, …). The contract:

- **`GET /api/v1/algos` is authoritative.** It lists, per algorithm, the accepted parameter names,
  their types and their tier. Managers must read it rather than hardcoding, because the set differs
  between the two miners and between builds.
- Parameters are applied **live** — no process restart. They are validated per algorithm; an unknown
  name, a wrong type or an out-of-range value is `400` and **nothing** is applied.
- **Omitted ≠ `null`.** Omitting a parameter keeps the value currently in effect; sending `null`
  resets it to the algorithm's default.
- Parameters are **sticky per algorithm**: switching away and back restores what you last set for
  that algorithm.
- **Two tiers.** `fast` parameters take effect within the park window like an algorithm switch.
  `slow` parameters need file or network I/O (`data_file` for verthash, `scratchpad_url` for
  wildkeccak) and take seconds to minutes; those return `202` and are polled (section 7.5). Failure
  leaves the previous configuration running and populates `last_error`.
- A parameter accepted by one miner and not the other is listed in section 10.

## 10. Differences by miner kind

The table integrators actually need. Everything else is identical.

| Path / field | `gpu` | `cpu` | Why |
|---|---|---|---|
| `/history`, `/scanlog`, `/meminfo` | ✔ | `501` | the statistics and hash-log subsystems exist only on the GPU side; `/scanlog` is additionally debug-build-only |
| `POST /pools/switch` | ✔ | **`501`, permanently** | a `cpu` miner has no pool array; pool selection belongs to the manager, which supplies a pool with every `/control/profile` call |
| `/pools` array length | `0..n` | always `1` | single-pool miner |
| `threads[].accepted` / `.rejected` | ✔ | `null` | per-thread share accounting not tracked |
| `threads[].intensity` / `.throughput` | ✔ | `null` | GPU-only concepts |
| `pools[].stale` | ✔ | `null` | not tracked |
| `devices[].gpu` | present | absent | — |
| `devices[].cpu` | absent | present | — |
| `system.driver` | ✔ | `null` | no GPU driver |
| Write gate | group `W` via `--api-allow` | `--api-remote` | pre-existing option semantics, unchanged |

Out of scope for v1 on both miners, stated so it is not mistaken for an omission: no process
restart or self-update, no overclock/fan/power control, no profitability logic inside the miner, no
pool inventory management, no push/streaming (the API is strictly pull), no TLS in-process.

## 11. Metrics

`GET /metrics` — Prometheus text exposition, deliberately **outside** `/api/v1/` because it is not
versioned JSON and scrapers default to that path. Read privilege; the token applies if set.
`Content-Type: text/plain; version=0.0.4; charset=utf-8`. Base units (seconds, watts), `_total` on
counters, `# HELP`/`# TYPE` on every family. No self-reported `up` metric — Prometheus synthesises
that from the scrape.

| Metric | Type | Labels | Unit |
|---|---|---|---|
| `miner_hashrate_hashes_per_second` | gauge | `algo` | H/s |
| `miner_device_hashrate_hashes_per_second` | gauge | `device`, `type`, `algo` | H/s |
| `miner_network_difficulty`, `miner_pool_difficulty` | gauge | — | difficulty |
| `miner_shares_total` | counter | `result="accepted\|rejected\|stale"` | shares |
| `miner_blocks_solved_total` | counter | — | blocks |
| `miner_pool_disconnects_total` | counter | `pool` | disconnects (**unintentional only**) |
| `miner_pool_last_share_age_seconds` | gauge | `pool` | s |
| `miner_pool_connected` | gauge 0/1 | `pool` | — (absent for getwork/GBT) |
| `miner_mining_active` | gauge 0/1 | — | — |
| `miner_control_state` | gauge 0/1 | `state="running\|paused\|stopped\|switching"` | — (exactly one series is 1) |
| `miner_uptime_seconds` | gauge | — | s |
| `miner_info` | gauge (always 1) | `version`, `algo`, `kind` | — |
| `miner_device_temperature_celsius` | gauge | `device` | °C |
| `miner_device_power_watts` | gauge | `device` | W |
| `miner_device_fan_percent` | gauge | `device` | % |
| `miner_device_hw_errors_total` | counter | `device` | errors |

`miner_shares_total` is **process-lifetime monotonic**: the metrics layer keeps its own accumulating
totals, because some internal counters are reset on an algorithm switch and a counter that decreases
corrupts `rate()`.

Scrape config:

```yaml
scrape_configs:
  - job_name: miners
    scrape_interval: 30s
    authorization:
      credentials: <the --api-token value>
    static_configs:
      - targets: ['rig1:4068', 'rig2:4068']
```

Worked queries — these three are why the endpoint exists:

```promql
# unintended downtime only: ignores manager-initiated stops
miner_mining_active == 0
  unless on(instance) miner_control_state{state=~"stopped|paused|switching"} == 1

# reject rate over 15 minutes, as pool health
sum(rate(miner_shares_total{result="rejected"}[15m]))
  / sum(rate(miner_shares_total[15m])) > 0.02

# effective hashrate per algorithm, for the profitability model
sum by (algo) (miner_hashrate_hashes_per_second)
```

## 12. Migration from the binary API

The binary protocol is unchanged and stays the default. Mapping for existing consumers:

| Binary | REST |
|---|---|
| `summary` → `KHS` | `/summary` → `hashrate_hs` (**H/s, not kH/s**) |
| `summary` → `ACC`, `REJ`, `ACCMN`, `SOLV` | `/summary` → `shares.accepted`, `.rejected`, `.accepted_per_min`, `.solved` |
| `summary` → `DIFF`, `NETKHS` | `/summary` → `difficulty.network`, `network.hashrate_hs` |
| `summary` → `UPTIME`, `TS` | `/summary` → `uptime_s`, `timestamp` |
| `threads` → `GPU`, `KHS`, `HWF`, `I`, `THR` | `/threads[]` → `device_id`, `hashrate_hs`, `hw_errors`, `intensity`, `throughput` |
| `hwinfo` → `TEMP`, `FAN`, `RPM`, `POWER`, `PLIM` | `/devices[]` → `temp_c`, `fan_pct`, `fan_rpm`, `power_mw`, `power_limit_mw` |
| `hwinfo` → `FREQ`, `MEMFREQ` (base) | `/devices[]` → `gpu.base_clock_mhz`, `gpu.base_mem_clock_mhz` |
| `hwinfo` → `GPUF`, `MEMF` (current) | `/devices[]` → `clock_mhz`, `mem_clock_mhz` |
| `hwinfo` → `SM`, `MEM`, `PST`, `VID`, `PID`, `SN`, `BIOS` | `/devices[]` → `gpu.sm`, `gpu.mem_bytes` (**bytes, not MB**), `gpu.pstate`, `gpu.vendor_id`, `gpu.device_id`, `gpu.serial`, `gpu.bios` |
| `hwinfo` → `OS`, `NVDRIVER`, `CPUS`, `CPUTEMP`, `CPUFREQ` | `/system` → `os`, `driver`, `cpus`, `cpu_temp_c`, `cpu_clock_mhz` |
| `pool` → `POOL`, `URL`, `USER`, `DIFF`, `BEST` | `/pools/{n}` → `name`, `url`, `user`, `difficulty`, `best_share` |
| `pool` → `JOB`, `H`, `N2SZ`, `N2` | `/pools/{n}` → `job.id`, `job.height`, `job.extranonce2_size`, `job.extranonce2` |
| `pool` → `ACC`, `REJ`, `STALE`, `SOLV` | `/pools/{n}` → `shares.accepted`, `.rejected`, `.stale`, `.solved` |
| `pool` → `PING`, `DISCO`, `WAIT`, `UPTIME`, `LAST` | `/pools/{n}` → `ping_ms`, `disconnects`, `wait_time_s`, `uptime_s`, `last_share_age_s` |
| `histo`, `scanlog`, `meminfo` | `/history`, `/scanlog`, `/meminfo` |
| `histo` → `KHS` | `/history[]` → `hashrate_hs`. ⚠️ **The binary key is mislabelled**: `histo`'s `KHS` already carries **H/s**, not kH/s, so this is the one mapping where the value does *not* change by 1000. Unchanged in the binary API for compatibility. |
| `switchpool\|n`, `seturl\|url`, `quit` | `POST /pools/switch`, `POST /pools/url`, `POST /quit` |

Every value that was a bare number in a `;`-separated record is now a typed JSON field, and
unavailable values are `null` instead of `0` or an empty string.

## 13. Changelog

| Revision | Change |
|---|---|
| 1.0 (unreleased) | Initial contract: read surface, write surface, control API, metrics. |
