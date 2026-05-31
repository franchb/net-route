# mapscan-route

[![CI](https://github.com/franchb/net-route/actions/workflows/ci.yml/badge.svg)](https://github.com/franchb/net-route/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.95.0-blue.svg)](#minimum-supported-rust-version)

Read the OS routing table on macOS and Windows — **read-only, synchronous, and
panic-free**. A deliberately slimmed fork of
[`johnyburd/net-route`](https://github.com/johnyburd/net-route), trimmed to just
the fetch-and-parse path needed by the Mapscan project.

> The crate is named `mapscan-route`; the repository keeps the `net-route` name
> from its upstream origin.

## Why this fork

Upstream `net-route` is a full-featured, cross-platform crate with a write path,
an async change-notification stream, a Linux netlink backend, and a
`bindgen`/`route.c` build step. Mapscan only needs to *read* the table, once,
synchronously. This fork keeps that and removes the rest:

| Area | Upstream `net-route` | `mapscan-route` |
| --- | --- | --- |
| Read routing table | ✅ | ✅ |
| Add / delete routes | ✅ | ❌ removed |
| Async route-change stream | ✅ | ❌ removed |
| Linux netlink backend | ✅ | ❌ (parser only — see below) |
| `bindgen` / `route.c` toolchain | ✅ | ❌ removed (no build script) |
| Runtime | `async` (tokio) | `sync` |

The payoff: a tiny dependency surface, no build script, and a pure parser that
is **`cfg`-independent and fuzzed** — so the macOS wire-format logic can be
tested and fuzzed on any host, including the Linux CI runner.

## Platform support

| Platform | `list_routes()` | Mechanism | `unsafe` |
| --- | --- | --- | --- |
| macOS | ✅ | `sysctl(NET_RT_DUMP)` + `if_indextoname` | sysctl + name lookup only |
| Windows | ✅ | `GetIpForwardTable2` + `ConvertInterfaceLuidToNameW` | FFI call boundary only |
| Linux | ❌ | not provided — Mapscan reads `/proc/net/route` directly | — |

The pure parser ([`parse_route_messages`]) is available on **all** targets,
Linux included.

## Install

```toml
[dependencies]
mapscan-route = { git = "https://github.com/franchb/net-route" }
```

The pure parser pulls in nothing but `std`. Platform FFI is gated, so a Linux
build of a downstream crate links no `libc`/`windows-sys` — those dependencies
are declared `cfg`-gated inside `mapscan-route` and you don't add them yourself.

## Usage

### Live routing table (macOS / Windows)

```rust
// macOS / Windows
fn main() -> std::io::Result<()> {
    for route in mapscan_route::list_routes()? {
        println!("{route:?}");
    }
    Ok(())
}
```

There is a runnable example:

```sh
cargo run --example dump_table   # macOS/Windows: fetch + parse the live table
```

### Pure parser (any platform)

`parse_route_messages` turns a raw macOS `NET_RT_DUMP` buffer (a sequence of
`rt_msghdr` + sockaddr blocks) into route entries. It never panics — every
malformed-input path returns a `RouteParseError` instead.

```rust
use mapscan_route::{parse_route_messages, RouteParseError};

fn parse(raw: &[u8]) -> Result<(), RouteParseError> {
    let routes = parse_route_messages(raw)?;
    for r in routes {
        println!("{} /{} via {:?}", r.destination, r.prefix, r.gateway);
    }
    Ok(())
}
```

## API at a glance

```rust
pub struct ParsedRoute {
    pub destination: IpAddr,        // 0.0.0.0/:: with prefix 0 == default route
    pub prefix: u8,                 // destination prefix length in bits
    pub gateway: Option<IpAddr>,    // None == on-link
    pub ifindex: Option<u32>,       // egress interface index
    pub ifname: Option<String>,     // resolved at the FFI boundary
    pub metric: Option<u32>,        // Some on Windows; None on macOS
}

pub enum RouteParseError {
    Truncated { what: &'static str, need: usize, got: usize },
    BadAddressFamily(u16),
    UnexpectedRtmVersion(u8),
}

pub fn parse_route_messages(buf: &[u8]) -> Result<Vec<ParsedRoute>, RouteParseError>;

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn list_routes() -> std::io::Result<Vec<ParsedRoute>>;
```

## Safety and robustness

- **Panic-free parser.** All buffer access is bounds-checked; no input can make
  `parse_route_messages` panic. This is enforced by a `cargo-fuzz` target.
- **Minimal `unsafe`.** The only `unsafe` is the unavoidable syscall/FFI
  boundary (`sysctl` + `if_indextoname` on macOS; `GetIpForwardTable2` +
  `ConvertInterfaceLuidToNameW` on Windows), each with a `SAFETY:` justification.
- **Fail-open.** A single malformed table entry skips only that entry; header
  framing errors (bad `rtm_version`, truncation) still surface as errors.

## Fuzzing

The parser is fuzzed in CI on a nightly toolchain, and you can run it locally:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run parse_route_messages
```

`cargo-fuzz` requires a nightly toolchain (it uses libFuzzer).

## Minimum supported Rust version

`mapscan-route` targets **Rust 1.95.0** (edition 2024).

## License

MIT, inherited from upstream `johnyburd/net-route` (see the `license` field in
`Cargo.toml`).

## Credits

Forked from [`johnyburd/net-route`](https://github.com/johnyburd/net-route) by
John Burdick. This fork narrows the scope to a read-only, synchronous, safe
parser for the [Mapscan](https://github.com/franchb) project.

[`parse_route_messages`]: https://docs.rs/mapscan-route
