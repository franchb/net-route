// SPDX-License-Identifier: MIT
//! Read-only OS routing-table access (slimmed fork of `johnyburd/net-route`).
//!
//! - [`parse_route_messages`] — pure, `cfg`-independent, panic-free parser for a
//!   macOS `NET_RT_DUMP` buffer (fuzzable on any host).
//! - `list_routes` — live routing table on macOS (sysctl) and Windows
//!   (`GetIpForwardTable2`). Not provided on Linux (mapscan uses `/proc/net/route`).
//!   (Not linked here: it is `cfg`-gated to those targets and would be an
//!   unresolved intra-doc link on a Linux docs build.)
//!
//! The write path (`add`/`delete`), the routing-socket change stream, the Linux
//! netlink backend, and the `bindgen`/`route.c` toolchain from upstream are
//! intentionally removed.
//!
//! ## Example
//! ```no_run
//! # #[cfg(any(target_os = "macos", target_os = "windows"))]
//! # fn main() -> std::io::Result<()> {
//! for route in mapscan_route::list_routes()? {
//!     println!("{route:?}");
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(any(target_os = "macos", target_os = "windows")))]
//! # fn main() {}
//! ```

mod parse;
pub use parse::{ParsedRoute, RouteParseError, parse_route_messages};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::list_routes;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::list_routes;
