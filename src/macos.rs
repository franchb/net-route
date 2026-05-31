//! macOS routing-table fetch. The ONLY `unsafe` on macOS: the sysctl syscall
//! boundary and `if_indextoname`. Parsing is delegated to the pure
//! [`crate::parse::parse_route_messages`].

use std::ffi::CStr;
use std::io;

use crate::parse::{ParsedRoute, parse_route_messages};

const CTL_NET: libc::c_int = 4;
const AF_ROUTE: libc::c_int = 17;
const NET_RT_DUMP: libc::c_int = 7;

/// Fetch the raw `NET_RT_DUMP` buffer via sysctl.
///
/// The table size can change between the sizing call and the fetch call, so a
/// busy system can return `ENOMEM`/`ENOBUFS` if it grew in between. Re-query the
/// size, over-allocate by a small pad, and retry a bounded number of times
/// rather than surfacing a transient race to the caller.
fn fetch_raw_table() -> io::Result<Vec<u8>> {
    let mut mib: [libc::c_int; 6] = [CTL_NET, AF_ROUTE, 0, 0, NET_RT_DUMP, 0];

    for _ in 0..3 {
        let mut needed: libc::size_t = 0;
        // SAFETY: `mib` is a 6-element array matching the `namelen = 6` argument;
        // passing a null `oldp` with a valid `oldlenp` asks the kernel for the
        // required buffer size only (no write). All pointers are valid.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                std::ptr::null_mut(),
                &mut needed,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Pad against the table growing between the sizing and fetch calls.
        needed += 2048;
        let mut buf = vec![0u8; needed];
        // SAFETY: `buf` is allocated for `needed` bytes (the reported size plus
        // pad); `oldp = buf.as_mut_ptr()` is valid for `needed` bytes and
        // `oldlenp` points at the same `needed`. The kernel writes at most
        // `needed` bytes and updates `needed` to the amount written.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                buf.as_mut_ptr().cast(),
                &mut needed,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc >= 0 {
            buf.truncate(needed);
            return Ok(buf);
        }

        // Only a size race (table grew past our buffer) is retryable; surface
        // any other error immediately.
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) && err.raw_os_error() != Some(libc::ENOBUFS) {
            return Err(err);
        }
    }

    Err(io::Error::other("routing table size changing too rapidly"))
}

/// Resolve an interface index to its name via `if_indextoname`.
fn ifindex_to_name(idx: u32) -> Option<String> {
    let mut name = [0_i8; libc::IF_NAMESIZE];
    // SAFETY: `name` is an IF_NAMESIZE buffer, the size `if_indextoname`
    // requires; on success it writes a NUL-terminated string within bounds.
    let ret = unsafe { libc::if_indextoname(idx, name.as_mut_ptr()) };
    if ret.is_null() {
        return None;
    }
    // SAFETY: `ret` points at `name`, which holds a NUL-terminated C string.
    let cstr = unsafe { CStr::from_ptr(name.as_ptr()) };
    cstr.to_str().ok().map(str::to_owned)
}

/// Fetch + parse + resolve interface names. The mapscan loader calls this.
///
/// # Errors
///
/// Returns an error if the `sysctl` fetch fails or the parser rejects the
/// buffer's framing.
pub fn list_routes() -> io::Result<Vec<ParsedRoute>> {
    let buf = fetch_raw_table()?;
    let mut routes = parse_route_messages(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    for r in &mut routes {
        if let Some(idx) = r.ifindex {
            r.ifname = ifindex_to_name(idx);
        }
    }
    Ok(routes)
}
