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
fn fetch_raw_table() -> io::Result<Vec<u8>> {
    let mut mib: [libc::c_int; 6] = [CTL_NET, AF_ROUTE, 0, 0, NET_RT_DUMP, 0];
    let mut needed: libc::size_t = 0;

    // SAFETY: `mib` is a 6-element array matching the `namelen = 6` argument;
    // passing a null `oldp` with a valid `oldlenp` asks the kernel for the
    // required buffer size only (no write). All pointers are valid for the call.
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

    let mut buf = vec![0u8; needed];
    // SAFETY: `buf` has capacity `needed` (the size the kernel just reported);
    // `oldp = buf.as_mut_ptr()` is valid for `needed` bytes and `oldlenp`
    // points at the same `needed`. The kernel writes at most `needed` bytes.
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
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(needed);
    Ok(buf)
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
