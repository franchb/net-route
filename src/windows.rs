//! Windows routing-table list via `GetIpForwardTable2` (read-only). All FFI is
//! contained here with SAFETY comments; no panics. The exact `windows-sys` 0.61
//! union field paths are verified by the `cross`/CI Windows build (plan A8);
//! runtime correctness (incl. the Q2 Npcap `\Device\NPF_{GUID}` mapping) is
//! deferred to a Windows CI runner.

use std::io;
use std::net::IpAddr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToNameW, FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

use crate::parse::ParsedRoute;

/// RAII guard so the kernel table is always freed, even on early return.
struct TableGuard(*mut MIB_IPFORWARD_TABLE2);

impl Drop for TableGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by GetIpForwardTable2 and is freed
            // exactly once (here); not used afterwards.
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}

fn luid_to_name(luid: NET_LUID_LH) -> Option<String> {
    let mut buf = [0u16; 257]; // NDIS_IF_MAX_STRING_SIZE + 1
    // SAFETY: `luid` is a valid NET_LUID_LH; `buf` is a 257-wchar buffer of the
    // size ConvertInterfaceLuidToNameW requires; it writes a NUL-terminated
    // UTF-16 string within bounds.
    let rc = unsafe { ConvertInterfaceLuidToNameW(&luid, buf.as_mut_ptr(), buf.len()) };
    if rc != NO_ERROR {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

/// List the IPv4 + IPv6 forwarding table.
///
/// # Errors
///
/// Returns an error if `GetIpForwardTable2` fails.
pub fn list_routes() -> io::Result<Vec<ParsedRoute>> {
    let mut ptable: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: out-param pointer is valid; on ERROR_SUCCESS the kernel allocates
    // `*ptable`, freed by TableGuard below.
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut ptable) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _guard = TableGuard(ptable);

    // SAFETY: `ptable` is non-null and valid (rc == ERROR_SUCCESS); NumEntries
    // bounds the Table flexible array.
    let n = unsafe { (*ptable).NumEntries } as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: i < NumEntries; Table is an array of NumEntries rows.
        let row: &MIB_IPFORWARD_ROW2 = unsafe { &*(*ptable).Table.as_ptr().add(i) };
        if let Some(route) = row_to_route(row) {
            out.push(route);
        }
    }
    Ok(out)
}

fn row_to_route(row: &MIB_IPFORWARD_ROW2) -> Option<ParsedRoute> {
    // SAFETY (per union access): the arm read matches the `si_family` checked first.
    let dst_family = unsafe { row.DestinationPrefix.Prefix.si_family };
    let destination: IpAddr = match dst_family {
        AF_INET => {
            let a = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr };
            IpAddr::from(a.to_ne_bytes())
        }
        AF_INET6 => {
            let a = unsafe { row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte };
            IpAddr::from(a)
        }
        _ => return None, // was `panic!` upstream — skip instead
    };
    let prefix = row.DestinationPrefix.PrefixLength;

    // SAFETY: union access matched against `si_family`.
    let nh_family = unsafe { row.NextHop.si_family };
    let gateway: Option<IpAddr> = match nh_family {
        AF_INET => {
            let a = unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_addr };
            Some(IpAddr::from(a.to_ne_bytes()))
        }
        AF_INET6 => {
            let a = unsafe { row.NextHop.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::from(a))
        }
        _ => None,
    };
    // An unspecified next hop means on-link (no gateway).
    let gateway = gateway.filter(|ip| !ip.is_unspecified());

    Some(ParsedRoute {
        destination,
        prefix,
        gateway,
        ifindex: Some(row.InterfaceIndex),
        ifname: luid_to_name(row.InterfaceLuid),
        metric: Some(row.Metric),
    })
}
