//! Pure, `cfg`-independent, panic-free parser for a macOS `NET_RT_DUMP`
//! routing-table buffer (a sequence of `rt_msghdr` + sockaddr blocks).
//!
//! The ABI constants below are hardcoded macOS values *on purpose*: this
//! function must compile and fuzz on the Linux CI host, where the system
//! headers would give Linux's (different) values. They are pinned against a
//! real captured table by the mapscan fixture test (plan task A6/B5).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// --- macOS routing ABI (pinned by the B5 real-fixture test) ---
pub(crate) const AF_INET: u16 = 2;
pub(crate) const AF_INET6: u16 = 30; // NOTE: 30 on macOS, not Linux's 10
pub(crate) const AF_LINK: u16 = 18;
pub(crate) const RTM_VERSION: u8 = 5;
pub(crate) const RT_MSGHDR_LEN: usize = 92; // sizeof(struct rt_msghdr), 64-bit macOS
pub(crate) const RTAX_DST: usize = 0;
pub(crate) const RTAX_GATEWAY: usize = 1;
pub(crate) const RTAX_NETMASK: usize = 2;
pub(crate) const RTAX_MAX: usize = 8;
const RTF_WASCLONED: i32 = 0x0002_0000;
const RTF_HOST: i32 = 0x0000_0004;

/// One forwarding-table entry, platform-agnostic. The pure parser fills every
/// field except `ifname` (resolved later, at the FFI boundary) and `metric`
/// (`None` on macOS; `Some` on Windows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRoute {
    /// Destination network address (`0.0.0.0`/`::` with `prefix == 0` is the default route).
    pub destination: IpAddr,
    /// Destination prefix length in bits.
    pub prefix: u8,
    /// Next-hop gateway, or `None` for an on-link destination.
    pub gateway: Option<IpAddr>,
    /// Egress interface index, if present in the message.
    pub ifindex: Option<u32>,
    /// Egress interface name, resolved at the FFI boundary (None at parse time).
    pub ifname: Option<String>,
    /// Route metric (`Some` on Windows; `None` on macOS — synthesized later).
    pub metric: Option<u32>,
}

/// Route-table parse failures. NEVER panics — every malformed-input path
/// returns one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteParseError {
    /// A header or sockaddr field was shorter than its fixed minimum size.
    Truncated {
        /// Which structure was being read.
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// A sockaddr carried an address family the parser does not handle.
    BadAddressFamily(u16),
    /// The `rt_msghdr` version byte did not match the expected `RTM_VERSION`.
    UnexpectedRtmVersion(u8),
}

#[inline]
fn le_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn le_i32(b: &[u8], off: usize) -> Option<i32> {
    b.get(off..off + 4)
        .map(|s| i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// macOS `ROUNDUP`: sockaddr blocks are padded to a multiple of 4; a 0-length
/// sockaddr still consumes one 4-byte slot.
#[inline]
fn roundup(sa_len: u8) -> usize {
    if sa_len == 0 {
        4
    } else {
        (((sa_len as usize) - 1) | 0x3) + 1
    }
}

/// Parse a `NET_RT_DUMP` buffer (concatenated `rt_msghdr` + sockaddr blocks)
/// into route entries.
///
/// # Errors
///
/// Returns [`RouteParseError::UnexpectedRtmVersion`] if a message header
/// carries an unexpected version (the stream framing cannot be trusted), or
/// [`RouteParseError::Truncated`] if a header field runs past the buffer.
/// Per-entry address errors are *not* fatal — they skip the entry (fail-open).
pub fn parse_route_messages(buf: &[u8]) -> Result<Vec<ParsedRoute>, RouteParseError> {
    let mut routes = Vec::new();
    let mut offset = 0usize;

    while offset + RT_MSGHDR_LEN <= buf.len() {
        let hdr = &buf[offset..];
        let msglen = le_u16(hdr, 0).ok_or(RouteParseError::Truncated {
            what: "rtm_msglen",
            need: 2,
            got: hdr.len(),
        })? as usize;
        // A zero/short msglen would not advance the cursor — treat as
        // truncation and stop rather than spin.
        if msglen < RT_MSGHDR_LEN || offset + msglen > buf.len() {
            break;
        }
        let version = *hdr.get(2).ok_or(RouteParseError::Truncated {
            what: "rtm_version",
            need: 3,
            got: hdr.len(),
        })?;
        if version != RTM_VERSION {
            return Err(RouteParseError::UnexpectedRtmVersion(version));
        }
        let rtm_index = le_u16(hdr, 4).unwrap_or(0);
        let rtm_flags = le_i32(hdr, 8).unwrap_or(0);
        let rtm_addrs = le_i32(hdr, 12).unwrap_or(0);

        let body = &buf[offset + RT_MSGHDR_LEN..offset + msglen];
        offset += msglen;

        // Skip host-cloned ARP/neighbour entries (else the table fills with neighbours).
        if rtm_flags & RTF_WASCLONED != 0 {
            continue;
        }
        if let Some(route) = parse_one(rtm_addrs, rtm_index, rtm_flags, body) {
            routes.push(route);
        }
    }
    Ok(routes)
}

/// Parse the sockaddr block following one `rt_msghdr` into a [`ParsedRoute`].
/// Returns `None` when there is no usable destination (fail-open).
fn parse_one(rtm_addrs: i32, rtm_index: u16, rtm_flags: i32, body: &[u8]) -> Option<ParsedRoute> {
    // Slice out up to RTAX_MAX sockaddrs by walking ROUNDUP(sa_len).
    let mut slots: [Option<&[u8]>; RTAX_MAX] = [None; RTAX_MAX];
    let mut pos = 0usize;
    for (idx, slot) in slots.iter_mut().enumerate() {
        if rtm_addrs & (1 << idx) == 0 {
            continue;
        }
        let sa = match body.get(pos..).filter(|s| !s.is_empty()) {
            Some(s) => s,
            None => break, // mask claims more sockaddrs than bytes; stop (no panic)
        };
        let sa_len = sa[0];
        let take = roundup(sa_len).max(4);
        *slot = body.get(pos..pos + take.min(sa.len()));
        pos += take;
        if pos > body.len() {
            break;
        }
    }

    // FAIL-OPEN (decision): a per-entry address error skips ONLY that entry; it
    // never aborts the whole table. Rationale — `spawn_refresh` keeps the prior
    // table on a loader `Err`, so a single persistently-odd row would otherwise
    // freeze route refresh indefinitely. Header-framing errors (rtm_version,
    // truncation) still propagate; per-entry family/address errors do not.
    let destination = match sa_to_ip(slots[RTAX_DST]?) {
        Ok(Some(ip)) => ip,
        Ok(None) | Err(_) => return None, // AF_LINK / unknown / bad family => skip entry
    };

    let gateway = match slots[RTAX_GATEWAY] {
        Some(sa) => normalize_v6_scope(sa_to_ip(sa).ok().flatten()),
        None => None,
    };

    let mut prefix = match destination {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };
    if rtm_addrs & (1 << RTAX_NETMASK) != 0 {
        prefix = match slots[RTAX_NETMASK] {
            None => 0,
            Some(sa) => mask_to_prefix(sa, destination),
        };
    } else if rtm_flags & RTF_HOST == 0 {
        // No netmask and not a host route => default route.
        prefix = 0;
    }

    Some(ParsedRoute {
        destination,
        prefix,
        gateway,
        ifindex: Some(u32::from(rtm_index)),
        ifname: None,
        metric: None,
    })
}

/// Decode a sockaddr into an `IpAddr`. `AF_LINK` => `Ok(None)` (on-link, no IP).
fn sa_to_ip(sa: &[u8]) -> Result<Option<IpAddr>, RouteParseError> {
    let family = match sa.get(1) {
        Some(&f) => u16::from(f),
        None => return Ok(None),
    };
    match family {
        f if f == AF_INET => {
            let o = sa.get(4..8).ok_or(RouteParseError::Truncated {
                what: "sockaddr_in",
                need: 8,
                got: sa.len(),
            })?;
            Ok(Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))))
        }
        f if f == AF_INET6 => {
            let o = sa.get(8..24).ok_or(RouteParseError::Truncated {
                what: "sockaddr_in6",
                need: 24,
                got: sa.len(),
            })?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(o);
            Ok(Some(IpAddr::V6(Ipv6Addr::from(octets))))
        }
        f if f == AF_LINK => Ok(None),
        other => Err(RouteParseError::BadAddressFamily(other)),
    }
}

/// macOS encodes the v6 scope_id into bytes 2-3 of link-local / interface-or-
/// link-local-multicast gateways; zero them to recover the real address.
fn normalize_v6_scope(ip: Option<IpAddr>) -> Option<IpAddr> {
    if let Some(IpAddr::V6(v6)) = ip {
        let segs = v6.segments();
        let is_ll = segs[0] == 0xfe80;
        let oct = v6.octets();
        let is_mc = oct[0] == 0xff;
        let mc_scope = oct[1] & 0x0f;
        if is_ll || (is_mc && (mc_scope == 1 || mc_scope == 2)) {
            return Some(IpAddr::V6(Ipv6Addr::new(
                segs[0], 0, segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
            )));
        }
    }
    ip
}

/// Convert a (possibly BSD-compressed) netmask sockaddr to a prefix length by
/// counting contiguous leading 1-bits across the present address bytes. A
/// compressed mask has a short `sa_len` with trailing zero bytes omitted.
fn mask_to_prefix(sa: &[u8], dst: IpAddr) -> u8 {
    let sa_len = sa.first().copied().unwrap_or(0) as usize;
    // Address bytes begin at offset 4 (mirroring sockaddr_in's sin_addr); for a
    // compressed mask sa_family is often 0, so key the width off the dst family.
    let (addr_off, width) = match dst {
        IpAddr::V4(_) => (4usize, 4usize),
        IpAddr::V6(_) => (8usize, 16usize),
    };
    let mut full = vec![0u8; width];
    let present = sa_len.saturating_sub(addr_off).min(width);
    if let Some(bytes) = sa.get(addr_off..addr_off + present) {
        full[..present].copy_from_slice(bytes);
    }
    // Count contiguous leading 1-bits (BSD masks are contiguous); stop at the
    // first 0 bit. Zero-extended trailing bytes contribute nothing.
    let mut bits = 0u8;
    'outer: for byte in &full {
        for i in (0..8).rev() {
            if byte & (1 << i) != 0 {
                bits += 1;
            } else {
                break 'outer;
            }
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // Build one rt_msghdr (RT_MSGHDR_LEN bytes) with the given rtm_addrs mask,
    // followed by the supplied sockaddr blocks. Little-endian (macOS x86_64/arm64).
    fn msg(rtm_addrs: i32, rtm_index: u16, rtm_flags: i32, sockaddrs: &[Vec<u8>]) -> Vec<u8> {
        let mut body: Vec<u8> = sockaddrs.iter().flatten().copied().collect();
        let msglen = (RT_MSGHDR_LEN + body.len()) as u16;
        let mut hdr = vec![0u8; RT_MSGHDR_LEN];
        hdr[0..2].copy_from_slice(&msglen.to_le_bytes()); // rtm_msglen
        hdr[2] = RTM_VERSION; // rtm_version
        hdr[3] = 4; // rtm_type (RTM_GET; unused by parser)
        hdr[4..6].copy_from_slice(&rtm_index.to_le_bytes()); // rtm_index
        hdr[8..12].copy_from_slice(&rtm_flags.to_le_bytes()); // rtm_flags
        hdr[12..16].copy_from_slice(&rtm_addrs.to_le_bytes()); // rtm_addrs
        hdr.append(&mut body);
        hdr
    }

    // sockaddr_in: [sa_len=16, sa_family=AF_INET, port(2), addr(4), zero(8)]
    fn sa_in(addr: Ipv4Addr) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[0] = 16;
        v[1] = AF_INET as u8;
        v[4..8].copy_from_slice(&addr.octets());
        v
    }

    // BSD-compressed v4 netmask: sa_len counts only the significant bytes.
    fn sa_in_masklen_v4(prefix: u8) -> Vec<u8> {
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let bytes = mask.to_be_bytes();
        let significant = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let mut v = vec![0u8; 4 + significant];
        v[0] = (4 + significant) as u8; // sa_len
        v[1] = 0; // sa_family commonly 0 on compressed masks
        v[4..4 + significant].copy_from_slice(&bytes[..significant]);
        v
    }

    #[test]
    fn parses_default_route_via_gateway() {
        let buf = msg(
            (1 << RTAX_DST) | (1 << RTAX_GATEWAY),
            5,
            0,
            &[
                sa_in(Ipv4Addr::UNSPECIFIED),
                sa_in(Ipv4Addr::new(10, 0, 0, 1)),
            ],
        );
        let routes = parse_route_messages(&buf).expect("valid table parses");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            routes[0].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(routes[0].prefix, 0); // no NETMASK present => /0
        assert_eq!(routes[0].ifindex, Some(5));
        assert_eq!(routes[0].ifname, None); // resolved later, at FFI boundary
        assert_eq!(routes[0].metric, None); // macOS synthesizes 0 in es-netstack
    }

    #[test]
    fn parses_onlink_v4_slash24_with_compressed_mask() {
        let buf = msg(
            (1 << RTAX_DST) | (1 << RTAX_NETMASK),
            7,
            0,
            &[sa_in(Ipv4Addr::new(192, 0, 2, 0)), sa_in_masklen_v4(24)],
        );
        let r = parse_route_messages(&buf).expect("parses");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].prefix, 24);
        assert_eq!(r[0].gateway, None);
        assert_eq!(r[0].ifindex, Some(7));
    }

    #[test]
    fn truncated_buffer_is_not_a_panic() {
        // Half a header: must return Ok(empty) or Err, never panic.
        let buf = vec![0xFFu8; RT_MSGHDR_LEN / 2];
        let _ = parse_route_messages(&buf); // must not panic
    }

    #[test]
    fn bad_rtm_version_is_an_error_not_panic() {
        let mut buf = msg(1 << RTAX_DST, 1, 0, &[sa_in(Ipv4Addr::UNSPECIFIED)]);
        buf[2] = 99; // corrupt rtm_version
        assert!(matches!(
            parse_route_messages(&buf),
            Err(RouteParseError::UnexpectedRtmVersion(99))
        ));
    }
}
