#![no_main]
//! The pure macOS route parser MUST NOT panic on any input. It is
//! `cfg`-independent, so this fuzzes on any host (incl. the Linux CI host).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mapscan_route::parse_route_messages(data);
});
