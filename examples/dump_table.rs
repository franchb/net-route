//! Run on macOS to confirm the live fetch+parse path works end-to-end.
//! Prints the parsed routes to stderr. The RAW `NET_RT_DUMP` bytes for the
//! mapscan fixture are captured separately by the CI workflow (a small C
//! sysctl one-shot), keeping the lib API free of a raw-buffer accessor.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() -> std::io::Result<()> {
    let routes = mapscan_route::list_routes()?;
    eprintln!("parsed {} routes:", routes.len());
    for r in &routes {
        eprintln!("{r:?}");
    }
    assert!(!routes.is_empty(), "live routing table should not be empty");
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn main() {
    eprintln!("dump_table is macOS/Windows-only (Linux uses /proc/net/route)");
}
