//! CLI reference text derived from the same defaults used by parsing.

use crate::settings::{DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS, MAX_CONCURRENCY, MAX_TARGETS};

pub fn usage() -> String {
    format!(
        "Usage: rmap --target TARGET[,TARGET...] [--tcp | --udp] [--syn] [--ports LIST] [--exclude-ports LIST] [--timeout-ms MILLISECONDS] [--concurrency N] [--ai]\n--syn selects TCP SYN scanning, optionally with --tcp; it cannot be combined with --udp. Linux raw sockets require CAP_NET_RAW; no application banners are collected.\nDefaults: TCP, all ports from 1 to 65535, timeout {DEFAULT_TIMEOUT_MS} ms, concurrency {DEFAULT_CONCURRENCY} (1-{MAX_CONCURRENCY}).\nFull-range scans and --ports lists containing ranges show only open ports; individual-port lists show all outcomes.\nPort lists accept individual ports and inclusive ranges, e.g. 22,80-82,443.\nTargets accept IPv4 addresses and CIDR subnets; at most {MAX_TARGETS} unique targets. Targets are scanned once each, in first-occurrence order.\n--exclude-ports requires an earlier --ports list and must leave at least one port."
    )
}
