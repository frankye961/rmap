//! IPv4 and CIDR expansion with first-occurrence deduplication and a scope limit.

use crate::settings::MAX_TARGETS;
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub(super) fn parse_targets(targets: &str) -> Result<Vec<String>, String> {
    let mut valid_targets = Vec::new();
    let mut seen = HashSet::new();
    for target in targets.split(',') {
        let (first, last) = if target.contains('/') {
            let (address, prefix) = parse_subnet(target)?;
            let (network, broadcast) = subnet_bounds(address, prefix);
            let first = u32::from(network);
            let last = u32::from(broadcast);
            // /31 includes both endpoints; /32 includes its single address.
            if prefix < 31 {
                (first + 1, last - 1)
            } else {
                (first, last)
            }
        } else {
            let address = target
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("Invalid IPv4 address: {target}"))?;
            let address = u32::from(address);
            (address, address)
        };
        // Count in u64 so /0 cannot overflow; reject oversized subnets before expansion.
        let count = u64::from(last) - u64::from(first) + 1;
        if count > MAX_TARGETS as u64 {
            return Err(format!(
                "Target subnet {target} exceeds the limit of {MAX_TARGETS} unique targets"
            ));
        }
        for address in first..=last {
            let address = Ipv4Addr::from(address);
            if seen.insert(address) {
                if valid_targets.len() == MAX_TARGETS {
                    return Err(format!(
                        "Target list exceeds the limit of {MAX_TARGETS} unique targets"
                    ));
                }
                valid_targets.push(address.to_string());
            }
        }
    }
    Ok(valid_targets)
}

pub(super) fn parse_subnet(target: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address_str, prefix) = target
        .split_once('/')
        .ok_or_else(|| format!("Invalid subnet format: {target}"))?;
    let address = address_str
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid IPv4 address: {address_str}"))?;
    let prefix_length = prefix
        .parse::<u8>()
        .map_err(|_| format!("Invalid subnet prefix length: {prefix}"))?;

    if prefix_length > 32 {
        return Err(format!("Invalid subnet prefix length: {prefix_length}"));
    }
    Ok((address, prefix_length))
}

pub(super) fn subnet_bounds(address: Ipv4Addr, prefix_length: u8) -> (Ipv4Addr, Ipv4Addr) {
    if prefix_length > 32 {
        panic!("Invalid subnet prefix length: {prefix_length}");
    }
    let mask = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    };
    let network = u32::from(address) & mask;
    let broadcast = network | !mask;
    (Ipv4Addr::from(network), Ipv4Addr::from(broadcast))
}
