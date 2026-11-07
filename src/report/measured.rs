//! Presentation of measured results and separate AI interpretation.

use super::constants::{ERROR_PREVIEW_BYTES, RPC_TABLE_WIDTH, SCAN_TABLE_WIDTH};
use crate::model::{PortStatus, ScanResult};
use crate::utils::banner::{PREVIEW_BYTES, escape_bytes};

pub fn print_results(target: &str, results: &[ScanResult], open_only: bool) {
    write_results(&mut std::io::stdout().lock(), target, results, open_only)
        .expect("Failed to print scan results");
}

fn write_results(
    output: &mut impl std::io::Write,
    target: &str,
    results: &[ScanResult],
    open_only: bool,
) -> std::io::Result<()> {
    writeln!(output, "Scan results for {target}\n")?;
    writeln!(
        output,
        "{:<9} {:<14} {:<9} {:>11}  DETAIL",
        "PORT", "STATE", "SERVICE", "ELAPSED"
    )?;
    writeln!(output, "{}", "-".repeat(SCAN_TABLE_WIDTH))?;

    let mut displayed = 0;
    for result in results {
        if !open_only || result.status == PortStatus::Open {
            writeln!(output, "{}", format_result(result))?;
            displayed += 1;
        }
    }
    if open_only {
        write_open_summary(output, results, displayed)?;
    } else {
        write_timeout_notes(output, results)?;
    }
    write_rpc_mappings(output, results)?;
    Ok(())
}

fn write_open_summary(
    output: &mut impl std::io::Write,
    results: &[ScanResult],
    displayed: usize,
) -> std::io::Result<()> {
    let undetermined = results
        .iter()
        .filter(|result| result.status == PortStatus::Unknown)
        .count();
    if displayed == 0 && undetermined > 0 {
        writeln!(
            output,
            "No open ports confirmed; {undetermined} of {} probes were undetermined.",
            results.len()
        )?;
    } else if displayed == 0 {
        writeln!(
            output,
            "No open ports found among {} scanned ports.",
            results.len()
        )?;
    } else {
        writeln!(
            output,
            "\nOpen ports shown: {displayed}; ports scanned: {}.",
            results.len()
        )?;
    }
    if undetermined > 0 {
        write_undetermined(output, results, undetermined)?;
    }
    Ok(())
}

fn write_undetermined(
    output: &mut impl std::io::Write,
    results: &[ScanResult],
    undetermined: usize,
) -> std::io::Result<()> {
    writeln!(
        output,
        "Undetermined probes: {undetermined}. These are not confirmed closed or filtered ports."
    )?;
    if let Some(error) = results
        .iter()
        .filter(|result| result.status == PortStatus::Unknown)
        .find_map(|result| result.error.as_deref())
    {
        writeln!(
            output,
            "Example failure: {}",
            escape_bytes(error.as_bytes(), ERROR_PREVIEW_BYTES)
        )?;
    }
    Ok(())
}

fn write_timeout_notes(
    output: &mut impl std::io::Write,
    results: &[ScanResult],
) -> std::io::Result<()> {
    if results
        .iter()
        .any(|result| result.status == PortStatus::Filtered)
    {
        writeln!(
            output,
            "\nfiltered = TCP probe timed out; filtering is unconfirmed."
        )?;
    }
    if results
        .iter()
        .any(|result| result.status == PortStatus::OpenOrFiltered)
    {
        writeln!(
            output,
            "\nopen|filtered = no UDP response before timeout; the port may be open or filtered."
        )?;
    }
    Ok(())
}

/// Show registrations as advertised data, never as additional measured open ports.
fn write_rpc_mappings(
    output: &mut impl std::io::Write,
    results: &[ScanResult],
) -> std::io::Result<()> {
    for result in results {
        let Some(mappings) = result.rpc_mappings.as_ref() else {
            continue;
        };
        writeln!(
            output,
            "\nRPC registrations advertised by {}/{}",
            result.port,
            result.transport.transport().as_str()
        )?;
        writeln!(
            output,
            "Advertised endpoints; connectivity has not been tested by enumeration."
        )?;
        if mappings.is_empty() {
            writeln!(output, "No registrations advertised.")?;
            continue;
        }
        writeln!(
            output,
            "{:<12} {:<12} {:<14} PORT",
            "PROGRAM", "VERSION", "TRANSPORT"
        )?;
        writeln!(output, "{}", "-".repeat(RPC_TABLE_WIDTH))?;
        for mapping in mappings {
            let transport = match mapping.protocol {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                protocol => format!("IP({protocol})"),
            };
            writeln!(
                output,
                "{:<12} {:<12} {:<14} {}",
                mapping.program, mapping.program_version, transport, mapping.port
            )?;
        }
    }
    Ok(())
}

fn format_result(result: &ScanResult) -> String {
    let status = match result.status {
        PortStatus::Open => "open",
        PortStatus::Closed => "closed",
        PortStatus::Filtered => "filtered",
        PortStatus::OpenOrFiltered => "open|filtered",
        PortStatus::Unknown => "undetermined",
    };
    let detail = if let Some(error) = &result.error {
        error.clone()
    } else if let Some(data) = result.banner.as_deref().filter(|data| !data.is_empty()) {
        let preview = format_preview(data);
        match result
            .observation
            .as_deref()
            .filter(|reason| !reason.is_empty())
        {
            Some(reason) => format!("{preview} ({reason})"),
            None => preview,
        }
    } else {
        result
            .observation
            .as_deref()
            .filter(|text| !text.is_empty())
            .unwrap_or("-")
            .to_string()
    };
    format!(
        "{:<9} {:<14} {:<9} {:>8.2} ms  {detail}",
        format!("{}/{}", result.port, result.transport.as_str()),
        status,
        result.service.as_deref().unwrap_or("-"),
        result.elapsed.as_secs_f64() * 1_000.0
    )
}

fn format_preview(data: &[u8]) -> String {
    let data = data
        .strip_suffix(b"\r\n")
        .or_else(|| data.strip_suffix(b"\n"))
        .unwrap_or(data);
    let preview_len = data.len().min(PREVIEW_BYTES);
    let preview = escape_bytes(data, preview_len);
    if data.len() > preview_len {
        format!("{preview} (preview truncated)")
    } else {
        preview
    }
}

#[cfg(test)]
#[path = "../../tests/report/measured.rs"]
mod tests;
