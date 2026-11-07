//! Parse explicit ports and inclusive ranges without changing their order.

pub(super) fn parse_ports(s: &str) -> Result<Vec<String>, String> {
    let mut ports = Vec::new();
    for item in s.split(',') {
        if let Some((start, end)) = item.split_once('-') {
            let start_port = start
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {start}"))?;
            let end_port = end
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {end}"))?;
            if start_port == 0 || end_port == 0 || start_port > end_port {
                return Err(format!("Invalid port range: {item}"));
            }
            for port in start_port..=end_port {
                ports.push(port.to_string());
            }
        } else {
            let port = item
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {item}"))?;
            if port == 0 {
                return Err("Ports must be between 1 and 65535".to_string());
            }
            ports.push(port.to_string());
        }
    }
    Ok(ports)
}
