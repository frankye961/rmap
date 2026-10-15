//! Settings for explicitly requested DeepSeek analysis and local CVE retrieval.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;

pub struct AiConfig {
    pub api_key: String,
    pub base_url: Option<String>,
    pub model: String,
    pub timeout: Duration,
    pub cve_file: Option<PathBuf>,
}

impl AiConfig {
    pub fn load() -> Result<Self, String> {
        let dotenv = match fs::read_to_string(".env") {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("Cannot read .env: {error}")),
        };
        let setting = |name| env::var(name).ok().or_else(|| file_setting(&dotenv, name));

        let api_key = required(setting("RUST_NMAP_AI_API_KEY"), "RUST_NMAP_AI_API_KEY")?;
        let model = required(setting("RUST_NMAP_AI_MODEL"), "RUST_NMAP_AI_MODEL")?;
        let base_url = setting("RUST_NMAP_AI_BASE_URL").filter(|value| !value.trim().is_empty());
        if let Some(url) = &base_url
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return Err("RUST_NMAP_AI_BASE_URL must start with http:// or https://".into());
        }
        let timeout_ms = setting("RUST_NMAP_AI_TIMEOUT_MS")
            .unwrap_or_else(|| "15000".into())
            .parse::<u64>()
            .map_err(|_| "RUST_NMAP_AI_TIMEOUT_MS must be a positive integer")?;
        if timeout_ms == 0 {
            return Err("RUST_NMAP_AI_TIMEOUT_MS must be greater than zero".into());
        }
        let cve_file = setting("RUST_NMAP_CVE_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Ok(Self {
            api_key,
            base_url,
            model,
            timeout: Duration::from_millis(timeout_ms),
            cve_file,
        })
    }
}

fn required(value: Option<String>, name: &str) -> Result<String, String> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required when --ai is used"))
}

fn file_setting(contents: &str, name: &str) -> Option<String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            if key.trim() != name {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|quoted| quoted.strip_suffix('"'))
                .or_else(|| {
                    value
                        .strip_prefix('\'')
                        .and_then(|quoted| quoted.strip_suffix('\''))
                })
                .unwrap_or(value);
            Some(value.to_string())
        })
        .next_back()
}

#[cfg(test)]
#[path = "../../tests/ai/config.rs"]
mod tests;
