//! Settings for explicitly requested DeepSeek analysis and public web search.

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
    pub search_api_key: Option<String>,
}

impl AiConfig {
    pub fn load() -> Result<Self, String> {
        let dotenv = match fs::read_to_string(".env") {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("Cannot read .env: {error}")),
        };
        let setting = |name: &str| {
            let legacy = name.replacen("RMAP_", "RUST_NMAP_", 1);
            [
                env::var(name).ok(),
                env::var(&legacy).ok(),
                file_setting(&dotenv, name),
                file_setting(&dotenv, &legacy),
            ]
            .into_iter()
            .flatten()
            .find(|value| !value.trim().is_empty())
        };

        let api_key = required(setting("RMAP_AI_API_KEY"), "RMAP_AI_API_KEY")?;
        let model = required(setting("RMAP_AI_MODEL"), "RMAP_AI_MODEL")?;
        let base_url = setting("RMAP_AI_BASE_URL").filter(|value| !value.trim().is_empty());
        if let Some(url) = &base_url
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return Err("RMAP_AI_BASE_URL must start with http:// or https://".into());
        }
        let timeout_ms = setting("RMAP_AI_TIMEOUT_MS")
            .unwrap_or_else(|| "60000".into())
            .parse::<u64>()
            .map_err(|_| "RMAP_AI_TIMEOUT_MS must be a positive integer")?;
        if timeout_ms == 0 {
            return Err("RMAP_AI_TIMEOUT_MS must be greater than zero".into());
        }
        let cve_file = setting("RMAP_CVE_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Ok(Self {
            api_key,
            base_url,
            model,
            timeout: Duration::from_millis(timeout_ms),
            cve_file,
            search_api_key: setting("RMAP_SEARCH_API_KEY"),
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
