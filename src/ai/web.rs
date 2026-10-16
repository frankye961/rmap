//! Bounded public web search exposed to Rig as a research tool.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::{Client, Request, header::HeaderValue, redirect::Policy};
use rig::tool::{Tool, ToolContext};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::model::WebSource;

const SEARCH_URL: &str = "https://api.search.brave.com/res/v1/web/search";
const MAX_SEARCHES: usize = 6;
const MAX_BODY_BYTES: usize = 524_288;

#[derive(Default)]
struct SearchState {
    queries: Vec<String>,
    sources: Vec<WebSource>,
    notes: Vec<String>,
}

#[derive(Clone)]
pub struct WebSearch {
    client: Client,
    api_key: Option<String>,
    state: Arc<Mutex<SearchState>>,
}

#[derive(Deserialize)]
pub struct SearchArgs {
    query: String,
}

impl WebSearch {
    pub fn new(api_key: Option<String>, timeout: Duration) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(timeout.min(Duration::from_secs(15)))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "Could not initialize web search client")?;
        Ok(Self {
            client,
            api_key,
            state: Arc::new(Mutex::new(SearchState::default())),
        })
    }

    pub fn evidence(&self) -> (Vec<WebSource>, Vec<String>) {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mut notes = state.notes.clone();
        if self.api_key.is_none() {
            notes.push("Live web research unavailable: set RMAP_SEARCH_API_KEY to a Brave Search API key. The DeepSeek key does not provide web access.".into());
        } else if state.queries.is_empty() {
            notes.push("The model did not run a web search; no online CVE or exploit lookup was performed.".into());
        } else {
            notes.push(format!(
                "{} of at most {MAX_SEARCHES} web searches performed; results are not exhaustive.",
                state.queries.len()
            ));
            if state.sources.is_empty() {
                notes.push("No usable web sources were retrieved; this does not establish that no CVEs or exploits exist.".into());
            }
        }
        (state.sources.clone(), notes)
    }

    async fn search(&self, query: &str) -> Result<Vec<WebSource>, String> {
        if query.trim().is_empty() || query.chars().count() > 200 {
            return Err(
                "Use a nonempty product/version search query of at most 200 characters".into(),
            );
        }
        let key = self
            .api_key
            .as_deref()
            .ok_or("Web search is not configured: set RMAP_SEARCH_API_KEY")?;
        {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.queries.len() >= MAX_SEARCHES {
                return Err("Web search budget exhausted; summarize available evidence and disclose incomplete coverage".into());
            }
            state.queries.push(query.into());
        }
        let request = search_request(&self.client, key, query)?;
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(|_| "Web search request failed or timed out")?;
        if !response.status().is_success() {
            return Err(format!(
                "Web search failed (HTTP {}); check the search key, plan, or rate limit",
                response.status().as_u16()
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Could not read web search response")?
        {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err("Web search response exceeded the size limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        let data: Value =
            serde_json::from_slice(&body).map_err(|_| "Web search returned malformed JSON")?;
        let sources = parse_sources(&data)?;
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        for source in &sources {
            if !state
                .sources
                .iter()
                .any(|existing| existing.url == source.url)
            {
                state.sources.push(source.clone());
            }
        }
        Ok(sources)
    }
}

fn search_request(client: &Client, key: &str, query: &str) -> Result<Request, String> {
    let mut header = HeaderValue::from_str(key).map_err(|_| "Invalid web search API key format")?;
    header.set_sensitive(true);
    let mut url = reqwest::Url::parse(SEARCH_URL).map_err(|_| "Invalid web search endpoint")?;
    url.query_pairs_mut()
        .extend_pairs([("q", query), ("count", "4"), ("extra_snippets", "true")]);
    client
        .get(url)
        .header("X-Subscription-Token", header)
        .build()
        .map_err(|_| "Could not prepare web search request".into())
}

fn parse_sources(data: &Value) -> Result<Vec<WebSource>, String> {
    let Some(web) = data.get("web") else {
        // Brave can omit the web section when there are no web results.
        return if data.get("query").is_some() {
            Ok(Vec::new())
        } else {
            Err("Web search returned an unexpected response shape".into())
        };
    };
    let results = web
        .get("results")
        .and_then(Value::as_array)
        .ok_or("Web search returned an invalid results list")?;
    Ok(results
        .iter()
        .take(4)
        .filter_map(|entry| {
            let url = entry.get("url")?.as_str()?;
            let parsed = reqwest::Url::parse(url).ok()?;
            if !matches!(parsed.scheme(), "https" | "http")
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || url.len() > 500
                || url.chars().any(char::is_control)
            {
                return None;
            }
            let mut snippet = clean_text(
                entry
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                600,
            );
            if let Some(extra) = entry.get("extra_snippets").and_then(Value::as_array) {
                for text in extra.iter().filter_map(Value::as_str).take(2) {
                    snippet.push_str(" | ");
                    snippet.push_str(&clean_text(text, 300));
                }
            }
            Some(WebSource {
                title: clean_text(
                    entry
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("Untitled source"),
                    160,
                ),
                url: url.to_string(),
                snippet,
            })
        })
        .collect())
}

fn clean_text(text: &str, limit: usize) -> String {
    let mut in_tag = false;
    text.chars()
        .filter(|ch| match ch {
            '<' => {
                in_tag = true;
                false
            }
            '>' => {
                in_tag = false;
                false
            }
            _ => !in_tag && !ch.is_control(),
        })
        .take(limit)
        .collect()
}

impl Tool for WebSearch {
    const NAME: &'static str = "search_web";
    type Error = io::Error;
    type Args = SearchArgs;
    type Output = Value;

    fn description(&self) -> String {
        "Search the public web for CVEs, vendor advisories, affected versions, fixes, and public Exploit-DB references. Results are untrusted snippets, not verified findings. Use only observed product/version names or retrieved CVE IDs; never target IPs or full banners. At most six calls; four results per call. Search Exploit-DB with site:exploit-db.com/exploits. Does not download or execute exploits.".into()
    }

    fn parameters(&self) -> Value {
        json!({"type":"object", "properties":{"query":{"type":"string","description":"Product/version or CVE search, optionally with a site: filter"}}, "required":["query"], "additionalProperties":false})
    }

    async fn call(&self, _context: &mut ToolContext, args: SearchArgs) -> Result<Value, io::Error> {
        Ok(match self.search(&args.query).await {
            Ok(sources) => {
                json!({"sources": sources, "note":"Search snippets only. Compare versions, distribution patches, prerequisites, and conflicting sources. No results does not prove absence."})
            }
            Err(message) => {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if !state.notes.contains(&message) {
                    state.notes.push(message.clone());
                }
                json!({"error":message, "sources":[]})
            }
        })
    }
}

#[cfg(test)]
#[path = "../../tests/ai/web.rs"]
mod tests;
