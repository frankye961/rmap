//! Rig-backed DeepSeek interpretation of completed, measured scan results.

use rig::completion::{CompletionError, Prompt, PromptError};
use rig::prelude::*;
use rig::providers::deepseek;

use super::constants::{MAX_TOKENS, MAX_TURNS, TEMPERATURE};
use super::prompt::{build_prompt, instructions};
use crate::ai::config::AiConfig;
use crate::ai::retrieval;
use crate::model::{AiAnalysis, ScanResult};

#[tokio::main(flavor = "current_thread")]
pub async fn analyze(config: &AiConfig, results: &[ScanResult]) -> Result<AiAnalysis, String> {
    let (candidates, local_notice) = match retrieval::retrieve(config.cve_file.as_deref(), results)
    {
        Ok(candidates) => (candidates, None),
        Err(error) => (
            Vec::new(),
            Some(format!("Optional local advisory lookup failed: {error}")),
        ),
    };
    let mut prompt = build_prompt(results, &candidates);
    prompt.push_str(if config.search_api_key.is_some() {
        "\nLive web search is configured. Use search_web for CVE research and Exploit-DB references before answering.\n"
    } else {
        "\nLive web search is unavailable: RMAP_SEARCH_API_KEY is not configured. Explain this limitation and use only supplied local evidence.\n"
    });
    let web_search = super::web::WebSearch::new(config.search_api_key.clone(), config.timeout)?;

    let mut builder = deepseek::Client::builder().api_key(config.api_key.clone());
    if let Some(base_url) = &config.base_url {
        builder = builder.base_url(base_url);
    }
    let client = builder
        .build()
        .map_err(|_| "Could not initialize DeepSeek client".to_string())?;
    let agent = client
        .agent(config.model.clone())
        .preamble(&instructions())
        .max_tokens(MAX_TOKENS)
        .temperature(TEMPERATURE)
        .additional_params(serde_json::json!({"thinking": {"type": "disabled"}}))
        .tool(web_search.clone())
        .build();

    let response = tokio::time::timeout(config.timeout, agent.prompt(prompt).max_turns(MAX_TURNS))
        .await
        .map_err(|_| {
            "AI research timed out; increase RMAP_AI_TIMEOUT_MS for web searches and model calls"
                .to_string()
        })?
        .map_err(|error| describe_ai_error(&error))?;
    if response.trim().is_empty() {
        return Err("DeepSeek returned no final answer".into());
    }
    let (web_sources, mut research_notes) = web_search.evidence();
    if let Some(notice) = local_notice {
        research_notes.push(notice);
    }
    Ok(AiAnalysis {
        interpretation: response,
        candidates,
        web_sources,
        research_notes,
    })
}

fn describe_ai_error(error: &PromptError) -> String {
    if let Some(status) = error.provider_response_status() {
        let explanation = match status.as_u16() {
            400 | 422 => {
                "DeepSeek rejected the request parameters; check the model and API endpoint"
            }
            401 => {
                "DeepSeek rejected the API key; check the key and any exported environment override"
            }
            402 => "DeepSeek reports insufficient account balance",
            403 => "DeepSeek denied access; check the key and account permissions",
            404 => "DeepSeek did not find the requested endpoint or model",
            429 => "DeepSeek rate limit reached",
            500..=599 => "DeepSeek server error; try again later",
            _ => "DeepSeek rejected the request",
        };
        return format!("{explanation} (HTTP {})", status.as_u16());
    }

    match error {
        PromptError::CompletionError(CompletionError::HttpError(_)) => {
            "Could not reach DeepSeek; check network, DNS, TLS, proxy, and API endpoint".into()
        }
        PromptError::CompletionError(CompletionError::JsonError(error)) => format!(
            "Rig could not decode DeepSeek's JSON response (line {}, column {}); the response shape may be incompatible with Rig 0.42",
            error.line(),
            error.column()
        ),
        PromptError::CompletionError(CompletionError::ResponseError(_)) => {
            "Rig could not use DeepSeek's response; it may lack final answer text".into()
        }
        PromptError::CompletionError(CompletionError::UrlError(_)) => {
            "Invalid DeepSeek API endpoint URL".into()
        }
        _ => "DeepSeek request failed before a usable response was received".into(),
    }
}

#[cfg(test)]
#[path = "../../tests/ai/service.rs"]
mod tests;
