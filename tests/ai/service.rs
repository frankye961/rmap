use rig::completion::{CompletionError, PromptError};
use rig::http_client::Error as HttpError;

use super::describe_ai_error;

#[test]
fn reports_provider_status_without_echoing_response_text() {
    let error = PromptError::CompletionError(CompletionError::HttpError(
        HttpError::InvalidStatusCodeWithMessage(
            "401".parse().unwrap(),
            "provider response may contain sensitive text".into(),
        ),
    ));
    let message = describe_ai_error(&error);
    assert!(message.contains("HTTP 401"));
    assert!(!message.contains("sensitive text"));
}

#[test]
fn reports_json_location_without_response_body() {
    let parse_error = serde_json::from_str::<String>("null").unwrap_err();
    let error = PromptError::CompletionError(CompletionError::JsonError(parse_error));
    let message = describe_ai_error(&error);
    assert!(message.contains("line 1, column 4"));
    assert!(!message.contains("null"));
}
