use std::time::Duration;

use reqwest::Client;
use serde_json::json;

use super::{MAX_SEARCHES, WebSearch, parse_sources, search_request};

#[test]
fn prepares_encoded_web_queries_and_keeps_key_out_of_url() {
    let request = search_request(
        &Client::new(),
        "test-only-placeholder",
        "vsFTPd 3.0.5 site:exploit-db.com/exploits",
    )
    .unwrap();
    assert_eq!(request.url().host_str(), Some("api.search.brave.com"));
    assert!(
        request
            .url()
            .query_pairs()
            .any(|(key, value)| key == "q" && value == "vsFTPd 3.0.5 site:exploit-db.com/exploits")
    );
    assert!(!request.url().as_str().contains("test-only-placeholder"));
    assert!(request.headers()["X-Subscription-Token"].is_sensitive());
}

#[test]
fn returns_real_source_links_and_bounded_untrusted_snippets() {
    let data = json!({"web":{"results":[
        {"title":"vsftpd advisory", "url":"https://security-tracker.debian.org/tracker/CVE-2025-14242", "description":"<strong>vsftpd</strong>: distribution-specific patch", "extra_snippets":["Verify the installed package"]},
        {"title":"Public PoC", "url":"https://www.exploit-db.com/exploits/12345", "description":"Fixture only, not a real match"},
        {"title":"Unsafe URL", "url":"javascript:alert(1)"},
        {"title":"URL with credentials", "url":"https://user:password@example.test"}
    ]}});
    let sources = parse_sources(&data).unwrap();
    assert_eq!(sources.len(), 2);
    assert!(
        sources[0]
            .snippet
            .contains("vsftpd: distribution-specific patch")
    );
    assert!(!sources[0].snippet.contains("<strong>"));
    assert!(sources[1].url.contains("exploit-db.com/exploits/"));
}

#[test]
fn distinguishes_empty_results_from_invalid_json_shape() {
    assert!(
        parse_sources(&json!({"query":{"original":"vsftpd"}}))
            .unwrap()
            .is_empty()
    );
    assert!(
        parse_sources(&json!({"web":{"results":[]}}))
            .unwrap()
            .is_empty()
    );
    assert!(parse_sources(&json!({"unexpected":true})).is_err());
    assert!(parse_sources(&json!({"web":{"results":"invalid"}})).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn missing_credentials_and_exhausted_budget_make_no_requests() {
    let tool = WebSearch::new(None, Duration::from_secs(1)).unwrap();
    assert!(
        tool.search("vsftpd 3.0.5 CVE")
            .await
            .unwrap_err()
            .contains("RMAP_SEARCH_API_KEY")
    );
    assert!(tool.evidence().0.is_empty());
    assert!(
        tool.evidence()
            .1
            .iter()
            .any(|note| note.contains("unavailable"))
    );
    let tool =
        WebSearch::new(Some("test-only-placeholder".into()), Duration::from_secs(1)).unwrap();
    tool.state.lock().unwrap().queries = vec!["already searched".into(); MAX_SEARCHES];
    assert!(
        tool.search("vsftpd 3.0.5 CVE")
            .await
            .unwrap_err()
            .contains("budget exhausted")
    );
}
