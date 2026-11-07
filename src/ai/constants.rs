//! Independent bounds for provider sessions, prompt context, and web evidence.

pub(super) const DEFAULT_TIMEOUT_MS: u64 = 60000;
pub(super) const MAX_TOKENS: u64 = 1800;
pub(super) const TEMPERATURE: f64 = 0.2;
pub(super) const MAX_TURNS: usize = 8;
pub(super) const MAX_OBSERVATIONS: usize = 8;
pub(super) const MAX_DETAIL_CHARS: usize = 160;
pub(super) const MAX_ANSWER_LINES: usize = 45;

pub(super) const SEARCH_URL: &str = "https://api.search.brave.com/res/v1/web/search";
pub(super) const SEARCH_TIMEOUT_SECS: u64 = 15;
pub(super) const MAX_SEARCHES: usize = 6;
pub(super) const RESULTS_PER_SEARCH: usize = 4;
pub(super) const MAX_BODY_BYTES: usize = 524_288;
pub(super) const MAX_QUERY_CHARS: usize = 200;
pub(super) const MAX_URL_BYTES: usize = 500;
pub(super) const MAX_DESCRIPTION_CHARS: usize = 600;
pub(super) const MAX_EXTRA_SNIPPETS: usize = 2;
pub(super) const MAX_EXTRA_SNIPPET_CHARS: usize = 300;
pub(super) const MAX_TITLE_CHARS: usize = 160;
