# AI research and interpretation

`--ai` requests a separate DeepSeek interpretation after measured results are printed. The scanner does not call AI. The AI service uses Rig to give DeepSeek the observations and a `search_web` tool. Source links actually returned by the tool are collected independently of generated prose. Model, search, and optional local lookup failures never discard measured results.

For build/install instructions, commands, and troubleshooting, see [usage](usage.md). The [README example](../README.md#example-tcp-scan-with-ai-research) contains a complete recorded TCP run, including source links; expand its console-output section to view it.

## Configuration

Set `RMAP_AI_API_KEY` and `RMAP_AI_MODEL` for DeepSeek. `RMAP_AI_BASE_URL` optionally overrides the API endpoint. Add `RMAP_SEARCH_API_KEY` for [Brave Search](https://api-dashboard.search.brave.com/api-reference/web/search/get); the DeepSeek key alone does not provide browsing. Missing search credentials produce an explicit research notice. `RMAP_AI_TIMEOUT_MS` limits the complete research session and defaults to 60000 milliseconds; each search has a timeout of at most 15 seconds. Existing configurations with 15000 milliseconds may need a higher timeout for multiple model/tool calls.

Settings come from environment variables or a local `.env` in the working directory, loaded only with `--ai`. Nonempty environment values take precedence over file settings. Use plain `KEY=value` lines; the current file parser does not handle `export` prefixes. `.env.example` is a template and is not loaded directly. Legacy `RUST_NMAP_*` aliases remain accepted, with the new `RMAP_*` names preferred within each source. See [`.env.example`](../.env.example). Credentials never enter prompts, reports, or source control.

## Research flow

The prompt contains up to eight measured outcomes, with open ports first, and up to 160 characters of each observation or error. It includes closed and uncertain outcomes so the agent can explain a scan even when nothing is open. Product and version text from banners and HTTP headers are the starting point, including space-separated banners such as `220 (vsFTPd 3.0.5)`. Port numbers alone are insufficient for identifying a product.

When search is configured, the prompt requires general web searches for CVEs and affected versions, followed by searches restricted to `site:exploit-db.com/exploits` for public exploit references. The model can refine searches using retrieved CVE IDs. It must compare vendor and distribution advisories, package revisions, backported fixes, prerequisites and contradictory evidence. It must cite retrieved sources and label uncertainty. For example, [Debian identifies CVE-2025-14242 as originating in a Red Hat specific patch](https://security-tracker.debian.org/tracker/CVE-2025-14242); an upstream banner version alone does not establish that this CVE applies.

The tool searches the public web through Brave and returns titles, URLs, snippets, and additional excerpts. It does not download full pages or execute exploit code. Exploit-DB entries are potential references for review: the interpretation should explain their reported affected versions, prerequisites if available, and applicability to the observed service. No matching search result does not prove absence of vulnerabilities or public exploits.

At most six searches and eight model calls are allowed per analysis. Each search returns up to four sources and reads at most 512 KiB. Titles and snippets are bounded before reaching the model. The request is sent to a fixed HTTPS search endpoint, redirects are disabled, and credentials are sent only in a sensitive header. HTTP failures, malformed responses, missing credentials and exhausted budgets are reported without exposing provider response bodies or keys. The total timeout covers all tool and model calls; coverage may be incomplete.

With AI and search enabled, product/version queries are sent to Brave Search and retrieved evidence is sent to DeepSeek. The agent is instructed to exclude target addresses, credentials, and full banners from search queries. Banner and web content are untrusted data, never instructions. A connected TCP socket or a UDP response does not prove vulnerability; UDP silence does not prove filtering.

## Optional local evidence and reporting

`RMAP_CVE_FILE` can provide an additional UTF-8 advisory TSV file. Five tab-separated fields are required: CVE ID, product, exact version, HTTPS source URL, and description. Files are limited to 1 MiB; at most five exact product/version text matches are supplied. Slash, underscore and space separators are supported. Local lookup errors become research notes and do not prevent online research.

`AiAnalysis` holds the generated interpretation, optional local `CveCandidate` records, actual retrieved `WebSource` records, and research notes. The console shows measured results first, then interpretation, search status and retrieved sources, plus local candidates when present. Source snippets are incomplete evidence, and generated applicability judgments require verification. Unit tests use fixtures and never need live scans, search requests, or AI calls.

## Reading the console report

The measured table is independent of the generated answer. `SERVICE` is a limited protocol label; the observation can contain a usable product/version even when the label is `-`. An FTP banner such as `220 (vsFTPd 3.0.5)` reaches the model and can guide research without a dedicated FTP service label.

The generated sections describe observed services, possible CVEs, public exploit references and verification. The application then prints `WEB RESEARCH` notes and source URLs actually returned by the tool. The tool may retrieve irrelevant or contradictory hits: those are evidence for comparison, not automatically accepted findings. An exploit entry for a different product or version must not be treated as proof that the observed service is exploitable.

Check the research notes if the model says browsing was unavailable. The model's words can be mistaken; missing credentials, no tool invocation, HTTP errors, and empty results are recorded independently. A six-search count describes the bounded research session rather than complete internet coverage. Only the first eight observations reach the prompt, with open ports first, so some measured rows may be omitted from the interpretation.
