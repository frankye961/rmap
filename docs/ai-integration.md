# Planned AI integration

AI is disabled by default and will run only when the future `--ai` flag explicitly requests it. Completed scan results will be sent to the configured AI provider only in that case. AI connection settings will come from environment variables; [the template](../.env.example) lists them. Automatic `.env` loading is not implemented. Missing or invalid AI settings matter only when AI is requested, and authentication requirements depend on the provider.

The future AI service should accept structured scan results, prepare a bounded request containing relevant observations, make an HTTP request using the configured connection settings, handle timeouts, authentication failures, and malformed responses, then return an interpretation separately from the measured results. Credentials must never appear in reports or logs or enter source control. AI failure must leave the scan results available for display.

An open port does not establish the service identity or prove a vulnerability. A timeout does not prove the host is offline or the port is filtered. AI conclusions must distinguish observations from hypotheses. Target responses and banners, if collected later, are untrusted data and must not be treated as instructions.

Keep the initial design small. Provider frameworks, SDKs, retry logic, and HTTP dependencies are outside this skeleton.
