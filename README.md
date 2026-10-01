# AI Security Agent

AI-assisted vulnerability assessment for local and authorized security labs.

## Goal

Build a security agent that can discover a target, inspect its security posture, analyze findings, verify evidence safely, and produce a clear report.

## Scope

- Localhost, Docker labs, and systems the user is authorized to test
- Non-destructive assessment by default
- Evidence-first findings
- AI is used for planning, analysis, prioritization, and explanation

## Architecture

```text
Target -> Scanner -> Findings -> Decision Layer -> LLM Analysis -> Verification -> Report
```

## MVP v0.1

1. HTTP target input
2. Basic HTTP response inspection
3. Security header checks
4. Cookie flag checks
5. Finding model with severity, evidence, and remediation
6. JSON report
7. Tests

## Decision architecture

The MVP separates responsibilities deliberately:

- deterministic scanner collects evidence
- decision layer chooses report vs safe verification
- LLM adapter explains evidence and remediation
- future Jev integration can replace the decision layer without giving the LLM unrestricted execution

The current LLM adapter is local and deterministic; it makes no network calls.

## Project status

v0.2 architecture: scanner + decision layer + LLM boundary + tests.


## Decision provider

The CLI uses the deterministic rule engine by default and makes no LLM API calls. To opt in to the OpenAI-compatible provider, set the API key in your shell environment and pass `--decision-provider llm`:

```powershell
$env:AI_SECURITY_LLM_API_KEY = "your-key"
ai-security-agent http://127.0.0.1:8080 --decision-provider llm
```

The provider defaults to `https://api.openai.com/v1` and model `gpt-4o-mini`. Set `AI_SECURITY_LLM_BASE_URL` or `AI_SECURITY_LLM_MODEL` to use a compatible endpoint or another model. The provider sends each finding's title, severity, evidence, and recommendation to that endpoint. Decisions are constrained to `report` or `verify`; they do not execute verification actions. The JSON report includes these decisions when the provider is used (and retains the existing format when omitted).
