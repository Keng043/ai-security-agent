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
