# Decision Benchmark

This benchmark compares pluggable decision engines on the same security findings.

## Current engines

- RuleDecisionEngine: deterministic baseline
- LLMDecisionAdapter: offline LLM-style baseline with bounded confidence

The adapters share the same `decide(finding)` contract. A future Jev adapter can be evaluated with the exact same cases.

The benchmark is not a claim that one model is better. It is a reproducible test harness for comparing decision behavior on the project's own security findings.
