# SOC Alert Triage Analyst (LLM Prompt)

A structured system prompt that turns an LLM into a SOC tier-1 alert
triage analyst: feed it one security alert (Wazuh JSON or similar)
plus optional enrichment, and it returns a strict JSON triage verdict.

**Analysis-only by design.** The prompt forbids the model from taking
or claiming any action — it recommends; a human (or your SOAR
playbook, with human approval) acts.

## What's here

| File | Purpose |
|------|---------|
| [`prompt.md`](prompt.md) | The complete system prompt |
| [`examples/example-alert.json`](examples/example-alert.json) | Sample input: Wazuh SSH brute-force alert + enrichment context |
| [`examples/example-verdict.json`](examples/example-verdict.json) | The corresponding structured verdict |

## How it works

The prompt enforces three things most ad-hoc "triage this alert"
prompts get wrong:

1. **An evidence rule** — every claim in the output must cite the
   input field it came from (`key_evidence[].source_field`). Missing
   data goes in `evidence_gaps` and lowers `confidence`; the model is
   forbidden from inventing IPs, hashes, CVEs, usernames, or ATT&CK
   IDs.
2. **Benign-first reasoning** — the model must check maintenance,
   scanners, admin activity, and misconfiguration before concluding
   malicious intent.
3. **Severity vs. confidence, separately** — severity reflects
   potential impact (asset criticality); confidence reflects evidence
   quality. Thin enrichment lowers confidence, not severity.

Verdict scale: `true_positive` · `likely_true_positive` ·
`needs_investigation` · `likely_false_positive` · `false_positive` ·
`benign_true_positive` (correctly detected but authorized activity).

## Usage

Use `prompt.md` as the system prompt and pass the alert JSON as the
user message — in the Claude app directly, via the API, or as an
enrichment step in a SOAR pipeline:

```python
import json
import anthropic

client = anthropic.Anthropic()
system_prompt = open("prompt.md").read()
alert = open("examples/example-alert.json").read()

response = client.messages.create(
    model="claude-sonnet-5",
    max_tokens=2048,
    system=system_prompt,
    messages=[{"role": "user", "content": alert}],
)
verdict = json.loads(response.content[0].text)
print(verdict["verdict"], verdict["confidence"])
```

All data in the examples is synthetic (RFC 5737 documentation IPs,
fictional hostnames).
