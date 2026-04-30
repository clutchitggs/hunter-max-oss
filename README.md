# hunter-max

A bug-bounty research framework. Two pieces:

1. **Deep Read** — a recon module that fetches the JavaScript bundles of a single-page app (including webpack Module Federation chunks the rest of the SPA loads at runtime), extracts the API surface from the minified code, and ranks the discovered endpoints by attack potential using an LLM.

2. **Hunter pipeline** — a multi-tier scanning pipeline that watches public bug-bounty programs for newly-launched scope, runs nuclei templates and JS analysis against live hosts, escalates interesting findings through tiered LLM review (cheap triage → Sonnet investigation → Opus verdict), and posts to Discord.

> ⚠️ **For authorized security research only.** Read [the disclaimer](#disclaimer) before using.

---

## What makes Deep Read different

Most SPA recon tools fetch the two or three entry bundles a browser loads on the first page hit. Modern apps use webpack Module Federation: the entry bundle contains a `__webpack_require__.u` chunk-name map that points at dozens or hundreds of additional bundles, lazily loaded as the user clicks around. Deep Read parses that map and probes the federated micro-frontend hosts, expanding the visible surface from ~3 bundles to 100+.

The expanded surface gets parsed for endpoints (`fetch`, `axios`, `XMLHttpRequest`, `helper(METHOD, PATH, …)` wrappers, OpenAPI / Swagger specs, GraphQL operations). Endpoints are then deduplicated, scored, and sent to an LLM that writes ranked attack hypotheses with reasoning.

The output is a markdown report — endpoints, hypotheses, supporting evidence — that a human operator manually verifies before submitting.

---

## Quickstart — Deep Read only

```bash
git clone https://github.com/clutchitggs/hunter-max.git
cd hunter-max
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY=sk-ant-...    # or set OPENAI_API_KEY for the OpenAI path

# 1. Log into the target in Chrome (handle WAF / 2FA / SSO manually)
# 2. DevTools → Network → copy the Cookie header from any XHR
# 3. Run:
python -m src.deep_read app.example.com \
    --cookie "session=...; csrf=..." \
    --header "Authorization: Bearer eyJ..."
```

Output lands in `reports/deep_read/<host>_<timestamp>.md`.

## Quickstart — full pipeline

Requires more setup (Discord webhook, Hetzner / DO VPS recommended for the long-running modes):

```bash
cp config.example.json config.json
# Edit config.json — set anthropic_balance_usd, daily_budget_usd, Discord webhook
python -m src.infinite_hunter
```

The pipeline runs forever, polling new-program feeds, scope changes, CVE feeds, M&A news, and rotating through registered targets.

---

## Architecture (one screenful)

```
┌─────────────────────────────────────────────────────────────┐
│  infinite_hunter — top-level scheduler                      │
│   ├── program_scanner    new-program polling                │
│   ├── scope_checker      scope-diff detection               │
│   ├── cve_monitor        CVE → affected-target lookup       │
│   ├── ma_recon           M&A news → newly-acquired targets  │
│   └── orchestrator       pulls targets, drives the pipeline │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│  recon  →  vuln_scanner  →  evidence_enricher  →  AI tiers  │
│                                                              │
│   recon: subfinder, dns_checker, wayback, s3_enum,           │
│          nuclei_runner, js_analyzer, deep_read               │
│                                                              │
│   AI tiers (cost-controlled, daily budget per tier):         │
│     T1: GPT-4o-mini                triage                    │
│     T2: Claude Sonnet              investigate               │
│     T3: Claude Sonnet              challenge T2 reject       │
│     T4: Claude Opus                final verdict             │
│     T5: Claude Opus                challenge T4 reject       │
│                                                              │
│   approved findings → report_drafter → Discord notification  │
└─────────────────────────────────────────────────────────────┘
```

Each tier has its own daily budget cap. When all caps are hit the system stops new analysis until the next day or until the operator tops up.

---

## Repository layout

```
src/
├── deep_read/             SPA recon: bundle fetch, JS parsing, LLM ranking
│   ├── cli.py             entry point: python -m src.deep_read
│   ├── fetcher.py         SPA-aware, S3-safe HTTP fetcher
│   ├── webpack_chunks.py  Module Federation chunk-map expansion
│   ├── js_parser.py       endpoint extraction from minified JS
│   ├── spec_finder.py     OpenAPI / Swagger / GraphQL probing
│   ├── analyzer.py        LLM hypothesis ranking + kill-rules
│   └── report.py          markdown report writer
│
├── infinite_hunter.py     top-level scheduler
├── orchestrator.py        per-target pipeline driver
├── ai_analyzer.py         tiered LLM review
├── llm_client.py          unified Anthropic / OpenAI client
├── nuclei_runner.py       nuclei integration
├── js_analyzer.py         JS-bundle secret/endpoint extraction
├── program_scanner.py     bug-bounty platform polling
├── scope_checker.py       scope-diff detection
├── scope_importer.py      scope import from various platforms
├── cve_monitor.py         CVE → affected-target lookup
├── ma_recon.py            M&A news → newly-acquired-asset recon
├── target_scorer.py       target prioritisation
├── notifier_discord.py    Discord webhook notifier
├── dashboard.py           local Flask status dashboard
└── …

data/
└── wordlist.txt           small built-in wordlist

requirements.txt
config.example.json
```

---

## Configuration

Copy `config.example.json` to `config.json` and edit. Important fields:

| Field                                | Meaning                                              |
|--------------------------------------|------------------------------------------------------|
| `llm.provider`                       | `"anthropic"` or `"openai"`                          |
| `llm.api_key_env`                    | name of the env var holding the API key             |
| `llm.anthropic_balance_usd`          | your current balance — system stops at the floor    |
| `llm.stop_at_remaining_usd`          | floor below which AI calls halt                      |
| `tiers.tier1.daily_budget_usd`       | per-tier daily cap                                   |
| `signals.*_interval_*`               | how often each scheduled signal fires                |

The config is a plain JSON file; structure is stable across versions.

---

## Disclaimer

This software is intended **only** for authorized security research:

- Bug-bounty programs whose scope explicitly authorizes automated scanning.
- Penetration-testing engagements with written authorization.
- Targets you own.
- CTF / lab environments.

Running this against systems you do not have written permission to test is illegal under most computer-misuse laws (Israel: Computer Law 1995 §2/§4; US: CFAA 18 USC §1030; UK: Computer Misuse Act 1990; EU: NIS2 / national equivalents).

Configure scope checks before pointing the pipeline at anything. **The author assumes no liability for misuse.**

---

## License

MIT — see [LICENSE](LICENSE).
