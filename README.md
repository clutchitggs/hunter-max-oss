# hunter-max

Bug-bounty recon tool for single-page apps. Pulls the JavaScript bundles a SPA loads at runtime, extracts every API endpoint hidden in them, asks an LLM which ones look attackable, and writes a markdown report you can verify by hand.

> ⚠️ **For authorized security research only.** Read [the disclaimer](#disclaimer) before using.

> 📦 **About this repo.** Public, sanitized mirror of a private dev tree where active engagement findings are kept under bug-bounty disclosure terms. Fresh commit history is intentional.

> 🧭 **Design rule — the tool finds, the human submits.** No report leaves Discord without a person running the live verification step manually. The pipeline is a noise filter, not an autonomous submitter.

---

## What it does (Deep Read)

`src/deep_read/` is the part of this repo that does real work. The flow:

```
target URL  →  fetch all JS bundles (incl. Module Federation chunks)
            →  extract API endpoints from minified code
            →  probe for OpenAPI / Swagger / GraphQL specs
            →  one LLM call ranks endpoints by attack potential
            →  kill-list drops known false-positive shapes
            →  markdown report  →  human verifies  →  human submits
```

The interesting bit is the bundle expansion. Most SPA recon tools fetch the two or three entry bundles a browser loads on the first page hit. Modern apps use webpack Module Federation: the entry bundle contains a chunk-name map pointing at dozens or hundreds of additional bundles, lazily loaded as the user clicks around. Deep Read parses that map and probes the federated micro-frontend hosts, expanding the visible surface from ~3 bundles to 100+.

The expanded surface gets parsed for endpoints (`fetch`, `axios`, `XMLHttpRequest`, helper-wrapper patterns, OpenAPI / Swagger specs, GraphQL operations), deduplicated, and sent to one Opus call. The model ranks them and writes attack hypotheses. A kill-list of "looks like a bug, isn't" patterns (401→403 differential, S3 403-exists, CloudFront takeover, etc.) drops shapes that historically waste reviewer time.

The output is a markdown file with ranked hypotheses, supporting evidence, and curl one-liners for verification. That file is the artifact a human acts on.

---

## Quickstart

Requires Python 3.10+ and an Anthropic or OpenAI API key.

```bash
git clone https://github.com/clutchitggs/hunter-max-oss.git
cd hunter-max-oss
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY=sk-ant-...

# 1. Log into the target in Chrome (handle WAF / 2FA / SSO manually)
# 2. DevTools → Network → copy the Cookie header from any XHR
# 3. Run:
python -m src.deep_read app.example.com \
    --cookie "session=...; csrf=..." \
    --header "Authorization: Bearer eyJ..."
```

Output lands in `reports/deep_read/<host>_<timestamp>.md`.

---

## Earlier architecture (kept in the repo, no longer the active path)

This project started as a bigger system: an async multi-stage pipeline with subdomain recon, nuclei scanning, JS-secret detection, a Scout-Sniper ReAct agent for active testing, a five-tier LLM review (T1 cheap triage → T2/T3 Sonnet investigate/challenge → T4/T5 Opus verdict/challenge), an HTTP-only enrichment layer producing auto-verdicts before any LLM saw a finding, and Discord notifications.

The whole thing worked. It just produced a lot of leads and very few that survived a human verification pass. After a fair-shake review, I cut back to Deep Read + manual verification. The slim loop converts time and API spend more honestly than the wide one did.

The earlier modules are still in `src/` — kept for now as a reference for the prior design and because Deep Read's kill-list is informed by lessons from those false-positive shapes. They aren't the recommended entry point. See "Repository layout" below for which files belong to which era.

---

## Repository layout

```
src/
├── deep_read/                 ◄── the active tool
│   ├── cli.py                 entry: python -m src.deep_read
│   ├── fetcher.py             SPA-aware, S3-safe HTTP fetcher
│   ├── webpack_chunks.py      Module Federation chunk-map expansion
│   ├── js_parser.py           endpoint extraction from minified JS
│   ├── spec_finder.py         OpenAPI / Swagger / GraphQL probing
│   ├── analyzer.py            single Opus reasoning pass + kill-list
│   └── report.py              markdown report writer
│
│   ── earlier-architecture modules (legacy, kept for reference) ──
├── pipeline.py                async multi-target orchestrator
├── infinite_hunter.py         signal-driven scheduler
├── orchestrator.py            per-target phase driver
├── api_mapper.py              Katana deep-crawl + spec discovery
├── react_agent.py             Scout + Sniper ReAct orchestration
├── scout_agent.py             fast lead identification (Sonnet, ReAct)
├── sniper_object.py           BOLA + Mass-Assignment specialist
├── sniper_resource.py         SSRF + OAST specialist
├── oast_client.py             OAST callback client
├── ai_analyzer.py             T1–T5 LLM tier review
├── evidence_enricher.py       HTTP-only auto-verdict layer
├── nuclei_runner.py           nuclei integration
├── js_analyzer.py             JS-bundle secret / endpoint scan
├── vuln_scanner.py            misc. checks
├── dns_checker.py             DNS / HTTP liveness probes
├── wayback.py                 Wayback Machine URL harvest
├── s3_enum.py                 S3 bucket enumeration
├── program_scanner.py         bug-bounty platform polling
├── scope_checker.py           scope-diff detection
├── scope_importer.py          scope import
├── cve_monitor.py             CVE → affected-target lookup
├── ma_recon.py                M&A news → newly-acquired-asset recon
├── target_scorer.py           target prioritisation
├── llm_client.py              unified Anthropic / OpenAI client + budget
├── report_drafter.py          markdown report drafting
├── notifier.py                generic notifier
├── notifier_discord.py        Discord webhook
├── dashboard.py               local Flask status dashboard
└── db.py                      SQLite (targets, findings, react_leads, …)

data/
└── wordlist.txt               small built-in wordlist

templates/                     Flask dashboard templates (legacy)
static/                        Flask dashboard CSS (legacy)

requirements.txt
config.example.json
```

---

## Configuration

Copy `config.example.json` to `config.json`. The fields most users touch:

| Field                                | What it controls                                 |
|--------------------------------------|--------------------------------------------------|
| `llm.provider`                       | `"anthropic"` or `"openai"`                      |
| `llm.api_key_env`                    | env var holding the API key                      |
| `llm.anthropic_balance_usd`          | your current balance                             |
| `llm.stop_at_remaining_usd`          | floor below which AI calls halt                  |

Daily-budget and signal-interval fields are used by the legacy pipeline and can be left at defaults.

---

## Disclaimer

This software is intended **only** for authorized security research:

- Bug-bounty programs whose scope explicitly authorizes automated scanning.
- Penetration-testing engagements with written authorization.
- Targets you own.
- CTF / lab environments.

Running this against systems you do not have written permission to test is illegal under most computer-misuse laws (Israel: Computer Law 1995 §2/§4; US: CFAA 18 USC §1030; UK: Computer Misuse Act 1990; EU: NIS2 / national equivalents).

Configure scope checks before pointing the tool at anything. **The author assumes no liability for misuse.**

The author is an approved participant in the Anthropic Cyber Verification Program, vetting LLM-augmented offensive-security research.

---

## License

MIT — see [LICENSE](LICENSE).
