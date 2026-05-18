# Tripwire

Event-driven supply-chain remediation orchestrator built around the
[Devin API](https://docs.devin.ai/api-reference/overview). When a new advisory is
published for an npm or PyPI package pinned in a tracked manifest, Tripwire detects
the finding, files a tracking issue, and spins up **one Devin session per affected
manifest** to produce a reviewed PR that remediates every finding in that manifest —
upgrading direct deps, resolving transitive ones via `overrides` / pip constraints,
and fixing any breakage the upgrade causes.

The headline metric is **mean time from advisory disclosure to remediation PR
opened**. The system is event-driven (an OSV poll cycle is the trigger), observable
(per-cycle HTML report with funnel + MTTR + cost-per-fix), and bounded (per-manifest
state machine, wall-clock cap, bounded concurrency).

The demo target is a fork of **Apache Superset** at
[`cdugo/superset`](https://github.com/cdugo/superset) on the `tripwire/demo` branch,
with four manifest scenarios spanning npm and PyPI.

## Run modes

| Mode | Network | Credentials | What it does |
|---|---|---|---|
| `demo` | none | none | Fixture-backed dry run. Deterministic; finishes in seconds. What a reviewer runs. |
| `live` | OSV.dev, GitHub, Devin | `.env` required | Real pipeline against the Superset fork. Opens real PRs. |

## Quickstart — `demo` (no credentials)

```sh
docker compose run --rm tripwire demo
```

Writes `data/tripwire.sqlite` and `data/reports/report-1.html` (plus a rolling
`data/reports/report.html`). Open the HTML in a browser to see the funnel, per-manifest
MTTR, and cost-per-fix.

Run it again with `--cycle 2` to verify **idempotency** — the second cycle should
detect zero new findings, file zero new issues, create zero new sessions.

Without Docker:

```sh
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m tripwire demo --report-dir ./reports --state-db ./tripwire.sqlite
```

## Live mode

Requires a populated `.env` (copy `.env.example` and fill in):

```sh
docker compose run --rm tripwire live
```

`live` validates the env first and **fails fast with a clear message naming every
missing variable** — no half-run sessions on a misconfigured environment. Before
burning ACUs, run the cheap pre-flight to confirm the fork matches the configured
pins:

```sh
set -a; source .env; set +a
.venv/bin/python scripts/preflight.py
```

## Two proof surfaces

1. **Clone-and-`demo`** — the system runs in seconds with zero credentials.
2. **The fork's real PR + issue history** — the genuine remediation work Devin
   actually performed during a live cycle.
   PRs land on [`cdugo/superset/pulls`](https://github.com/cdugo/superset/pulls)
   against the `tripwire/demo` branch.

## Architecture

```
                ┌────────────────┐
                │ TriggerSource  │   (OsvPoller today;
                │   (interface)  │    webhooks/Dependabot
                └───────┬────────┘    next)
                        │ Findings
                        ▼
   ┌─────────────────────────────────────────────────┐
   │              Orchestrator (one brain)           │
   │                                                 │
   │  1. detect    → OsvPoller.poll                  │
   │  2. group     → findings by manifest_path       │
   │  3. fan-out   → ThreadPoolExecutor              │
   │       per manifest, in parallel:                │
   │         GitHub issue (audit sink)               │
   │         Devin session (remediation)             │
   │  4. reconcile → re-poll in-flight sessions      │
   │       advance state on terminal signal          │
   │  5. report    → render HTML                     │
   └────────┬────────────────────────────┬───────────┘
            │                            │
       Boundaries                      Store
       ───────────                     ─────
       OsvClient (real | fake)         SQLite
       GitHubClient                    findings table
       DevinClient                     manifests table
                                       state machine
```

### Single pipeline, single brain

`Orchestrator.run_cycle` (in `tripwire/orchestrator.py`) is the whole pipeline. One
cycle: detect → group-by-manifest → per-manifest fan-out → reconcile in-flight
sessions → render report.

### Manifest is the unit of work

Fan-out is across manifests, never across individual findings. **One Devin session
per manifest, one PR per manifest.** Two coupled findings — e.g. a package and its
vulnerable transitive — get one coherent fix from one session. Splitting them into
sibling sessions would race on the lockfile and contradict each other.

### Issues are an audit sink

The GitHub issue is created **in parallel with** the Devin session, never as a
prerequisite. Devin's input is the prompt; the issue is just an audit record. Either
failing must not block the other.

### Three-layer Devin context

Per-session prompts (`tripwire/prompts.py`) carry **only** the variable per-session
specifics: manifest path + the finding list. The Playbook ID and Knowledge note IDs
ride on dedicated API fields (`playbook_id`, `knowledge_ids`), never inlined as
prompt text. This is the split that makes the system actually scale — fleet-wide
doctrine lives in the Playbook, environment specifics in Knowledge, only the
remediation target travels in each prompt.

The Playbook + Knowledge fixtures we configure live in
[`devin/playbook.json`](devin/playbook.json) and
[`devin/knowledge-fixtures.json`](devin/knowledge-fixtures.json).

### Read-only Monitor

`tripwire/monitor.py` returns a `Verdict ∈ {in_flight, resolved, needs_human,
timed_out}`. **It records; Devin acts.** There is no "no-progress" rule — judging
whether a fix is still progressing belongs to Devin (Autofix), not us. The wall-clock
cap is a liveness backstop only.

Two ways Devin signals "done":
- **Canonical:** `status_detail == "waiting_for_user"`. PR present → `resolved`. No
  PR → Devin asked a clarifying question → `needs_human`. (Top-level `status` stays
  `"running"` for the session's lifetime — do not trust it as a terminal signal.)
- **Text-marker fallback:** the last `source: "devin"` message body contains
  `"Terminal status: COMPLETE"` / `"BLOCKED"`. Retained for playbooks that emit it.

Hard-error statuses (`suspended`, `error`) → `needs_human`. Age > cap → `timed_out`.

### State machine

```
detected ──► in_flight ──► {resolved, needs_human, timed_out}
        └──► needs_human / timed_out         (escalation before session)
```

Terminal states are absorbing. `Store.advance_manifest` raises on illegal
transitions. `start_session` is the only path into `in_flight` and is atomic with
recording `session_id` + `started_at`. `pr_opened_at` is an **observation**, not a
transition — set the first time reconcile sees a non-null `pr_url`, never unset.

### Cross-cycle reconciliation

A real Devin session takes minutes. The Monitor used to run inline at
session-creation time with `age=0`, so a single `run_cycle` could never advance a
slow session past `in_flight`. The reconcile pass re-polls every in-flight session
each cycle, which is what gives the wall-clock cap real teeth and lets the system
converge across multiple ticks.

### Boundaries (Protocol + Real + Fake)

Every external system sits behind a `Protocol` in `tripwire/boundaries/`:

| Boundary | Protocol | Real client | Fake |
|---|---|---|---|
| OSV | `OsvClient` | `RealOsvClient` (`/v1/querybatch`) | `FakeOsvClient` |
| GitHub | `GitHubClient` | `RealGitHubClient` (`POST /issues`) | `FakeGitHubClient` |
| Devin | `DevinClient` | `RealDevinClient` (`/v3/organizations/{org}/sessions`) | `FakeDevinClient` |

The orchestrator takes a `Boundaries` bundle — never raw clients — so
`demo_boundaries()` / `live_boundaries(env)` are the only wiring seams. Tests
exercise real client classes against `httpx.MockTransport` (no network).

`RealDevinClient.get_session` does *two* GETs (session + messages) and normalizes the
API's `acus_consumed` / `pull_requests` payload into the `acu_usage` / `pr_url` keys
the orchestrator + Monitor consume. The boundary owns key-normalization so callers
don't need to know either spelling.

## Observability

A reviewer can answer **"is this working?"** from a single HTML file
(`reports/report-{cycle}.html`). It surfaces:

- **Cost per fix** — `total_dollars / PRs landed`. The denominator is PRs landed,
  *not* sessions started — a `needs_human` escalation burned ACUs but produced no fix
  to amortize against. Zero PRs returns `None` (rendered as "pending — no PRs landed
  yet"), never zero or infinity.
- **Funnel** — findings → manifests → sessions → PRs opened → CI green → merged.
  `merged` is **deliberately always zero** — merging is a human action by design.
- **MTTR per manifest** — `detected_at → pr_opened_at`. `None` for any manifest
  that hasn't opened a PR yet (we don't lie and report zero).
- **All findings + their state** — by manifest, ecosystem, package, severity,
  advisory IDs.

Per-cycle snapshots persist (`report-1.html`, `report-2.html`, …) so the funnel can
be told as a story across cycles; a rolling `report.html` always points to the
latest.

### Live-mode reality check

A few honest notes about what live mode does and doesn't show today:

- **ACUs report `0.0` for every session on this account tier.** Verified against the
  v3 consumption endpoint; the tier doesn't bill Autofix work. The metric is wired
  and would populate against a billed account. We narrate this honestly rather than
  filling in fake numbers.
- **Pre-existing CI rot on the fork** can cause unrelated failures on some PRs.
  Devin sessions correctly wait on CI; the failure does not block a session reaching
  a terminal signal once Devin's own checks pass.
- **The GitHub PAT** needs `Pull requests: Write` and `Contents: Write` if you want
  programmatic cleanup of stale branches; we only need `Issues: Write` and `Contents:
  Read` for the actual pipeline.

## Tests

```sh
.venv/bin/pytest
```

The full suite runs against fakes in milliseconds; no network. Test files named
`test_boundaries_real_*.py` exercise the *real* client classes against
`httpx.MockTransport` to verify request shapes (URL, headers, batching) without
hitting external APIs. ~90 tests total.

## Repo layout

```
tripwire/
  orchestrator.py        run_cycle: the 5-step pipeline
  monitor.py             read-only Verdict from a Devin session
  store.py               SQLite + state machine
  findings.py            Finding model + advisory collapser
  prompts.py             per-session prompt template
  metrics.py             funnel / MTTR / cost-per-fix
  report.py              HTML renderer
  cli.py                 `tripwire demo` / `tripwire live`
  triggers/osv.py        OsvPoller — TriggerSource impl
  boundaries/            Protocol + real + fake per external system
  demo_fixtures.py       canned manifests + OSV payloads (offline demo)
  live_config.py         live mode env loader + manifest slate

tests/                   pytest suite (fakes only, no network)
scripts/
  preflight.py           cheap pre-`live` sanity check
  live_smoke.py          single-manifest live smoke (1 ACU)
  poll_sessions.py       poll in-flight sessions until terminal
  osv_lockfile_scan.py   ad-hoc lockfile → OSV batch query
  devin.sh               curl wrapper for ad-hoc Devin API calls

devin/                   Playbook + Knowledge note fixtures we ship
reports/                 generated; per-cycle + rolling HTML
```

## Why this shape (the design call-outs)

A few non-obvious choices worth flagging:

- **Detection is deterministic code, not Devin.** Reading manifests and calling OSV
  is deterministic; agentic work there would cost ACUs, add latency, and break
  idempotency. Tenet: *deterministic work is code, judgment work is Devin.*
- **No eligibility / approval gate.** Every detected finding is remediated. A gate
  that passes all fixtures is theater; a real fleet policy can't be honestly
  exhibited with curated fixtures. Banked as a real-customer "next step."
- **One Devin session per manifest, not per finding.** Per-finding sessions on a
  shared manifest collide on the lockfile and can contradict each other. One session
  per manifest dissolves both problems and matches how a real engineer works: one PR
  for one manifest's vulns.
- **Sessions run in parallel, code-orchestrated**, bounded concurrency cap (4 by
  default). Sequential would make Devin look like a slow batch job; unbounded would
  melt the API.
- **Monitor is read-only.** The fix loop — verify, repair, iterate — is Devin
  (Autofix). The orchestrator runs the boundaries: detection, fan-out, escalation,
  liveness. Mixing the two would couple a deterministic loop to an agent that
  already owns it.
- **SQLite, file-mounted.** State (findings dedupe, per-manifest state, ACU usage,
  PR observations) lives in one file that survives container restart. The whole
  store is ~250 lines.

## Next steps (real-customer engagement)

- More `TriggerSource` adapters behind the same interface — GitHub webhook for
  Dependabot alerts, ticketing webhooks, custom scanner feeds.
- Per-finding eligibility / approval gate with real customer policy.
- CI/CD workflow hardening on the customer fork (so Devin's "wait for CI green"
  loop has real signal instead of pre-existing rot).
- Fleet-wide rollout: same orchestrator, config-driven manifest slates per repo.
- Devin ships a no-code Automations layer with a native issue trigger; this system
  deliberately builds the orchestration itself so we *own* the dispatch logic,
  metrics, and escalation rules — which is what the brief is asking us to do.
