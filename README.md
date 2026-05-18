# Tripwire

Event-driven supply-chain remediation built on the
[Devin API](https://docs.devin.ai/api-reference/overview).
New OSV advisory → detect which manifests are affected → one Devin session per
manifest → reviewed PR that fixes every finding in that manifest, including
transitives and any build breakage from the upgrade.

Headline metric: **MTTR from advisory disclosure to remediation PR opened**.
Demo target: a fork of Apache Superset at
[`cdugo/superset`](https://github.com/cdugo/superset) on `tripwire/demo`, with
four manifest scenarios across npm and PyPI.

## Run modes

| Mode | Network | Credentials | What it does |
|---|---|---|---|
| `demo` | none | none | Fixture-backed, deterministic, <1s. What a reviewer runs. |
| `live` | OSV.dev, GitHub, Devin | `.env` required | Real pipeline against the fork. Opens real PRs. |

## Quickstart

```sh
docker compose run --rm tripwire demo
```

Writes `data/tripwire.sqlite` and `data/reports/report-1.html`. Re-run with
`--cycle 2` to see idempotency — zero new findings, zero new sessions.

Without Docker:

```sh
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m tripwire demo --report-dir ./reports --state-db ./tripwire.sqlite
```

## Live mode

Populate `.env` (see `.env.example`), then:

```sh
docker compose run --rm tripwire live
```

Fails fast, naming any missing env var. Before burning ACUs, run preflight:

```sh
.venv/bin/python scripts/preflight.py
```

Predicts cycle-1 finding count and confirms manifest files exist on the fork.

## Two proof surfaces

1. **`demo`** — runs in <1s with zero credentials.
2. **Real PRs + Devin sessions** at
   [`cdugo/superset/pulls`](https://github.com/cdugo/superset/pulls).

## Architecture

```
                ┌────────────────┐
                │ TriggerSource  │   (OsvPoller today;
                │   (interface)  │    webhooks next)
                └───────┬────────┘
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
   │  5. report    → render HTML                     │
   └────────┬────────────────────────────┬───────────┘
            │                            │
       Boundaries                      Store
       (real | fake per system)        SQLite, state machine
```

**Manifest is the unit of work.** One Devin session per manifest, one PR per
manifest. Coupled findings (a package + its vulnerable transitive) get a
coherent fix from one session; splitting them would race on the lockfile.

**Issues are an audit sink.** Filed in parallel with the session, never a
prerequisite — either failing must not block the other.

**Three-layer Devin context.** Prompt body carries only manifest path +
findings. Playbook ID and Knowledge note IDs ride on dedicated API fields.
Doctrine scales; prompt stays small.

**Read-only Monitor.** Records terminal signal; never re-prompts. The fix
loop (verify / repair / iterate) is Devin Autofix's job. Wall-clock cap is a
liveness backstop only.

Devin's "done" signal:
- `status_detail == "waiting_for_user"` + PR present → `resolved`. No PR →
  Devin asked a clarifying question → `needs_human`. Top-level `status` stays
  `"running"` for the session's lifetime; don't trust it.
- Fallback: last `source: "devin"` message body contains `"Terminal status:
  COMPLETE"` / `"BLOCKED"`.

**State machine:**

```
detected ──► in_flight ──► {resolved, needs_human, timed_out}
        └──► needs_human / timed_out          (escalation before session)
```

Terminal states are absorbing. `pr_opened_at` is an observation, not a
transition.

**Cross-cycle reconcile.** Real Devin sessions take minutes; a single cycle
can't resolve work it just dispatched. Each cycle re-polls every in-flight
session, which is what gives the wall-clock cap real teeth.

### Boundaries (Protocol + Real + Fake)

| Boundary | Real client | Fake |
|---|---|---|
| OSV | `RealOsvClient` (`/v1/querybatch`) | `FakeOsvClient` |
| GitHub | `RealGitHubClient` (`POST /issues`) | `FakeGitHubClient` |
| Devin | `RealDevinClient` (`/v3/organizations/{org}/sessions`) | `FakeDevinClient` |

Orchestrator takes a `Boundaries` bundle, never raw clients — demo/live wiring
is one seam. Tests exercise real clients against `httpx.MockTransport`.

`RealDevinClient.get_session` does two GETs (session + messages) and normalizes
the API's `acus_consumed` / `pull_requests` into `acu_usage` / `pr_url`.

## Observability

A reviewer answers "is this working?" from one HTML file
(`reports/report-{cycle}.html`):

- **Cost per fix** — `total_dollars / PRs landed`. Denominator is PRs landed,
  not sessions started; escalations don't get amortized. Zero PRs → `None`,
  never zero.
- **Funnel** — findings → manifests → sessions → PRs → CI green → merged.
  `merged` is always zero by design (human action).
- **MTTR per manifest** — `detected_at → pr_opened_at`. `None` if no PR yet.

Per-cycle snapshots persist; rolling `report.html` points at the latest.

### Live-mode caveats

- **ACUs report 0.0** on this account tier — Autofix is bundled. The metric
  is wired and would populate against a billed account via the v3 consumption
  endpoint.
- **GitHub PAT scope:** `Issues: Write` + `Contents: Read` for the pipeline.
  Add `Pull requests: Write` + `Contents: Write` for programmatic
  PR/branch cleanup.

## Tests

```sh
.venv/bin/pytest
```

88 tests, fakes only, milliseconds. `test_boundaries_real_*.py` exercises
real clients against `httpx.MockTransport` (no network).

## Repo layout

```
tripwire/
  orchestrator.py        run_cycle: 5-step pipeline
  monitor.py             read-only Verdict
  store.py               SQLite + state machine
  findings.py            Finding model + advisory collapser
  prompts.py             per-session prompt
  metrics.py             funnel / MTTR / cost-per-fix
  report.py              HTML renderer
  cli.py                 `tripwire demo` / `tripwire live`
  triggers/osv.py        OsvPoller
  boundaries/            Protocol + real + fake per system

tests/                   pytest suite
scripts/
  preflight.py           cheap pre-`live` sanity check
  live_smoke.py          single-manifest live smoke (1 ACU)
  poll_sessions.py       poll in-flight sessions until terminal
  osv_lockfile_scan.py   lockfile → OSV batch query
  devin.sh               curl wrapper for Devin API

devin/                   Playbook + Knowledge note fixtures
reports/                 generated; per-cycle + rolling HTML
```

## Design call-outs

- **Detection is code, not Devin.** Reading manifests and calling OSV is
  deterministic; an agent there would cost ACUs and break idempotency.
- **No eligibility gate.** Every finding is remediated. A gate that passes
  all curated fixtures is theater — real policy is a customer next-step.
- **One session per manifest, not per finding.** Per-finding sessions on a
  shared manifest collide on the lockfile.
- **Bounded parallel sessions** (4 by default). Sequential makes Devin look
  slow; unbounded melts the API.
- **Monitor is read-only.** The fix loop is Devin's. Mixing the two would
  couple a deterministic loop to an agent that already owns it.
- **SQLite, file-mounted.** State survives container restart. The whole
  store is ~250 lines.

## Next steps

- More `TriggerSource` adapters: Dependabot webhooks, ticketing, custom
  scanner feeds — same interface.
- Per-finding eligibility / approval gate with customer policy.
- CI hardening on the customer fork so Devin's CI-watch loop has clean signal.
- Fleet-wide rollout via config-driven manifest slates per repo.
