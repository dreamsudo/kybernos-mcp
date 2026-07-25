# Corpus verification — triage notes

## Note: DLP secret payloads are redacted (repo hygiene)

The DLP-category probes originally embedded **real-format** secret strings (AWS
`AKIA…`, Stripe `sk_live_…`, Slack `xox…`, Google `AIza…`, GitHub `ghp_…`, JWTs,
PEM headers) so they would exercise the format-based DLP firewall rules. Those
literal payloads have been **redacted to labelled placeholders**
(`STRIPEKEY_REDACTED_DLP_TEST`, `AWSKEY_REDACTED_DLP_TEST`, …) so this public repo
does not ship secret-shaped strings and does not trip secret scanners / GitHub
push protection. Consequences:
- The **DLP rules themselves are unchanged** (`config/security_policy.yaml`) and
  still detect the real formats in production. Only the *test payloads* changed.
- Prefix/keyword DLP probes (`api_key=…`, `id_rsa`, `.env`, `bearer …`) are
  **unaffected** — they still block on replay.
- The ~30 pure *format-match* DLP probes will now replay as ALLOW (their redacted
  payload no longer matches the format regex); their recorded `expect`/`control`
  documents the rule they were written to exercise. The intermediate generator
  dump `generated_raw.json` (which also held raw secret formats) is not shipped.


Baseline false positives: **28 → 0** after tightening 12 over-broad firewall
rules (word boundaries + command/value context) and adding
`additionalProperties: false` to the three resource schemas.

Detection preserved: after the tightening, re-verification flagged 67
expected-BLOCK-but-ALLOWED probes. Triaged:
- **Real regressions (fixed):** URL-field loopback SSRF (`https://localhost`,
  `127.0.0.1`), `env`-exec forms (`/usr/bin/env bash`, `env -i sh`), and
  IP-encoding SSRF evasions (short-form `10.1`, zero-padded `010.010...`).
  A new rule `RCE_DEVTCP` (`/dev/(tcp|udp)/`) closes reverse-shell strings.
- **Residual ~53 (accepted):** three classes, none high-severity in this system:
  1. **Generator mislabels** (~30): benign prose/domains the generator wrongly
     tagged BLOCK — e.g. "the sunset was lovely", "cdn10.example.com",
     "asset inventory". ALLOW is correct here; these are corpus-label noise.
  2. **Inherent denylist limits**: split-token evasion (`net cat`, `so cat`),
     common filenames (`config.json`), IP alias edge cases
     (`localhost.localdomain`). Covered by RBAC + sandbox + egress DLP.
  3. **Content-field mentions** of sensitive strings written to a sandboxed
     file (not executed) — inert in this architecture.

The authoritative controls remain RBAC + JSON-Schema validation; the firewall is
defense-in-depth. Replacing `node-db`/`node-net` mocks with SSRF-safe / read-only
connectors is the production follow-up that removes the residual content-field risk.

---

## Adversarial bug-hunt (2026-07) — 11 confirmed findings

A find→verify multi-agent pass over the newest code confirmed 11 issues the
109-assertion suite missed. **9 were unambiguous bugs and are fixed**, each with
a regression test (`tests/test_regressions.py`, plus the `read missing file`
pipeline probe):

| # | Sev | Fix |
|---|-----|-----|
| BH-1 | high | Bedrock SigV4 signed `json.dumps(body)` but httpx transmitted a different serialization → every native Bedrock call `403 SignatureDoesNotMatch`. Now signs and sends the *same* bytes via `serialize_body()` + `content=`. |
| BH-2 | high | Enforcer returned worker-node 4xx/5xx as HTTP 200, handing the model an error dict as if it were a result (and marking denials as EGRESS success). Now surfaces node status. Exposed a latent bug: `list .` was silently broken because the sandbox root was never created → `node_fs` now `makedirs` it on startup. |
| BH-3 | med | Gemini dropped a list-form system prompt (guardrail loss). |
| BH-4 | med | Gemini crashed (`AttributeError`→502) on a safety-blocked null candidate. |
| BH-5 | med | Non-object JSON body → 500; now 400. |
| BH-6 | med | Rate limiter failed **open** on a Redis outage; now fails closed by default (compose env aligned to k8s). |
| BH-8 | med | Banner crashed service startup on a non-UTF-8 stdout (`UnicodeEncodeError` on the Greek motto); fallback is now encoding-safe. |
| BH-9 | low | Oversized body was buffered before the 413; now rejected on `Content-Length` first. |
| BH-11 | low | Capability token was replayable within its TTL; enforcer now `getdel`s the jti → single-use. |

### Self-verification pass (fixes reviewed for regressions)

A second find→verify pass audited the 9 fixes themselves. It **refuted 4 of 6**
candidate regressions in the critical SigV4 / gateway / enforcer changes (no
regression there) and **confirmed 2 low-severity follow-ups**, both in the
`node_fs` `makedirs` added for BH-2 — now fixed + tested (`BH-2b`): the sandbox
init was swallowing all `OSError`s (a broken/read-only `SANDBOX_DIR` was masked
as healthy) and created the sandbox world-writable. `node_fs` now sets `0o770`,
validates the sandbox is a writable directory, and fails `/healthz` (503) loudly
when it isn't.

### Two DEFERRED design decisions (not silently changed)

BH-7 and BH-10 are real *inconsistencies*, but "fixing" them is a product
decision with a ~424-probe ground-truth ripple, so they are surfaced here rather
than patched unilaterally. The corpus already documents both as deliberate
boundary probes (`fs_content_deadzone_*`, `gap_ext_*`, `*_wronglayer`).

- **BH-7 — `FMT_OVERFLOW` (`.{8193,}`) vs `content maxLength: 10240`.** The
  schema advertises 10 KB writes but the firewall blocks any payload ≥ 8193 chars,
  so a schema-valid 8–10 KB write is rejected with a misleading "overflow" error.
  Because the firewall measures the *whole stringified payload*, no single
  `maxLength` can fully reconcile it. **Decision needed:** either (a) cap file
  writes small and keep the crude backstop, or (b) raise `FMT_OVERFLOW` above the
  largest legitimate field (e.g. `.{32769,}`) and let per-field `maxLength` +
  `max_input_size` (512 KB) be authoritative — then recompute the ~30 affected
  content probes to ALLOW.
- **BH-10 — `path` pattern does not enforce the documented extension allow-list.**
  `[a-zA-Z0-9_/.-]+(\.txt|\.json|\.log|\.md|/)?$` lets the optional group and the
  `.` in the class absorb arbitrary extensions (`app.py`, `data.zip`, `etc/passwd`
  all pass schema). The sandbox boundary + DLP filename rules still contain the
  real risk, so this is contract-vs-enforcement drift, not an escape. **Decision
  needed:** strict enforcement (`…[a-zA-Z0-9_/-]+(\.txt|\.json|\.log|\.md|/)$` +
  `maxLength: 4096`) blocks extensionless paths **and the `list .`/`./` action**,
  flipping 166 baseline-ALLOW probes to BLOCK — so it needs a special-case for
  `.`/dir listings and a corpus re-baseline before it ships.
