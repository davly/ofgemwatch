# ofgemwatch → Nexus capability exposure (operator runbook)

**Capability:** `ofgemwatch.riio_compliance_verdict` · **Shape:** (1) MCP-tool proxy
**Added:** 2026-06-02 · **Branch:** `feat/nexus-mcp-riio-compliance-verdict`

This document is the operator runbook for exposing ofgemwatch's deterministic
**Ofgem RIIO-ED2 price-control compliance verdict** as a Nexus-routable capability.
It follows the RubberDuck exemplar (`davly/RubberDuck#38`) and the capability-hub
thesis (ADR-001): consumer apps integrate ONLY with Nexus; Nexus routes to producers
**by capability**; every call carries **provenance** (which end-user originated it).

---

## 1. What was added (this branch, minimal + additive)

| File | Purpose |
|---|---|
| `cmd/ofgemwatch-server/main.go` | `net/http` daemon; mounts `/mcp/tools`; reads `PORT` + `OFGEMWATCH_NEXUS_SERVICE_TOKEN` |
| `internal/mcpserver/mcpserver.go` | Manifest + invoke handlers; constant-time fail-closed token auth; provenance; size cap |
| `internal/mcpserver/mcpserver_test.go` | Reachability + unset-token-401 + wrong/missing-token-401 + missing-`X-User-Id`-400 + **real-engine** golden invoke |
| `internal/audit-ledger/ledger.go` | `+ NewScaffoldLedger()` — the single shared placeholder-marker ledger factory (CLI + server use it) |
| `internal/firewall/firewall_test.go` | **R145.B paired regression** — `net/http`+env scans scoped to exclude the producer host; new `TestFirewall_HTTPConfinedToProducerHost` re-pins the carve-out so it is scoped, not a hole |

**Why the firewall change is sanctioned (not a silent invariant flip):** ARCHITECTURE.md
§Phase 2 explicitly anticipates *"HTTP daemon mode for regulator-pull-based row delivery"*
with *"the firewall test pin shifted via R145.B paired regression."* The CLI
(`cmd/ofgemwatch`) and every domain package stay strictly stdlib-only / HTTP-free /
env-free — only the two Nexus-facing producer-host packages are exempted, and that
confinement is itself asserted by a test.

No new domain logic was written. The handler is a pure adapter over the existing,
already-tested engine: `ofgemriio.DNO.Verdict` / `DeltaPct` / `FindByID` /
`CanonicalDNOs` + `auditledger.NewRIIORow` / `Append`.

---

## 2. The wire contract (the WIRE is the spec)

Tool name `ofgemwatch.riio_compliance_verdict` **is the routing key** — Nexus needs no
per-capability Go code for this Shape-1 leg.

### `GET /mcp/tools/` → manifest
Headers: `X-Nexus-Service-Token: <SHARED>` (no auth cookie needed).
```json
{
  "tools": [
    {
      "name": "ofgemwatch.riio_compliance_verdict",
      "description": "Compute an Ofgem RIIO-ED2 price-control compliance verdict ...",
      "input_schema": {
        "type": "object",
        "properties": {
          "dno_id": { "type": "string" },
          "determination_totex_million_gbp": { "type": "number" },
          "reported_totex_million_gbp": { "type": "number" }
        },
        "additionalProperties": false
      },
      "approval_required": false
    }
  ]
}
```

### `POST /mcp/tools/ofgemwatch.riio_compliance_verdict` → invoke
Headers: `X-Nexus-Service-Token: <SHARED>` **and** `X-User-Id: <end-user>` (400 if absent).

Request — EITHER a canonical `dno_id` OR a raw totex pair (the verdict math is general;
`dno_id` takes precedence if both are present):
```json
{ "dno_id": "WPD-WMID" }
```
```json
{ "determination_totex_million_gbp": 1000, "reported_totex_million_gbp": 1200 }
```

Response envelope (Nexus unwraps `content`):
```json
{
  "content": {
    "dno_id": "WPD-WMID",
    "region": "West Midlands",
    "determination_totex_million_gbp": 1850,
    "reported_totex_million_gbp": 1923,
    "verdict": "compliant",
    "delta_pct": 3.945945945945946,
    "tolerance_band": 0.15,
    "lower_band_million_gbp": 1572.5,
    "upper_band_million_gbp": 2127.5,
    "mark": "lore@v1:...",
    "audit_ts": "2026-06-02T16:15:00Z",
    "requested_by": "<X-User-Id>",
    "caveats": [
      "OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE: ...",
      "OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER: ..."
    ]
  },
  "is_error": false,
  "error_message": ""
}
```
Logical tool failures (unknown `dno_id`, neither input form) ride the envelope:
HTTP `200` + `is_error: true` + `error_message`. Transport/trust failures use real
HTTP codes (`401` / `400` / `404`).

---

## 3. Trust boundary (two tokens, never confused)

- **`X-Nexus-Service-Token`** — machine trust (Nexus ↔ ofgemwatch). Shared secret,
  constant-time compared. **FAIL-CLOSED: an UNSET/empty `OFGEMWATCH_NEXUS_SERVICE_TOKEN`
  ⇒ every request 401s — never fail-open.** (`TestAuth_UnsetToken_401Everything` pins this.)
- **`X-User-Id`** — provenance (who originated the request). Nexus sets it only after
  validating the end-user JWT. Recorded into the Mirror-Mark-stamped audit row
  (`requested_by`). 400 if absent.

The `/mcp/tools` group is mounted with **no app-wide auth middleware in front of it**
(dedicated server; STEP-1.5) — the only gate is the constant-time token check.
`GET /healthz` is the one unauthenticated route (liveness only).

---

## 4. Go-live

1. **Deploy** `cmd/ofgemwatch-server`, reachable from Nexus's network
   (e.g. `https://ofgemwatch.promptboy.dev`).
2. **Set** `OFGEMWATCH_NEXUS_SERVICE_TOKEN=<SHARED>` (non-empty ⇒ not fail-open).
   Optionally `PORT` (default `8080`).
3. **Register in Nexus** (zero Nexus code change — config only):
   ```
   FLAGSHIP_TOOL_PROVIDERS += ofgemwatch|https://ofgemwatch.promptboy.dev|<SHARED>
   ```
   (`name|url|token`, comma-separated for many; bad entries are logged + skipped — never
   fails Nexus startup; a down-at-startup flagship does not abort the others.)
4. **Smoke** (see below).

The shared secret is **one value**: identical in `OFGEMWATCH_NEXUS_SERVICE_TOKEN` and the
Nexus `FLAGSHIP_TOOL_PROVIDERS` token field.

---

## 5. Smoke (operator, against live Nexus + ofgemwatch)

```sh
# 1. Reachability (STEP-1.5): service-token header, NO cookie ⇒ 200, not 3xx/401.
curl -i -H "X-Nexus-Service-Token: $TOK" https://ofgemwatch.promptboy.dev/mcp/tools/
#    EXPECT 200 + JSON listing ofgemwatch.riio_compliance_verdict.

# 2. Fail-closed: omit/wrong token ⇒ 401. With the env var empty even a header ⇒ 401.
curl -i https://ofgemwatch.promptboy.dev/mcp/tools/                 # 401
curl -i -H "X-Nexus-Service-Token: wrong" .../mcp/tools/            # 401

# 3. Provenance: invoke with token but NO X-User-Id ⇒ 400.
curl -i -H "X-Nexus-Service-Token: $TOK" -d '{"dno_id":"WPD-WMID"}' \
  https://ofgemwatch.promptboy.dev/mcp/tools/ofgemwatch.riio_compliance_verdict   # 400

# 4. Real invoke through Nexus: list the tool registry — ofgemwatch.riio_compliance_verdict
#    is present; invoke it for a test user; expect content.verdict + a lore@v1: mark +
#    the caveats array; cost appears on Nexus's meter.
```

---

## 6. Honest scoping (do NOT skip)

ofgemwatch is a **Phase-1 scaffold**. Two `Error`-severity R143 advisories fire at boot
and are echoed in every verdict's `caveats`:

- **`OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE`** — `dno_id` lookups resolve against a
  6-DNO **canned-fixture** corpus, not a live Ofgem feed. The verdict **math** is real and
  general (use the raw `{determination,reported}` pair form for the fixture-independent
  capability). Gate any "live regulatory compliance" claim on the Phase-2 feed.
- **`OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT`** — the audit-ledger marker is in
  **placeholder mode**. Rows are tamper-*evident* but cold-verify will (correctly) refuse
  them at a real regulator boundary until Phase-2 wires a production key.

The `caveats` field is the guardrail: a downstream consumer can refuse scaffold output.

**Deferred to Phase-2 (separate R145.B branch each):** live Ofgem RIIO-2 D2 feed; durable
ledger + production marker key; the `ofgemwatch.riio_fleet_summary` and
`ofgemwatch.entsoe_emit_report` tools (specced in the capability-exposure doc, intentionally
out of scope here to keep this change minimal). ofgemwatch makes **zero** AI calls today,
so there is no consumer-leg (flywheel) wire to add.
