# ofgemwatch — SECURITY

## Threat model

Ofgemwatch is a regulatory-reporting CLI + library. Threat surface is narrow because:

- No users (single-machine CLI; no auth, no multi-tenancy)
- No daemon (no HTTP listener, no socket binding)
- No DB at Phase 1 (no SQL injection surface)
- No PII (energy-regulatory data is corporate, not personal)
- No money semantics (£m totex figures are reported, not collected)

## Patterns intentionally absent (Phase 1)

The `internal/firewall/firewall_test.go` test pins absence of these patterns. Adding any one requires a sibling R145.B branch with paired regression.

1. **No `database/sql` import** — no DB driver, no `sql.Open()`. Phase-1 is in-memory only.
2. **No `net/http` listener** — `http.ListenAndServe`, `net.Listen()` absent. No daemon mode.
3. **No `net/http` client** — no outbound HTTP. Live Ofgem feed + ENTSO-E API are Phase-2 deferred.
4. **No `os.Getenv` / `os.LookupEnv`** — pure-argv CLI. No env-var configuration surface.
5. **No `crypto/tls`** — no TLS handshakes, no certificate handling.
6. **No `github.com/golang-jwt/jwt` / `golang.org/x/crypto/bcrypt`** — no auth surface; no users.
7. **No external `go.mod` requires** — pure-stdlib Go 1.22. Every byte is auditable.
8. **No money/payment semantics** — no Stripe, no checkout, no subscription tiers. Ofgemwatch reports £m totex; it does not collect payment.
9. **No `face_recognition` / `identity_database`** — no biometric data; not applicable for energy regulatory reporting.
10. **No PII persistence** — DNO IDs (`WPD-WMID`) and report IDs (`RPT-2026-Q3-001`) are not personal data.

## Mirror-Mark integrity property

Every audit-ledger row carries a cohort-canonical L43 Mirror-Mark stamped on its canonical JSON bytes. Property:

- **Integrity:** any byte change in the canonical row breaks `Verify()` (HMAC-SHA256 collision resistance).
- **Provenance:** the corpus-SHA prefix in the mark body identifies which lore corpus signed the row.
- **Regulator cold-verify:** OpenSSL alone reproduces the mark — no Limitless toolchain required.
- **Property bed:** FIPS PUB 180-4 (SHA-256) + RFC 2104 (HMAC) + RFC 4648 (base64url). Not Limitless code.

## Phase-1 placeholder-mode posture

Phase-1 scaffold ships with a **placeholder marker** (zero corpus SHA + a sentinel key string `ofgemwatch-placeholder-key-DO-NOT-USE-IN-PRODUCTION`). Two safeguards apply:

1. **Boot-time R143 LOUD-ONCE-WARN** (`OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT`, Error severity) fires once per process when `Ledger.BootCheck()` is called against a placeholder marker. The CLI calls `BootCheck()` before any command.
2. **Placeholder `Verify()` refusal** — `StdlibMarker.Verify()` returns `ErrMarkerNotConfigured` for placeholder markers. A regulator-side cold-verify path REFUSES placeholder marks at the boundary.

Production deployments MUST wire a real `(corpusSHA, key)` via a separate scaffold entry-point.

## Reviewer-class signoff (R150.E)

The 12-entry manifest seed flags `ReviewedByCounsel: false` for every entry at Phase 1. Phase-3 deliverable adds qualified-counsel review (UK energy regulatory barrister + US FERC counsel) and promotes selected entries to `ReviewedByCounsel: true`. Until then:

- The `OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE` R143 advisory fires at boot.
- FERC Order 1000 entries are always-stale (`IsStale == true`) at Phase 1 — `ReviewedByCounsel: false` is the load-bearing freshness gate.

## Cohort cross-substrate parity (R151 KAT-1)

The cohort-canonical KAT-1 hex `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca` is pinned at three sites:

- `internal/lore/kat1.go` (canonical constant)
- `internal/lore/kat1_test.go` (regression pin)
- `internal/firewall/firewall_test.go` (cohort firewall pin)

Drift at any site breaks the cohort. Re-derivation via OpenSSL is documented in `internal/lore/kat1.go` doc-comment.

## Cross-flagship byte-clone advisory

The Apache-2.0 LICENSE file is a byte-clone (md5 `1870f68b015802092d5a94bd7bf0d0f5`, 11,504 bytes, copyright "David Carson, 2026"). Cohort siblings under the same byte-clone include `memoria`, `gridlock`, `gambit`, `gaia`, `garnet`, `garrison`, `grain`, `ghost`, `atlas`, `almanac`, `academy`, `abyss`, `atelier`, `echo-chamber`, and others. The byte-clone is intentional; substituting a different LICENSE file requires an R145.B paired-regression branch.
