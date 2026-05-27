# ofgemwatch

**Status:** Phase-1 scaffold from inception (BR6 new flagship 2026-05-27).

**One-line:** Ofgem RIIO ED2 + ENTSO-E IEC 62325-451-3 regulatory reporting with Mirror-Mark stamped audit ledger.

**Category:** B2B Enterprise | Energy Regulatory Reporting
**Target Market:** UK Distribution Network Operators (DNOs), GB transmission operators, ENTSO-E transparency-platform consumers, energy regulators (Ofgem, CMA, deferred FERC).
**Substrate:** Go 1.22, pure-stdlib (zero `go.mod` requires), Apache-2.0.

---

## Problem Statement

UK + EU energy regulatory reporting is high-stakes, manual, and inconsistent:

- **Ofgem RIIO ED2** governs UK Distribution Network Operator (DNO) price controls under 5-year cycles. DNOs file totex actuals against final-determination allowances; verdicts (compliant vs breach) drive revenue allowances of ~£1bn/DNO/year.
- **ENTSO-E transparency-platform** publishes hourly market-monitoring data across 36 European Transmission System Operators under Regulation (EU) 543/2013. The IEC 62325-451-3 XML schema is publicly published; the data flow is regulator-load-bearing.
- **No common audit trail.** A regulator (Ofgem auditor, ENTSO-E Market Monitoring Forum, future FERC Order 1000 cross-Atlantic harmonization) cannot independently cold-verify the wire-form bytes of an operator's submitted report.

ofgemwatch ships:

1. **Ofgem RIIO-CF compliance verdicts** at the 6-DNO Phase-1 corpus level (scaffold; live feed Phase-2).
2. **ENTSO-E IEC 62325-451-3 transparency XML producer** emitting against the published XSD (placeholder payload Phase-1).
3. **Mirror-Mark stamped audit ledger** — every emitted verdict + every emitted XML body crosses `internal/audit-ledger/Append()`, which stamps a cohort-canonical L43 Mirror-Mark on the canonical wire-form bytes. Downstream regulators cold-verify with OpenSSL alone.

---

## R174 5-of-5 Cohort Maturity (from inception)

Ofgemwatch ships ALL FIVE cohort disciplines in dedicated packages on the first commit:

| Package | Discipline | What it pins |
|---|---|---|
| `internal/firewall/` | R145.C FIREWALL-TEST-DISCIPLINE | No external deps, no HTTP listener/client at Phase-1, no env-vars, R174 5-of-5 on-disk check, R175 KAT-1 hex pin |
| `internal/lore/` | R151 KAT-AS-COHORT-INVARIANT-PIN | `KAT1Digest = 239a7d0d…` byte-identical to ~34-language cohort + `AssertKAT1Parity()` exported helper |
| `internal/mirrormark/` | L43 Mirror-Mark v1 signer | `"lore@v1:" + base64url(54-char body)` byte-identical to `foundation/pkg/mirrormark` |
| `internal/manifest/` | R150 PARALLEL-MAP-R144-REVIEW-METADATA | 6-field envelope (5-field R150.D + R150.E `ReviewedByCounsel`), 9-path `IsStale`, 12-entry seed |
| `internal/honest/` | R143 LOUD-ONCE + R143.A 3-tier ladder | 5 BR6-required advisories (2 Error + 3 Warn) |

## R175 LOAD-BEARING-IN-PRODUCTION (from inception)

All 4 R175 criteria satisfied at inception:

1. **Production emit-path** — `internal/audit-ledger/ledger.go` calls `marker.Sign()` for every verdict + every XML emission (the CLI `riio-check` + `entsoe-emit` both write through `Append`).
2. **Cold-verify path** — OpenSSL one-liner reproduces `239a7d0d…` against canonical `0x01 || 32×0x00` with empty key.
3. **Boot-time R143 LOUD-ONCE-WARN** — `Ledger.BootCheck()` fires the `OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT` advisory once when the marker is placeholder-mode.
4. **KAT-1 hex pin** — `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca` byte-literal pinned in `internal/lore/kat1.go` + `internal/firewall/firewall_test.go` + `internal/lore/kat1_test.go`.

---

## CLI

```
ofgemwatch riio-check <dno-id>    # RIIO-CF verdict + Mirror-Mark stamped audit row
ofgemwatch riio-fleet             # Fleet-wide compliance summary
ofgemwatch riio-list              # List all canonical DNO IDs
ofgemwatch entsoe-emit <rpt-id>   # IEC 62325-451-3 XML emit + audit row
ofgemwatch manifest               # R150 manifest inventory (12 entries)
ofgemwatch honest                 # R143 advisories ofgemwatch declares
ofgemwatch kat1-verify            # R151 KAT-1 cohort byte-identity check
ofgemwatch ledger                 # Audit-ledger session snapshot
```

Boot fires the 5 BR6 R143 LOUD-ONCE advisories before every command — operators see the degraded-mode signals before any verdict is computed.

---

## Revenue Model

| Tier | Target | ACV |
|---|---|---|
| **DNO Operations** | UK Distribution Network Operators (6 named: WPD / UKPN / NPG / SSEN / ENWL / SPEN) | £180k-360k |
| **Regulator** | Ofgem (price-control verification), CMA (appeals), ENTSO-E Market Monitoring Forum | £480k-720k |
| **Transmission** | National Grid ESO + Scottish Power Transmission + Scottish Hydro Electric Transmission | £240k-480k |
| **Cross-Atlantic (Phase 3)** | FERC Order 1000 cross-Atlantic harmonization consumers | TBD post-counsel-review |

**Y1 revenue target:** $800k (BR6 rank #4 of overnight-3 cohort).

---

## R143 Advisories (5 fired at boot)

| Code | Severity |
|---|---|
| `OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE` | Error |
| `OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER` | Error |
| `OFGEMWATCH_FERC_ORDER_1000_SCOPE_DEFERRED` | Warn |
| `OFGEMWATCH_REPORTING_CADENCE_MONTHLY_REQUIRED` | Warn |
| `OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE` | Warn |

Plus an audit-ledger-specific 6th:

| Code | Severity |
|---|---|
| `OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT` | Error |

---

## Build / Test

```sh
cd flagships/ofgemwatch
go test ./...
go run ./cmd/ofgemwatch riio-check WPD-WMID
go run ./cmd/ofgemwatch entsoe-emit RPT-2026-Q3-001
```

Pure-stdlib Go 1.22; `TestFirewall_NoExternalDeps` pins zero `go.mod` requires.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Byte-clone with the canonical Apache-2.0 license (md5 `1870f68b015802092d5a94bd7bf0d0f5`, 11,504 bytes, copyright "David Carson, 2026"). Cohort siblings include the broader L43 + R151 Go-cohort (memoria, gridlock, gambit, gaia, garnet, etc).
