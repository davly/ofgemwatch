# ofgemwatch — ARCHITECTURE

## Substrate shape

Pure Go 1.22 + stdlib. Pinned by `internal/firewall/TestFirewall_NoExternalDeps`. No external `require` block in `go.mod`. No `go.sum`. Every byte is auditable by reading stdlib + repo source only.

## Package layout

```
ofgemwatch/
├── cmd/ofgemwatch/main.go        # CLI entry point — wires all 5 cohort packages + 3 domain packages
├── internal/
│   ├── audit-ledger/              # R175 production emit-path (load-bearing)
│   │   ├── ledger.go              #   Ledger.Append(row) → MarkedRow + BootCheck()
│   │   └── ledger_test.go
│   ├── entso-e/                   # Phase-1 IEC 62325-451-3 XML producer
│   │   ├── entsoe.go              #   Emit(reportID, area, zone, start, end) → MarketReport
│   │   └── entsoe_test.go
│   ├── firewall/                  # R145.C FIREWALL-TEST-DISCIPLINE (test-only)
│   │   └── firewall_test.go
│   ├── honest/                    # R143 + R143.A 5-advisory shape
│   │   ├── honest.go              #   LoudOnce, Advisory, Severity 3-tier
│   │   └── honest_test.go
│   ├── lore/                      # R151 KAT-1 cohort pin
│   │   ├── kat1.go                #   KAT1Digest, AssertKAT1Parity, ComputeKAT1, VerifyKAT1
│   │   └── kat1_test.go
│   ├── manifest/                  # R150 schematised-knowledge envelope
│   │   ├── manifest.go            #   Entry struct, IsStale 9-path, Manifest API
│   │   ├── manifest_test.go
│   │   └── seed.go                #   12 inception entries
│   ├── mirrormark/                # L43 Mirror-Mark v1 signer
│   │   ├── marker.go              #   StdlibMarker, Sign(), Verify(), placeholder mode
│   │   └── marker_test.go
│   └── ofgem-riio/                # Phase-1 RIIO-CF compliance verifier
│       ├── riio.go                #   DNO.Verdict(), 6-DNO canonical corpus
│       └── riio_test.go
├── ARCHITECTURE.md
├── CONTEXT.md
├── LICENSE                        # Apache-2.0 byte-clone (md5 1870f68b…)
├── README.md
├── SECURITY.md
├── docs/
└── go.mod                         # stdlib-only (no `require`)
```

## Data flow

```
CLI (cmd/ofgemwatch/main.go)
  │
  ├── advisoriesAtBoot() — fires 5 BR6 LOUD-ONCE advisories
  ├── newScaffoldLedger() — placeholder Marker + BootCheck (fires 6th advisory if placeholder)
  │
  ├── riio-check <dno-id>
  │     ofgemriio.FindByID(dnoID) ──► DNO.Verdict() ──► CanonicalRow ──► Ledger.Append() ──► MarkedRow
  │                                                                       │
  │                                                                       ▼
  │                                                            mirrormark.Sign(canonicalBytes)
  │                                                                       │
  │                                                                       ▼
  │                                                            "lore@v1:" + base64url(40-byte body)
  │
  ├── entsoe-emit <rpt-id>
  │     entsoe.Emit(...) ──► MarketReport ──► entsoe.Marshal() ──► XML bytes
  │                                                                       │
  │                                                                       ▼
  │                                                            auditledger.NewENTSOERow + Ledger.Append()
  │
  ├── manifest ──► manifest.Seed() — 12 entries with R150.E ReviewedByCounsel field
  ├── honest ──► honest.CanonicalAdvisories() — 5 BR6 advisories
  └── kat1-verify ──► lore.AssertKAT1Parity()
```

## Phase 1 — Scaffold (BR6 inception, 2026-05-27)

Goals:

- 5 dedicated cohort-discipline packages from inception (R174 5/5)
- Mirror-Mark stamped audit ledger as the load-bearing production emit-path (R175 4/4)
- 6-DNO canonical RIIO-CF compliance corpus (canned fixtures)
- IEC 62325-451-3 XML producer with placeholder payload (schema-syntactically valid)
- 5 BR6 R143 LOUD-ONCE advisories fired at boot
- 12 R150 manifest entries (5 Ofgem RIIO + 4 ENTSO-E + 3 FERC-deferred)

Non-goals:

- Live Ofgem feed integration (deferred Phase 2)
- Live ENTSO-E API integration (deferred Phase 2)
- Durable audit ledger storage (deferred Phase 2)
- Monthly cadence ingestion (deferred Phase 2)
- FERC Order 1000 cross-Atlantic harmonization (deferred Phase 3)
- Qualified-counsel signoff per R150.E (deferred Phase 3)

## Phase 2 — Live data + durable ledger (deferred)

Adds:

- Live Ofgem RIIO-2 D2 feed integration (monthly cadence)
- Live ENTSO-E transparency-platform API integration
- Durable audit ledger (Postgres-backed append-only or filesystem-backed append-only)
- HTTP daemon mode for regulator-pull-based row delivery

R145.B branch posture: live-feed integration adds `net/http` client + `database/sql` deps; each lands on its own branch with the firewall test pin shifted via R145.B paired regression.

## Phase 3 — Cross-Atlantic harmonization (deferred)

Adds:

- FERC Order 1000 (18 CFR § 35.34) transmission-planning compliance checks
- Cross-Atlantic harmonization framework between Ofgem RIIO + FERC Order 1000
- Qualified-counsel review pass against all manifest entries (R150.E `ReviewedByCounsel: true` for blessed entries)
- US-FERC counsel + UK energy regulatory barrister reviewer-class signoff

## R145.C firewall mode

Distributed-firewall per R145.C compliance modes. The umbrella firewall lives at `internal/firewall/firewall_test.go` (single dedicated package) and pins:

- Substrate-boundary invariants (no HTTP listener/client, no DB, no env-vars, no auth, no money)
- R174 5-of-5 on-disk package layout
- R175 KAT-1 hex byte-literal
- L43 wire-form constants (`MarkPrefix = "lore@v1:"`, `MarkBodyLen = 40`)
- R143.A 3-tier severity ladder ordinal pins
- R150 manifest schema-version + seed-size
- R150.E `ReviewedByCounsel=false` at scaffold
- Domain forge invariants (RIIO Verdict closed set, 15% tolerance band, 6-DNO corpus)

## R150.E ReviewedByCounsel extension

Manifest `Entry` struct includes `ReviewedByCounsel: bool` field. Phase-1 entries default to `false`; Phase-3 deliverable promotes selected entries to `true` after UK energy regulatory barrister + US FERC counsel review. `IsStale` returns `true` for `ClassFERCOrder1000` entries whose `ReviewedByCounsel == false`.
