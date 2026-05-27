# ofgemwatch — CONTEXT

## Substrate

Pure Go 1.22 + stdlib. Zero `go.mod` requires. Pinned by `internal/firewall/TestFirewall_NoExternalDeps`.

## Inception

BR6 marathon 2026-05-27 — new flagship rank #4 from overnight-3 ($800k Y1 target).

## R174 5-of-5 cohort maturity from inception

5 dedicated cohort-discipline packages plus 3 domain packages:

```
internal/
├── audit-ledger/        # R175 production emit-path (load-bearing)
├── entso-e/             # Phase-1 IEC 62325-451-3 XML producer
├── firewall/            # R145.C FIREWALL-TEST-DISCIPLINE
├── honest/              # R143 + R143.A 5-advisory shape
├── lore/                # R151 KAT-1 cohort pin
├── manifest/            # R150 schematised-knowledge + R150.E ReviewedByCounsel
├── mirrormark/          # L43 Mirror-Mark v1 signer
└── ofgem-riio/          # Phase-1 RIIO-CF compliance verifier
```

## R175 load-bearing posture

Every regulator-grade output crosses `internal/audit-ledger/Append()`. The CLI `riio-check` and `entsoe-emit` both write through `Append`. `BootCheck()` fires the `OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT` advisory at process boot if the marker is placeholder-mode.

`grep -rEn "marker\.Sign|signMark" internal/audit-ledger/` returns ≥1 match in non-test code (criterion-1 satisfied).

## Phase boundaries

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Scaffold; canned RIIO corpus (6 DNOs); IEC 62325-451-3 XML producer with placeholder payload; Mirror-Mark stamped in-memory audit ledger | SHIPPED (BR6 inception) |
| Phase 2 | Live Ofgem data feed; monthly RIIO-2 D2 (Determinations) data; ENTSO-E API integration; durable audit ledger (Postgres/append-only file) | DEFERRED |
| Phase 3 | FERC Order 1000 (US RTO) cross-Atlantic harmonization; qualified-counsel signoff per R150.E `ReviewedByCounsel` flag; counsel-blessed regulatory outputs | DEFERRED |

## Regulator boundaries

Ofgemwatch is a Phase-1 SCAFFOLD. The 5 BR6 R143 advisories surface degraded-mode signals at boot:

1. `OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE` (Error) — no live Ofgem feed
2. `OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER` (Error) — placeholder XML payload
3. `OFGEMWATCH_FERC_ORDER_1000_SCOPE_DEFERRED` (Warn) — FERC out of Phase 1+2 scope
4. `OFGEMWATCH_REPORTING_CADENCE_MONTHLY_REQUIRED` (Warn) — annual cadence only
5. `OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE` (Warn) — no UK barrister / US FERC counsel review

## Cohort posture

| R-rule | Posture |
|---|---|
| R143 + R143.A | 5 advisories (2 Error + 3 Warn) per BR6 procedure |
| R145.C | dedicated `internal/firewall/firewall_test.go` per R145.C compliance modes |
| R150 + R150.D + R150.E | 6-field manifest envelope, 9-path `IsStale`, 12-entry seed, `ReviewedByCounsel=false` for all Phase-1 entries |
| R151 | KAT-1 `239a7d0d…` pinned at 3 sites (lore + lore_test + firewall) |
| R155 | Verdict on inception ships paired commit SHAs in BR6 impl log |
| R155.A sub-class 8 | `AssertKAT1Parity()` exported helper grep-verifiable |
| R166 | LICENSE byte-clone (Apache-2.0 1870f68b…) + `OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE` advisory |
| R174 | 5/5 maturity strict from inception |
| R175 | 4/4 load-bearing-in-production from inception |

## How regulator cold-verifies a row

Given a `MarkedRow` carried over a trust boundary:

```sh
# 1. Recompute canonical bytes (JSON of CanonicalRow in canonical key order).
# 2. Reproduce the Mirror-Mark via:
openssl dgst -sha256 -mac hmac -macopt key:<production-key-hex> <canonical-bytes>
# 3. Encode as: "lore@v1:" + base64url(corpusSHA[:8] || hmac-digest)
# 4. Byte-equal against carried mark.
```

The regulator does NOT need any Limitless toolchain. Property is bedded in FIPS PUB 180-4 + RFC 2104 + RFC 4648.

KAT-1 anchor (independent of any host data):

```sh
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
# → 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```
