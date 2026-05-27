// Package lore — R151 KAT-1 cross-substrate pin for ofgemwatch.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship). Pure-
// stdlib; zero deps. Pins the ecosystem-canonical HMAC-SHA256 KAT-1
// anchor as an ofgemwatch-resident constant + verification helper so
// the cohort cross-substrate parity gate holds at ofgemwatch's
// boundary FROM INCEPTION.
//
// R151 R-KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN promotion
// (godfather memory 2026-05-22 / 5/3 strict / 4 substrate languages;
// expanded ~34 substrate languages by 2026-05-27): the KAT-1
// HMAC-SHA256 hex `239a7d0d…` is the strongest single-claim moat
// artefact in the ecosystem (OpenSSL-reproducible).
//
// Cohort role: ofgemwatch is an energy-regulator-grade consumer. The
// KAT-1 vector is anchored here so any future ENTSO-E XML producer
// (Phase 2) or FERC Order 1000 sidecar (Phase 3) can reproduce
// byte-identical HMAC-SHA256 against the same canonical input
// (0x01 || 32×0x00) with the same empty key.
//
// Why ofgemwatch specifically: ofgemwatch emits regulatory-grade
// audit-ledger rows that cross trust boundaries into Ofgem RIIO ED2
// price-control compliance pipelines + ENTSO-E transparency-platform
// publication queues. A regulator with the corpus SHA + audit key
// must be able to cold-verify a row's Mirror-Mark independently of
// the host filesystem — the KAT-1 anchor is the cohort-canonical
// proof that the HMAC-SHA256 primitive is byte-identical across
// every substrate that will ever consume an ofgemwatch row.
//
// Reproducibility recipe (OpenSSL — no Go toolchain involved):
//
//	# KAT-1 input: 0x01 || 32×0x00 (33 bytes); HMAC key: empty
//	printf '\x01' > /tmp/kat1.bin
//	printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
//	openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
//	# → HMAC-SHA256(stdin) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
//
// The constant is pinned as the regulator-evidence gate: a regulator
// with `openssl dgst` and this hex string can reproduce the digest
// from canonical inputs WITHOUT any Limitless toolchain. The property
// is bedded in FIPS PUB 180-4 + RFC 2104 + RFC 4648 — not in
// ofgemwatch source.
package lore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// KAT1Digest is the cohort-canonical L43 Mirror-Mark v1 KAT-1
// HMAC-SHA256 digest, hex-encoded. Byte-identical to the value pinned
// across ~34 substrate languages in the cohort.
//
// Drift on this literal breaks the cohort. The OpenSSL reproducibility
// recipe in this package's doc-comment provides the regulator-grade
// cold-verify gate that holds independently of any cohort toolchain.
const KAT1Digest = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// KAT1InputFirstByte is the canonical first byte of the KAT-1 input.
// The full canonical input is: KAT1InputFirstByte || 32 zero bytes.
const KAT1InputFirstByte byte = 0x01

// KAT1InputZeroPadLen is the canonical zero-pad length following the
// first-byte tag. Total input length = 1 + KAT1InputZeroPadLen = 33.
const KAT1InputZeroPadLen = 32

// KAT1Input returns a freshly-allocated copy of the canonical KAT-1
// input bytes: 0x01 || 32×0x00 (33 bytes total). Callers can mutate
// the returned slice without affecting future calls.
//
// This is the input fed to HMAC-SHA256 (with empty key) to produce
// KAT1Digest. The function is pure — no state, no I/O.
func KAT1Input() []byte {
	out := make([]byte, 1+KAT1InputZeroPadLen)
	out[0] = KAT1InputFirstByte
	// zero-pad already implicit from make()
	return out
}

// ComputeKAT1 returns the HMAC-SHA256-hex of the canonical KAT-1
// input with the empty HMAC key. Returns a lowercase 64-char hex
// string that MUST equal KAT1Digest under all conditions.
//
// Pure-stdlib (`crypto/hmac` + `crypto/sha256`). Determinism is bedded
// in FIPS PUB 180-4 + RFC 2104; the result is byte-identical to the
// OpenSSL recipe in the package doc-comment.
func ComputeKAT1() string {
	mac := hmac.New(sha256.New, []byte{}) // empty key per KAT-1 canonical
	mac.Write(KAT1Input())
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyKAT1 returns nil iff ComputeKAT1() byte-matches KAT1Digest.
// Returns KATMismatchError with both values logged for the (extremely
// unlikely) case that the canonical inputs drift in a future build.
//
// Use this in regulator-pre-flight / readiness probes / audit-ledger
// emit gates that want to surface KAT-1 cross-substrate parity as a
// check.
func VerifyKAT1() error {
	got := ComputeKAT1()
	if got != KAT1Digest {
		return &KATMismatchError{
			Vector:   "KAT-1",
			Computed: got,
			Expected: KAT1Digest,
		}
	}
	return nil
}

// AssertKAT1Parity is the cohort-canonical exported helper that
// satisfies R155.A sub-class 8 VERDICT-OVERCLAIMS-WIRE-SHIP. Returns
// nil on cohort byte-identity; an error on any deviation. Callable
// from a host integration bootstrap to fail loud if a future edit
// silently drifts KAT-1.
//
// Cohort-canonical shape — byte-identical re-derivation to every
// cohort port (foundation/pkg/mirrormark / grove / greenwatch /
// gambit / etc).
func AssertKAT1Parity() error {
	return VerifyKAT1()
}

// KATMismatchError is returned when a canonical KAT vector fails to
// reproduce its expected digest. Surfaces both computed + expected
// values so a forensic operator can diagnose the drift without
// re-running the recipe.
type KATMismatchError struct {
	Vector   string // "KAT-1" etc.
	Computed string // what we got
	Expected string // what the cohort pinned
}

func (e *KATMismatchError) Error() string {
	return "ofgemwatch/lore: " + e.Vector + " mismatch — computed=" + e.Computed + " expected=" + e.Expected + " (cohort-canonical regulator-evidence gate broken)"
}
