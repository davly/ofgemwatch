// Package mirrormark — L43 Mirror-Mark v1 seed for ofgemwatch.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship). Pure-
// stdlib (`crypto/hmac` + `crypto/sha256` + `encoding/base64`); zero
// external deps. Byte-identical algorithm to
// `foundation/pkg/mirrormark` and to the ~34-substrate-language
// Mirror-Mark v1 cohort.
//
// Cohort role: ofgemwatch stamps Mirror-Mark receipts onto audit-
// ledger rows so any downstream regulator (Ofgem RIIO ED2 price-
// control auditor, ENTSO-E transparency-platform consumer, future
// FERC Order 1000 sidecar) can verify-not-inherit: regenerate the
// canonical wire form of an audit row + compute the mark + match
// against the carried signature. Tampered rows surface immediately;
// load-bearing for the architectural invariant that ofgemwatch's
// regulatory-reporting output is provenance-anchored.
//
// Wire-in posture (R175 LOAD-BEARING-IN-PRODUCTION + R176 LIBRARY-
// FIRST-WIRE-LATER):
//
//   - Library shipped FROM INCEPTION (this package + tests + KAT
//     pin in `internal/lore/`).
//   - Production wire-in is in `internal/audit-ledger/` — every
//     emitted row is stamped via Sign(). The boot-time R143
//     LOUD-ONCE-WARN advisory fires once if the marker is in
//     placeholder mode (no production key configured).
//   - Phase-2 ENTSO-E XML publishing + Phase-3 FERC Order 1000
//     sidecar will reuse the same Marker interface — no second
//     copy.
//
// Cross-substrate parity: byte-identical algorithm to every cohort
// port. The mark format is:
//
//	"lore@v1:" + base64url( corpusSHA[:8] || hmacSHA256(0x01 || corpusSHA || payload, key) )
//
// Ofgemwatch does NOT import `foundation/pkg/mirrormark` directly
// because (a) ofgemwatch's go.mod is stdlib-only (`TestFirewall_
// NoExternalDeps` pin in `internal/firewall/`) and (b) the package
// shape is small enough to ship locally and consume foundation later
// via R145-strict additive replacement. The N-of-N byte-identical
// implementation IS the cohort firewall — foundation extraction
// migrates ofgemwatch in a future sweep.
//
// Mirror-Mark v1 derivation recipe — see KAT-1 anchor in
// `internal/lore/kat1.go` for the OpenSSL cold-verify gate that holds
// independently of any cohort toolchain.
package mirrormark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"sync"
)

// markVersion is the 1-byte tag prefixing the HMAC input. Bumping
// this byte invalidates every mark in flight — necessary if the
// canonicalization rule ever changes.
//
// v1 = 0x01. Do not silently change without a migration plan.
// Byte-identical to foundation/pkg/mirrormark.markVersion.
const markVersion byte = 0x01

// MarkPrefix is the documented header-value prefix that lets a
// downstream reader (regulator portal, partner ops) identify a v1
// Mirror-Mark and reject unknown versions. Byte-identical to every
// cohort port.
const MarkPrefix = "lore@v1:"

// MarkCorpusPrefixLen is the corpus-SHA prefix length embedded in
// the mark body. Exposed as a constant so a non-Limitless
// re-implementation of Verify can be byte-compatible.
const MarkCorpusPrefixLen = 8

// MarkBodyLen is the unencoded length of the mark body (corpus prefix
// + HMAC digest). Encoded with base64.RawURLEncoding it becomes the
// fixed 54-character suffix after MarkPrefix.
const MarkBodyLen = MarkCorpusPrefixLen + sha256.Size

// ErrEmptyKey is returned when constructing a Marker with a zero-byte
// key. Empty-key fail-closed: ofgemwatch refuses to emit marks with
// an empty key under production discipline.
var ErrEmptyKey = errors.New("mirrormark: HMAC key MUST be at least 1 byte")

// ErrInvalidCorpusLength is returned when constructing a Marker with
// a corpus SHA of the wrong length (must be exactly 32 bytes).
var ErrInvalidCorpusLength = errors.New("mirrormark: corpus SHA MUST be exactly 32 bytes (sha256.Size)")

// ErrMarkerNotConfigured is returned when Verify is called against a
// Marker that has no production key configured (e.g. placeholder-only).
// Useful in regulator-pre-flight to refuse marks from un-configured
// instances.
var ErrMarkerNotConfigured = errors.New("mirrormark: marker not configured for verification — placeholder mode")

// ErrMarkMismatch is returned when Verify fails because the
// recomputed HMAC does not match the carried signature. Carries no
// hint about which byte diverged (preventing oracle attacks against
// downstream tampering).
var ErrMarkMismatch = errors.New("mirrormark: mark/verify mismatch — payload tampered or wrong key")

// Marker is the cohort-canonical signing interface. Implementations
// MUST be goroutine-safe and MUST produce byte-identical output for
// the same (corpusSHA, payload, key) triple across all ~34 substrate
// languages in the cohort.
type Marker interface {
	// Sign returns the canonical 62-char Mirror-Mark string for
	// payload. Output is deterministic: identical inputs → identical
	// bytes.
	Sign(payload []byte) string
}

// StdlibMarker is the ofgemwatch-resident pure-stdlib Marker
// implementation. Goroutine-safe: corpusSHA + key are immutable once
// constructed.
//
// Byte-identical algorithm to foundation/pkg/mirrormark.StdlibMarker
// and to every cohort port.
type StdlibMarker struct {
	corpusSHA [sha256.Size]byte
	key       []byte

	// usingPlaceholder tags whether the marker was constructed with
	// sentinel placeholder values rather than real production inputs.
	// Surfaced via UsingPlaceholder for readiness probes; never gates
	// Sign emission (a placeholder mark is still syntactically valid).
	usingPlaceholder bool

	// warnedOnce is the R143 LOUD-ONCE-WARN-FLAG. Fires the first
	// time Sign is called on a placeholder-mode marker, then never
	// again for the lifetime of this StdlibMarker.
	warnedOnce sync.Once
}

// NewStdlibMarker constructs a StdlibMarker from explicit (corpusSHA,
// key). Returns an error if key is empty.
func NewStdlibMarker(corpusSHA [sha256.Size]byte, key []byte) (*StdlibMarker, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	keyCopy := append([]byte(nil), key...)
	return &StdlibMarker{corpusSHA: corpusSHA, key: keyCopy}, nil
}

// NewPlaceholderMarker constructs a StdlibMarker tagged as placeholder-
// mode. The marker emits syntactically valid marks but the first Sign
// call emits an R143 LOUD-ONCE-WARN log entry; downstream consumers
// can refuse placeholder marks via UsingPlaceholder().
//
// Used in tests + Phase 0-2 scaffolding before production key
// management is wired into Ofgem RIIO + ENTSO-E pipelines.
func NewPlaceholderMarker() *StdlibMarker {
	var zeroSHA [sha256.Size]byte
	return &StdlibMarker{
		corpusSHA:        zeroSHA,
		key:              []byte("ofgemwatch-placeholder-key-DO-NOT-USE-IN-PRODUCTION"),
		usingPlaceholder: true,
	}
}

// UsingPlaceholder reports whether this marker was constructed in
// placeholder mode. A readiness handler can surface this so a
// regulator pre-flight check can refuse to consume marks from a
// placeholder-mode instance.
func (m *StdlibMarker) UsingPlaceholder() bool {
	return m.usingPlaceholder
}

// CorpusSHA returns a copy of the corpus SHA-256 configured on this
// marker. Exposed for diagnostic endpoints; the returned array is a
// copy so the caller cannot mutate marker state.
func (m *StdlibMarker) CorpusSHA() [sha256.Size]byte {
	return m.corpusSHA
}

// Sign returns the canonical Mirror-Mark string for the payload.
// Implements the Marker interface.
//
// First Sign call on a placeholder-mode marker emits an R143
// LOUD-ONCE-WARN log entry. Subsequent calls are silent (per R143
// the warning is loud-once, not loud-forever).
func (m *StdlibMarker) Sign(payload []byte) string {
	if m.usingPlaceholder {
		m.warnedOnce.Do(func() {
			log.Printf("[LOUD-ONCE-WARNING] mirrormark: signing with placeholder key + zero corpus SHA; emitted marks will NOT pass cold-verify against a real lore corpus / production key — ofgemwatch/internal/mirrormark placeholder mode")
		})
	}
	return Sign(m.corpusSHA, payload, m.key)
}

// Verify returns nil iff signature is the canonical Mirror-Mark for
// payload under this marker's (corpusSHA, key). Constant-time compare
// via hmac.Equal to prevent timing leakage of which byte diverged.
//
// Returns ErrMarkMismatch on any drift; ErrMarkerNotConfigured if
// the marker is in placeholder mode (the regulator-cold-verify shape
// refuses placeholder marks at the verify boundary).
func (m *StdlibMarker) Verify(payload []byte, signature string) error {
	if m.usingPlaceholder {
		// Placeholder markers can SIGN (for scaffold/test) but MUST
		// NOT pass production VERIFY. This is the verify-not-inherit
		// shape: a regulator with this marker would reject the mark
		// out-of-hand.
		return ErrMarkerNotConfigured
	}
	want := Sign(m.corpusSHA, payload, m.key)
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return ErrMarkMismatch
	}
	return nil
}

// Sign is the package-level signer for callers that do not need a
// long-lived StdlibMarker instance. Pure: no runtime state; safe to
// call from a regulator binary holding only (corpusSHA, payload, key).
//
// Mark format:
//
//	"lore@v1:" + base64url( corpusSHA[:8] || hmacSHA256(0x01 || corpusSHA || payload, key) )
//
// Pure stdlib; minimal heap allocation. Byte-identical to
// foundation/pkg/mirrormark.Sign and every cohort port.
func Sign(corpusSHA [sha256.Size]byte, payload []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte{markVersion})
	_, _ = mac.Write(corpusSHA[:])
	_, _ = mac.Write(payload)
	digest := mac.Sum(nil) // 32 bytes

	body := make([]byte, 0, MarkBodyLen)
	body = append(body, corpusSHA[:MarkCorpusPrefixLen]...)
	body = append(body, digest...)

	return MarkPrefix + base64.RawURLEncoding.EncodeToString(body)
}

// Verify is the package-level verifier — convenience for one-shot
// regulator-side use. Returns nil iff signature is the canonical mark
// for (corpusSHA, payload, key).
func Verify(corpusSHA [sha256.Size]byte, payload []byte, key []byte, signature string) error {
	if len(key) == 0 {
		return ErrEmptyKey
	}
	want := Sign(corpusSHA, payload, key)
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return ErrMarkMismatch
	}
	return nil
}
