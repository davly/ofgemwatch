// Package honest — R143 LOUD-ONCE-WARNING-FLAG + R143.A severity-
// ladder seed for ofgemwatch.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship). Pure-
// stdlib; zero deps. Surfaces ofgemwatch's honest-defaults discipline
// as cohort-aligned R143 LOUD-ONCE-WARN advisories at the canonical
// 3-tier severity ladder (Error + Warn + Info) per R143.A.
//
// R143 LOUD-ONCE-WARNING-FLAG promotion (godfather memory 2026-05-11,
// 4/3 saturation): the canonical cohort shape for surfacing degraded-
// mode operation. The literal `[LOUD-ONCE-WARNING]` prefix is the
// cohort-grep contract — every emit across the ecosystem starts with
// it so a single grep across logs surfaces every degraded-mode
// instance.
//
// R143.A SEVERITY-LADDER-CONVENTION (godfather 2026-05-26 overnight,
// `01056ed`): closed 3-tier (Error / Warn / Info) ladder. Drift on
// any rung requires R145.B branching.
//
// ofgemwatch-specific advisories (5 per BR6 procedure):
//
//	OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE (Error) —
//	    the Ofgem RIIO ED2 price-control compliance gate has not
//	    yet been wired to a live Ofgem data feed. Production
//	    callers consuming RIIO-CF (Cost-Forecast) verdicts today
//	    get scaffold-stub responses, NOT live regulator data.
//	    Refuse to ship regulator-load-bearing decisions on
//	    placeholder data.
//
//	OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER (Error) —
//	    the ENTSO-E transparency-platform XML producer is stubbed
//	    against canned fixtures. Emitted XML conforms to the
//	    ENTSO-E IEC 62325-451-3 schema syntactically but the
//	    payload values are placeholder. Do NOT submit to the
//	    real ENTSO-E platform.
//
//	OFGEMWATCH_FERC_ORDER_1000_SCOPE_DEFERRED (Warn) — FERC Order
//	    1000 (US RTO transmission planning) is OUT OF SCOPE for
//	    Phase 1. Cross-Atlantic harmonization (Ofgem RIIO ↔ FERC
//	    Order 1000) is a Phase 3 deliverable. Surfacing this so
//	    operators don't assume silent absence-of-FERC-coverage
//	    means FERC-covered.
//
//	OFGEMWATCH_REPORTING_CADENCE_MONTHLY_REQUIRED (Warn) — Ofgem
//	    RIIO ED2 reporting cadence is MONTHLY at the per-DNO
//	    granularity. The current scaffold ingests at annual
//	    cadence only; monthly RIIO-2 D2 (Determinations) data is
//	    not yet plumbed. Production deployments depending on
//	    monthly granularity MUST wire the upstream feed.
//
//	OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE (Warn) — the
//	    regulatory-classification surface (Ofgem RIIO + ENTSO-E +
//	    deferred FERC) is software-generated from public Ofgem
//	    methodology + ENTSO-E Network Code documents. It has NOT
//	    been reviewed by a UK-qualified energy regulatory
//	    barrister + a US-qualified FERC counsel (Phase-3
//	    deliverable per R166-LIABILITY-FOOTER-CONST). Do NOT
//	    rely on ofgemwatch outputs for legal-binding regulatory
//	    submissions without paired counsel review.
//
// Cross-substrate parity: byte-aligned `[LOUD-ONCE-WARNING]` prefix
// + Code + Severity + Message + DocLink shape with the cohort
// canonical (memoria / gridlock / atelier / canvas / paradox /
// forge-central R143 emitters).
package honest

import (
	"io"
	"log"
	"os"
	"sync"
)

// LoudOncePrefix is the cohort-canonical prefix every advisory emit
// starts with. Pinned byte-identically across the R143 cohort.
const LoudOncePrefix = "[LOUD-ONCE-WARNING]"

// Severity is the closed-set severity label for advisories. Closed
// 3-tier enum per R143.A SEVERITY-LADDER-CONVENTION.
type Severity int

const (
	// SeverityInfo — informational only (e.g. architectural-gate
	// triggered as designed; surfaces presence not absence).
	SeverityInfo Severity = iota

	// SeverityWarn — degraded mode active (e.g. cadence misaligned,
	// reviewer-class signoff pending). Production callers may still
	// proceed but should know.
	SeverityWarn

	// SeverityError — load-bearing invariant at risk (e.g. live
	// regulator feed not wired; placeholder data being treated as
	// authoritative). Production callers SHOULD refuse to proceed.
	SeverityError
)

// String returns the canonical name for a Severity.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	}
	return "unknown"
}

// Advisory is the cohort-canonical R143 advisory shape.
type Advisory struct {
	// Code is the canonical machine-grep identifier (e.g.
	// OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE). MUST be
	// non-empty + stable across releases (downstream grep depends
	// on it).
	Code string

	// Severity is the closed-set severity tier for this advisory.
	Severity Severity

	// Message is the human-readable explanation of the degraded
	// mode or architectural gate. Forensic-readability aid; the
	// Code is the grep contract.
	Message string

	// DocLink is the canonical docs path explaining the advisory
	// in detail. SHOULD point at ARCHITECTURE.md or CONTEXT.md
	// or SECURITY.md.
	DocLink string
}

// String returns the canonical multi-line representation of an
// Advisory suitable for log output. Includes the LoudOncePrefix.
func (a Advisory) String() string {
	return LoudOncePrefix + " ofgemwatch: " + a.Code + " (" + a.Severity.String() + ") — " + a.Message + " [see " + a.DocLink + "]"
}

// loudOnceState tracks which Codes have already been emitted; per
// godfather R143 canonical shape, each advisory emits exactly ONCE
// per process lifetime.
type loudOnceState struct {
	mu   sync.Mutex
	seen map[string]bool
}

var defaultState = &loudOnceState{seen: make(map[string]bool)}

// LoudOnce emits Advisory.String() to w iff this Code has not been
// emitted before in this process. Subsequent calls with the same
// Code are silent.
//
// Distinct Codes emit independently. Process-global state
// (sync.Mutex-guarded map); call site is goroutine-safe.
//
// Returns true iff the advisory was actually emitted (i.e. first
// time this Code surfaced).
func LoudOnce(adv Advisory, w io.Writer) bool {
	if adv.Code == "" {
		// Refuse to emit advisories with empty Code — grep contract
		// requires the Code be stable. An empty Code violates the
		// cohort grep contract.
		return false
	}
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	if defaultState.seen[adv.Code] {
		return false
	}
	defaultState.seen[adv.Code] = true
	if w == nil {
		w = os.Stderr
	}
	_, _ = io.WriteString(w, adv.String()+"\n")
	return true
}

// LoudOnceLog is the convenience entry point routing to log.Default()
// rather than a caller-provided writer. Most production callers use
// this; tests use LoudOnce with a captured buffer.
func LoudOnceLog(adv Advisory) bool {
	if adv.Code == "" {
		return false
	}
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	if defaultState.seen[adv.Code] {
		return false
	}
	defaultState.seen[adv.Code] = true
	log.Print(adv.String())
	return true
}

// Reset clears the process-global emit state. Intended for tests
// that need to re-test the first-time-emit path; production code
// MUST NOT call this (would re-emit every advisory on next call).
func Reset() {
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	defaultState.seen = make(map[string]bool)
}

// CanonicalAdvisories returns the canonical ofgemwatch-specific
// advisories. Used by tests + diagnostic / readiness handlers to
// enumerate all known degraded-mode signals.
//
// Order matches the BR6 procedure declaration order: 2 Error then
// 3 Warn (Info reserved for future Phase-2+ informational gates).
// R143.A SEVERITY-LADDER coverage today: 2 Error + 3 Warn + 0 Info.
func CanonicalAdvisories() []Advisory {
	return []Advisory{
		{
			Code:     "OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE",
			Severity: SeverityError,
			Message:  "Ofgem RIIO ED2 price-control compliance gate is NOT wired to a live Ofgem data feed. Production RIIO-CF (Cost-Forecast) verdicts come from scaffold-stub fixtures, NOT live regulator data. Refuse to ship regulator-load-bearing decisions on placeholder data.",
			DocLink:  "ARCHITECTURE.md §Phase 1 — Ofgem RIIO scaffold + CONTEXT.md §Live-data wiring",
		},
		{
			Code:     "OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER",
			Severity: SeverityError,
			Message:  "ENTSO-E transparency-platform XML producer emits placeholder-payload XML against the IEC 62325-451-3 schema. Schema validation passes but values are NOT derived from live ENTSO-E data. Do NOT submit emitted XML to the real ENTSO-E transparency platform.",
			DocLink:  "ARCHITECTURE.md §Phase 2 — ENTSO-E XML producer + SECURITY.md §Patterns intentionally absent",
		},
		{
			Code:     "OFGEMWATCH_FERC_ORDER_1000_SCOPE_DEFERRED",
			Severity: SeverityWarn,
			Message:  "FERC Order 1000 (US RTO transmission planning, 18 CFR § 35.34) is OUT OF SCOPE for Phase 1 + Phase 2. Cross-Atlantic harmonization (Ofgem RIIO ↔ FERC Order 1000) is a Phase 3 deliverable. Surfacing so operators don't assume silent absence-of-FERC-coverage means FERC-covered.",
			DocLink:  "ARCHITECTURE.md §Phase 3 — Cross-Atlantic harmonization (deferred)",
		},
		{
			Code:     "OFGEMWATCH_REPORTING_CADENCE_MONTHLY_REQUIRED",
			Severity: SeverityWarn,
			Message:  "Ofgem RIIO ED2 reporting cadence is MONTHLY at per-DNO (Distribution Network Operator) granularity per RIIO-2 Annual Reporting Pack guidance. Current scaffold ingests annually only; monthly RIIO-2 D2 (Determinations) data is not yet plumbed. Production deployments depending on monthly granularity MUST wire the upstream feed.",
			DocLink:  "ARCHITECTURE.md §RIIO cadence + CONTEXT.md §Reporting cadence",
		},
		{
			Code:     "OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE",
			Severity: SeverityWarn,
			Message:  "Regulatory-classification surface (Ofgem RIIO + ENTSO-E + deferred FERC) is software-generated from public Ofgem methodology + ENTSO-E Network Code documents. NOT reviewed by UK-qualified energy regulatory barrister + US-qualified FERC counsel. Do NOT rely on ofgemwatch outputs for legal-binding regulatory submissions without paired counsel review.",
			DocLink:  "SECURITY.md §Reviewer-class signoff + manifest entry REVIEWED_BY_COUNSEL",
		},
	}
}
