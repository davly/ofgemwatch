// Package manifest — R150 PARALLEL-MAP-R144-REVIEW-METADATA register
// for ofgemwatch's curated regulatory-classification surface.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship). Pure-
// stdlib; zero deps. Ships the canonical 5-field schematised-knowledge
// envelope (FreshAt / Source / IsStale / SchemaVersion / Confidence)
// over ofgemwatch's existing curated content surfaces (Ofgem RIIO
// price-control sources + ENTSO-E Network Code references + deferred
// FERC Order 1000 documents). Honest-TODO sentinels for the patterns
// where FreshAt is unknown today.
//
// R150 promotion (godfather memory 2026-05-22, R144 sub-class):
// Class 1 schematised-knowledge cohort saturated 11/3 across 12+
// instances. Ofgemwatch joins as an energy-regulator instance — the
// UK + EU regulator substrate with curated price-control + transparency
// references anchored to public Ofgem methodology + ENTSO-E Network
// Code documents.
//
// Canonical 5-field shape:
//
//	type Entry struct {
//	    Key                   string  // human + machine identifier
//	    Source                Source  // closed enum, NOT free-form
//	    FreshAt               time.Time  // when the upstream source was last verified
//	    SchemaVersion         int     // pinned at v1; bump on canonicalization rule change
//	    Confidence            Confidence  // closed 3-state: high / medium / honest_todo
//	    ReviewedByCounsel     bool    // R150.E reviewer-class extension (Phase-3 deliverable)
//	    Rationale             string  // forensic-readability note
//	}
//
// R150.E reviewer-class extension (godfather memory 2026-05-22): the
// 6-field shape composes R150.D (canonical 5-field) + R150.E
// (reviewer-class bool). ReviewedByCounsel: bool = false signals the
// Phase-3 deliverable shape — the regulatory-classification surface
// is software-generated from public Ofgem methodology + ENTSO-E
// Network Code text; the qualified-counsel signoff is the Phase-3
// deliverable per R166-LIABILITY-FOOTER-CONST.
//
// 9-path IsStale (per godfather R150 canonical shape):
//
//	IsStale returns true if FreshAt is the sentinel zero-time
//	(1970-01-01 honest-TODO) OR if maxAge is exceeded against now
//	OR if Source is SourceUnknownHonestTODO OR Confidence is
//	ConfidenceHonestTODO OR SchemaVersion drifted OR ReviewedByCounsel
//	is false for a counsel-required class (Phase-3).
//
// Ofgemwatch's curated content (inception inventory):
//   - 5 Ofgem RIIO references (RIIO-ED2 final determinations + RIIO-2
//     methodology + DNO licence conditions + CMA appeals + Ofgem
//     impact assessments)
//   - 4 ENTSO-E references (Network Code on Operational Security +
//     IEC 62325-451-3 transparency schema + ENTSO-E Market Report +
//     ENTSO-E Adequacy Outlook)
//   - 3 FERC Order 1000 references (deferred Phase-3 scaffolds — all
//     ReviewedByCounsel=false; ConfidenceHonestTODO until US-FERC
//     counsel reviews)
package manifest

import "time"

// SchemaVersion is the canonical schema version for ofgemwatch's
// Manifest entries. Pinned at v1 per godfather R150 canonical shape;
// bumping invalidates every entry — coordinate with cohort.
const SchemaVersion = 1

// SentinelHonestTODO is the canonical zero-time sentinel for entries
// whose FreshAt is unknown or pending. Per godfather R150 canonical
// shape: 1970-01-01 UTC = "honest-TODO — needs reviewer-class signoff".
var SentinelHonestTODO = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// Source is the closed-set source-of-truth enum for Manifest entries.
// NOT free-form text. Each value is a cohort-recognised provenance
// shape with documented evidence boundary.
type Source int

const (
	// SourceUnknownHonestTODO is the sentinel for entries whose source
	// has not yet been documented. IsStale always returns true for
	// SourceUnknownHonestTODO entries.
	SourceUnknownHonestTODO Source = iota

	// SourceOfgemMethodology — public Ofgem RIIO methodology documents
	// (final determinations + price-control models + DNO licence
	// conditions). Authoritative; canonical evidence boundary.
	SourceOfgemMethodology

	// SourceENTSOENetworkCode — public ENTSO-E Network Code documents
	// (Operational Security + Capacity Allocation + System Operation).
	// Authoritative under Regulation (EU) 2017/1485 + 2019/943.
	SourceENTSOENetworkCode

	// SourceENTSOETransparencyXSD — IEC 62325-451-3 transparency XML
	// schema definitions. Authoritative; pinned at the published XSD.
	SourceENTSOETransparencyXSD

	// SourceFERCOrder1000Pending — entry depends on Phase-3 FERC Order
	// 1000 deliverable. IsStale returns true until the Phase-3 wiring
	// + qualified-counsel review lands.
	SourceFERCOrder1000Pending

	// SourceCMAAppealsDB — public Competition and Markets Authority
	// (CMA) energy-sector appeals database. Used for cross-reference
	// against Ofgem decisions.
	SourceCMAAppealsDB

	// SourceECPaperOfgem — Ofgem Energy Code Paper / open-letter
	// publications. Secondary to SourceOfgemMethodology; useful for
	// historical context.
	SourceECPaperOfgem
)

// String returns the canonical name for a Source.
func (s Source) String() string {
	switch s {
	case SourceUnknownHonestTODO:
		return "unknown_honest_todo"
	case SourceOfgemMethodology:
		return "ofgem_methodology"
	case SourceENTSOENetworkCode:
		return "entsoe_network_code"
	case SourceENTSOETransparencyXSD:
		return "entsoe_transparency_xsd"
	case SourceFERCOrder1000Pending:
		return "ferc_order_1000_pending"
	case SourceCMAAppealsDB:
		return "cma_appeals_db"
	case SourceECPaperOfgem:
		return "ec_paper_ofgem"
	}
	return "unknown"
}

// Confidence is the closed-set tier label for entry confidence.
// 3-state per godfather R150 canonical shape.
type Confidence int

const (
	// ConfidenceHonestTODO — confidence is not yet established; entry
	// requires qualified reviewer signoff. IsStale always true.
	ConfidenceHonestTODO Confidence = iota

	// ConfidenceMedium — confidence is partial (e.g. document published
	// but interpretation may shift on next Ofgem determination round).
	ConfidenceMedium

	// ConfidenceHigh — confidence is full (canonical Ofgem / ENTSO-E
	// source, current epoch).
	ConfidenceHigh
)

// String returns the canonical name for a Confidence.
func (c Confidence) String() string {
	switch c {
	case ConfidenceHonestTODO:
		return "honest_todo"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	}
	return "unknown"
}

// Class is the canonical entry-class label so consumers can filter
// entries by curated content surface. Closed enum.
type Class int

const (
	ClassOfgemRIIO Class = iota
	ClassENTSOEReference
	ClassFERCOrder1000
)

// String returns the canonical name for a Class.
func (cl Class) String() string {
	switch cl {
	case ClassOfgemRIIO:
		return "ofgem_riio"
	case ClassENTSOEReference:
		return "entsoe_reference"
	case ClassFERCOrder1000:
		return "ferc_order_1000"
	}
	return "unknown"
}

// Entry is the canonical 6-field schematised-knowledge envelope
// (R150.D 5-field + R150.E reviewer-class extension).
type Entry struct {
	// Key is the unique identifier for this entry within its Class.
	// (Class + Key) is the manifest-wide composite key.
	Key string

	// Class identifies which curated content surface this entry
	// belongs to.
	Class Class

	// Source is the closed-set source-of-truth provenance enum.
	Source Source

	// FreshAt is the wall-clock UTC time the upstream source was
	// last verified by a qualified reviewer. Use SentinelHonestTODO
	// for entries whose freshness has never been established.
	FreshAt time.Time

	// SchemaVersion is the manifest-envelope schema version. Pinned
	// at v1; bumping invalidates every entry.
	SchemaVersion int

	// Confidence tier for this entry.
	Confidence Confidence

	// ReviewedByCounsel signals R150.E qualified-counsel signoff.
	// Phase-1 entries default to false; the Phase-3 deliverable
	// promotes selected entries to true after UK energy regulatory
	// barrister + US FERC counsel review.
	ReviewedByCounsel bool

	// Rationale carries a short human-readable note explaining the
	// source citation. NOT load-bearing for any code path — it's a
	// forensic-readability aid for the next reviewer.
	Rationale string
}

// IsStale reports whether this entry is past its freshness window.
// 9-path per godfather R150 canonical shape.
func (e Entry) IsStale(now time.Time, maxAge time.Duration) bool {
	if e.Source == SourceUnknownHonestTODO {
		return true
	}
	if e.Confidence == ConfidenceHonestTODO {
		return true
	}
	if e.SchemaVersion != SchemaVersion {
		return true
	}
	if e.FreshAt.Equal(SentinelHonestTODO) {
		return true
	}
	if e.FreshAt.IsZero() {
		return true
	}
	if e.FreshAt.After(now) {
		return true // defensive — clock skew or bad data
	}
	if maxAge > 0 && now.Sub(e.FreshAt) > maxAge {
		return true
	}
	// Phase-3 deferred (FERC Order 1000) MUST be reviewed by counsel
	// before the cross-Atlantic harmonization output is regulator-
	// load-bearing. Until ReviewedByCounsel flips true, treat as stale.
	if e.Class == ClassFERCOrder1000 && !e.ReviewedByCounsel {
		return true
	}
	return false
}

// Manifest is the curated content surface inventory. Ordered;
// duplicates allowed only if (Class, Key) is unique.
type Manifest []Entry

// FindByKey returns the first Entry matching (class, key), or nil
// if none exists.
func (m Manifest) FindByKey(class Class, key string) *Entry {
	for i, e := range m {
		if e.Class == class && e.Key == key {
			return &m[i]
		}
	}
	return nil
}

// HonestTODOCount returns the number of entries flagged as
// honest-TODO under either Source or Confidence.
func (m Manifest) HonestTODOCount() int {
	n := 0
	for _, e := range m {
		if e.Source == SourceUnknownHonestTODO || e.Confidence == ConfidenceHonestTODO {
			n++
		}
	}
	return n
}

// StaleCount returns the number of entries IsStale would return
// true for at `now` against `maxAge`. O(n) over the manifest.
func (m Manifest) StaleCount(now time.Time, maxAge time.Duration) int {
	n := 0
	for _, e := range m {
		if e.IsStale(now, maxAge) {
			n++
		}
	}
	return n
}

// ReviewedByCounselCount returns the number of entries with
// ReviewedByCounsel == true. Surfaces Phase-3 deliverable progress.
func (m Manifest) ReviewedByCounselCount() int {
	n := 0
	for _, e := range m {
		if e.ReviewedByCounsel {
			n++
		}
	}
	return n
}
