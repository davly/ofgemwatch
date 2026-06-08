// Package ofgemriio — Ofgem RIIO price-control compliance verification
// for ofgemwatch.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship). Pure-
// stdlib; zero deps. Phase-1 scaffold against the RIIO-ED2 (Electricity
// Distribution, second round) price-control framework — the 5-year
// price control Ofgem applies to UK Distribution Network Operators
// (DNOs).
//
// IMPORTANT: this package is PHASE 1 SCAFFOLD. The Ofgem live-data
// feed is NOT wired — verdicts are computed against canned fixture
// data in CanonicalDNOs(). Production callers MUST surface
// OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE before consuming
// verdicts as regulator-load-bearing.
//
// What RIIO verifies (Phase 1 scope):
//
//   - Cost-Forecast (CF) adherence — each DNO submits a 5-year
//     totex (total expenditure) forecast; Ofgem applies the RIIO-2
//     methodology to produce final-determination allowances.
//   - DNO is in compliance if reported expenditure stays within
//     the determination band (typically determined ± a defined
//     tolerance under Standard Licence Conditions).
//
// Phase-2 deferred: ENTSO-E XML producer (separate package); monthly
// cadence ingestion (currently annual scaffold only); CMA appeals
// cross-reference.
//
// Phase-3 deferred: FERC Order 1000 harmonization; qualified-counsel
// signoff per R150.E ReviewedByCounsel field.
package ofgemriio

import (
	"fmt"
	"math"
	"sort"
)

// Verdict is the closed-set 3-state outcome enum per R115 SINGLE-ENUM-
// REJECTION-OUTCOME. Drift here requires R145.B paired-regression.
type Verdict int

const (
	// VerdictUncertain — insufficient evidence to converge a verdict.
	// E.g. DNO has not yet filed sufficient RIIO-CF rows.
	VerdictUncertain Verdict = iota

	// VerdictCompliant — DNO totex stays within the Ofgem
	// determination band.
	VerdictCompliant

	// VerdictBreach — DNO totex exceeds the determination band by
	// more than the licence-condition tolerance.
	VerdictBreach
)

// String returns the canonical name for a Verdict.
func (v Verdict) String() string {
	switch v {
	case VerdictUncertain:
		return "uncertain"
	case VerdictCompliant:
		return "compliant"
	case VerdictBreach:
		return "breach"
	}
	return "unknown"
}

// ToleranceBand is the default RIIO-2 totex tolerance band (15% of
// determination per the RIIO-2 Methodology Decision §4 totex
// adjustment mechanism). Pinned as the cohort canonical for the
// Phase-1 scaffold; Phase-2 will plumb the per-DNO licence-condition
// band override.
const ToleranceBand = 0.15

// DNO represents a UK Distribution Network Operator under the Ofgem
// RIIO-ED2 price-control framework.
type DNO struct {
	// ID is the canonical Ofgem identifier (e.g. "WPD-WMID" for
	// Western Power Distribution West Midlands).
	ID string

	// Name is the human-readable DNO name.
	Name string

	// Region names the licence area (e.g. "West Midlands").
	Region string

	// DeterminationTotexMillionGBP is the Ofgem final-determination
	// totex allowance for the current 5-year RIIO-ED2 period.
	DeterminationTotexMillionGBP float64

	// ReportedTotexMillionGBP is the DNO's reported totex spend
	// to date. Phase-1 scaffold uses canned fixture data; production
	// reads from the live Ofgem data feed.
	ReportedTotexMillionGBP float64
}

// Verdict returns the RIIO-CF compliance verdict for this DNO.
// VerdictCompliant if ReportedTotex is within ±ToleranceBand of
// DeterminationTotex; VerdictBreach if outside.
//
// VerdictUncertain if either DeterminationTotex or ReportedTotex
// is zero (no data filed).
func (d DNO) Verdict() Verdict {
	if d.DeterminationTotexMillionGBP <= 0 || d.ReportedTotexMillionGBP <= 0 {
		return VerdictUncertain
	}
	lower := d.DeterminationTotexMillionGBP * (1.0 - ToleranceBand)
	upper := d.DeterminationTotexMillionGBP * (1.0 + ToleranceBand)
	if d.ReportedTotexMillionGBP < lower || d.ReportedTotexMillionGBP > upper {
		return VerdictBreach
	}
	return VerdictCompliant
}

// DeltaPct returns the percentage delta of ReportedTotex against
// DeterminationTotex. Positive means over-spend; negative under-spend.
// Returns 0 if DeterminationTotex is zero.
func (d DNO) DeltaPct() float64 {
	if d.DeterminationTotexMillionGBP == 0 {
		return 0
	}
	return (d.ReportedTotexMillionGBP - d.DeterminationTotexMillionGBP) / d.DeterminationTotexMillionGBP * 100.0
}

// String returns the canonical human-readable representation of a
// DNO verdict.
func (d DNO) String() string {
	v := d.Verdict()
	return fmt.Sprintf("  %s (%s, %s) — verdict=%s det=£%.0fm reported=£%.0fm delta=%+.1f%%",
		d.ID, d.Name, d.Region, v.String(),
		d.DeterminationTotexMillionGBP, d.ReportedTotexMillionGBP, d.DeltaPct())
}

// CanonicalDNOs returns the canonical Phase-1 scaffold DNO corpus.
// 6 entries spanning all GB DNO licence-area classifications. Values
// are CANNED FIXTURES — not from a live Ofgem feed. The R143
// OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE advisory MUST surface
// before downstream consumers treat these as regulator-load-bearing.
func CanonicalDNOs() []DNO {
	return []DNO{
		{
			ID:                           "WPD-WMID",
			Name:                         "Western Power Distribution",
			Region:                       "West Midlands",
			DeterminationTotexMillionGBP: 1850.0,
			ReportedTotexMillionGBP:      1923.0, // within ±15%
		},
		{
			ID:                           "UKPN-LPN",
			Name:                         "UK Power Networks",
			Region:                       "London",
			DeterminationTotexMillionGBP: 2410.0,
			ReportedTotexMillionGBP:      2380.0,
		},
		{
			ID:                           "NPG-NEDL",
			Name:                         "Northern Powergrid",
			Region:                       "Northeast",
			DeterminationTotexMillionGBP: 1620.0,
			ReportedTotexMillionGBP:      2050.0, // breach: +26.5%
		},
		{
			ID:                           "SSEN-SHEPD",
			Name:                         "SSE Networks",
			Region:                       "Scottish Hydro Electric",
			DeterminationTotexMillionGBP: 1450.0,
			ReportedTotexMillionGBP:      1480.0,
		},
		{
			ID:                           "ENWL-NWL",
			Name:                         "Electricity North West",
			Region:                       "Northwest",
			DeterminationTotexMillionGBP: 1280.0,
			ReportedTotexMillionGBP:      980.0, // breach: -23.4% under-spend
		},
		{
			ID:                           "SPEN-MANCHWB",
			Name:                         "SP Energy Networks",
			Region:                       "Manweb",
			DeterminationTotexMillionGBP: 1380.0,
			ReportedTotexMillionGBP:      0.0, // not yet filed → uncertain
		},
	}
}

// FindByID returns the canonical DNO record for the given Ofgem ID,
// or nil if no match.
func FindByID(id string) *DNO {
	dnos := CanonicalDNOs()
	for i := range dnos {
		if dnos[i].ID == id {
			return &dnos[i]
		}
	}
	return nil
}

// SummariseFleet returns a 4-tuple count of (uncertain, compliant,
// breach, total) across the canonical DNO fleet.
func SummariseFleet() (uncertain, compliant, breach, total int) {
	for _, d := range CanonicalDNOs() {
		total++
		switch d.Verdict() {
		case VerdictUncertain:
			uncertain++
		case VerdictCompliant:
			compliant++
		case VerdictBreach:
			breach++
		}
	}
	return
}

// ExcessMillionGBP is the signed £m by which a DNO's reported totex falls
// OUTSIDE the ±ToleranceBand around its determination: positive = over-spend
// beyond the band, negative = under-spend beyond it. It returns 0 for any DNO
// that is not VerdictBreach (compliant or uncertain), so it agrees exactly with
// Verdict()'s strict band test -- a DNO on the band edge is Compliant -> 0. This
// turns DeltaPct's magnitude (computed and logged, but read by no decision) into
// a materiality figure.
func (d DNO) ExcessMillionGBP() float64 {
	if d.Verdict() != VerdictBreach {
		return 0
	}
	diff := d.ReportedTotexMillionGBP - d.DeterminationTotexMillionGBP
	band := d.DeterminationTotexMillionGBP * ToleranceBand
	if diff > 0 {
		return diff - band // over-spend beyond the band
	}
	return diff + band // under-spend beyond the band (kept negative)
}

// RankBreachesByMateriality returns the breaching DNOs ordered by absolute £m
// materiality (largest exposure first), ties broken by ID for determinism;
// non-breaching DNOs are excluded. A FLAG/signal against the canonical band --
// not a regulatory determination.
func RankBreachesByMateriality(dnos []DNO) []DNO {
	breaches := make([]DNO, 0, len(dnos))
	for _, d := range dnos {
		if d.Verdict() == VerdictBreach {
			breaches = append(breaches, d)
		}
	}
	sort.SliceStable(breaches, func(i, j int) bool {
		ai, aj := math.Abs(breaches[i].ExcessMillionGBP()), math.Abs(breaches[j].ExcessMillionGBP())
		if ai != aj {
			return ai > aj
		}
		return breaches[i].ID < breaches[j].ID
	})
	return breaches
}
