package manifest

import (
	"testing"
	"time"
)

// TestSchemaVersionV1 pins the cohort-canonical v1 schema version.
func TestSchemaVersionV1(t *testing.T) {
	if SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1 (R150 canonical)", SchemaVersion)
	}
}

// TestSentinelHonestTODOIsUnixEpoch pins the canonical 1970-01-01
// honest-TODO sentinel per godfather R150 canonical shape.
func TestSentinelHonestTODOIsUnixEpoch(t *testing.T) {
	want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if !SentinelHonestTODO.Equal(want) {
		t.Errorf("SentinelHonestTODO = %v, want %v (R150 canonical 1970-01-01 UTC)", SentinelHonestTODO, want)
	}
}

// TestSourceClosedSet pins the 7-state Source enum.
func TestSourceClosedSet(t *testing.T) {
	pairs := []struct {
		src  Source
		name string
	}{
		{SourceUnknownHonestTODO, "unknown_honest_todo"},
		{SourceOfgemMethodology, "ofgem_methodology"},
		{SourceENTSOENetworkCode, "entsoe_network_code"},
		{SourceENTSOETransparencyXSD, "entsoe_transparency_xsd"},
		{SourceFERCOrder1000Pending, "ferc_order_1000_pending"},
		{SourceCMAAppealsDB, "cma_appeals_db"},
		{SourceECPaperOfgem, "ec_paper_ofgem"},
	}
	for i, p := range pairs {
		if int(p.src) != i {
			t.Errorf("Source %q ordinal = %d, want %d", p.name, int(p.src), i)
		}
		if got := p.src.String(); got != p.name {
			t.Errorf("Source(%d).String() = %q, want %q", p.src, got, p.name)
		}
	}
}

// TestConfidenceClosedSet pins the 3-tier Confidence enum.
func TestConfidenceClosedSet(t *testing.T) {
	pairs := []struct {
		c    Confidence
		name string
	}{
		{ConfidenceHonestTODO, "honest_todo"},
		{ConfidenceMedium, "medium"},
		{ConfidenceHigh, "high"},
	}
	for i, p := range pairs {
		if int(p.c) != i {
			t.Errorf("Confidence %q ordinal = %d, want %d", p.name, int(p.c), i)
		}
	}
}

// TestClassClosedSet pins the 3-state Class enum.
func TestClassClosedSet(t *testing.T) {
	pairs := []struct {
		cl   Class
		name string
	}{
		{ClassOfgemRIIO, "ofgem_riio"},
		{ClassENTSOEReference, "entsoe_reference"},
		{ClassFERCOrder1000, "ferc_order_1000"},
	}
	for i, p := range pairs {
		if int(p.cl) != i {
			t.Errorf("Class %q ordinal = %d, want %d", p.name, int(p.cl), i)
		}
	}
}

// TestSeedSize pins the inception seed inventory: 5 Ofgem RIIO + 4
// ENTSO-E + 3 FERC Order 1000 = 12 entries.
func TestSeedSize(t *testing.T) {
	seed := Seed()
	if len(seed) != 12 {
		t.Fatalf("Seed size = %d, want 12 (5 RIIO + 4 ENTSO-E + 3 FERC)", len(seed))
	}
}

// TestSeedClassBreakdown pins the BR6 inception class breakdown.
func TestSeedClassBreakdown(t *testing.T) {
	counts := map[Class]int{}
	for _, e := range Seed() {
		counts[e.Class]++
	}
	if counts[ClassOfgemRIIO] != 5 {
		t.Errorf("ClassOfgemRIIO count = %d, want 5", counts[ClassOfgemRIIO])
	}
	if counts[ClassENTSOEReference] != 4 {
		t.Errorf("ClassENTSOEReference count = %d, want 4", counts[ClassENTSOEReference])
	}
	if counts[ClassFERCOrder1000] != 3 {
		t.Errorf("ClassFERCOrder1000 count = %d, want 3", counts[ClassFERCOrder1000])
	}
}

// TestSeedNoReviewedByCounsel pins that Phase-1 inception scaffold
// ships NO entries with ReviewedByCounsel=true. Phase-3 deliverable
// promotes selected entries — until then, no entry is counsel-blessed.
func TestSeedNoReviewedByCounsel(t *testing.T) {
	got := Seed().ReviewedByCounselCount()
	if got != 0 {
		t.Errorf("ReviewedByCounsel count = %d, want 0 at scaffold (Phase-3 deliverable)", got)
	}
}

// TestSeedFERCAlwaysStale pins that FERC Order 1000 entries are
// always-stale at Phase 1 — they require Phase-3 + counsel review.
func TestSeedFERCAlwaysStale(t *testing.T) {
	now := time.Now()
	for _, e := range Seed() {
		if e.Class != ClassFERCOrder1000 {
			continue
		}
		if !e.IsStale(now, 0) {
			t.Errorf("FERC entry %q IsStale = false, want true (Phase-3 deferred)", e.Key)
		}
	}
}

// TestSeedNonFERCNotAllStale pins that the Ofgem RIIO + ENTSO-E
// entries with current FreshAt + High/Medium confidence are NOT stale.
func TestSeedNonFERCFreshEntriesNotStale(t *testing.T) {
	// Anchor at a time after the canonical publication dates so
	// FreshAt is in the past + within any reasonable maxAge.
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	maxAge := 365 * 24 * time.Hour // 1 year window

	freshFound := 0
	for _, e := range Seed() {
		if e.Class == ClassFERCOrder1000 {
			continue
		}
		if e.Source == SourceUnknownHonestTODO || e.Confidence == ConfidenceHonestTODO {
			continue
		}
		if e.FreshAt.Equal(SentinelHonestTODO) {
			continue
		}
		if !e.IsStale(now, maxAge) {
			freshFound++
		}
	}
	if freshFound < 5 {
		t.Errorf("fresh non-FERC entry count = %d, want at least 5 (Ofgem RIIO + ENTSO-E core references)", freshFound)
	}
}

// TestIsStaleNinePathCoverage pins all 9 IsStale paths per R150
// canonical shape (godfather memory 2026-05-22).
func TestIsStaleNinePathCoverage(t *testing.T) {
	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	maxAge := 365 * 24 * time.Hour

	// Path 1: SourceUnknownHonestTODO → true
	e1 := Entry{Source: SourceUnknownHonestTODO, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: now}
	if !e1.IsStale(now, maxAge) {
		t.Errorf("Path 1: SourceUnknownHonestTODO IsStale = false, want true")
	}

	// Path 2: ConfidenceHonestTODO → true
	e2 := Entry{Source: SourceOfgemMethodology, Confidence: ConfidenceHonestTODO, SchemaVersion: SchemaVersion, FreshAt: now}
	if !e2.IsStale(now, maxAge) {
		t.Errorf("Path 2: ConfidenceHonestTODO IsStale = false, want true")
	}

	// Path 3: SchemaVersion drift → true
	e3 := Entry{Source: SourceOfgemMethodology, Confidence: ConfidenceHigh, SchemaVersion: 999, FreshAt: now}
	if !e3.IsStale(now, maxAge) {
		t.Errorf("Path 3: SchemaVersion drift IsStale = false, want true")
	}

	// Path 4: FreshAt == SentinelHonestTODO → true
	e4 := Entry{Source: SourceOfgemMethodology, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: SentinelHonestTODO}
	if !e4.IsStale(now, maxAge) {
		t.Errorf("Path 4: SentinelHonestTODO IsStale = false, want true")
	}

	// Path 5: maxAge <= 0 + other clauses fine → false
	e5 := Entry{Source: SourceOfgemMethodology, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: now}
	if e5.IsStale(now, 0) {
		t.Errorf("Path 5: maxAge<=0 IsStale = true, want false")
	}

	// Path 6: zero-time → true
	e6 := Entry{Source: SourceOfgemMethodology, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: time.Time{}}
	if !e6.IsStale(now, maxAge) {
		t.Errorf("Path 6: zero-time IsStale = false, want true")
	}

	// Path 7: FreshAt in future → true
	future := now.Add(365 * 24 * time.Hour)
	e7 := Entry{Source: SourceOfgemMethodology, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: future}
	if !e7.IsStale(now, maxAge) {
		t.Errorf("Path 7: future FreshAt IsStale = false, want true")
	}

	// Path 8: now.Sub(FreshAt) > maxAge → true
	stale := now.Add(-2 * 365 * 24 * time.Hour) // 2 years ago
	e8 := Entry{Source: SourceOfgemMethodology, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: stale}
	if !e8.IsStale(now, maxAge) {
		t.Errorf("Path 8: age exceeded IsStale = false, want true")
	}

	// Path 9: all clauses pass → false
	e9 := Entry{
		Source:            SourceOfgemMethodology,
		Confidence:        ConfidenceHigh,
		SchemaVersion:     SchemaVersion,
		FreshAt:           now.Add(-30 * 24 * time.Hour),
		ReviewedByCounsel: false, // FERC class is the only one that requires this
		Class:             ClassOfgemRIIO,
	}
	if e9.IsStale(now, maxAge) {
		t.Errorf("Path 9: clean entry IsStale = true, want false")
	}
}

// TestSeedAllKeysUnique pins (Class, Key) uniqueness across the seed.
func TestSeedAllKeysUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range Seed() {
		k := e.Class.String() + ":" + e.Key
		if seen[k] {
			t.Errorf("duplicate composite key %q", k)
		}
		seen[k] = true
	}
}

// TestFindByKeyExists pins the FindByKey API.
func TestFindByKeyExists(t *testing.T) {
	seed := Seed()
	got := seed.FindByKey(ClassOfgemRIIO, "riio_ed2_final_determinations")
	if got == nil {
		t.Errorf("FindByKey(ClassOfgemRIIO, riio_ed2_final_determinations) = nil, want entry")
	}
	missing := seed.FindByKey(ClassOfgemRIIO, "does_not_exist")
	if missing != nil {
		t.Errorf("FindByKey(missing) = %+v, want nil", missing)
	}
}

// TestHonestTODOCount pins the count of honest-TODO-flagged entries.
// FERC entries are all Confidence=HonestTODO + Source=Pending →
// 3 FERC + 1 CMA (FreshAt sentinel only — Source/Confidence are set)
// → only the 3 FERC entries trigger HonestTODOCount.
func TestHonestTODOCount(t *testing.T) {
	got := Seed().HonestTODOCount()
	want := 3 // 3 FERC entries (Source=Pending + Confidence=HonestTODO)
	if got != want {
		t.Errorf("HonestTODOCount = %d, want %d", got, want)
	}
}
