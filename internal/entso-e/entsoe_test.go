package entsoe

import (
	"strings"
	"testing"
	"time"
)

// TestSchemaVersionCanonical pins the IEC 62325-451-3 schema v1.0.
func TestSchemaVersionCanonical(t *testing.T) {
	if SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q, want %q (IEC 62325-451-3 canonical)", SchemaVersion, "1.0")
	}
}

// TestBusinessTypeCanonicalCodes pins the IEC 62325-451-3 BusinessType
// codes. These are publicly-documented enum values; drift breaks every
// downstream ENTSO-E consumer.
func TestBusinessTypeCanonicalCodes(t *testing.T) {
	wants := map[string]string{
		"Generation":         "A04",
		"Load":               "A65",
		"PhysicalFlow":       "A66",
		"DayAheadPrice":      "A62",
		"Frequency":          "A85",
		"ProductionForecast": "A71",
	}
	gots := map[string]string{
		"Generation":         BusinessTypeGeneration,
		"Load":               BusinessTypeLoad,
		"PhysicalFlow":       BusinessTypePhysicalFlow,
		"DayAheadPrice":      BusinessTypeDayAheadPrice,
		"Frequency":          BusinessTypeFrequency,
		"ProductionForecast": BusinessTypeProductionForecast,
	}
	for k, want := range wants {
		if gots[k] != want {
			t.Errorf("BusinessType %s = %q, want %q (IEC 62325-451-3 canonical)", k, gots[k], want)
		}
	}
}

// TestPlaceholderDisclaimerLiteral pins the canonical disclaimer
// text every Phase-1 scaffold MarketReport carries.
func TestPlaceholderDisclaimerLiteral(t *testing.T) {
	wantSubstrs := []string{
		"PLACEHOLDER-PHASE-1-SCAFFOLD",
		"do NOT submit",
	}
	for _, want := range wantSubstrs {
		if !strings.Contains(PlaceholderDisclaimer, want) {
			t.Errorf("PlaceholderDisclaimer missing substring %q: %q", want, PlaceholderDisclaimer)
		}
	}
}

// TestEmitShape pins the basic Emit output shape.
func TestEmitShape(t *testing.T) {
	start := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)

	mr := Emit("RPT-001", "GB", "10YGB----------A", start, end)

	if mr.SchemaVersion != "1.0" {
		t.Errorf("mr.SchemaVersion = %q, want 1.0", mr.SchemaVersion)
	}
	if mr.ReportID != "RPT-001" {
		t.Errorf("mr.ReportID = %q, want RPT-001", mr.ReportID)
	}
	if mr.AreaCode != "GB" {
		t.Errorf("mr.AreaCode = %q, want GB", mr.AreaCode)
	}
	if mr.BiddingZone != "10YGB----------A" {
		t.Errorf("mr.BiddingZone = %q, want 10YGB----------A", mr.BiddingZone)
	}
	if mr.Disclaimer != PlaceholderDisclaimer {
		t.Errorf("mr.Disclaimer missing placeholder disclaimer")
	}
}

// TestEmitFourSeries pins the 4-series UK Phase-1 canonical scaffold.
func TestEmitFourSeries(t *testing.T) {
	start := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	mr := Emit("RPT", "GB", "10YGB----------A", start, end)

	want := 4
	if len(mr.TimeSeries) != want {
		t.Errorf("TimeSeries count = %d, want %d (gen + load + price + freq)", len(mr.TimeSeries), want)
	}

	wantBT := []string{
		BusinessTypeGeneration,
		BusinessTypeLoad,
		BusinessTypeDayAheadPrice,
		BusinessTypeFrequency,
	}
	for i, bt := range wantBT {
		if mr.TimeSeries[i].BusinessType != bt {
			t.Errorf("TimeSeries[%d].BusinessType = %q, want %q", i, mr.TimeSeries[i].BusinessType, bt)
		}
	}
}

// TestMarshalSucceeds pins that Marshal produces valid XML bytes.
func TestMarshalSucceeds(t *testing.T) {
	start := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	mr := Emit("RPT", "GB", "10YGB----------A", start, end)

	out, err := Marshal(mr)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)
	wantSubstrs := []string{
		"<MarketReport",
		"schemaVersion=\"1.0\"",
		"<ReportID>RPT</ReportID>",
		"<AreaCode>GB</AreaCode>",
		"<BiddingZone>10YGB----------A</BiddingZone>",
		"<BusinessType>A04</BusinessType>",
		"<BusinessType>A65</BusinessType>",
		"<BusinessType>A62</BusinessType>",
		"<BusinessType>A85</BusinessType>",
		"PLACEHOLDER-PHASE-1-SCAFFOLD",
	}
	for _, want := range wantSubstrs {
		if !strings.Contains(s, want) {
			t.Errorf("Marshal output missing %q\nfull output:\n%s", want, s)
		}
	}
}

// TestMarshalDeterministic pins that two consecutive Marshal calls
// against the same MarketReport produce identical bytes (canonical
// serialization).
func TestMarshalDeterministic(t *testing.T) {
	start := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	mr := Emit("RPT", "GB", "10YGB----------A", start, end)

	a, err := Marshal(mr)
	if err != nil {
		t.Fatalf("Marshal a: %v", err)
	}
	b, err := Marshal(mr)
	if err != nil {
		t.Fatalf("Marshal b: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("Marshal non-deterministic")
	}
}

// TestEmitDisclaimerAlwaysPresent pins that EVERY emitted report
// carries the PlaceholderDisclaimer at Phase 1 — no path forgets it.
func TestEmitDisclaimerAlwaysPresent(t *testing.T) {
	now := time.Now()
	cases := []struct {
		reportID, areaCode, biddingZone string
	}{
		{"A", "GB", "10YGB----------A"},
		{"B", "FR", "10YFR-RTE------C"},
		{"C", "DE", "10Y1001A1001A82H"},
	}
	for _, c := range cases {
		mr := Emit(c.reportID, c.areaCode, c.biddingZone, now, now.Add(time.Hour))
		if mr.Disclaimer != PlaceholderDisclaimer {
			t.Errorf("Emit(%q): Disclaimer = %q, want %q", c.reportID, mr.Disclaimer, PlaceholderDisclaimer)
		}
	}
}
