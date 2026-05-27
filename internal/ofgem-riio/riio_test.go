package ofgemriio

import "testing"

// TestVerdictClosedSet pins the 3-state Verdict enum.
func TestVerdictClosedSet(t *testing.T) {
	pairs := []struct {
		v    Verdict
		name string
	}{
		{VerdictUncertain, "uncertain"},
		{VerdictCompliant, "compliant"},
		{VerdictBreach, "breach"},
	}
	for i, p := range pairs {
		if int(p.v) != i {
			t.Errorf("Verdict %q ordinal = %d, want %d", p.name, int(p.v), i)
		}
		if got := p.v.String(); got != p.name {
			t.Errorf("Verdict(%d).String() = %q, want %q", p.v, got, p.name)
		}
	}
}

// TestToleranceBandCanonical pins the RIIO-2 15% tolerance band.
func TestToleranceBandCanonical(t *testing.T) {
	if ToleranceBand != 0.15 {
		t.Errorf("ToleranceBand = %g, want 0.15 (RIIO-2 Methodology Decision §4 canonical)", ToleranceBand)
	}
}

// TestDNOVerdictCompliant pins that reported-within-band returns Compliant.
func TestDNOVerdictCompliant(t *testing.T) {
	d := DNO{DeterminationTotexMillionGBP: 1000, ReportedTotexMillionGBP: 1050}
	if got := d.Verdict(); got != VerdictCompliant {
		t.Errorf("Verdict() = %v, want VerdictCompliant", got)
	}
}

// TestDNOVerdictBreachOver pins that over-spend > 15% returns Breach.
func TestDNOVerdictBreachOver(t *testing.T) {
	d := DNO{DeterminationTotexMillionGBP: 1000, ReportedTotexMillionGBP: 1500}
	if got := d.Verdict(); got != VerdictBreach {
		t.Errorf("Verdict() over-spend = %v, want VerdictBreach", got)
	}
}

// TestDNOVerdictBreachUnder pins that under-spend < 15% also returns Breach.
func TestDNOVerdictBreachUnder(t *testing.T) {
	d := DNO{DeterminationTotexMillionGBP: 1000, ReportedTotexMillionGBP: 500}
	if got := d.Verdict(); got != VerdictBreach {
		t.Errorf("Verdict() under-spend = %v, want VerdictBreach", got)
	}
}

// TestDNOVerdictUncertainNoData pins that zero-determination returns Uncertain.
func TestDNOVerdictUncertainNoData(t *testing.T) {
	d := DNO{DeterminationTotexMillionGBP: 0, ReportedTotexMillionGBP: 100}
	if got := d.Verdict(); got != VerdictUncertain {
		t.Errorf("Verdict() zero-determination = %v, want VerdictUncertain", got)
	}

	d2 := DNO{DeterminationTotexMillionGBP: 1000, ReportedTotexMillionGBP: 0}
	if got := d2.Verdict(); got != VerdictUncertain {
		t.Errorf("Verdict() zero-reported = %v, want VerdictUncertain", got)
	}
}

// TestDNODeltaPct pins the delta-percentage calculation.
func TestDNODeltaPct(t *testing.T) {
	d := DNO{DeterminationTotexMillionGBP: 1000, ReportedTotexMillionGBP: 1100}
	got := d.DeltaPct()
	want := 10.0
	if got != want {
		t.Errorf("DeltaPct() = %g, want %g", got, want)
	}

	dEmpty := DNO{DeterminationTotexMillionGBP: 0, ReportedTotexMillionGBP: 100}
	if got := dEmpty.DeltaPct(); got != 0 {
		t.Errorf("DeltaPct() zero-determination = %g, want 0", got)
	}
}

// TestCanonicalDNOsSize pins the 6-DNO Phase-1 corpus.
func TestCanonicalDNOsSize(t *testing.T) {
	got := len(CanonicalDNOs())
	want := 6
	if got != want {
		t.Errorf("CanonicalDNOs() count = %d, want %d", got, want)
	}
}

// TestCanonicalDNOsRequiredIDs pins the canonical DNO IDs.
func TestCanonicalDNOsRequiredIDs(t *testing.T) {
	wantIDs := []string{
		"WPD-WMID",
		"UKPN-LPN",
		"NPG-NEDL",
		"SSEN-SHEPD",
		"ENWL-NWL",
		"SPEN-MANCHWB",
	}
	got := make(map[string]bool)
	for _, d := range CanonicalDNOs() {
		got[d.ID] = true
	}
	for _, want := range wantIDs {
		if !got[want] {
			t.Errorf("CanonicalDNOs missing required ID %q", want)
		}
	}
}

// TestFindByIDHit pins the find-by-id success path.
func TestFindByIDHit(t *testing.T) {
	got := FindByID("WPD-WMID")
	if got == nil {
		t.Fatalf("FindByID(WPD-WMID) = nil")
	}
	if got.Region != "West Midlands" {
		t.Errorf("FindByID(WPD-WMID).Region = %q, want West Midlands", got.Region)
	}
}

// TestFindByIDMiss pins that unknown ID returns nil.
func TestFindByIDMiss(t *testing.T) {
	if FindByID("DOES-NOT-EXIST") != nil {
		t.Errorf("FindByID(DOES-NOT-EXIST) returned non-nil")
	}
}

// TestSummariseFleet pins the canonical-corpus fleet breakdown.
// 6 DNOs: 3 compliant (WPD + UKPN + SSEN) + 2 breach (NPG over,
// ENWL under) + 1 uncertain (SPEN no report).
func TestSummariseFleet(t *testing.T) {
	uncertain, compliant, breach, total := SummariseFleet()
	if total != 6 {
		t.Errorf("total = %d, want 6", total)
	}
	if uncertain != 1 {
		t.Errorf("uncertain = %d, want 1 (SPEN-MANCHWB)", uncertain)
	}
	if compliant != 3 {
		t.Errorf("compliant = %d, want 3 (WPD + UKPN + SSEN)", compliant)
	}
	if breach != 2 {
		t.Errorf("breach = %d, want 2 (NPG over + ENWL under)", breach)
	}
}

// TestDNOStringNonEmpty pins that String() produces non-empty output.
func TestDNOStringNonEmpty(t *testing.T) {
	d := CanonicalDNOs()[0]
	got := d.String()
	if got == "" {
		t.Errorf("DNO.String() returned empty")
	}
}
