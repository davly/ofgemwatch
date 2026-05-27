package honest

import (
	"bytes"
	"strings"
	"testing"
)

// TestLoudOncePrefixCohortCanonical pins the cohort-grep contract.
// Drift on this literal breaks every grep across ecosystem logs.
func TestLoudOncePrefixCohortCanonical(t *testing.T) {
	if LoudOncePrefix != "[LOUD-ONCE-WARNING]" {
		t.Errorf("LoudOncePrefix = %q, want %q (cohort-canonical grep contract)", LoudOncePrefix, "[LOUD-ONCE-WARNING]")
	}
}

// TestSeverityLadderClosedSet pins the 3-tier ladder per R143.A.
// Adding a 4th rung silently changes every downstream switch.
func TestSeverityLadderClosedSet(t *testing.T) {
	pairs := []struct {
		sev  Severity
		name string
	}{
		{SeverityInfo, "info"},
		{SeverityWarn, "warn"},
		{SeverityError, "error"},
	}
	for i, p := range pairs {
		if int(p.sev) != i {
			t.Errorf("Severity %q ordinal = %d, want %d", p.name, int(p.sev), i)
		}
		if got := p.sev.String(); got != p.name {
			t.Errorf("Severity(%d).String() = %q, want %q", p.sev, got, p.name)
		}
	}
}

// TestCanonicalAdvisoriesCount pins exactly 5 advisories per BR6.
func TestCanonicalAdvisoriesCount(t *testing.T) {
	got := len(CanonicalAdvisories())
	want := 5
	if got != want {
		t.Errorf("CanonicalAdvisories() count = %d, want %d (BR6 5-advisory procedure)", got, want)
	}
}

// TestCanonicalAdvisoriesRequiredCodes pins the exact 5 Codes named
// in the BR6 procedure. Renames break the cohort-grep contract.
func TestCanonicalAdvisoriesRequiredCodes(t *testing.T) {
	wantCodes := []string{
		"OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE",
		"OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER",
		"OFGEMWATCH_FERC_ORDER_1000_SCOPE_DEFERRED",
		"OFGEMWATCH_REPORTING_CADENCE_MONTHLY_REQUIRED",
		"OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE",
	}
	advs := CanonicalAdvisories()
	gotCodes := make(map[string]bool, len(advs))
	for _, a := range advs {
		gotCodes[a.Code] = true
	}
	for _, want := range wantCodes {
		if !gotCodes[want] {
			t.Errorf("CanonicalAdvisories missing required Code %q", want)
		}
	}
}

// TestCanonicalAdvisoriesSeverityCoverage pins the BR6 severity
// breakdown: 2 Error + 3 Warn + 0 Info. Drift breaks R143.A
// LADDER-CONVENTION compliance check.
func TestCanonicalAdvisoriesSeverityCoverage(t *testing.T) {
	advs := CanonicalAdvisories()
	counts := map[Severity]int{}
	for _, a := range advs {
		counts[a.Severity]++
	}
	if counts[SeverityError] != 2 {
		t.Errorf("Error advisory count = %d, want 2 (BR6: RIIO + ENTSO-E)", counts[SeverityError])
	}
	if counts[SeverityWarn] != 3 {
		t.Errorf("Warn advisory count = %d, want 3 (BR6: FERC + cadence + counsel)", counts[SeverityWarn])
	}
}

// TestCanonicalAdvisoriesShape pins every advisory has non-empty
// Code + Message + DocLink. Empty fields break the grep contract.
func TestCanonicalAdvisoriesShape(t *testing.T) {
	for _, a := range CanonicalAdvisories() {
		if a.Code == "" {
			t.Errorf("Advisory has empty Code: %+v", a)
		}
		if a.Message == "" {
			t.Errorf("Advisory %q has empty Message", a.Code)
		}
		if a.DocLink == "" {
			t.Errorf("Advisory %q has empty DocLink", a.Code)
		}
	}
}

// TestLoudOnceEmitsExactlyOnce pins the loud-once contract per Code.
func TestLoudOnceEmitsExactlyOnce(t *testing.T) {
	Reset() // isolate test state
	defer Reset()

	adv := Advisory{
		Code:     "TEST_ONCE_CODE",
		Severity: SeverityWarn,
		Message:  "test",
		DocLink:  "test.md",
	}
	var buf bytes.Buffer
	if !LoudOnce(adv, &buf) {
		t.Errorf("First LoudOnce returned false, want true")
	}
	if LoudOnce(adv, &buf) {
		t.Errorf("Second LoudOnce returned true, want false (loud-once contract)")
	}
	if LoudOnce(adv, &buf) {
		t.Errorf("Third LoudOnce returned true, want false")
	}
	count := strings.Count(buf.String(), "[LOUD-ONCE-WARNING]")
	if count != 1 {
		t.Errorf("LOUD-ONCE-WARNING emit count = %d, want 1 (loud-once contract)", count)
	}
}

// TestLoudOnceDistinctCodesEmitIndependently pins independence of
// Code state — one Code emitting does not silence others.
func TestLoudOnceDistinctCodesEmitIndependently(t *testing.T) {
	Reset()
	defer Reset()

	advA := Advisory{Code: "CODE_A", Severity: SeverityWarn, Message: "a", DocLink: "a.md"}
	advB := Advisory{Code: "CODE_B", Severity: SeverityWarn, Message: "b", DocLink: "b.md"}

	var buf bytes.Buffer
	if !LoudOnce(advA, &buf) {
		t.Errorf("LoudOnce(A) = false, want true")
	}
	if !LoudOnce(advB, &buf) {
		t.Errorf("LoudOnce(B) = false, want true")
	}
}

// TestLoudOnceRefusesEmptyCode pins the empty-Code refusal.
func TestLoudOnceRefusesEmptyCode(t *testing.T) {
	Reset()
	defer Reset()

	adv := Advisory{Code: "", Severity: SeverityWarn, Message: "x", DocLink: "x.md"}
	var buf bytes.Buffer
	if LoudOnce(adv, &buf) {
		t.Errorf("LoudOnce(empty Code) = true, want false")
	}
	if buf.Len() != 0 {
		t.Errorf("LoudOnce(empty Code) emitted %q, want empty", buf.String())
	}
}

// TestAdvisoryStringShape pins the canonical render shape.
func TestAdvisoryStringShape(t *testing.T) {
	adv := Advisory{
		Code:     "X_CODE",
		Severity: SeverityError,
		Message:  "msg",
		DocLink:  "doc.md",
	}
	got := adv.String()
	wantSubstrs := []string{
		"[LOUD-ONCE-WARNING]",
		"ofgemwatch:",
		"X_CODE",
		"(error)",
		"msg",
		"[see doc.md]",
	}
	for _, want := range wantSubstrs {
		if !strings.Contains(got, want) {
			t.Errorf("Advisory.String() = %q, missing %q", got, want)
		}
	}
}
