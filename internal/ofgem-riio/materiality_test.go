package ofgemriio

import (
	"math"
	"testing"
)

func dnoFixture(id string, det, rep float64) DNO {
	return DNO{ID: id, DeterminationTotexMillionGBP: det, ReportedTotexMillionGBP: rep}
}

func TestExcessMillionGBP(t *testing.T) {
	cases := []struct {
		name     string
		det, rep float64
		want     float64
	}{
		{"over breach", 1620, 2050, 187},          // diff 430, band 243 -> +187
		{"under breach", 1280, 980, -108},         // diff -300, band 192 -> -108
		{"compliant within band", 1000, 1100, 0},  // +10% < 15%
		{"exactly on band edge", 1000, 1150, 0},   // +15% -> Compliant (strict >)
		{"uncertain (zero det)", 0, 500, 0},
	}
	for _, c := range cases {
		got := dnoFixture("x", c.det, c.rep).ExcessMillionGBP()
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("%s: ExcessMillionGBP = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestExcessSignDirection(t *testing.T) {
	if dnoFixture("o", 1000, 1500).ExcessMillionGBP() <= 0 {
		t.Error("over-spend breach must be positive (over the band)")
	}
	if dnoFixture("u", 1000, 500).ExcessMillionGBP() >= 0 {
		t.Error("under-spend breach must be negative (under the band)")
	}
}

func TestRankBreachesByMateriality(t *testing.T) {
	dnos := []DNO{
		dnoFixture("small", 1000, 1200), // over 200, band 150 -> excess 50
		dnoFixture("big", 1620, 2050),   // excess 187
		dnoFixture("mid", 1280, 980),    // under, |excess| 108
		dnoFixture("ok", 1000, 1050),    // +5% -> compliant, excluded
	}
	ranked := RankBreachesByMateriality(dnos)
	if len(ranked) != 3 {
		t.Fatalf("expected 3 breaches, got %d", len(ranked))
	}
	got := []string{ranked[0].ID, ranked[1].ID, ranked[2].ID}
	want := []string{"big", "mid", "small"} // by |excess| desc: 187, 108, 50
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rank position %d = %s, want %s (full order %v)", i, got[i], want[i], got)
		}
	}
}

func TestRankExcludesNonBreaches(t *testing.T) {
	dnos := []DNO{dnoFixture("a", 1000, 1050), dnoFixture("b", 2000, 2000)}
	if r := RankBreachesByMateriality(dnos); len(r) != 0 {
		t.Errorf("all-compliant fleet should rank no breaches, got %d", len(r))
	}
}

func TestMaterialityIgnoresDeltaSignForOrdering(t *testing.T) {
	// A large UNDER-spend outranks a small over-spend (magnitude, not sign).
	dnos := []DNO{
		dnoFixture("smallover", 1000, 1200), // +50
		dnoFixture("bigunder", 1000, 400),   // diff -600, band 150 -> -450
	}
	ranked := RankBreachesByMateriality(dnos)
	if ranked[0].ID != "bigunder" {
		t.Errorf("largest |materiality| should rank first, got %s", ranked[0].ID)
	}
}
