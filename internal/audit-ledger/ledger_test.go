package auditledger

import (
	"bytes"
	"crypto/sha256"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/davly/ofgemwatch/internal/honest"
	"github.com/davly/ofgemwatch/internal/mirrormark"
)

// TestClassConstants pins the closed-set Class values.
func TestClassConstants(t *testing.T) {
	if ClassOfgemRIIO != "ofgem_riio" {
		t.Errorf("ClassOfgemRIIO = %q, want ofgem_riio", ClassOfgemRIIO)
	}
	if ClassENTSOEXML != "entsoe_xml" {
		t.Errorf("ClassENTSOEXML = %q, want entsoe_xml", ClassENTSOEXML)
	}
}

// TestCanonicalBytesDeterministic pins the deterministic-wire-form
// contract: the same row produces byte-identical canonical bytes.
func TestCanonicalBytesDeterministic(t *testing.T) {
	r := CanonicalRow{
		Timestamp:   "2026-05-27T12:00:00Z",
		Subject:     "WPD-WMID",
		Class:       ClassOfgemRIIO,
		PayloadJSON: `{"verdict":"compliant"}`,
	}
	a, err := r.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes a: %v", err)
	}
	b, err := r.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("CanonicalBytes non-deterministic: a=%q b=%q", a, b)
	}
}

// TestNewLedgerRejectsNilMarker pins fail-closed constructor.
func TestNewLedgerRejectsNilMarker(t *testing.T) {
	if _, err := NewLedger(nil); err == nil {
		t.Errorf("NewLedger(nil) = no error, want fail-closed")
	}
}

// TestAppendStampsMark pins the R175 production emit-path: every
// Append produces a row carrying the cohort-canonical "lore@v1:"
// prefix on its Mirror-Mark.
func TestAppendStampsMark(t *testing.T) {
	// Use a real (non-placeholder) marker so we test the production
	// path; suppress log output from the placeholder path tests.
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i)
	}
	marker, err := mirrormark.NewStdlibMarker(corpus, []byte("test-prod-key"))
	if err != nil {
		t.Fatalf("NewStdlibMarker: %v", err)
	}

	l, err := NewLedger(marker)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}

	row := CanonicalRow{
		Timestamp:   "2026-05-27T12:00:00Z",
		Subject:     "WPD-WMID",
		Class:       ClassOfgemRIIO,
		PayloadJSON: `{"verdict":"compliant"}`,
	}

	marked, err := l.Append(row)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	if !strings.HasPrefix(marked.Mark, "lore@v1:") {
		t.Errorf("marked.Mark = %q, missing cohort-canonical prefix lore@v1:", marked.Mark)
	}
	if len(marked.Mark) != 62 {
		t.Errorf("marked.Mark length = %d, want 62 (8 prefix + 54 body)", len(marked.Mark))
	}
}

// TestAppendDeterministic pins that two appends of the same row
// produce identical marks (byte-equality of Mirror-Mark stamping).
func TestAppendDeterministic(t *testing.T) {
	var corpus [sha256.Size]byte
	marker, _ := mirrormark.NewStdlibMarker(corpus, []byte("k"))
	l, _ := NewLedger(marker)

	row := CanonicalRow{
		Timestamp:   "2026-05-27T12:00:00Z",
		Subject:     "X",
		Class:       ClassOfgemRIIO,
		PayloadJSON: `{}`,
	}

	a, _ := l.Append(row)
	b, _ := l.Append(row)
	if a.Mark != b.Mark {
		t.Errorf("Append non-deterministic: a=%q b=%q", a.Mark, b.Mark)
	}
}

// TestSnapshotCopies pins that Snapshot returns a copy (caller
// cannot mutate ledger state).
func TestSnapshotCopies(t *testing.T) {
	var corpus [sha256.Size]byte
	marker, _ := mirrormark.NewStdlibMarker(corpus, []byte("k"))
	l, _ := NewLedger(marker)

	row := CanonicalRow{
		Timestamp:   "2026-05-27T12:00:00Z",
		Subject:     "X",
		Class:       ClassOfgemRIIO,
		PayloadJSON: `{}`,
	}
	_, _ = l.Append(row)

	snap1 := l.Snapshot()
	snap1[0].Mark = "TAMPERED"
	snap2 := l.Snapshot()
	if snap2[0].Mark == "TAMPERED" {
		t.Errorf("Snapshot returned shared state: post-mutation mark = %q, want untampered", snap2[0].Mark)
	}
}

// TestBootCheckEmitsR143ForPlaceholder pins R175 criterion-3:
// boot-time loud-once warning fires when marker is placeholder mode.
func TestBootCheckEmitsR143ForPlaceholder(t *testing.T) {
	honest.Reset() // isolate test state
	defer honest.Reset()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	pm := mirrormark.NewPlaceholderMarker()
	l, err := NewLedger(pm)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}

	l.BootCheck()

	out := buf.String()
	if !strings.Contains(out, "[LOUD-ONCE-WARNING]") {
		t.Errorf("BootCheck on placeholder did NOT emit LOUD-ONCE-WARNING: %q", out)
	}
	if !strings.Contains(out, "OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT") {
		t.Errorf("BootCheck did NOT emit OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT advisory: %q", out)
	}
}

// TestBootCheckSilentForProductionMarker pins that production
// markers DO NOT fire the loud-once at boot.
func TestBootCheckSilentForProductionMarker(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	var corpus [sha256.Size]byte
	marker, _ := mirrormark.NewStdlibMarker(corpus, []byte("prod-key"))
	l, _ := NewLedger(marker)

	l.BootCheck()

	out := buf.String()
	if strings.Contains(out, "OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT") {
		t.Errorf("BootCheck on production marker emitted placeholder advisory: %q", out)
	}
}

// TestNewRIIORowShape pins the RIIO row constructor.
func TestNewRIIORowShape(t *testing.T) {
	row, err := NewRIIORow("WPD-WMID", map[string]any{"verdict": "compliant"})
	if err != nil {
		t.Fatalf("NewRIIORow: %v", err)
	}
	if row.Subject != "WPD-WMID" {
		t.Errorf("Subject = %q, want WPD-WMID", row.Subject)
	}
	if row.Class != ClassOfgemRIIO {
		t.Errorf("Class = %q, want %q", row.Class, ClassOfgemRIIO)
	}
	if !strings.Contains(row.PayloadJSON, `"verdict":"compliant"`) {
		t.Errorf("PayloadJSON = %q, missing verdict", row.PayloadJSON)
	}
	if row.Timestamp == "" {
		t.Errorf("Timestamp empty")
	}
}

// TestNewENTSOERowShape pins the ENTSO-E row constructor.
func TestNewENTSOERowShape(t *testing.T) {
	row := NewENTSOERow("RPT-001", []byte("<MarketReport/>"))
	if row.Subject != "RPT-001" {
		t.Errorf("Subject = %q, want RPT-001", row.Subject)
	}
	if row.Class != ClassENTSOEXML {
		t.Errorf("Class = %q, want %q", row.Class, ClassENTSOEXML)
	}
	if row.PayloadJSON != "<MarketReport/>" {
		t.Errorf("PayloadJSON = %q, want <MarketReport/>", row.PayloadJSON)
	}
}

// TestAppendRoundTripCohortVerify pins the R175 cold-verify contract:
// a row appended via Ledger.Append can be verified by recomputing
// the canonical bytes + matching the carried Mirror-Mark using the
// PACKAGE-LEVEL Verify (the regulator-side cold-verify path).
func TestAppendRoundTripCohortVerify(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i * 3)
	}
	key := []byte("prod-key-2026")
	marker, _ := mirrormark.NewStdlibMarker(corpus, key)
	l, _ := NewLedger(marker)

	row := CanonicalRow{
		Timestamp:   "2026-05-27T12:00:00Z",
		Subject:     "WPD-WMID",
		Class:       ClassOfgemRIIO,
		PayloadJSON: `{"verdict":"compliant"}`,
	}
	marked, err := l.Append(row)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Regulator-side: recompute canonical bytes + verify mark.
	bs, err := marked.Row.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if err := mirrormark.Verify(corpus, bs, key, marked.Mark); err != nil {
		t.Errorf("regulator cold-verify failed: %v", err)
	}

	// Tampered row: change subject, recompute, expect mismatch.
	tampered := marked.Row
	tampered.Subject = "WPD-WMID-TAMPERED"
	tBytes, _ := tampered.CanonicalBytes()
	if err := mirrormark.Verify(corpus, tBytes, key, marked.Mark); err == nil {
		t.Errorf("regulator cold-verify accepted TAMPERED row, want refusal")
	}
}
