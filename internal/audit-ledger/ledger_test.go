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

// TestSelfCheckGreenAndDeterministic pins the SelfCheck contract used
// by Stele spine anchoring: a healthy ledger self-checks green, and
// the canonical run serialization is deterministic — the same rows in
// the same order produce the same digest across independent ledgers.
func TestSelfCheckGreenAndDeterministic(t *testing.T) {
	var corpus [sha256.Size]byte
	rowA := CanonicalRow{
		Timestamp:   "2026-06-11T12:00:00Z",
		Subject:     "WPD-WMID",
		Class:       ClassOfgemRIIO,
		PayloadJSON: `{"verdict":"compliant"}`,
	}
	rowB := CanonicalRow{
		Timestamp:   "2026-06-11T12:00:01Z",
		Subject:     "RPT-001",
		Class:       ClassENTSOEXML,
		PayloadJSON: `<MarketReport/>`,
	}

	build := func(rows ...CanonicalRow) *Ledger {
		marker, _ := mirrormark.NewStdlibMarker(corpus, []byte("k"))
		l, _ := NewLedger(marker)
		for _, r := range rows {
			if _, err := l.Append(r); err != nil {
				t.Fatalf("Append: %v", err)
			}
		}
		return l
	}

	l1 := build(rowA, rowB)
	n1, d1, err := l1.SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on healthy ledger: %v", err)
	}
	if n1 != 2 {
		t.Errorf("SelfCheck count = %d, want 2", n1)
	}
	var zero [sha256.Size]byte
	if d1 == zero {
		t.Errorf("SelfCheck digest is zero for a non-empty ledger")
	}

	// Determinism: an independent ledger with the same rows in the
	// same order produces the same digest.
	_, d2, err := build(rowA, rowB).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on second ledger: %v", err)
	}
	if d1 != d2 {
		t.Errorf("SelfCheck digest non-deterministic: %x vs %x", d1, d2)
	}

	// Order-sensitivity: append order is load-bearing for an
	// append-only ledger — swapping rows MUST change the digest.
	_, d3, err := build(rowB, rowA).SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on swapped ledger: %v", err)
	}
	if d3 == d1 {
		t.Errorf("SelfCheck digest insensitive to row order: %x", d3)
	}
}

// TestSelfCheckDetectsTamper pins the integrity half of SelfCheck:
// post-Append mutation of row content or carried mark MUST fail the
// self-check (this is the gate that keeps a tampered ledger from
// being anchored LIT into the Stele spine).
func TestSelfCheckDetectsTamper(t *testing.T) {
	var corpus [sha256.Size]byte
	row := CanonicalRow{
		Timestamp:   "2026-06-11T12:00:00Z",
		Subject:     "WPD-WMID",
		Class:       ClassOfgemRIIO,
		PayloadJSON: `{"verdict":"compliant"}`,
	}

	// Tampered row content.
	marker, _ := mirrormark.NewStdlibMarker(corpus, []byte("k"))
	l, _ := NewLedger(marker)
	_, _ = l.Append(row)
	l.rows[0].Row.Subject = "WPD-WMID-TAMPERED"
	if _, _, err := l.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a tampered row subject, want failure")
	}

	// Tampered mark (still cohort-prefixed so the prefix gate alone
	// cannot catch it).
	marker2, _ := mirrormark.NewStdlibMarker(corpus, []byte("k"))
	l2, _ := NewLedger(marker2)
	marked, _ := l2.Append(row)
	l2.rows[0].Mark = marked.Mark[:len(marked.Mark)-2] + "xx"
	if _, _, err := l2.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a tampered mark, want failure")
	}

	// Mark missing the cohort prefix entirely.
	marker3, _ := mirrormark.NewStdlibMarker(corpus, []byte("k"))
	l3, _ := NewLedger(marker3)
	_, _ = l3.Append(row)
	l3.rows[0].Mark = "not-a-mark"
	if _, _, err := l3.SelfCheck(); err == nil {
		t.Errorf("SelfCheck accepted a prefix-less mark, want failure")
	}
}

// TestSelfCheckEmptyLedger pins the empty-ledger shape: zero rows is
// not an integrity failure (count 0, the sha256 of the empty stream,
// nil error).
func TestSelfCheckEmptyLedger(t *testing.T) {
	var corpus [sha256.Size]byte
	marker, _ := mirrormark.NewStdlibMarker(corpus, []byte("k"))
	l, _ := NewLedger(marker)
	n, d, err := l.SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck on empty ledger: %v", err)
	}
	if n != 0 {
		t.Errorf("SelfCheck count = %d, want 0", n)
	}
	if got, want := d, sha256.Sum256(nil); got != want {
		t.Errorf("empty-ledger digest = %x, want sha256 of empty stream %x", got, want)
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
