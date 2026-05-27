package mirrormark

import (
	"bytes"
	"crypto/sha256"
	"log"
	"os"
	"strings"
	"testing"
)

// TestMarkPrefixCohortCanonical pins the "lore@v1:" prefix.
// Drift here breaks every cohort port's wire-form interop.
func TestMarkPrefixCohortCanonical(t *testing.T) {
	if MarkPrefix != "lore@v1:" {
		t.Errorf("MarkPrefix = %q, want %q (cohort-canonical wire-form)", MarkPrefix, "lore@v1:")
	}
}

// TestMarkBodyLenCohortCanonical pins the 40-byte body length.
// 8-byte corpus prefix + 32-byte HMAC-SHA256 digest = 40 bytes.
func TestMarkBodyLenCohortCanonical(t *testing.T) {
	if MarkCorpusPrefixLen != 8 {
		t.Errorf("MarkCorpusPrefixLen = %d, want 8", MarkCorpusPrefixLen)
	}
	if MarkBodyLen != 40 {
		t.Errorf("MarkBodyLen = %d, want 40 (8-byte corpus + 32-byte HMAC)", MarkBodyLen)
	}
}

// TestSignDeterministic pins that identical inputs produce identical
// output bytes — the cohort-canonical determinism contract.
func TestSignDeterministic(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i)
	}
	key := []byte("test-key")
	payload := []byte("ofgemwatch-audit-row-canonical-bytes")

	a := Sign(corpus, payload, key)
	b := Sign(corpus, payload, key)
	if a != b {
		t.Errorf("Sign non-deterministic: %q vs %q", a, b)
	}
}

// TestSignWireFormat pins the wire-form invariants:
//   - prefix is "lore@v1:"
//   - total length is 62 characters (8 prefix + 54 base64url body)
func TestSignWireFormat(t *testing.T) {
	var corpus [sha256.Size]byte
	mark := Sign(corpus, []byte("payload"), []byte("k"))

	if !strings.HasPrefix(mark, MarkPrefix) {
		t.Errorf("Sign() = %q, missing prefix %q", mark, MarkPrefix)
	}
	if len(mark) != 62 {
		t.Errorf("Sign() length = %d, want 62 (8 prefix + 54 body)", len(mark))
	}
}

// TestSignWithEmptyKey returns a mark (no fail-closed at package-Sign
// level — fail-closed lives at NewStdlibMarker constructor + Verify).
func TestSignWithEmptyKey(t *testing.T) {
	var corpus [sha256.Size]byte
	mark := Sign(corpus, []byte("payload"), nil)
	if !strings.HasPrefix(mark, MarkPrefix) {
		t.Errorf("Sign() with empty key produced malformed mark: %q", mark)
	}
}

// TestVerifyRoundTrip pins that Sign + Verify round-trip cleanly.
func TestVerifyRoundTrip(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(7 * i)
	}
	key := []byte("ofgem-prod-key-2026")
	payload := []byte(`{"row":"riio-ed2-cf-2026-q3","value":12345}`)

	mark := Sign(corpus, payload, key)
	if err := Verify(corpus, payload, key, mark); err != nil {
		t.Errorf("Verify() = %v, want nil for matching inputs", err)
	}
}

// TestVerifyRejectsTamperedPayload pins that any payload byte change
// fails verify (HMAC integrity property).
func TestVerifyRejectsTamperedPayload(t *testing.T) {
	var corpus [sha256.Size]byte
	key := []byte("ofgem-prod-key-2026")
	payload := []byte("original-audit-row")
	tampered := []byte("tampered-audit-row")

	mark := Sign(corpus, payload, key)
	if err := Verify(corpus, tampered, key, mark); err == nil {
		t.Errorf("Verify() = nil for tampered payload, want ErrMarkMismatch")
	}
}

// TestVerifyRejectsWrongKey pins that a different key fails verify.
func TestVerifyRejectsWrongKey(t *testing.T) {
	var corpus [sha256.Size]byte
	keyA := []byte("ofgem-prod-key-2026")
	keyB := []byte("entso-e-prod-key-2026")
	payload := []byte("audit-row")

	mark := Sign(corpus, payload, keyA)
	if err := Verify(corpus, payload, keyB, mark); err == nil {
		t.Errorf("Verify() = nil for wrong key, want ErrMarkMismatch")
	}
}

// TestVerifyRejectsEmptyKey pins that Verify fail-closed on empty key.
func TestVerifyRejectsEmptyKey(t *testing.T) {
	var corpus [sha256.Size]byte
	if err := Verify(corpus, []byte("p"), nil, "lore@v1:x"); err != ErrEmptyKey {
		t.Errorf("Verify() with empty key = %v, want ErrEmptyKey", err)
	}
}

// TestNewStdlibMarkerRejectsEmptyKey pins the constructor fail-closed.
func TestNewStdlibMarkerRejectsEmptyKey(t *testing.T) {
	var corpus [sha256.Size]byte
	if _, err := NewStdlibMarker(corpus, nil); err != ErrEmptyKey {
		t.Errorf("NewStdlibMarker(empty key) = %v, want ErrEmptyKey", err)
	}
	if _, err := NewStdlibMarker(corpus, []byte{}); err != ErrEmptyKey {
		t.Errorf("NewStdlibMarker(zero-byte key) = %v, want ErrEmptyKey", err)
	}
}

// TestStdlibMarkerSignMatches pins that StdlibMarker.Sign(p) ==
// package Sign(corpus, p, key).
func TestStdlibMarkerSignMatches(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = 0x42
	}
	key := []byte("production-key")
	payload := []byte("audit-row-payload")

	m, err := NewStdlibMarker(corpus, key)
	if err != nil {
		t.Fatalf("NewStdlibMarker error: %v", err)
	}
	got := m.Sign(payload)
	want := Sign(corpus, payload, key)
	if got != want {
		t.Errorf("StdlibMarker.Sign() = %q, want %q (package Sign byte-identical)", got, want)
	}
}

// TestPlaceholderMarkerWarnsOnce pins R143 LOUD-ONCE-WARN behaviour:
// the first Sign on placeholder mode emits one warning; subsequent
// calls are silent.
func TestPlaceholderMarkerWarnsOnce(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr) // restore default logger output

	m := NewPlaceholderMarker()
	if !m.UsingPlaceholder() {
		t.Errorf("NewPlaceholderMarker.UsingPlaceholder() = false, want true")
	}

	m.Sign([]byte("first"))
	m.Sign([]byte("second"))
	m.Sign([]byte("third"))

	out := buf.String()
	count := strings.Count(out, "[LOUD-ONCE-WARNING]")
	if count != 1 {
		t.Errorf("LOUD-ONCE-WARNING emit count = %d, want 1 (loud-once contract)", count)
	}
	if !strings.Contains(out, "placeholder key") {
		t.Errorf("LOUD-ONCE-WARNING missing 'placeholder key' substring: %q", out)
	}
}

// TestPlaceholderVerifyRefuses pins that placeholder-mode markers
// refuse Verify at the boundary (regulator-cold-verify shape).
func TestPlaceholderVerifyRefuses(t *testing.T) {
	m := NewPlaceholderMarker()
	mark := m.Sign([]byte("p"))
	if err := m.Verify([]byte("p"), mark); err != ErrMarkerNotConfigured {
		t.Errorf("Placeholder Verify() = %v, want ErrMarkerNotConfigured", err)
	}
}

// TestStdlibMarkerCorpusSHACopy pins that CorpusSHA returns a copy so
// callers cannot mutate marker state.
func TestStdlibMarkerCorpusSHACopy(t *testing.T) {
	var corpus [sha256.Size]byte
	corpus[0] = 0xAB
	key := []byte("k")
	m, err := NewStdlibMarker(corpus, key)
	if err != nil {
		t.Fatalf("NewStdlibMarker: %v", err)
	}
	got := m.CorpusSHA()
	got[0] = 0xCD // mutate the copy
	got2 := m.CorpusSHA()
	if got2[0] != 0xAB {
		t.Errorf("CorpusSHA returned shared state: post-mutation [0] = 0x%02x, want 0xAB", got2[0])
	}
}

// TestKAT1MarkRoundTrip pins the canonical KAT-1 mark string.
// Byte-identical to the cohort KAT1Mark across every port. This is
// the cohort cross-substrate wire-form anchor.
func TestKAT1MarkRoundTrip(t *testing.T) {
	var zeroCorpus [sha256.Size]byte
	mark := Sign(zeroCorpus, nil, nil)
	const wantKAT1Mark = "lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg"
	if mark != wantKAT1Mark {
		t.Errorf("KAT-1 mark = %q, want %q (cohort cross-substrate wire-form anchor)", mark, wantKAT1Mark)
	}
}
