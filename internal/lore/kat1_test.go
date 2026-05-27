package lore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestKAT1DigestLiteral pins the cohort-canonical hex string at
// ofgemwatch's boundary. Byte-equality is the contract: any drift on
// KAT1Digest breaks the ~34-substrate-language cohort.
func TestKAT1DigestLiteral(t *testing.T) {
	want := "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"
	if KAT1Digest != want {
		t.Errorf("KAT-1 cohort-canonical drift: KAT1Digest = %q, want %q", KAT1Digest, want)
	}
	// Format invariants: lowercase, 64 chars, valid hex.
	if KAT1Digest != strings.ToLower(KAT1Digest) {
		t.Errorf("KAT1Digest = %q has uppercase chars; cohort canonical is lowercase", KAT1Digest)
	}
	if len(KAT1Digest) != 64 {
		t.Errorf("KAT1Digest length = %d, want 64 (SHA-256 hex)", len(KAT1Digest))
	}
	if _, err := hex.DecodeString(KAT1Digest); err != nil {
		t.Errorf("KAT1Digest is not valid hex: %v", err)
	}
}

// TestKAT1InputCanonical pins the canonical KAT-1 input bytes.
// 0x01 first byte || 32 zero bytes = 33 bytes total.
func TestKAT1InputCanonical(t *testing.T) {
	if KAT1InputFirstByte != 0x01 {
		t.Errorf("KAT1InputFirstByte = 0x%02x, want 0x01 (cohort canonical)", KAT1InputFirstByte)
	}
	if KAT1InputZeroPadLen != 32 {
		t.Errorf("KAT1InputZeroPadLen = %d, want 32 (cohort canonical)", KAT1InputZeroPadLen)
	}
	got := KAT1Input()
	if len(got) != 33 {
		t.Fatalf("KAT1Input length = %d, want 33", len(got))
	}
	if got[0] != 0x01 {
		t.Errorf("KAT1Input()[0] = 0x%02x, want 0x01", got[0])
	}
	for i := 1; i < 33; i++ {
		if got[i] != 0x00 {
			t.Errorf("KAT1Input()[%d] = 0x%02x, want 0x00", i, got[i])
		}
	}
}

// TestKAT1InputIsFreshCopy pins that KAT1Input returns a freshly-
// allocated slice — callers can mutate without affecting future calls.
func TestKAT1InputIsFreshCopy(t *testing.T) {
	a := KAT1Input()
	a[5] = 0xFF // mutate
	b := KAT1Input()
	if b[5] != 0x00 {
		t.Errorf("KAT1Input() returned shared state: post-mutation b[5] = 0x%02x, want 0x00", b[5])
	}
}

// TestComputeKAT1MatchesAnchor pins that the live Go HMAC-SHA256
// computation reproduces the cohort-canonical hex byte-identically.
// This is the live cross-substrate parity check.
func TestComputeKAT1MatchesAnchor(t *testing.T) {
	got := ComputeKAT1()
	if got != KAT1Digest {
		t.Errorf("ComputeKAT1() = %q, want %q (cohort-canonical anchor drift)", got, KAT1Digest)
	}
}

// TestVerifyKAT1NilOnMatch pins that VerifyKAT1 returns nil when the
// live computation matches the pinned hex.
func TestVerifyKAT1NilOnMatch(t *testing.T) {
	if err := VerifyKAT1(); err != nil {
		t.Errorf("VerifyKAT1() = %v, want nil", err)
	}
}

// TestAssertKAT1Parity pins that the cohort-canonical exported helper
// returns nil on parity. R155.A sub-class 8 firewall: the helper MUST
// exist on disk to satisfy VERDICT-OVERCLAIMS-WIRE-SHIP.
func TestAssertKAT1Parity(t *testing.T) {
	if err := AssertKAT1Parity(); err != nil {
		t.Errorf("AssertKAT1Parity() = %v, want nil", err)
	}
}

// TestKATMismatchErrorMessage pins the error surface (forensic-
// readability requirement — operator should see both computed +
// expected without re-running the recipe).
func TestKATMismatchErrorMessage(t *testing.T) {
	err := &KATMismatchError{
		Vector:   "KAT-1",
		Computed: "0000000000000000000000000000000000000000000000000000000000000000",
		Expected: KAT1Digest,
	}
	msg := err.Error()
	wantSubstrs := []string{
		"KAT-1",
		"computed=0000000000000000000000000000000000000000000000000000000000000000",
		"expected=" + KAT1Digest,
		"cohort-canonical",
	}
	for _, want := range wantSubstrs {
		if !strings.Contains(msg, want) {
			t.Errorf("KATMismatchError.Error() = %q, missing substring %q", msg, want)
		}
	}
}

// TestComputeKAT1Deterministic pins that recomputing yields identical
// bytes — required for offline parity check (regulator can re-run
// against the same recipe and get identical output).
func TestComputeKAT1Deterministic(t *testing.T) {
	a := ComputeKAT1()
	b := ComputeKAT1()
	if a != b {
		t.Errorf("ComputeKAT1 non-deterministic: %q vs %q", a, b)
	}
}

// TestComputeKAT1RecipeCorrespondence pins that ComputeKAT1 uses
// EXACTLY the same primitive shape as the OpenSSL recipe documented
// in the package doc-comment: HMAC-SHA256 with empty key.
func TestComputeKAT1RecipeCorrespondence(t *testing.T) {
	// Recompute manually using the documented recipe shape.
	input := make([]byte, 33)
	input[0] = 0x01
	// remaining 32 bytes are zero per make()

	mac := hmac.New(sha256.New, []byte{}) // empty key
	mac.Write(input)
	gotHex := hex.EncodeToString(mac.Sum(nil))

	if gotHex != KAT1Digest {
		t.Errorf("doc-recipe correspondence broken: HMAC-SHA256 of (0x01 || 32×0x00) with empty key = %q, want %q", gotHex, KAT1Digest)
	}
	if gotHex != ComputeKAT1() {
		t.Errorf("ComputeKAT1() diverged from recipe: ComputeKAT1=%q, recipe=%q", ComputeKAT1(), gotHex)
	}
}
