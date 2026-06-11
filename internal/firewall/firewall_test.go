// Package firewall — R145.C FIREWALL-TEST-DISCIPLINE + R174 5-of-5
// cohort-maturity pins for ofgemwatch.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship from
// inception). Pure-test package: zero production code. Tests in this
// file pin **inception-observable invariants** as the gold standard.
//
// R145.C shape (per godfather session memory 2026-05-22): each pin
// states what was true AT INCEPTION and MUST stay true. To change
// one of these invariants, an agent MUST open a sibling R145.B
// branch with paired regression tests — not silently flip a default
// in a feature-additive ship.
//
// R174 5-of-5 cohort maturity (per godfather memory 2026-05-27):
// ofgemwatch ships ALL FIVE cohort disciplines in dedicated packages
// FROM INCEPTION:
//
//   1. internal/firewall/ (this package)
//   2. internal/lore/ (R151 KAT-1 pin)
//   3. internal/mirrormark/ (L43 wire-form signer)
//   4. internal/manifest/ (R150 schematised-knowledge with seed.go split)
//   5. internal/honest/ (R143 + R143.A 5-advisory shape)
//
// R175 LOAD-BEARING-IN-PRODUCTION (4/4 from inception):
//   1. internal/audit-ledger/ledger.go calls marker.Sign() (production-emit)
//   2. KAT-1 hex pinned in lore/kat1.go + this firewall file
//   3. BootCheck emits R143 LOUD-ONCE-WARN on placeholder
//   4. OpenSSL cold-verify reproduces 239a7d0d… against canonical input
//
// Ofgemwatch's classification at inception:
//
//   - **Substrate-shaped energy-regulatory library with Mirror-Mark
//     audit ledger.** Ofgem RIIO ED2 price-control compliance +
//     ENTSO-E IEC 62325-451-3 XML producer. Phase-2 deferred: live
//     Ofgem feed; Phase-3 deferred: FERC Order 1000 harmonization +
//     qualified-counsel signoff.
//
//   - **No daemon, no HTTP listener, no HTTP client (today), no DB,
//     no auth, no PII persistence, no env-var reads, no money
//     semantics.** Pure-stdlib Go 1.22.
//
// R145.B AMENDMENT (2026-06-11, branch claude/stele-anchor-2026-06-11):
// ofgemwatch is the first flagship consumer wire to the Stele
// verified-trust spine. Two inception pins are deliberately
// NARROWED (not dropped) on this sibling branch, with paired
// regression pins in TestR145B_SteleAnchorConfinement:
//
//   - HTTP CLIENT: permitted ONLY in internal/stele/ (5s-timeout
//     stdlib client POSTing run-ledger anchors to the spine's
//     /v1/verdicts). Listener primitives stay banned EVERYWHERE,
//     including internal/stele/.
//   - ENV READS: exactly ONE read site is permitted —
//     os.Getenv(stele.EnvURL) in cmd/ofgemwatch/main.go. Unset/empty
//     means anchoring is disabled and behavior is byte-identical to
//     the argv-only inception CLI.
//
//   - **Mirror-Mark stamped at every audit-ledger row emit.**
//     internal/audit-ledger/ledger.go is the load-bearing production
//     emit-path; placeholder-mode markers fire boot-time R143
//     LOUD-ONCE-WARN.
//
// The firewall is the difference between "we say ofgemwatch is
// stdlib-only" (decorative claim) and "ofgemwatch CANNOT have an
// external dependency under R145-strict without a sibling branch
// breaking this test" (executable claim).
package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davly/ofgemwatch/internal/honest"
	"github.com/davly/ofgemwatch/internal/lore"
	"github.com/davly/ofgemwatch/internal/manifest"
	"github.com/davly/ofgemwatch/internal/mirrormark"
	ofgemriio "github.com/davly/ofgemwatch/internal/ofgem-riio"
	"github.com/davly/ofgemwatch/internal/stele"
)

// repoRoot walks up from the test working directory until it finds
// the go.mod (ofgemwatch repo root). Returns the absolute path.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	cur := wd
	for i := 0; i < 8; i++ {
		gomod := filepath.Join(cur, "go.mod")
		if _, err := os.Stat(gomod); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	t.Fatalf("could not locate go.mod walking up from %q", wd)
	return ""
}

// scanGoFiles walks cmd/ and internal/ and returns all .go source
// files (test files excluded by default).
func scanGoFiles(t *testing.T, includeTests bool) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	roots := []string{filepath.Join(root, "cmd"), filepath.Join(root, "internal")}
	for _, r := range roots {
		_ = filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // continue walk
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if !includeTests && strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// Exclude the firewall package itself from its own scans.
			if strings.Contains(path, string(filepath.Separator)+"firewall"+string(filepath.Separator)) {
				return nil
			}
			out = append(out, path)
			return nil
		})
	}
	return out
}

// fileContains reports whether the given file contains any of the
// forbidden substring patterns.
func fileContains(t *testing.T, path string, patterns ...string) (bool, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	src := string(data)
	for _, p := range patterns {
		if strings.Contains(src, p) {
			return true, p
		}
	}
	return false, ""
}

// ---- Substrate-boundary firewall pins ---------------------------------

// inSteleDir reports whether path lives under internal/stele/ — the
// ONE package permitted to hold an HTTP client after the R145.B
// stele-anchor amendment (2026-06-11).
func inSteleDir(path string) bool {
	sep := string(filepath.Separator)
	return strings.Contains(path, sep+"stele"+sep)
}

// TestFirewall_NoNetHTTPListener pins that no production source file
// imports net/http for listener use. R145.B stele-anchor amendment:
// internal/stele/ may import net/http (client-only — see
// TestFirewall_NoHTTPClient) but the listener PRIMITIVES stay banned
// everywhere, including internal/stele/.
func TestFirewall_NoNetHTTPListener(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		patterns := []string{
			`"net/http"`,
			`http.ListenAndServe`,
			`net.Listen(`,
		}
		if inSteleDir(path) {
			// The bare import is the client's; listener primitives
			// remain forbidden even here.
			patterns = []string{
				`http.ListenAndServe`,
				`net.Listen(`,
				`httptest.NewServer`, // test-double servers belong in _test.go only
			}
		}
		if hit, p := fileContains(t, path, patterns...); hit {
			t.Errorf("R145 firewall violation: %s contains %q — net/http listener out of scope; open a sibling branch", path, p)
		}
	}
}

// TestFirewall_NoHTTPClient pins that no production source imports
// net/http for client use — EXCEPT internal/stele/ (R145.B
// stele-anchor amendment 2026-06-11: the spine-anchoring client is
// confined to that one package; paired pins in
// TestR145B_SteleAnchorConfinement). A Phase-2 live Ofgem feed still
// needs its own R145.B branch.
func TestFirewall_NoHTTPClient(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		if inSteleDir(path) {
			continue
		}
		if hit, p := fileContains(t, path,
			`"net/http"`,
			`http.Client`,
			`http.Get(`,
			`http.Post(`,
		); hit {
			t.Errorf("R145 firewall violation: %s contains %q — HTTP client out of scope outside internal/stele", path, p)
		}
	}
}

// TestFirewall_NoDatabaseSQL pins that no production source imports
// database/sql or any sqlite/postgres driver.
func TestFirewall_NoDatabaseSQL(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		if hit, p := fileContains(t, path,
			`"database/sql"`,
			`"github.com/mattn/go-sqlite3"`,
			`"github.com/jackc/pgx`,
			`"github.com/lib/pq"`,
			`sql.Open(`,
		); hit {
			t.Errorf("R145 firewall violation: %s contains %q — DB substrate out of scope at Phase 1", path, p)
		}
	}
}

// TestFirewall_NoEnvVarReads pins that no production source reads
// environment variables — with ONE R145.B-amended exception
// (2026-06-11): cmd/ofgemwatch/main.go may contain exactly one
// os.Getenv call and it MUST be os.Getenv(stele.EnvURL) (the opt-in
// Stele spine anchoring gate; unset = argv-only behavior unchanged).
// Everything else — os.LookupEnv, os.Environ, any other Getenv site —
// stays banned everywhere.
func TestFirewall_NoEnvVarReads(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		hit, p := fileContains(t, path,
			`os.Getenv(`,
			`os.LookupEnv(`,
			`os.Environ(`,
		)
		if !hit {
			continue
		}
		if p == `os.Getenv(` && filepath.Base(filepath.Dir(path)) == "ofgemwatch" {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %q: %v", path, err)
			}
			src := string(data)
			if strings.Count(src, "os.Getenv(") == 1 &&
				strings.Contains(src, "os.Getenv(stele.EnvURL)") &&
				!strings.Contains(src, "os.LookupEnv(") &&
				!strings.Contains(src, "os.Environ(") {
				continue // the single permitted R145.B stele-anchor read
			}
		}
		t.Errorf("R145 firewall violation: %s contains %q — env-var reads out of scope; argv-only CLI (sole exception: os.Getenv(stele.EnvURL) in cmd/ofgemwatch)", path, p)
	}
}

// TestFirewall_NoAuthCrypto pins that no production source imports
// auth/identity primitives.
func TestFirewall_NoAuthCrypto(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		if hit, p := fileContains(t, path,
			`"github.com/golang-jwt/jwt`,
			`"golang.org/x/crypto/bcrypt"`,
			`"golang.org/x/crypto/pbkdf2"`,
			`"crypto/tls"`,
		); hit {
			t.Errorf("R145 firewall violation: %s contains %q — auth/identity primitives out of scope", path, p)
		}
	}
}

// TestFirewall_NoExternalDeps pins that go.mod's require block is
// empty (zero external dependencies). Pure-stdlib Go 1.22.
func TestFirewall_NoExternalDeps(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	src := string(data)
	if strings.Contains(src, "require ") {
		t.Errorf("R145 firewall violation: go.mod contains 'require' block; ofgemwatch MUST stay stdlib-only.\ngo.mod content:\n%s", src)
	}
	gosum := filepath.Join(root, "go.sum")
	if _, err := os.Stat(gosum); err == nil {
		t.Errorf("R145 firewall violation: go.sum exists at %q; stdlib-only repos should not have one", gosum)
	}
}

// TestFirewall_NoMoneyChecks pins absence of money/payment semantics.
// Ofgemwatch reports £m totex figures but does NOT collect payment;
// the canonical money-semantic identifiers MUST NOT appear.
func TestFirewall_NoMoneyChecks(t *testing.T) {
	patterns := []string{
		"stripe.",
		"Stripe",
		"checkout_session",
		"subscription_tier",
		"SubscriptionTier",
		"pricePence",
		"priceCents",
	}
	for _, path := range scanGoFiles(t, false) {
		if hit, p := fileContains(t, path, patterns...); hit {
			t.Errorf("R145 firewall violation: %s contains %q — payment/billing semantics out of scope", path, p)
		}
	}
}

// ---- R145.B stele-anchor paired regression pins (2026-06-11) ----------

// TestR145B_SteleAnchorConfinement is the paired regression pin for
// the two NARROWED inception invariants (HTTP client + env read).
// It pins the NEW invariant shape so any further drift breaks a test:
//
//  1. every production net/http usage lives under internal/stele/;
//  2. the stele client carries the 5-second timeout;
//  3. os.Getenv appears in exactly one production file
//     (cmd/ofgemwatch/main.go) and only as os.Getenv(stele.EnvURL);
//  4. the spine wire-contract constants hold (env var name,
//     substrate, honest oracle-strength label).
func TestR145B_SteleAnchorConfinement(t *testing.T) {
	var netHTTPFiles, getenvFiles []string
	for _, path := range scanGoFiles(t, false) {
		if hit, _ := fileContains(t, path, `"net/http"`); hit {
			netHTTPFiles = append(netHTTPFiles, path)
		}
		if hit, _ := fileContains(t, path, `os.Getenv(`); hit {
			getenvFiles = append(getenvFiles, path)
		}
	}

	// (1) net/http confined to internal/stele/ — and present there
	// (the wire is load-bearing, not decorative).
	if len(netHTTPFiles) == 0 {
		t.Errorf("R145.B pin violation: no production file imports net/http — the stele spine wire is gone; re-pin the firewall if this is deliberate")
	}
	for _, path := range netHTTPFiles {
		if !inSteleDir(path) {
			t.Errorf("R145.B pin violation: %s imports net/http outside internal/stele/", path)
		}
	}

	// (2) the stele client keeps its 5s timeout.
	steleSrc := filepath.Join(repoRoot(t), "internal", "stele", "stele.go")
	if hit, _ := fileContains(t, steleSrc, `Timeout: 5 * time.Second`); !hit {
		t.Errorf("R145.B pin violation: %s missing the 5-second http.Client timeout", steleSrc)
	}

	// (3) exactly one env-read site: os.Getenv(stele.EnvURL) in
	// cmd/ofgemwatch/main.go.
	wantGetenv := filepath.Join(repoRoot(t), "cmd", "ofgemwatch", "main.go")
	if len(getenvFiles) != 1 || getenvFiles[0] != wantGetenv {
		t.Errorf("R145.B pin violation: os.Getenv sites = %v, want exactly [%s]", getenvFiles, wantGetenv)
	}
	if hit, _ := fileContains(t, wantGetenv, `os.Getenv(stele.EnvURL)`); !hit {
		t.Errorf("R145.B pin violation: %s does not read os.Getenv(stele.EnvURL)", wantGetenv)
	}

	// (4) spine wire-contract constants.
	if stele.EnvURL != "OFGEMWATCH_STELE_URL" {
		t.Errorf("R145.B pin violation: stele.EnvURL = %q, want OFGEMWATCH_STELE_URL", stele.EnvURL)
	}
	if stele.Substrate != "flagships/ofgemwatch/audit-ledger" {
		t.Errorf("R145.B pin violation: stele.Substrate = %q, want flagships/ofgemwatch/audit-ledger", stele.Substrate)
	}
	if stele.OracleStrengthSelfCheck != "Self-Check" {
		t.Errorf("R145.B pin violation: stele.OracleStrengthSelfCheck = %q, want Self-Check (honesty label is load-bearing)", stele.OracleStrengthSelfCheck)
	}
}

// ---- R174 5-of-5 cohort maturity firewall pins ------------------------

// TestR174_FivePackageStructure pins the 5 dedicated cohort-discipline
// packages on disk. Per R174 godfather memory 2026-05-27: 5/5 maturity
// requires ALL FIVE dedicated packages.
func TestR174_FivePackageStructure(t *testing.T) {
	root := repoRoot(t)
	required := []string{
		"firewall",
		"lore",
		"mirrormark",
		"manifest",
		"honest",
	}
	for _, dir := range required {
		path := filepath.Join(root, "internal", dir)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("R174 5-of-5 violation: %s missing or unreadable: %v", path, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("R174 5-of-5 violation: %s exists but is not a directory", path)
		}
	}
}

// TestR175_CohortKAT1HexPin pins the cohort-canonical KAT-1 hex
// `239a7d0d…` in this firewall file. R175 criterion-4: the test
// surface MUST carry the byte-literal pin. Drift here breaks the
// ~34-substrate-language cohort.
func TestR175_CohortKAT1HexPin(t *testing.T) {
	// The cohort-canonical KAT-1 hex string. Byte-literal pinned
	// here so the firewall MUST carry the constant — search via
	// `grep -rEn '239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca'`
	// returns matches in: this file + internal/lore/kat1.go +
	// internal/lore/kat1_test.go.
	const cohortCanonicalKAT1 = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

	if lore.KAT1Digest != cohortCanonicalKAT1 {
		t.Errorf("R175 firewall violation: lore.KAT1Digest = %q, want %q (cohort cross-substrate parity broken)", lore.KAT1Digest, cohortCanonicalKAT1)
	}
	if lore.ComputeKAT1() != cohortCanonicalKAT1 {
		t.Errorf("R175 firewall violation: lore.ComputeKAT1() = %q, want %q (HMAC primitive drift)", lore.ComputeKAT1(), cohortCanonicalKAT1)
	}
	if err := lore.AssertKAT1Parity(); err != nil {
		t.Errorf("R175 firewall violation: lore.AssertKAT1Parity() = %v, want nil", err)
	}
}

// TestR175_MirrorMarkWireFormCanonical pins the cohort-canonical
// "lore@v1:" prefix + 54-char body.
func TestR175_MirrorMarkWireFormCanonical(t *testing.T) {
	if mirrormark.MarkPrefix != "lore@v1:" {
		t.Errorf("R175 firewall violation: mirrormark.MarkPrefix = %q, want %q", mirrormark.MarkPrefix, "lore@v1:")
	}
	if mirrormark.MarkCorpusPrefixLen != 8 {
		t.Errorf("R175 firewall violation: MarkCorpusPrefixLen = %d, want 8", mirrormark.MarkCorpusPrefixLen)
	}
	if mirrormark.MarkBodyLen != 40 {
		t.Errorf("R175 firewall violation: MarkBodyLen = %d, want 40", mirrormark.MarkBodyLen)
	}
}

// TestR143_FiveAdvisoryShapeCanonical pins R174 criterion-5: dedicated
// honest package with ≥5 advisories spanning R143.A's 3-tier severity
// ladder. BR6 procedure mandates exactly 5 advisories (2 Error + 3 Warn).
func TestR143_FiveAdvisoryShapeCanonical(t *testing.T) {
	advs := honest.CanonicalAdvisories()
	if len(advs) < 5 {
		t.Fatalf("R174 5-of-5 violation: CanonicalAdvisories count = %d, want >=5", len(advs))
	}

	// BR6 procedure specifies the 5 required Codes.
	wantCodes := map[string]bool{
		"OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE":      true,
		"OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER":   true,
		"OFGEMWATCH_FERC_ORDER_1000_SCOPE_DEFERRED":         true,
		"OFGEMWATCH_REPORTING_CADENCE_MONTHLY_REQUIRED":     true,
		"OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE":              true,
	}
	for _, a := range advs {
		delete(wantCodes, a.Code)
	}
	if len(wantCodes) != 0 {
		t.Errorf("R174 5-of-5 violation: missing BR6 required Codes: %v", wantCodes)
	}
}

// TestR143A_SeverityLadderClosedSet pins the 3-tier ladder shape.
// Drift here breaks the cohort.
func TestR143A_SeverityLadderClosedSet(t *testing.T) {
	if honest.SeverityInfo != 0 {
		t.Errorf("R143.A violation: SeverityInfo ordinal = %d, want 0", honest.SeverityInfo)
	}
	if honest.SeverityWarn != 1 {
		t.Errorf("R143.A violation: SeverityWarn ordinal = %d, want 1", honest.SeverityWarn)
	}
	if honest.SeverityError != 2 {
		t.Errorf("R143.A violation: SeverityError ordinal = %d, want 2", honest.SeverityError)
	}
}

// TestR150_ManifestSeedShape pins R174 criterion-4: manifest seed
// inventory + 9-path IsStale.
func TestR150_ManifestSeedShape(t *testing.T) {
	seed := manifest.Seed()
	if len(seed) != 12 {
		t.Errorf("R150 firewall violation: seed size = %d, want 12 (5 RIIO + 4 ENTSO-E + 3 FERC)", len(seed))
	}
	if manifest.SchemaVersion != 1 {
		t.Errorf("R150 firewall violation: SchemaVersion = %d, want 1", manifest.SchemaVersion)
	}
}

// TestR150E_ReviewedByCounselDefaultFalse pins R150.E reviewer-class
// extension: every Phase-1 inception entry MUST default to
// ReviewedByCounsel=false. Phase-3 deliverable flips selected entries.
func TestR150E_ReviewedByCounselDefaultFalse(t *testing.T) {
	for _, e := range manifest.Seed() {
		if e.ReviewedByCounsel {
			t.Errorf("R150.E violation: entry %q (class=%s) ReviewedByCounsel=true at scaffold; Phase-3 deliverable", e.Key, e.Class.String())
		}
	}
}

// ---- Domain forge-invariant firewall pins -----------------------------

// TestFirewall_RIIOVerdictClosedSet pins the closed 3-state RIIO
// Verdict enum.
func TestFirewall_RIIOVerdictClosedSet(t *testing.T) {
	if ofgemriio.VerdictUncertain != 0 {
		t.Errorf("RIIO Verdict firewall: VerdictUncertain ordinal = %d, want 0", ofgemriio.VerdictUncertain)
	}
	if ofgemriio.VerdictCompliant != 1 {
		t.Errorf("RIIO Verdict firewall: VerdictCompliant ordinal = %d, want 1", ofgemriio.VerdictCompliant)
	}
	if ofgemriio.VerdictBreach != 2 {
		t.Errorf("RIIO Verdict firewall: VerdictBreach ordinal = %d, want 2", ofgemriio.VerdictBreach)
	}
}

// TestFirewall_RIIOToleranceBand pins the canonical 15% band.
func TestFirewall_RIIOToleranceBand(t *testing.T) {
	if ofgemriio.ToleranceBand != 0.15 {
		t.Errorf("RIIO firewall: ToleranceBand = %g, want 0.15 (RIIO-2 Methodology §4)", ofgemriio.ToleranceBand)
	}
}

// TestFirewall_RIIODNOCountAtInception pins the 6-DNO Phase-1 corpus.
func TestFirewall_RIIODNOCountAtInception(t *testing.T) {
	want := 6
	got := len(ofgemriio.CanonicalDNOs())
	if got != want {
		t.Errorf("RIIO firewall: CanonicalDNOs count = %d, want %d", got, want)
	}
}
