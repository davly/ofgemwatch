// Package stele — minimal stdlib-only client that anchors an
// ofgemwatch run-ledger into the Stele verified-trust spine
// (infrastructure/stele) via POST /v1/verdicts.
//
// 2026-06-11 first flagship consumer wire to the spine (R145.B
// sibling-branch ship; see internal/firewall/ re-pins). This is a
// deliberately LOCAL mirror of the spine wire-contract — the same
// pattern as nexus's internal stele_client — because ofgemwatch's
// go.mod is stdlib-only (TestFirewall_NoExternalDeps) and MUST NOT
// import the stele Go module.
//
// OFF BY DEFAULT: the CLI anchors only when OFGEMWATCH_STELE_URL is
// set (see EnvURL). Unset/empty = disabled = no HTTP, no new output,
// behavior identical to a non-anchoring build.
//
// HONESTY CONTRACT (load-bearing):
//
//   - The anchor verdict is LIT only after the run-ledger passes
//     auditledger.SelfCheck(). A failed self-check seals NOTHING and
//     the CLI fails loudly.
//   - oracle_strength is "Self-Check" and the evidence sentence says
//     so explicitly: the oracle is ofgemwatch's own ledger verifier,
//     NOT an independent gauntlet.
//   - subject_hash binds the spine entry to the exact ledger content:
//     sha256 hex over the canonical run serialization defined at
//     auditledger.(*Ledger).SelfCheck (JSONL of MarkedRow in append
//     order).
//   - A "sealed" receipt is only ever reported on HTTP 201 WITH an
//     entry_hash in the response body.
package stele

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EnvURL is the environment variable holding the Stele spine base URL
// (e.g. "http://localhost:8097"). Empty/unset disables anchoring
// entirely. This is the ONE env read ofgemwatch performs; the R145
// firewall pins it to a single call site in cmd/ofgemwatch.
const EnvURL = "OFGEMWATCH_STELE_URL"

// Substrate is the spine substrate identifier for ofgemwatch's
// run-ledger anchors.
const Substrate = "flagships/ofgemwatch/audit-ledger"

// OracleStrengthSelfCheck is the honest oracle-strength label for a
// run-ledger anchor: the verifier is ofgemwatch itself.
const OracleStrengthSelfCheck = "Self-Check"

// Verdict is the POST /v1/verdicts request body — a local mirror of
// the spine's verdictRequest wire contract
// (infrastructure/stele/internal/api/server.go).
type Verdict struct {
	Substrate      string `json:"substrate"`
	Verdict        string `json:"verdict"`
	Severity       string `json:"severity"`
	Location       string `json:"location"`
	Evidence       string `json:"evidence"`
	OracleStrength string `json:"oracle_strength"`
	SealedAt       string `json:"sealed_at"`
	GauntletRun    string `json:"gauntlet_run"`
	SubjectHash    string `json:"subject_hash"`
}

// Receipt is the spine's proof-of-seal: the sealed entry's sequence
// number + entry hash from the 201 response.
type Receipt struct {
	Seq       int
	EntryHash string
}

// SelfChecker is the slice of *auditledger.Ledger the anchor consumes
// (kept as a local interface so this package stays decoupled and the
// seam is trivially fakeable in tests).
type SelfChecker interface {
	SelfCheck() (int, [sha256.Size]byte, error)
}

// Client is a minimal HTTP client for the Stele spine. 5s timeout,
// stdlib only.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient constructs a Client for the given spine base URL.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		http: &http.Client{
			Timeout: 5 * time.Second,
			// REFUSE to follow redirects. This is ofgemwatch's only
			// production outbound path and the POSTed verdict carries the
			// full subject_hash + evidence. A compromised/misconfigured
			// spine that returns a 30x must NOT cause that body to be
			// re-sent to an unconfigured (possibly internal/link-local)
			// host (SSRF / data-exfil). ErrUseLastResponse returns the
			// redirect response unfollowed; Seal's strict StatusCode != 201
			// check then turns it into a clean error without re-POSTing.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// NewRunAnchor builds the canonical run-anchor verdict for a command's
// ledger. Callers MUST only invoke this after a PASSING SelfCheck —
// the verdict is unconditionally LIT because the no-pass path seals
// nothing at all (fail-loud, enforced in AnchorRun).
func NewRunAnchor(command string, entries int, ledgerDigest [sha256.Size]byte, sealedAt time.Time) Verdict {
	digestHex := hex.EncodeToString(ledgerDigest[:])
	return Verdict{
		Substrate: Substrate,
		Verdict:   "LIT",
		Severity:  "n/a",
		Location:  Substrate + "@" + command,
		Evidence: fmt.Sprintf(
			"run self-check: %d entries, ledger digest %s; oracle is ofgemwatch's own ledger verifier (self-check, NOT an independent gauntlet)",
			entries, digestHex[:16]),
		OracleStrength: OracleStrengthSelfCheck,
		SealedAt:       sealedAt.UTC().Format(time.RFC3339),
		GauntletRun:    "",
		SubjectHash:    digestHex,
	}
}

// Seal POSTs the verdict to /v1/verdicts and returns the spine
// receipt. It returns an error — and the caller MUST NOT claim the
// anchor happened — unless the spine answered 201 Created with a
// non-empty entry_hash.
func (c *Client) Seal(v Verdict) (Receipt, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return Receipt{}, fmt.Errorf("stele seal: marshal: %w", err)
	}
	resp, err := c.http.Post(c.baseURL+"/v1/verdicts", "application/json", bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("stele seal: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Receipt{}, fmt.Errorf("stele seal: read response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return Receipt{}, fmt.Errorf("stele seal: status %d (want 201): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		Sealed struct {
			Seq       int    `json:"seq"`
			EntryHash string `json:"entry_hash"`
		} `json:"sealed"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return Receipt{}, fmt.Errorf("stele seal: decode response: %w", err)
	}
	if out.Sealed.EntryHash == "" {
		return Receipt{}, errors.New("stele seal: got 201 but no sealed.entry_hash in response — refusing to claim anchored")
	}
	return Receipt{Seq: out.Sealed.Seq, EntryHash: out.Sealed.EntryHash}, nil
}

// AnchorRun is the single CLI anchoring seam.
//
//   - url empty/whitespace → DISABLED: returns (zero, false, nil)
//     without touching the ledger or the network (zero behavior
//     change vs. a non-anchoring run).
//   - ledger self-check fails → seals NOTHING, returns a non-nil
//     error (an integrity-suspect ledger must never be anchored LIT).
//   - seal fails (network / non-201 / no entry_hash) → non-nil error;
//     anchored stays false.
//   - success → (receipt, true, nil); only then may the caller print
//     a sealed claim.
func AnchorRun(url, command string, ledger SelfChecker, now time.Time) (Receipt, bool, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return Receipt{}, false, nil
	}
	entries, digest, err := ledger.SelfCheck()
	if err != nil {
		return Receipt{}, false, fmt.Errorf("refusing to anchor: %w", err)
	}
	rcpt, err := NewClient(url).Seal(NewRunAnchor(command, entries, digest, now))
	if err != nil {
		return Receipt{}, false, err
	}
	return rcpt, true, nil
}
