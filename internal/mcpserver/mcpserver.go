// Package mcpserver — Nexus-facing MCP-tool producer surface for
// ofgemwatch (Shape-1 capability-hub integration).
//
// 2026-06-02 capability-exposure ship. This is the ONLY package in
// ofgemwatch that imports net/http or reads environment variables;
// the firewall test (`internal/firewall/firewall_test.go`) scopes its
// no-HTTP / no-env invariants to EXCLUDE this package + the
// `cmd/ofgemwatch-server` host, landed together on the same R145.B
// branch with paired regression. The CLI + every domain package
// (`internal/ofgem-riio`, `internal/audit-ledger`, `internal/entso-e`,
// `internal/mirrormark`, `internal/honest`, `internal/lore`,
// `internal/manifest`) stay strictly stdlib-only / HTTP-free.
//
// Why this exists (capability-hub thesis, ADR-001): consumer apps
// integrate ONLY with Nexus; Nexus routes to producers BY CAPABILITY.
// ofgemwatch exposes the genuinely-consumer-valuable, deterministic
// RIIO-ED2 price-control compliance verdict as a Nexus-routable tool.
// The tool NAME (`ofgemwatch.riio_compliance_verdict`) IS the routing
// key — Nexus needs no per-capability Go code for this Shape-1 leg
// (it loads the manifest and registers a thin HTTP forwarder).
//
// Trust boundary (two tokens, never confused):
//
//   - X-Nexus-Service-Token = MACHINE trust (Nexus <-> ofgemwatch).
//     Shared secret. Constant-time compared. FAIL-CLOSED: if the
//     configured secret is empty/UNSET, EVERY request gets 401 —
//     never fail-open. (A P0 of exactly this class — a producer that
//     answered when its token env was unset — was found in the
//     2026-06-01 capability wave; this server refuses to.)
//
//   - X-User-Id = PROVENANCE — who originated the request. Nexus sets
//     it only after validating the end-user JWT. 400 if absent. It is
//     recorded into the audit-ledger row (RequestedBy field of the
//     payload) so the Mirror-Mark-stamped receipt carries originating
//     provenance.
//
// Honest scoping (self-declared by the engine, surfaced to consumers):
// RIIO verdicts run against the 6-DNO Phase-1 canned-fixture corpus
// (the verdict MATH is general and is also exposed via the raw
// {determination,reported} pair form). Every response carries a
// `caveats` array echoing the engine's two boot-time R143 Error
// advisories so a downstream consumer can never silently treat
// scaffold output as regulator-load-bearing.
package mcpserver

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	auditledger "github.com/davly/ofgemwatch/internal/audit-ledger"
	"github.com/davly/ofgemwatch/internal/honest"
	ofgemriio "github.com/davly/ofgemwatch/internal/ofgem-riio"
)

const (
	// CapabilityToolName is the Nexus routing key for the RIIO
	// compliance-verdict capability. Format: {project}.{verb_noun}.
	CapabilityToolName = "ofgemwatch.riio_compliance_verdict"

	// serviceTokenHeader carries the machine-trust shared secret.
	serviceTokenHeader = "X-Nexus-Service-Token"

	// userIDHeader carries the originating-end-user provenance.
	userIDHeader = "X-User-Id"

	// maxRequestBytes caps the invoke request body (matches the order
	// of magnitude of the Nexus loader's read posture; verdict inputs
	// are tiny).
	maxRequestBytes = 1 << 20 // 1 MiB
)

// Tool is one entry in the GET /mcp/tools/ manifest. Mirrors the
// shape the Nexus FlagshipToolLoader flattens into an ai.Tool.
type Tool struct {
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	InputSchema      json.RawMessage `json:"input_schema"`
	ApprovalRequired bool            `json:"approval_required"`
}

// manifestResponse is the GET /mcp/tools/ body.
type manifestResponse struct {
	Tools []Tool `json:"tools"`
}

// invokeResponse is the POST /mcp/tools/{name} envelope Nexus unwraps.
type invokeResponse struct {
	Content      json.RawMessage `json:"content"`
	IsError      bool            `json:"is_error"`
	ErrorMessage string          `json:"error_message,omitempty"`
}

// verdictRequest is the input for ofgemwatch.riio_compliance_verdict.
// EITHER dno_id (looked up in the canonical corpus) OR a raw
// {determination_totex_million_gbp, reported_totex_million_gbp} pair
// (the verdict math is general). dno_id takes precedence if both are
// supplied.
type verdictRequest struct {
	DNOID                        string   `json:"dno_id,omitempty"`
	DeterminationTotexMillionGBP *float64 `json:"determination_totex_million_gbp,omitempty"`
	ReportedTotexMillionGBP      *float64 `json:"reported_totex_million_gbp,omitempty"`
}

// verdictResult is the content payload for a successful verdict. Band
// edges are returned so the consumer can see WHY a verdict landed.
type verdictResult struct {
	DNOID                        string   `json:"dno_id,omitempty"`
	Region                       string   `json:"region,omitempty"`
	DeterminationTotexMillionGBP float64  `json:"determination_totex_million_gbp"`
	ReportedTotexMillionGBP      float64  `json:"reported_totex_million_gbp"`
	Verdict                      string   `json:"verdict"`
	DeltaPct                     float64  `json:"delta_pct"`
	ToleranceBand                float64  `json:"tolerance_band"`
	LowerBandMillionGBP          float64  `json:"lower_band_million_gbp"`
	UpperBandMillionGBP          float64  `json:"upper_band_million_gbp"`
	Mark                         string   `json:"mark"`
	AuditTS                      string   `json:"audit_ts"`
	RequestedBy                  string   `json:"requested_by"`
	Caveats                      []string `json:"caveats"`
}

// riioVerdictInputSchema is the JSON-Schema for the verdict tool input.
var riioVerdictInputSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "dno_id": {
      "type": "string",
      "description": "Canonical Ofgem DNO identifier (e.g. WPD-WMID). Looked up in the 6-DNO Phase-1 canonical corpus. Mutually exclusive with the raw totex pair; dno_id takes precedence."
    },
    "determination_totex_million_gbp": {
      "type": "number",
      "description": "Ofgem final-determination totex allowance (GBP millions). Supply with reported_totex_million_gbp to compute a verdict on an arbitrary pair (the verdict math is general)."
    },
    "reported_totex_million_gbp": {
      "type": "number",
      "description": "DNO reported totex spend to date (GBP millions)."
    }
  },
  "additionalProperties": false
}`)

// Handler is the Nexus-facing MCP producer. It holds the configured
// service token and an audit-ledger factory. It is goroutine-safe:
// a fresh ledger is constructed per invoke so the Mirror-Mark stamp
// is isolated per request (no shared mutable state across requests).
type Handler struct {
	// serviceToken is the configured machine-trust shared secret. An
	// EMPTY value means "no secret configured" => fail-closed 401 for
	// every request.
	serviceToken string

	// newLedger builds the per-invoke audit ledger. Injectable for
	// tests; defaults to a placeholder-marker-backed in-memory ledger
	// (the Phase-1 scaffold posture — placeholder marks are tamper-
	// evident but cold-verify refuses them at a real regulator
	// boundary, which is correct and honest until Phase-2 wires a key).
	newLedger func() (*auditledger.Ledger, error)
}

// NewHandler constructs a Handler with the given service token. An
// empty token is permitted at construction (the server still boots)
// but EVERY request will then 401 — fail-closed. The operator must
// set OFGEMWATCH_NEXUS_SERVICE_TOKEN to a non-empty value to make the
// surface reachable.
func NewHandler(serviceToken string) *Handler {
	return &Handler{
		serviceToken: serviceToken,
		newLedger:    auditledger.NewScaffoldLedger,
	}
}

// Mount registers the /mcp/tools routes on mux. This route group is
// mounted with NO app-wide auth middleware in front of it (this is a
// dedicated server; STEP-1.5) — the ONLY trust gate is the constant-
// time service-token check inside each handler, fail-closed.
func (h *Handler) Mount(mux *http.ServeMux) {
	// Manifest: GET /mcp/tools/
	mux.HandleFunc("/mcp/tools/", h.route)
}

// route dispatches GET (manifest) vs POST (invoke) on /mcp/tools/.
func (h *Handler) route(w http.ResponseWriter, r *http.Request) {
	// Trust gate FIRST — before any method/path branching — so an
	// unauthenticated probe learns nothing about the surface shape.
	if !h.authOK(r) {
		writeStatus(w, http.StatusUnauthorized, "unauthorized: invalid or missing X-Nexus-Service-Token")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if r.URL.Path == "/mcp/tools/" {
			h.handleManifest(w, r)
			return
		}
		writeStatus(w, http.StatusNotFound, "not found")
	case http.MethodPost:
		// POST /mcp/tools/{name}
		name := r.URL.Path[len("/mcp/tools/"):]
		h.handleInvoke(w, r, name)
	default:
		writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// authOK is the FAIL-CLOSED machine-trust gate. Returns false (=> 401)
// whenever the configured secret is empty OR the presented header does
// not constant-time-match it. Never fails open.
func (h *Handler) authOK(r *http.Request) bool {
	if h.serviceToken == "" {
		// No secret configured => deny everything. This is the P0
		// guard: a producer with an unset token env must NOT answer.
		return false
	}
	presented := r.Header.Get(serviceTokenHeader)
	if presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.serviceToken)) == 1
}

// handleManifest serves GET /mcp/tools/ — the tool catalogue Nexus
// loads at startup.
func (h *Handler) handleManifest(w http.ResponseWriter, _ *http.Request) {
	resp := manifestResponse{
		Tools: []Tool{
			{
				Name:             CapabilityToolName,
				Description:      "Compute an Ofgem RIIO-ED2 price-control compliance verdict (compliant/breach/uncertain) for a DNO's totex against its determination band (+/-15%), with a Mirror-Mark-stamped tamper-evident audit row. Accepts a canonical dno_id OR a raw {determination,reported} totex pair. NOTE: dno_id lookups use a Phase-1 canned-fixture corpus (see the caveats field on every response).",
				InputSchema:      riioVerdictInputSchema,
				ApprovalRequired: false, // read-only deterministic computation
			},
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleInvoke serves POST /mcp/tools/{name}. Enforces provenance
// (X-User-Id), routes by tool name, runs the real engine, stamps the
// audit ledger, and returns the {content,is_error,error_message}
// envelope. Engine-level failures (e.g. unknown DNO id) are returned
// as is_error:true with HTTP 200 — the wire transport succeeded; the
// tool logically failed (matching the RubberDuck exemplar's envelope
// contract). Transport/trust failures use real HTTP status codes.
func (h *Handler) handleInvoke(w http.ResponseWriter, r *http.Request, name string) {
	// PROVENANCE mandatory — 400 if absent. The service token is
	// machine trust; X-User-Id is who originated it.
	userID := r.Header.Get(userIDHeader)
	if userID == "" {
		writeStatus(w, http.StatusBadRequest, "missing X-User-Id: every Nexus->ofgemwatch call MUST carry originating-user provenance")
		return
	}

	if name != CapabilityToolName {
		writeStatus(w, http.StatusNotFound, fmt.Sprintf("unknown tool %q (this producer exposes %q)", name, CapabilityToolName))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req verdictRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeInvokeError(w, fmt.Sprintf("invalid request JSON: %v", err))
			return
		}
	}

	result, errMsg := h.computeVerdict(userID, req)
	if errMsg != "" {
		writeInvokeError(w, errMsg)
		return
	}

	content, err := json.Marshal(result)
	if err != nil {
		writeInvokeError(w, fmt.Sprintf("failed to marshal verdict: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, invokeResponse{Content: content, IsError: false})
}

// computeVerdict runs the REAL ofgemriio engine + stamps a Mirror-Mark
// audit row. Returns (result, "") on success or (nil-ish, errMsg) on a
// logical tool error (which the caller surfaces as is_error:true). No
// new domain logic — pure adapter over ofgemriio.DNO.Verdict / DeltaPct
// and auditledger.Append.
func (h *Handler) computeVerdict(userID string, req verdictRequest) (verdictResult, string) {
	var dno ofgemriio.DNO

	switch {
	case req.DNOID != "":
		found := ofgemriio.FindByID(req.DNOID)
		if found == nil {
			return verdictResult{}, fmt.Sprintf(
				"unknown dno_id %q; valid Phase-1 canonical IDs: %v",
				req.DNOID, canonicalIDs(),
			)
		}
		dno = *found
	case req.DeterminationTotexMillionGBP != nil && req.ReportedTotexMillionGBP != nil:
		// Raw-pair form — the verdict math is general.
		dno = ofgemriio.DNO{
			DeterminationTotexMillionGBP: *req.DeterminationTotexMillionGBP,
			ReportedTotexMillionGBP:      *req.ReportedTotexMillionGBP,
		}
	default:
		return verdictResult{}, "supply either dno_id OR both determination_totex_million_gbp and reported_totex_million_gbp"
	}

	verdict := dno.Verdict()
	lower := dno.DeterminationTotexMillionGBP * (1.0 - ofgemriio.ToleranceBand)
	upper := dno.DeterminationTotexMillionGBP * (1.0 + ofgemriio.ToleranceBand)

	// Stamp the verdict into a Mirror-Mark audit row (the production
	// emit-path). RequestedBy threads the originating provenance into
	// the canonical, tamper-evident row.
	payload := map[string]any{
		"dno_id":                          dno.ID,
		"region":                          dno.Region,
		"determination_totex_million_gbp": dno.DeterminationTotexMillionGBP,
		"reported_totex_million_gbp":      dno.ReportedTotexMillionGBP,
		"delta_pct":                       dno.DeltaPct(),
		"verdict":                         verdict.String(),
		"requested_by":                    userID,
	}
	subject := dno.ID
	if subject == "" {
		subject = "ANON-PAIR" // raw-pair form has no canonical DNO id
	}

	ledger, err := h.newLedger()
	if err != nil {
		return verdictResult{}, fmt.Sprintf("audit ledger init failed: %v", err)
	}
	row, err := auditledger.NewRIIORow(subject, payload)
	if err != nil {
		return verdictResult{}, fmt.Sprintf("audit row build failed: %v", err)
	}
	marked, err := ledger.Append(row)
	if err != nil {
		return verdictResult{}, fmt.Sprintf("audit ledger append failed: %v", err)
	}

	return verdictResult{
		DNOID:                        dno.ID,
		Region:                       dno.Region,
		DeterminationTotexMillionGBP: dno.DeterminationTotexMillionGBP,
		ReportedTotexMillionGBP:      dno.ReportedTotexMillionGBP,
		Verdict:                      verdict.String(),
		DeltaPct:                     dno.DeltaPct(),
		ToleranceBand:                ofgemriio.ToleranceBand,
		LowerBandMillionGBP:          lower,
		UpperBandMillionGBP:          upper,
		Mark:                         marked.Mark,
		AuditTS:                      marked.Row.Timestamp,
		RequestedBy:                  userID,
		Caveats:                      verdictCaveats(),
	}, ""
}

// canonicalIDs returns the valid Phase-1 DNO IDs (for error messages).
func canonicalIDs() []string {
	dnos := ofgemriio.CanonicalDNOs()
	out := make([]string, 0, len(dnos))
	for _, d := range dnos {
		out = append(out, d.ID)
	}
	return out
}

// verdictCaveats echoes the engine's two boot-time R143 ERROR
// advisories so a consumer can never silently treat scaffold output
// as regulator-load-bearing. Sourced from honest.CanonicalAdvisories
// (single source of truth) — only the Error-severity ones relevant to
// the RIIO verdict path.
func verdictCaveats() []string {
	var out []string
	for _, a := range honest.CanonicalAdvisories() {
		if a.Severity == honest.SeverityError {
			out = append(out, a.Code+": "+a.Message)
		}
	}
	return out
}

// ---- wire helpers -----------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeStatus is for transport/trust failures (real HTTP status code +
// a JSON error body).
func writeStatus(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeInvokeError is for LOGICAL tool failures: HTTP 200 with the
// envelope is_error:true (the transport succeeded; the tool did not).
func writeInvokeError(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusOK, invokeResponse{IsError: true, ErrorMessage: msg})
}
