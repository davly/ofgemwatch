// Tests for the Nexus-facing MCP producer surface.
//
// 2026-06-02 capability-exposure ship. These pin the load-bearing
// trust + reachability contract:
//
//   - REACHABILITY: with a valid service token and NO auth cookie, the
//     manifest answers 200 (the surface is mounted OUTSIDE any app-wide
//     auth group — STEP-1.5). A redirect/401 here would mean Nexus's
//     cookieless call can't reach the handler.
//   - FAIL-CLOSED on UNSET token: a server constructed with an empty
//     OFGEMWATCH_NEXUS_SERVICE_TOKEN 401s EVERY request — even with a
//     header present. (The exact P0 class found in the last wave.)
//   - FAIL-CLOSED on wrong token.
//   - PROVENANCE: invoke without X-User-Id => 400.
//   - REAL ENGINE: an authenticated, provenanced invoke runs the actual
//     ofgemriio engine + stamps a Mirror-Mark — verdicts match the
//     canned-fixture corpus AND the general raw-pair math.
package mcpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ofgemriio "github.com/davly/ofgemwatch/internal/ofgem-riio"
)

const testToken = "test-shared-service-token-1234567890"

// newTestServer spins an httptest.Server over a Handler with the given
// token. Empty token => fail-closed server.
func newTestServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	NewHandler(token).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func doReq(t *testing.T, method, url, token, userID, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("X-Nexus-Service-Token", token)
	}
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// ---- STEP-1.5 reachability ---------------------------------------------

// TestManifest_Reachable_WithToken_NoCookie pins the STEP-1.5
// invariant: a valid service-token header and NO auth cookie reaches
// the handler and returns 200 + the tool list. (A 3xx/401 here would
// be the "unreachable from Nexus" gap.)
func TestManifest_Reachable_WithToken_NoCookie(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodGet, srv.URL+"/mcp/tools/", testToken, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest status = %d, want 200 (surface unreachable from a cookieless Nexus call)", resp.StatusCode)
	}
	var m manifestResponse
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if len(m.Tools) != 1 {
		t.Fatalf("manifest tool count = %d, want 1", len(m.Tools))
	}
	if m.Tools[0].Name != CapabilityToolName {
		t.Errorf("tool name = %q, want %q", m.Tools[0].Name, CapabilityToolName)
	}
	if m.Tools[0].ApprovalRequired {
		t.Errorf("riio verdict is a read-only computation; approval_required must be false")
	}
	// input_schema must be valid JSON (Nexus flattens it).
	var schema map[string]any
	if err := json.Unmarshal(m.Tools[0].InputSchema, &schema); err != nil {
		t.Errorf("input_schema is not valid JSON: %v", err)
	}
}

// ---- FAIL-CLOSED auth (the P0 guard) -----------------------------------

// TestAuth_UnsetToken_401Everything is the headline P0 guard: a server
// whose configured secret is UNSET/empty MUST 401 every request — even
// the manifest, even WITH a header present. Never fail open.
func TestAuth_UnsetToken_401Everything(t *testing.T) {
	srv := newTestServer(t, "") // UNSET secret

	// Manifest with no header.
	resp := doReq(t, http.MethodGet, srv.URL+"/mcp/tools/", "", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unset-token manifest (no header) status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Manifest WITH a header — still 401, because no secret is
	// configured to compare against. This is the precise fail-open
	// trap: a present-but-uncheckable token must NOT pass.
	resp = doReq(t, http.MethodGet, srv.URL+"/mcp/tools/", "any-attacker-supplied-token", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unset-token manifest (attacker header) status = %d, want 401 (FAIL-OPEN BUG)", resp.StatusCode)
	}
	resp.Body.Close()

	// Invoke with a header + provenance — still 401.
	resp = doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		"any-token", "user-1", `{"dno_id":"WPD-WMID"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unset-token invoke status = %d, want 401 (FAIL-OPEN BUG)", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestAuth_WrongToken_401 pins that a configured server rejects a
// mismatched token.
func TestAuth_WrongToken_401(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodGet, srv.URL+"/mcp/tools/", "WRONG-token", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-token status = %d, want 401", resp.StatusCode)
	}
}

// TestAuth_MissingToken_401 pins that a configured server rejects a
// request with no token header at all.
func TestAuth_MissingToken_401(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		"", "user-1", `{"dno_id":"WPD-WMID"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing-token invoke status = %d, want 401", resp.StatusCode)
	}
}

// ---- PROVENANCE --------------------------------------------------------

// TestInvoke_MissingUserID_400 pins that a token-authed invoke WITHOUT
// X-User-Id is rejected 400 — provenance is mandatory.
func TestInvoke_MissingUserID_400(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		testToken, "", `{"dno_id":"WPD-WMID"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing X-User-Id status = %d, want 400", resp.StatusCode)
	}
}

// ---- REAL ENGINE invoke ------------------------------------------------

// decodeInvoke reads the {content,is_error,error_message} envelope and,
// on success, the verdictResult content.
func decodeInvoke(t *testing.T, resp *http.Response) (invokeResponse, verdictResult) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("invoke status = %d, want 200; body=%s", resp.StatusCode, string(b))
	}
	var env invokeResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	var res verdictResult
	if !env.IsError {
		if err := json.Unmarshal(env.Content, &res); err != nil {
			t.Fatalf("decode verdict content: %v", err)
		}
	}
	return env, res
}

// TestInvoke_RealEngine_DNOID_Compliant runs the REAL ofgemriio engine
// for a compliant canned-fixture DNO and checks the verdict matches the
// engine's own computation (not a hardcoded constant) + that a
// Mirror-Mark + caveats are stamped.
func TestInvoke_RealEngine_DNOID_Compliant(t *testing.T) {
	srv := newTestServer(t, testToken)

	// Ground truth straight from the engine.
	want := ofgemriio.FindByID("WPD-WMID")
	if want == nil {
		t.Fatal("fixture WPD-WMID missing from canonical corpus")
	}
	wantVerdict := want.Verdict().String()

	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		testToken, "user-regops-1", `{"dno_id":"WPD-WMID"}`)
	env, res := decodeInvoke(t, resp)

	if env.IsError {
		t.Fatalf("expected success, got is_error with %q", env.ErrorMessage)
	}
	if res.Verdict != wantVerdict {
		t.Errorf("verdict = %q, want %q (engine ground truth)", res.Verdict, wantVerdict)
	}
	if res.Verdict != "compliant" {
		t.Errorf("WPD-WMID expected compliant, got %q", res.Verdict)
	}
	if res.DNOID != "WPD-WMID" {
		t.Errorf("dno_id = %q, want WPD-WMID", res.DNOID)
	}
	if res.ToleranceBand != ofgemriio.ToleranceBand {
		t.Errorf("tolerance_band = %g, want %g", res.ToleranceBand, ofgemriio.ToleranceBand)
	}
	// Band edges must bracket the determination by +/-15%.
	if res.LowerBandMillionGBP >= res.DeterminationTotexMillionGBP ||
		res.UpperBandMillionGBP <= res.DeterminationTotexMillionGBP {
		t.Errorf("band edges [%g,%g] do not bracket determination %g",
			res.LowerBandMillionGBP, res.UpperBandMillionGBP, res.DeterminationTotexMillionGBP)
	}
	// Mirror-Mark stamped (production emit-path ran).
	if !strings.HasPrefix(res.Mark, "lore@v1:") {
		t.Errorf("mark = %q, want lore@v1: prefix (audit row not stamped)", res.Mark)
	}
	if res.AuditTS == "" {
		t.Error("audit_ts empty — audit row not stamped")
	}
	if res.RequestedBy != "user-regops-1" {
		t.Errorf("requested_by = %q, want user-regops-1 (provenance not threaded)", res.RequestedBy)
	}
	// Honest caveats (the two R143 Error advisories) MUST be present so
	// a consumer can't treat scaffold output as regulator-load-bearing.
	if len(res.Caveats) < 2 {
		t.Errorf("caveats count = %d, want >=2 (scaffold advisories not surfaced)", len(res.Caveats))
	}
	joined := strings.Join(res.Caveats, " | ")
	if !strings.Contains(joined, "OFGEMWATCH_OFGEM_RIIO_PRICE_CONTROL_NOT_LIVE") {
		t.Errorf("caveats missing the NOT_LIVE advisory: %q", joined)
	}
}

// TestInvoke_RealEngine_DNOID_Breach checks the breach fixture
// (NPG-NEDL, +26.5% over band) resolves to breach via the real engine.
func TestInvoke_RealEngine_DNOID_Breach(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		testToken, "user-1", `{"dno_id":"NPG-NEDL"}`)
	_, res := decodeInvoke(t, resp)
	if res.Verdict != "breach" {
		t.Errorf("NPG-NEDL verdict = %q, want breach", res.Verdict)
	}
	if res.DeltaPct <= 0 {
		t.Errorf("NPG-NEDL delta_pct = %g, want positive (over-spend)", res.DeltaPct)
	}
}

// TestInvoke_RealEngine_RawPair exercises the general verdict math via
// the raw {determination,reported} form (the genuinely-reusable,
// fixture-independent capability). 1000 vs 1200 is +20% => outside the
// +/-15% band => breach.
func TestInvoke_RealEngine_RawPair(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		testToken, "user-1",
		`{"determination_totex_million_gbp":1000,"reported_totex_million_gbp":1200}`)
	env, res := decodeInvoke(t, resp)
	if env.IsError {
		t.Fatalf("raw-pair invoke errored: %q", env.ErrorMessage)
	}
	if res.Verdict != "breach" {
		t.Errorf("1000/1200 verdict = %q, want breach (+20%% outside +/-15%%)", res.Verdict)
	}
	if res.DeltaPct < 19.9 || res.DeltaPct > 20.1 {
		t.Errorf("delta_pct = %g, want ~20", res.DeltaPct)
	}
	// Within-band pair => compliant.
	resp = doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		testToken, "user-1",
		`{"determination_totex_million_gbp":1000,"reported_totex_million_gbp":1050}`)
	_, res = decodeInvoke(t, resp)
	if res.Verdict != "compliant" {
		t.Errorf("1000/1050 verdict = %q, want compliant (+5%% within band)", res.Verdict)
	}
}

// TestInvoke_UnknownDNO_LogicalError pins that an unknown dno_id is a
// LOGICAL tool error (HTTP 200, is_error:true) — not a transport
// failure — and that the error lists the valid IDs.
func TestInvoke_UnknownDNO_LogicalError(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		testToken, "user-1", `{"dno_id":"DOES-NOT-EXIST"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unknown-dno transport status = %d, want 200 (logical error rides the envelope)", resp.StatusCode)
	}
	var env invokeResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.IsError {
		t.Error("expected is_error:true for unknown dno_id")
	}
	if !strings.Contains(env.ErrorMessage, "WPD-WMID") {
		t.Errorf("error message should list valid IDs; got %q", env.ErrorMessage)
	}
}

// TestInvoke_NeitherInput_LogicalError pins that supplying neither
// dno_id nor a raw pair is a logical error.
func TestInvoke_NeitherInput_LogicalError(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/"+CapabilityToolName,
		testToken, "user-1", `{}`)
	defer resp.Body.Close()
	var env invokeResponse
	_ = json.NewDecoder(resp.Body).Decode(&env)
	if !env.IsError {
		t.Error("expected is_error:true when neither input form is supplied")
	}
}

// TestInvoke_UnknownTool_404 pins that POSTing to a tool name this
// producer does not expose is a 404 (not a logical-error envelope).
func TestInvoke_UnknownTool_404(t *testing.T) {
	srv := newTestServer(t, testToken)
	resp := doReq(t, http.MethodPost, srv.URL+"/mcp/tools/ofgemwatch.not_a_tool",
		testToken, "user-1", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown-tool status = %d, want 404", resp.StatusCode)
	}
}
