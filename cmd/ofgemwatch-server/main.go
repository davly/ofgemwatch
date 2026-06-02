// Command ofgemwatch-server — Nexus-facing MCP-tool producer daemon
// for ofgemwatch.
//
// 2026-06-02 capability-exposure ship. Exposes the deterministic
// Ofgem RIIO-ED2 price-control compliance verdict as a Nexus-routable
// Shape-1 MCP tool (`ofgemwatch.riio_compliance_verdict`). This is the
// HTTP host the firewall test (`internal/firewall`) explicitly scopes
// its no-HTTP / no-env invariants to exclude — landed on the same
// R145.B branch as the relaxation, with paired regression. The CLI
// (cmd/ofgemwatch) and every domain package stay stdlib-only.
//
// Surface (the WIRE is the contract):
//
//	GET  /mcp/tools/                                  -> manifest
//	POST /mcp/tools/ofgemwatch.riio_compliance_verdict -> invoke
//	GET  /healthz                                     -> liveness (no auth)
//
// Trust: X-Nexus-Service-Token (machine, constant-time, FAIL-CLOSED on
// unset secret) + X-User-Id (provenance, 400 if absent). See
// internal/mcpserver for the boundary detail.
//
// Config (environment):
//
//	PORT                            listen port (default 8080)
//	OFGEMWATCH_NEXUS_SERVICE_TOKEN  shared machine-trust secret.
//	                                UNSET/empty => every /mcp/tools
//	                                request 401s (fail-closed). Set it
//	                                to make the surface reachable.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/davly/ofgemwatch/internal/honest"
	"github.com/davly/ofgemwatch/internal/mcpserver"
)

func main() {
	// Boot: fire the BR6 5 LOUD-ONCE advisories so placeholder-mode is
	// loud at startup (matching the CLI's advisoriesAtBoot). The
	// audit-ledger placeholder advisory additionally fires on the
	// first per-invoke Sign via the scaffold ledger's BootCheck.
	for _, adv := range honest.CanonicalAdvisories() {
		honest.LoudOnceLog(adv)
	}

	token := os.Getenv("OFGEMWATCH_NEXUS_SERVICE_TOKEN")
	if token == "" {
		// Loud, but DO NOT fail open: the server still boots so a
		// misconfigured deploy is observable (healthz up) while every
		// /mcp/tools request fail-closes to 401.
		log.Printf("[LOUD-ONCE-WARNING] ofgemwatch-server: OFGEMWATCH_NEXUS_SERVICE_TOKEN is UNSET; the /mcp/tools surface will 401 EVERY request (fail-closed). Set it to make the capability reachable from Nexus.")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","tool":"` + mcpserver.CapabilityToolName + `"}`))
	})

	mcpserver.NewHandler(token).Mount(mux)

	addr := ":" + port
	log.Printf("ofgemwatch-server: listening on %s; capability tool %q reachable via /mcp/tools (token %s)",
		addr, mcpserver.CapabilityToolName, tokenStateLabel(token))

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "ofgemwatch-server: %v\n", err)
		os.Exit(1)
	}
}

func tokenStateLabel(token string) string {
	if token == "" {
		return "UNSET => fail-closed 401"
	}
	return "configured"
}
