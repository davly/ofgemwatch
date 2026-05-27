// Command ofgemwatch — Ofgem RIIO + ENTSO-E regulatory reporting CLI
// with Mirror-Mark stamped audit ledger.
//
// 2026-05-27 BR6 ecosystem-uplift ship (new flagship rank #4).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	auditledger "github.com/davly/ofgemwatch/internal/audit-ledger"
	entsoe "github.com/davly/ofgemwatch/internal/entso-e"
	"github.com/davly/ofgemwatch/internal/honest"
	"github.com/davly/ofgemwatch/internal/lore"
	"github.com/davly/ofgemwatch/internal/manifest"
	"github.com/davly/ofgemwatch/internal/mirrormark"
	ofgemriio "github.com/davly/ofgemwatch/internal/ofgem-riio"
)

const version = "0.1.0-br6-ofgemwatch"

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: ofgemwatch <command> [flags]

Commands:
  riio-check <dno-id>     Run Ofgem RIIO-CF compliance verdict against
                          the canonical DNO corpus. Emits a Mirror-Mark
                          stamped audit-ledger row.
  riio-fleet              Print fleet-wide RIIO compliance summary
                          across the 6 canonical DNOs.
  riio-list               List all canonical DNO IDs.
  entsoe-emit <rpt-id>    Emit a Phase-1 IEC 62325-451-3 transparency
                          XML scaffold for GB area-code. Stamps the
                          row with a Mirror-Mark in the audit ledger.
  manifest                Print the R150 manifest entries (12 entries:
                          5 Ofgem RIIO + 4 ENTSO-E + 3 FERC-deferred).
  honest                  Print all R143 LOUD-ONCE advisories ofgemwatch
                          declares (the canonical degraded-mode signals).
  kat1-verify             Verify the cohort-canonical KAT-1 byte-identity
                          against R151 anchor.
  ledger                  Print the audit-ledger snapshot (Mirror-Mark
                          stamped rows from the current session).
  version                 Print ofgemwatch version

R143 advisories fired at boot:
  All 5 LOUD-ONCE advisories surface on the first command-invocation
  in placeholder-key mode (which is the default Phase-1 scaffold).

Examples:
  ofgemwatch riio-check WPD-WMID
  ofgemwatch riio-fleet
  ofgemwatch entsoe-emit RPT-2026-Q3-001
  ofgemwatch manifest
  ofgemwatch kat1-verify`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	// Boot: every CLI invocation fires the BR6 5 LOUD-ONCE advisories
	// + the ledger BootCheck (which surfaces placeholder-mode marker
	// state). Per R143 LoudOnce contract, repeated invocations within
	// the same process emit each Code exactly once — but each process
	// invocation is fresh, so a fresh CLI run surfaces them again.
	advisoriesAtBoot()

	// Construct the in-memory ledger backed by a placeholder marker
	// at Phase 1. Production deployments wire real (corpusSHA, key)
	// via a separate scaffold entry-point.
	ledger := newScaffoldLedger()

	switch cmd {
	case "version", "--version", "-V":
		fmt.Printf("ofgemwatch %s\n", version)
	case "riio-check":
		_ = fs.Parse(rest)
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "error: 'riio-check' requires a DNO ID")
			fmt.Fprintln(os.Stderr, "       example: ofgemwatch riio-check WPD-WMID")
			os.Exit(2)
		}
		dnoID := fs.Arg(0)
		runRIIOCheck(ledger, dnoID)
	case "riio-fleet":
		_ = fs.Parse(rest)
		runRIIOFleet(ledger)
	case "riio-list":
		_ = fs.Parse(rest)
		for _, d := range ofgemriio.CanonicalDNOs() {
			fmt.Println(d.String())
		}
	case "entsoe-emit":
		_ = fs.Parse(rest)
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "error: 'entsoe-emit' requires a report ID")
			fmt.Fprintln(os.Stderr, "       example: ofgemwatch entsoe-emit RPT-2026-Q3-001")
			os.Exit(2)
		}
		runENTSOEEmit(ledger, fs.Arg(0))
	case "manifest":
		_ = fs.Parse(rest)
		printManifest()
	case "honest":
		_ = fs.Parse(rest)
		for _, a := range honest.CanonicalAdvisories() {
			fmt.Println(a.String())
		}
	case "kat1-verify":
		_ = fs.Parse(rest)
		if err := lore.AssertKAT1Parity(); err != nil {
			fmt.Fprintf(os.Stderr, "KAT-1 verify FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("KAT-1 cohort-canonical byte-identity verified.")
		fmt.Printf("  cohort-canonical hex = %s\n", lore.KAT1Digest)
		fmt.Println("  reproduce externally: openssl dgst -sha256 -mac hmac -macopt key:")
		fmt.Println("    against canonical 33-byte input (0x01 || 32×0x00)")
	case "ledger":
		_ = fs.Parse(rest)
		printLedger(ledger)
	case "--help", "-h", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

// advisoriesAtBoot fires the BR6 5 LOUD-ONCE advisories. Each advisory
// emits exactly once per process — even on repeated boot calls within
// the same process — per the R143 LoudOnce contract.
func advisoriesAtBoot() {
	for _, adv := range honest.CanonicalAdvisories() {
		honest.LoudOnceLog(adv)
	}
}

// newScaffoldLedger constructs the Phase-1 in-memory ledger backed by
// a placeholder marker. BootCheck fires the audit-ledger placeholder
// advisory exactly once.
func newScaffoldLedger() *auditledger.Ledger {
	marker := mirrormark.NewPlaceholderMarker()
	l, err := auditledger.NewLedger(marker)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scaffold ledger init failed: %v\n", err)
		os.Exit(1)
	}
	l.BootCheck()
	return l
}

// runRIIOCheck executes the verdict workflow + stamps audit row.
func runRIIOCheck(ledger *auditledger.Ledger, dnoID string) {
	d := ofgemriio.FindByID(dnoID)
	if d == nil {
		fmt.Fprintf(os.Stderr, "error: DNO %q not found in canonical corpus\n", dnoID)
		fmt.Fprintln(os.Stderr, "       run 'ofgemwatch riio-list' to see valid IDs")
		os.Exit(2)
	}
	v := d.Verdict()
	fmt.Printf("RIIO-CF verdict for %s:\n", dnoID)
	fmt.Println(d.String())

	payload := map[string]any{
		"dno_id":                              d.ID,
		"region":                              d.Region,
		"determination_totex_million_gbp":     d.DeterminationTotexMillionGBP,
		"reported_totex_million_gbp":          d.ReportedTotexMillionGBP,
		"delta_pct":                           d.DeltaPct(),
		"verdict":                             v.String(),
	}
	row, err := auditledger.NewRIIORow(dnoID, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger row build failed: %v\n", err)
		os.Exit(1)
	}
	marked, err := ledger.Append(row)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger append failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nAudit-ledger row stamped with Mirror-Mark:\n")
	fmt.Printf("  mark    = %s\n", marked.Mark)
	fmt.Printf("  ts      = %s\n", marked.Row.Timestamp)
	fmt.Printf("  subject = %s\n", marked.Row.Subject)
}

// runRIIOFleet prints the fleet-wide compliance summary.
func runRIIOFleet(ledger *auditledger.Ledger) {
	uncertain, compliant, breach, total := ofgemriio.SummariseFleet()
	fmt.Printf("RIIO-CF fleet summary (Phase-1 scaffold corpus, %d DNOs):\n\n", total)
	for _, d := range ofgemriio.CanonicalDNOs() {
		fmt.Println(d.String())
	}
	fmt.Printf("\nVerdict breakdown:\n")
	fmt.Printf("  compliant: %d\n", compliant)
	fmt.Printf("  breach:    %d\n", breach)
	fmt.Printf("  uncertain: %d\n", uncertain)

	// Stamp a fleet-summary audit-ledger row.
	payload := map[string]any{
		"summary":    "fleet",
		"total":      total,
		"compliant":  compliant,
		"breach":     breach,
		"uncertain":  uncertain,
	}
	row, _ := auditledger.NewRIIORow("FLEET-SUMMARY", payload)
	if _, err := ledger.Append(row); err != nil {
		fmt.Fprintf(os.Stderr, "ledger append failed: %v\n", err)
	}
}

// runENTSOEEmit emits a Phase-1 scaffold ENTSO-E XML report.
func runENTSOEEmit(ledger *auditledger.Ledger, reportID string) {
	start := time.Now().UTC().Truncate(time.Hour)
	end := start.Add(time.Hour)
	mr := entsoe.Emit(reportID, "GB", "10YGB----------A", start, end)
	out, err := entsoe.Marshal(mr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ENTSO-E marshal failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))

	// Stamp the XML body in the audit ledger.
	row := auditledger.NewENTSOERow(reportID, out)
	marked, err := ledger.Append(row)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger append failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n<!-- Audit-ledger row stamped with Mirror-Mark:\n")
	fmt.Printf("       mark    = %s\n", marked.Mark)
	fmt.Printf("       ts      = %s\n", marked.Row.Timestamp)
	fmt.Printf("       subject = %s -->\n", marked.Row.Subject)
}

// printManifest dumps the 12 manifest entries.
func printManifest() {
	seed := manifest.Seed()
	fmt.Printf("R150 manifest inventory (%d entries):\n\n", len(seed))
	for _, e := range seed {
		fmt.Printf("  [%s] %s\n", e.Class.String(), e.Key)
		fmt.Printf("    source=%s confidence=%s reviewed_by_counsel=%v\n",
			e.Source.String(), e.Confidence.String(), e.ReviewedByCounsel)
		if !e.FreshAt.Equal(manifest.SentinelHonestTODO) {
			fmt.Printf("    fresh_at=%s\n", e.FreshAt.Format(time.RFC3339))
		} else {
			fmt.Printf("    fresh_at=<honest-TODO sentinel 1970-01-01>\n")
		}
		fmt.Printf("    rationale: %s\n\n", e.Rationale)
	}
	fmt.Printf("Honest-TODO entries: %d\n", seed.HonestTODOCount())
	fmt.Printf("Reviewed-by-counsel entries: %d (Phase-3 deliverable)\n", seed.ReviewedByCounselCount())
}

// printLedger dumps every Mirror-Mark stamped row in the current session.
func printLedger(ledger *auditledger.Ledger) {
	snap := ledger.Snapshot()
	fmt.Printf("Audit-ledger session snapshot (%d rows):\n\n", len(snap))
	for i, r := range snap {
		body, _ := json.MarshalIndent(r, "  ", "  ")
		fmt.Printf("Row %d:\n  %s\n\n", i+1, string(body))
	}
}
