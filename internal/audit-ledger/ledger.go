// Package auditledger — Mirror-Mark-stamped regulatory audit-ledger
// for ofgemwatch.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship). Pure-
// stdlib; zero deps. Every regulatory verdict + ENTSO-E XML emission
// crosses this package's Append() function, which stamps a cohort-
// canonical L43 Mirror-Mark on the canonical wire-form bytes of the
// row.
//
// R175 LOAD-BEARING-IN-PRODUCTION posture (godfather memory promotion
// 2026-05-27): ofgemwatch satisfies R175 from INCEPTION because:
//
//   - (1) Production emit-path: `auditledger.Append()` is the single
//     point through which every regulator-grade output flows. The
//     CLI commands `ofgemwatch riio-check` and `ofgemwatch entsoe-emit`
//     both write through Append. Search criterion: `grep -rEn
//     "marker\.Sign\|signMark" internal/audit-ledger/` returns ≥1
//     match in non-test code (this file).
//
//   - (2) Cold-verify path: the OpenSSL one-liner against the cohort-
//     canonical KAT-1 input (0x01 || 32×0x00) with empty key
//     reproduces `239a7d0d…`. The cohort property is FIPS PUB 180-4
//     + RFC 2104 + RFC 4648 — not Limitless toolchain.
//
//   - (3) Boot-time R143 LOUD-ONCE-WARN: BootCheck() fires once at
//     process boot if the marker is placeholder-mode (no production
//     key). Insights / casino canonical wire-discipline shipped 2026-
//     05-26.
//
//   - (4) KAT-1 hex pin: `KAT1Digest` constant is grep-verifiable
//     in `internal/lore/kat1.go` AND in `internal/firewall/firewall_
//     test.go`. The firewall pin is the cohort-canonical R175 anchor.
//
// Row shape (CanonicalRow):
//
//	type CanonicalRow struct {
//	    Timestamp    string  // RFC3339 UTC
//	    Subject      string  // e.g. "WPD-WMID" / "RPT-001"
//	    Class        string  // closed: "ofgem_riio" / "entsoe_xml"
//	    PayloadJSON  string  // canonicalised verdict/XML wire form
//	}
//
// MarkedRow attaches the Mirror-Mark to the canonical bytes of a
// CanonicalRow. Downstream consumers verify by recomputing the
// canonical bytes + matching against the carried mark.
package auditledger

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/davly/ofgemwatch/internal/honest"
	"github.com/davly/ofgemwatch/internal/mirrormark"
)

// ClassOfgemRIIO is the closed-set Class value for RIIO verdict rows.
const ClassOfgemRIIO = "ofgem_riio"

// ClassENTSOEXML is the closed-set Class value for ENTSO-E XML rows.
const ClassENTSOEXML = "entsoe_xml"

// CanonicalRow is the immutable canonical wire form of an audit row
// before Mirror-Mark stamping.
type CanonicalRow struct {
	// Timestamp is the wall-clock UTC time the row was created,
	// formatted as RFC3339. The canonical form pins the timestamp
	// at row-creation, not emit-time.
	Timestamp string `json:"timestamp"`

	// Subject is the entity identifier this row pertains to.
	// For Ofgem RIIO: DNO ID (e.g. "WPD-WMID").
	// For ENTSO-E XML: report ID (e.g. "RPT-001").
	Subject string `json:"subject"`

	// Class is the closed-set row-class identifier.
	Class string `json:"class"`

	// PayloadJSON is the verdict/XML wire-form as a JSON string.
	PayloadJSON string `json:"payload_json"`
}

// CanonicalBytes returns the deterministic JSON canonical byte form
// of this row. The same row MUST produce byte-identical output
// across calls — this is the input to mirrormark.Sign().
//
// Go's encoding/json marshals struct fields in declaration order, so
// the byte form is deterministic given the same struct. The order
// (timestamp / subject / class / payload_json) is the cohort wire-
// form contract.
func (r CanonicalRow) CanonicalBytes() ([]byte, error) {
	out, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MarkedRow is a CanonicalRow plus the Mirror-Mark stamped on its
// canonical bytes. Carries the row + mark over trust boundaries.
type MarkedRow struct {
	Row  CanonicalRow `json:"row"`
	Mark string       `json:"mirror_mark"`
}

// Ledger is the in-memory append-only audit ledger. Goroutine-safe.
// Phase-1 scaffold: in-memory only. Phase-2 deferred: durable storage
// (likely Postgres or append-only file).
type Ledger struct {
	mu     sync.Mutex
	rows   []MarkedRow
	marker mirrormark.Marker
}

// NewLedger constructs a Ledger backed by the given marker. The
// marker MUST be non-nil; production code typically passes
// *mirrormark.StdlibMarker but the interface allows test doubles.
func NewLedger(marker mirrormark.Marker) (*Ledger, error) {
	if marker == nil {
		return nil, errors.New("auditledger: marker MUST be non-nil")
	}
	return &Ledger{marker: marker}, nil
}

// Append stamps the row with a Mirror-Mark and appends it to the
// ledger. Returns the resulting MarkedRow (so the caller can carry
// it across the trust boundary) plus any error.
//
// This is THE R175 production emit-path. `grep -rEn "marker\.Sign"`
// in `internal/audit-ledger/` returns the call site here — the
// cohort-canonical production-wire grep contract.
func (l *Ledger) Append(row CanonicalRow) (MarkedRow, error) {
	bytes, err := row.CanonicalBytes()
	if err != nil {
		return MarkedRow{}, err
	}
	mark := l.marker.Sign(bytes)
	marked := MarkedRow{Row: row, Mark: mark}
	l.mu.Lock()
	l.rows = append(l.rows, marked)
	l.mu.Unlock()
	return marked, nil
}

// Snapshot returns a copy of every row in the ledger. Used by
// diagnostic + readiness handlers + tests.
func (l *Ledger) Snapshot() []MarkedRow {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]MarkedRow, len(l.rows))
	copy(out, l.rows)
	return out
}

// Len returns the current ledger size.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.rows)
}

// SelfCheck re-derives every row's Mirror-Mark from its canonical
// bytes via this ledger's OWN marker and compares it against the
// carried mark. On success it returns the row count plus the ledger
// digest; on the first mismatch it returns a non-nil error and a
// zero digest (callers MUST NOT anchor/attest a ledger whose
// self-check failed).
//
// LEDGER DIGEST — canonical run serialization (documented contract):
// sha256 over, for each MarkedRow in append order,
//
//	json.Marshal(MarkedRow) || '\n'
//
// Go's encoding/json marshals struct fields in declaration order
// (row, mirror_mark — and inside the row: timestamp, subject, class,
// payload_json), so the byte stream is deterministic: identical rows
// in identical order produce an identical digest, and any change to
// row content, mark, or ORDER changes it. The ledger is not hash-
// chained (Phase-1 in-memory scaffold), so this digest is the
// canonical binding for a Stele spine anchor's subject_hash.
//
// HONESTY: this is a SELF-check — the same marker that stamped the
// rows re-derives the marks. It surfaces post-Append tampering of
// in-memory rows, but it is NOT an independent oracle and does NOT
// prove the marker key is production-grade (a placeholder-mode
// marker self-checks green; the R143 boot advisory covers that
// loudly). Downstream consumers describing this check MUST label it
// self-check, not gauntlet.
func (l *Ledger) SelfCheck() (int, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	snap := l.Snapshot()
	h := sha256.New()
	for i, mr := range snap {
		if !strings.HasPrefix(mr.Mark, mirrormark.MarkPrefix) {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d mark missing cohort-canonical prefix %q", i, mirrormark.MarkPrefix)
		}
		cb, err := mr.Row.CanonicalBytes()
		if err != nil {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d canonical bytes: %w", i, err)
		}
		if l.marker.Sign(cb) != mr.Mark {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d mark does not re-derive from canonical bytes (row or mark tampered)", i)
		}
		line, err := json.Marshal(mr)
		if err != nil {
			return 0, digest, fmt.Errorf("auditledger: self-check failed: row %d serialization: %w", i, err)
		}
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	copy(digest[:], h.Sum(nil))
	return len(snap), digest, nil
}

// BootCheck is the R175 criterion-3 boot-time R143 LOUD-ONCE-WARN
// gate. Call once at process boot before consuming any ledger row
// downstream — if the marker is placeholder-mode, this emits the
// cohort-canonical advisory exactly once.
//
// Returns the marked-row count from any pre-existing rows in the
// ledger (typically 0 at fresh boot).
func (l *Ledger) BootCheck() int {
	// If the marker is a StdlibMarker in placeholder mode, surface
	// the R143 advisory once. The StdlibMarker itself emits a loud-
	// once warning at first Sign, but BootCheck gives the host a
	// boot-time hook so the operator sees the warning BEFORE any
	// row is emitted (and thus before any potentially-tampered row
	// could be silently treated as authentic).
	if pm, ok := l.marker.(*mirrormark.StdlibMarker); ok && pm.UsingPlaceholder() {
		honest.LoudOnceLog(honest.Advisory{
			Code:     "OFGEMWATCH_AUDIT_LEDGER_PLACEHOLDER_KEY_AT_BOOT",
			Severity: honest.SeverityError,
			Message:  "audit-ledger marker is in placeholder mode at boot; emitted rows will be syntactically-valid but cold-verify will refuse them at the regulator boundary. Wire a production key before treating any row as regulator-load-bearing.",
			DocLink:  "internal/mirrormark/marker.go §NewPlaceholderMarker + internal/honest/honest.go §OFGEMWATCH_REVIEWED_BY_COUNSEL_FALSE",
		})
	}
	return l.Len()
}

// NewRIIORow constructs a CanonicalRow for an Ofgem RIIO verdict.
// Subject is the DNO ID; payload is the wire-form JSON of the
// verdict.
func NewRIIORow(dnoID string, payload interface{}) (CanonicalRow, error) {
	pj, err := json.Marshal(payload)
	if err != nil {
		return CanonicalRow{}, err
	}
	return CanonicalRow{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Subject:     dnoID,
		Class:       ClassOfgemRIIO,
		PayloadJSON: string(pj),
	}, nil
}

// NewENTSOERow constructs a CanonicalRow for an ENTSO-E XML emission.
// Subject is the report ID; payload is the marshalled XML bytes
// converted to string.
func NewENTSOERow(reportID string, xmlBody []byte) CanonicalRow {
	return CanonicalRow{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Subject:     reportID,
		Class:       ClassENTSOEXML,
		PayloadJSON: string(xmlBody),
	}
}
