// Package entsoe — ENTSO-E transparency-platform XML producer for
// ofgemwatch.
//
// 2026-05-27 ecosystem-uplift ship (BR6 rank #4 new flagship). Pure-
// stdlib (`encoding/xml`); zero deps. Phase-1 scaffold against the
// IEC 62325-451-3 transparency XML schema — the standard ENTSO-E
// uses on its transparency platform for market-monitoring data.
//
// IMPORTANT: this package is PHASE 1 SCAFFOLD. Emitted XML conforms
// to the IEC 62325-451-3 schema SYNTACTICALLY but the payload values
// are placeholder fixtures, NOT derived from live ENTSO-E data.
// Production callers MUST surface
// OFGEMWATCH_ENTSO_E_TRANSPARENCY_XML_PLACEHOLDER before treating
// emitted XML as regulator-load-bearing.
//
// What ENTSO-E publishes (Phase 1 scope):
//
//   - Generation per type / production forecast
//   - Cross-border physical flows / scheduled exchanges
//   - Day-ahead prices
//   - System operator data (frequency, balancing)
//
// The IEC 62325-451-3 schema is publicly available; the XSD reference
// is pinned in `internal/manifest/seed.go` as
// `iec_62325_451_3_transparency_xsd`.
//
// Phase-2 deferred: live ENTSO-E API integration; multi-area
// publication (currently UK-only scaffold); Network Code on
// Operational Security real-time emit path.
package entsoe

import (
	"encoding/xml"
	"fmt"
	"time"
)

// SchemaVersion is the IEC 62325-451-3 schema version this package
// emits against. Pinned at v1.0 per the published XSD; bumping
// requires R145.B paired regression.
const SchemaVersion = "1.0"

// MarketReport is the canonical ENTSO-E transparency-platform report
// root element. Subset of the IEC 62325-451-3 schema sufficient for
// Phase 1 scaffolding.
type MarketReport struct {
	XMLName       xml.Name      `xml:"MarketReport"`
	SchemaVersion string        `xml:"schemaVersion,attr"`
	ReportID      string        `xml:"ReportID"`
	Created       string        `xml:"Created"`
	AreaCode      string        `xml:"AreaCode"`
	BiddingZone   string        `xml:"BiddingZone"`
	TimeSeries    []TimeSeries  `xml:"TimeSeries"`
	Disclaimer    string        `xml:"Disclaimer"`
}

// TimeSeries is one canonical ENTSO-E time series within a market
// report. Each series carries a closed-set BusinessType (generation /
// load / flow / price) + the observation periods.
type TimeSeries struct {
	XMLName      xml.Name   `xml:"TimeSeries"`
	BusinessType string     `xml:"BusinessType"`
	UnitOfMeasure string    `xml:"UnitOfMeasure"`
	Periods      []Period   `xml:"Period"`
}

// Period is one hour-granularity observation period.
type Period struct {
	XMLName  xml.Name `xml:"Period"`
	Start    string   `xml:"Start"`
	End      string   `xml:"End"`
	Quantity float64  `xml:"Quantity"`
}

// BusinessType values per IEC 62325-451-3 closed enum. Renames
// invalidate every downstream consumer.
const (
	BusinessTypeGeneration         = "A04" // Production / generation
	BusinessTypeLoad               = "A65" // Load / consumption
	BusinessTypePhysicalFlow       = "A66" // Cross-border physical flow
	BusinessTypeDayAheadPrice      = "A62" // Day-ahead price
	BusinessTypeFrequency          = "A85" // System frequency
	BusinessTypeProductionForecast = "A71" // Production forecast
)

// PlaceholderDisclaimer is the canonical disclaimer text every
// Phase-1 scaffold MarketReport carries. Downstream readers can grep
// for this literal to refuse placeholder XML at the submission
// boundary.
const PlaceholderDisclaimer = "PLACEHOLDER-PHASE-1-SCAFFOLD: not from a live ENTSO-E feed; do NOT submit to the real ENTSO-E transparency platform"

// Emit produces a canonical Phase-1 scaffold MarketReport for the
// given UK area-code + bidding-zone + time window. Returns the
// MarketReport struct ready for XML marshaling.
//
// The PlaceholderDisclaimer is always set on the emitted report —
// downstream consumers can refuse Phase-1-scaffold reports by
// grepping for the disclaimer.
func Emit(reportID, areaCode, biddingZone string, start, end time.Time) MarketReport {
	created := time.Now().UTC().Format(time.RFC3339)
	return MarketReport{
		SchemaVersion: SchemaVersion,
		ReportID:      reportID,
		Created:       created,
		AreaCode:      areaCode,
		BiddingZone:   biddingZone,
		TimeSeries:    canonicalUKTimeSeries(start, end),
		Disclaimer:    PlaceholderDisclaimer,
	}
}

// canonicalUKTimeSeries returns the Phase-1 canonical 4-series UK
// scaffold: generation + load + day-ahead price + frequency.
func canonicalUKTimeSeries(start, end time.Time) []TimeSeries {
	periodGen := Period{
		Start:    start.Format(time.RFC3339),
		End:      end.Format(time.RFC3339),
		Quantity: 30500.0, // MW — placeholder fixture
	}
	periodLoad := Period{
		Start:    start.Format(time.RFC3339),
		End:      end.Format(time.RFC3339),
		Quantity: 29800.0, // MW
	}
	periodPrice := Period{
		Start:    start.Format(time.RFC3339),
		End:      end.Format(time.RFC3339),
		Quantity: 78.50, // GBP/MWh
	}
	periodFreq := Period{
		Start:    start.Format(time.RFC3339),
		End:      end.Format(time.RFC3339),
		Quantity: 50.00, // Hz
	}
	return []TimeSeries{
		{BusinessType: BusinessTypeGeneration, UnitOfMeasure: "MW", Periods: []Period{periodGen}},
		{BusinessType: BusinessTypeLoad, UnitOfMeasure: "MW", Periods: []Period{periodLoad}},
		{BusinessType: BusinessTypeDayAheadPrice, UnitOfMeasure: "GBP/MWh", Periods: []Period{periodPrice}},
		{BusinessType: BusinessTypeFrequency, UnitOfMeasure: "Hz", Periods: []Period{periodFreq}},
	}
}

// Marshal serialises a MarketReport to XML bytes. Returns the
// IEC 62325-451-3-shaped XML body without an XML prolog (callers
// add the `<?xml ...?>` declaration if required).
func Marshal(mr MarketReport) ([]byte, error) {
	out, err := xml.MarshalIndent(mr, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("entsoe: xml marshal: %w", err)
	}
	return out, nil
}
