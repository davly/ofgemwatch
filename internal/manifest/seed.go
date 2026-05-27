package manifest

import "time"

// RIIO2DeterminationDate is the wall-clock UTC date of the Ofgem
// RIIO-2 final determinations (2026-04-08 — placeholder; actual
// document publication will be updated when next ED2 cycle lands).
var RIIO2DeterminationDate = time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC)

// ENTSOEPublicationDate is the wall-clock UTC date of the most recent
// ENTSO-E Network Code publication consulted at scaffold (2026-03-15
// — placeholder for the EU-public XSD version pinned at inception).
var ENTSOEPublicationDate = time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

// ScaffoldDate is the wall-clock UTC date of the ofgemwatch inception
// scaffold ship (BR6 marathon 2026-05-27).
var ScaffoldDate = time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)

// Seed returns the canonical manifest inventory for ofgemwatch's
// curated regulatory-classification surface. 12 entries total: 5
// Ofgem RIIO + 4 ENTSO-E + 3 FERC Order 1000 (all Phase-3 deferred,
// ReviewedByCounsel=false, ConfidenceHonestTODO).
func Seed() Manifest {
	return Manifest{
		// --- Ofgem RIIO references (5) ---

		{
			Key:               "riio_ed2_final_determinations",
			Class:             ClassOfgemRIIO,
			Source:            SourceOfgemMethodology,
			FreshAt:           RIIO2DeterminationDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewedByCounsel: false, // Phase-3 deliverable
			Rationale:         "Ofgem RIIO-ED2 (Distribution) Final Determinations — 5-year price-control framework for UK Distribution Network Operators (DNOs). The canonical reference for distribution-side price-control compliance verification.",
		},
		{
			Key:               "riio_2_methodology_decision",
			Class:             ClassOfgemRIIO,
			Source:            SourceOfgemMethodology,
			FreshAt:           RIIO2DeterminationDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewedByCounsel: false,
			Rationale:         "Ofgem RIIO-2 Methodology Decision — describes the framework Ofgem applies to set price controls (cost of capital, output incentives, totex assessment). Load-bearing for any cost-forecast verdict.",
		},
		{
			Key:               "dno_licence_conditions_standard",
			Class:             ClassOfgemRIIO,
			Source:            SourceOfgemMethodology,
			FreshAt:           RIIO2DeterminationDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewedByCounsel: false,
			Rationale:         "Electricity Distribution Licence — Standard Conditions (Ofgem-published licence document). Every DNO operates under this licence; compliance verification anchors to the standard conditions list.",
		},
		{
			Key:               "cma_appeals_energy_panel",
			Class:             ClassOfgemRIIO,
			Source:            SourceCMAAppealsDB,
			FreshAt:           SentinelHonestTODO, // not yet curated at scaffold
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewedByCounsel: false,
			Rationale:         "CMA energy-sector appeals against Ofgem decisions (Energy Appeals Panel). Used for cross-reference against Ofgem determinations. FreshAt is honest-TODO at scaffold — manual curation deferred to Phase 2.",
		},
		{
			Key:               "ofgem_impact_assessment_template",
			Class:             ClassOfgemRIIO,
			Source:            SourceECPaperOfgem,
			FreshAt:           ScaffoldDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewedByCounsel: false,
			Rationale:         "Ofgem Impact Assessment template — used in Better Regulation Framework process. Secondary reference for understanding regulatory rationale.",
		},

		// --- ENTSO-E references (4) ---

		{
			Key:               "entsoe_network_code_operational_security",
			Class:             ClassENTSOEReference,
			Source:            SourceENTSOENetworkCode,
			FreshAt:           ENTSOEPublicationDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewedByCounsel: false,
			Rationale:         "ENTSO-E Network Code on Operational Security (Regulation (EU) 2017/1485). Authoritative; load-bearing for transmission-side operational-security verdicts.",
		},
		{
			Key:               "iec_62325_451_3_transparency_xsd",
			Class:             ClassENTSOEReference,
			Source:            SourceENTSOETransparencyXSD,
			FreshAt:           ENTSOEPublicationDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewedByCounsel: false,
			Rationale:         "IEC 62325-451-3 Transparency XML Schema — the canonical XSD that ofgemwatch's ENTSO-E XML producer emits against. Pinned at the published XSD revision.",
		},
		{
			Key:               "entsoe_market_report_template",
			Class:             ClassENTSOEReference,
			Source:            SourceENTSOENetworkCode,
			FreshAt:           ENTSOEPublicationDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewedByCounsel: false,
			Rationale:         "ENTSO-E Market Report template — describes the required market-monitoring publication shape. Used as cross-reference for transparency-platform consistency.",
		},
		{
			Key:               "entsoe_adequacy_outlook_methodology",
			Class:             ClassENTSOEReference,
			Source:            SourceENTSOENetworkCode,
			FreshAt:           ENTSOEPublicationDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewedByCounsel: false,
			Rationale:         "ENTSO-E Mid-term Adequacy Forecast methodology — used in pan-European adequacy assessment cross-reference. Secondary to operational-security network code.",
		},

		// --- FERC Order 1000 references (3) — Phase-3 deferred ---

		{
			Key:               "ferc_order_1000_18cfr_35_34",
			Class:             ClassFERCOrder1000,
			Source:            SourceFERCOrder1000Pending,
			FreshAt:           SentinelHonestTODO,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHonestTODO,
			ReviewedByCounsel: false,
			Rationale:         "FERC Order 1000 — 18 CFR § 35.34 transmission planning + cost allocation. Phase-3 deferred — needs US-FERC counsel review before regulator-load-bearing.",
		},
		{
			Key:               "rto_transmission_planning_template",
			Class:             ClassFERCOrder1000,
			Source:            SourceFERCOrder1000Pending,
			FreshAt:           SentinelHonestTODO,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHonestTODO,
			ReviewedByCounsel: false,
			Rationale:         "US RTO (Regional Transmission Organization) transmission planning template. Phase-3 deferred — referenced for cross-Atlantic harmonization scope but not yet curated.",
		},
		{
			Key:               "interregional_cost_allocation_framework",
			Class:             ClassFERCOrder1000,
			Source:            SourceFERCOrder1000Pending,
			FreshAt:           SentinelHonestTODO,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHonestTODO,
			ReviewedByCounsel: false,
			Rationale:         "Interregional cost allocation framework under FERC Order 1000. Phase-3 deferred — cross-Atlantic transmission harmonization scope.",
		},
	}
}
