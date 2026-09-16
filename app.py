"""Streamlit dashboard for TawasolPay cyber risk prioritization.

Implements:
1. Dynamic Structured Risk Records (Step 1)
2. Offline Semantic NIST Query Generation & Vector DB Retrieval (Step 2)
3. Grounded Prompt Assembly & Gemini 1.5 Flash Briefing Generation (Step 3 & 4)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src.ingest import DataPackIngestion
from src.rag import (
    NIST80053RAG,
    BriefingSynthesizer,
    build_nist_retrieval_query,
)
from src.scorer import RiskScoringEngine, clean, first, is_true

load_dotenv()
logging.basicConfig(level=logging.INFO)

st.set_page_config(page_title="TawasolPay Cyber Risk Assistant", layout="wide")

UNKNOWN = "not recorded"
TOP_N = 5

INVENTORY_COLUMNS = [
    "cve_clean",
    "vulnerability_name",
    "asset_id",
    "asset_name",
    "affected_host_count",
    "business_service",
    "composite_risk_score",
    "cvss_sub",
    "exposure_sub",
    "exploit_sub",
    "threat_intel_sub",
    "business_impact_sub",
    "control_gap_sub",
    "cvss",
    "internet_exposed",
    "edr_installed",
    "score_breakdown",
]


def show(*values, default: str = UNKNOWN):
    value = first(*values)
    return default if value is None else value


def build_risk_record(rank: int, row: pd.Series) -> Dict[str, Any]:
    """Converts a DataFrame row into an immutable structured risk record."""
    campaigns = row.get("ti_campaigns") if isinstance(row.get("ti_campaigns"), list) else []
    if not campaigns and clean(row.get("report_campaign")):
        campaigns = [str(row.get("report_campaign"))]

    is_rw = bool(row.get("ti_ransomware")) or (row.get("report_ransomware") is True)
    kev_rw = clean(row.get("knownransomwarecampaignuse"))

    return {
        "rank": rank,
        "asset": {
            "asset_id": str(row.get("asset_id", "")),
            "asset_name": str(row.get("asset_name", "")),
            "criticality": clean(row.get("criticality")).capitalize() or "Unknown",
            "business_service": str(row.get("business_service", "")),
            "internet_exposed": is_true(row.get("internet_exposed")),
            "edr_installed": is_true(row.get("edr_installed")),
            "affected_host_count": int(row.get("affected_host_count", 1)),
        },
        "vulnerability": {
            "cve": str(row.get("cve_clean", row.get("cve", ""))),
            "name": str(row.get("vulnerability_name", "")),
            "cvss": float(row.get("cvss", 5.0)),
            "patch_available": not is_true(row.get("exploit_available")),
            "days_open": float(row.get("days_open", 0.0)),
        },
        "threat_intel": {
            "campaign_name": ", ".join(campaigns) if campaigns else "None matched",
            "threat_actor": ", ".join(row.get("ti_actors", [])) if isinstance(row.get("ti_actors"), list) else "Unknown",
            "confidence": clean(row.get("ti_confidence")).capitalize() or "Low",
            "ransomware_association": is_rw,
        },
        "kev": {
            "in_kev": bool(row.get("in_kev", False)),
            "knownRansomwareCampaignUse": kev_rw.capitalize() if kev_rw else ("Known" if is_rw else "Unknown"),
            "dateAdded": str(row.get("dateadded", "N/A")),
        },
        "business_service": {
            "customer_facing": is_true(row.get("customer_facing")),
            "compliance_scope": str(row.get("compliance_scope", "None")),
            "revenue_impact": clean(row.get("revenue_impact")).capitalize() or "Low",
        },
        "scores": {
            "threat_severity": float(row.get("exploit_sub", 0.0)),
            "exposure": float(row.get("exposure_sub", 0.0)),
            "business_impact": float(row.get("business_impact_sub", 0.0)),
            "threat_intel": float(row.get("threat_intel_sub", 0.0)),
            "control_gap": float(row.get("control_gap_sub", 0.0)),
            "composite": float(row.get("composite_risk_score", 0.0)),
        },
        "action_plan": str(row.get("action_plan", "")),
        "rank_reason": str(row.get("rank_reason", "")),
        "score_breakdown": str(row.get("score_breakdown", "")),
    }


@st.cache_resource(show_spinner=False)
def load_system():
    pack = DataPackIngestion(data_dir="data").run()
    ranked = RiskScoringEngine(pack).merge_and_rank(consolidate_assets=True)
    rag_engine = NIST80053RAG(pack["nist_catalog"])
    return pack, ranked, rag_engine


@st.cache_data(show_spinner=False)
def process_top_risks(_rag: NIST80053RAG, top_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Runs the Grounded RAG Pipeline over the Top N risks."""
    processed = []
    for rank, (_, row) in enumerate(top_df.iterrows(), start=1):
        record = build_risk_record(rank, row)
        retrieval_query = build_nist_retrieval_query(record)
        matched_controls = _rag.retrieve_guidance(retrieval_query, top_k=3)
        briefing = BriefingSynthesizer.synthesize(record, matched_controls)

        processed.append({
            "record": record,
            "controls": matched_controls,
            "briefing": briefing,
        })
    return processed


st.title("TawasolPay Cyber Risk Prioritization Assistant")
st.caption(
    "Deterministic 6-factor risk modeling paired with local NIST SP 800-53 Rev. 5 control retrieval "
    "and grounded Gemini 1.5 Flash executive briefings."
)

try:
    with st.spinner("Initializing scoring engine & indexing local Vector DB..."):
        pack, ranked_df, rag = load_system()
except Exception as exc:
    st.error(f"Startup failed: {exc}")
    st.stop()

top_risks_df = ranked_df.head(TOP_N)

with st.spinner("Retrieving NIST guidance & generating executive briefings via Gemini 1.5 Flash..."):
    briefings = process_top_risks(rag, top_risks_df)

st.subheader(f"Top {len(briefings)} Actionable Risks")
st.markdown("Prioritized deterministically with 3-decimal precision using active threat advisories, exposure, and business impact.")

for item in briefings:
    rec = item["record"]
    a = rec["asset"]
    v = rec["vulnerability"]
    t = rec["threat_intel"]
    k = rec["kev"]
    s = rec["scores"]
    controls = item["controls"]
    primary = controls[0] if controls else None

    host_badge = f" 🛡️ [{a['affected_host_count']} Redundant Hosts]" if a["affected_host_count"] > 1 else ""
    header = f"{rec['rank']}. {v['cve']} on {a['asset_name']} ({a['asset_id']}){host_badge} — Score: {s['composite']:.3f}"

    with st.expander(header, expanded=True):
        left, right = st.columns([1, 1])

        with left:
            st.markdown("#### Structured Evidence & Telemetry")
            st.write(f"**Service at risk:** {a['business_service']}")
            st.write(f"**Affected hosts:** {a['asset_name']} ({a['asset_id']})")
            st.write(f"**Vulnerability:** {v['name']}")
            st.write(f"**CVSS Base:** {v['cvss']:.1f}")
            st.write(f"**Internet exposed:** {'Yes' if a['internet_exposed'] else 'No'}")
            st.write(f"**Matched campaign:** {t['campaign_name']}")
            st.write(f"**In CISA KEV:** {'Yes' if k['in_kev'] else 'No'}")
            st.write(f"**EDR installed:** {'Yes' if a['edr_installed'] else 'No'}")

            st.caption(f"Calculation Breakdown: {rec['score_breakdown']}")

        with right:
            st.markdown("#### Grounded Executive Risk Briefing")
            st.markdown(item["briefing"])

            if primary:
                with st.expander(f"Inspect Complete NIST Guidance ({primary['control_id']})"):
                    st.write(primary["guidance"])

                if len(controls) > 1:
                    st.caption(
                        "Alternative vector matches: "
                        + ", ".join(f"{c['control_id']} ({c['similarity']:.3f})" for c in controls[1:])
                    )

st.divider()
st.subheader("Full Prioritized Inventory")
available = [c for c in INVENTORY_COLUMNS if c in ranked_df.columns]

display_df = ranked_df[available].copy()
float_cols = [c for c in display_df.columns if c.endswith("_score") or c.endswith("_sub")]
for c in float_cols:
    display_df[c] = display_df[c].map(lambda val: f"{float(val):.3f}" if pd.notna(val) else "")

st.dataframe(display_df, hide_index=True, use_container_width=True)