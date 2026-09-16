"""Deterministic risk scoring, asset-grouping, and justification generation."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import pandas as pd

log = logging.getLogger(__name__)

TRUE_TOKENS = {"yes", "true", "y", "1", "external", "public", "exposed"}
FALSE_TOKENS = {"no", "false", "n", "0", "internal", "private"}

CONFIDENCE_MAP = {"high": 1.0, "medium": 0.7, "low": 0.4}
CRITICALITY_MAP = {"critical": 100.0, "high": 80.0, "medium": 50.0, "low": 25.0}
CRITICALITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
REVENUE_MAP = {"critical": 20.0, "high": 15.0, "medium": 10.0, "low": 5.0}
COMPLIANCE_MAP = {
    "pci dss": 10.0,
    "pci-dss": 10.0,
    "gdpr": 5.0,
    "iso 27001": 5.0,
    "iso27001": 5.0,
    "soc 2": 5.0,
    "soc2": 5.0,
}

REGIONAL_TOKENS = ("middle east", "gulf", "gcc", "uae", "mena")
SECTOR_TOKENS = ("fintech", "finance", "financial", "banking", "payments")


def clean(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    text = str(value).strip().lower()
    return "" if text in {"nan", "none", "<na>"} else text


def first(*values: Any) -> Any:
    for value in values:
        if clean(value):
            return value
    return None


def is_true(value: Any) -> bool:
    text = clean(value)
    if not text or text in FALSE_TOKENS:
        return False
    return text in TRUE_TOKENS or any(t in text for t in ("yes", "true", "exposed"))


class RiskScoringEngine:
    def __init__(self, data_pack: Dict[str, Any]) -> None:
        self.assets = data_pack["assets"]
        self.vulns = data_pack["vulnerabilities"]
        self.threat_intel = data_pack["threat_intel"]
        self.biz_services = data_pack["biz_services"]
        self.remed_hints = data_pack["remediation_hints"]
        self.cisa_kev = data_pack["cisa_kev"]
        self.threat_campaigns = data_pack.get("threat_campaigns", [])

    def _collapse_intel(self) -> pd.DataFrame:
        ti = self.threat_intel.copy()
        key = "matched_cve_or_control"

        agg = {
            "ti_actors": ("threat_actor", lambda s: sorted({str(x) for x in s.dropna()})),
            "ti_campaigns": ("campaign_name", lambda s: sorted({str(x) for x in s.dropna()})),
            "ti_regions": ("target_region", lambda s: " | ".join(sorted({str(x) for x in s.dropna()}))),
            "ti_sectors": ("target_sector", lambda s: " | ".join(sorted({str(x) for x in s.dropna()}))),
            "ti_ransomware": ("ransomware_association", lambda s: any(is_true(x) for x in s)),
            "ti_exploit_maturity": ("exploit_maturity", lambda s: sorted({clean(x) for x in s.dropna()})[-1] if s.notna().any() else ""),
            "ti_confidence": ("confidence", lambda s: sorted({clean(x) for x in s.dropna()})[-1] if s.notna().any() else "low"),
            "ti_match_count": (key, "size"),
        }

        collapsed = ti.groupby(key, as_index=False).agg(**agg)
        return collapsed.rename(columns={key: "cve_clean"})

    def _campaign_report_map(self) -> Dict[str, Dict[str, Any]]:
        mapping: Dict[str, Dict[str, Any]] = {}
        for camp in self.threat_campaigns:
            for cve in camp.get("cves", []):
                mapping[cve.upper()] = {
                    "report_campaign": camp.get("campaign_name", ""),
                    "report_ransomware": camp.get("ransomware", False),
                }
        return mapping

    def merge_and_rank(self, consolidate_assets: bool = True) -> pd.DataFrame:
        df = self.vulns.copy()
        df["cve_clean"] = df["cve"].astype(str).str.strip().str.upper()

        df = df.merge(
            self.assets.drop_duplicates("asset_id"),
            on="asset_id",
            how="left",
            suffixes=("", "_asset"),
        )
        df = df.merge(
            self.biz_services.drop_duplicates("business_service"),
            on="business_service",
            how="left",
            suffixes=("", "_biz"),
        )
        df = df.merge(self._collapse_intel(), on="cve_clean", how="left", suffixes=("", "_ti"))

        kev = self.cisa_kev.drop_duplicates("cveid").rename(columns={"cveid": "cve_clean"})
        kev_cols = [
            c
            for c in ("cve_clean", "knownransomwarecampaignuse", "requiredaction", "dateadded")
            if c in kev.columns
        ]
        df = df.merge(kev[kev_cols], on="cve_clean", how="left", suffixes=("", "_kev"))
        df["in_kev"] = df["cve_clean"].isin(set(self.cisa_kev["cveid"].dropna()))

        report_map = self._campaign_report_map()
        df["report_campaign"] = df["cve_clean"].map(lambda c: report_map.get(c, {}).get("report_campaign"))
        df["report_ransomware"] = df["cve_clean"].map(
            lambda c: report_map.get(c, {}).get("report_ransomware", False)
        )

        df["action_plan"] = self._match_hints(df)

        eval_cols = [
            "composite_risk_score",
            "cvss_sub",
            "exposure_sub",
            "exploit_sub",
            "threat_intel_sub",
            "business_impact_sub",
            "control_gap_sub",
            "rank_reason",
            "score_breakdown",
            "exposure_source",
            "data_gaps",
            "_tie_kev",
            "_tie_rw",
            "_tie_exposed",
            "_tie_crit",
            "_tie_pci",
            "_tie_rev",
            "_tie_conf",
            "_tie_days",
            "_tie_cvss",
        ]
        results = df.apply(self._evaluate, axis=1, result_type="expand")
        df[eval_cols] = results

        # Primary sort: Exact composite score descending
        sort_columns = [
            "composite_risk_score",
            "_tie_kev",
            "_tie_rw",
            "_tie_exposed",
            "_tie_crit",
            "_tie_pci",
            "_tie_rev",
            "_tie_conf",
            "_tie_days",
            "_tie_cvss",
            "asset_id",
            "cve_clean",
        ]
        sort_asc = [False, False, False, False, False, False, False, False, False, False, True, True]

        sorted_df = df.sort_values(by=sort_columns, ascending=sort_asc, kind="mergesort")
        cleanup_cols = [c for c in sorted_df.columns if c.startswith("_tie_")]
        ranked = sorted_df.drop(columns=cleanup_cols).reset_index(drop=True)

        if consolidate_assets:
            return self._group_identical_risks(ranked)
        return ranked

    @staticmethod
    def _group_identical_risks(df: pd.DataFrame) -> pd.DataFrame:
        """Consolidates twin cluster nodes sharing the same CVE, business service, and score."""
        group_keys = [
            "cve_clean",
            "business_service",
            "vulnerability_name",
            "composite_risk_score",
        ]
        aggregated = []
        seen = set()

        for _, row in df.iterrows():
            key = tuple(row.get(k) for k in group_keys)
            if key in seen:
                continue
            seen.add(key)

            matches = df[
                (df["cve_clean"] == row["cve_clean"])
                & (df["business_service"] == row["business_service"])
                & (df["composite_risk_score"] == row["composite_risk_score"])
            ]

            row_copy = row.copy()
            asset_names = [str(x) for x in matches["asset_name"].dropna().unique()]
            asset_ids = [str(x) for x in matches["asset_id"].dropna().unique()]

            row_copy["asset_name"] = ", ".join(asset_names)
            row_copy["asset_id"] = ", ".join(asset_ids)
            row_copy["affected_host_count"] = int(len(matches))

            aggregated.append(row_copy)

        return pd.DataFrame(aggregated).reset_index(drop=True)

    def _match_hints(self, df: pd.DataFrame) -> pd.Series:
        if "finding_type" not in self.remed_hints.columns:
            return pd.Series([""] * len(df), index=df.index)

        hints: List[Tuple[set, str]] = []
        for _, row in self.remed_hints.iterrows():
            words = {w for w in clean(row["finding_type"]).split() if len(w) > 3}
            if words:
                hints.append((words, str(row.get("recommended_action", "")).strip()))

        def best(row: pd.Series) -> str:
            haystack = set(
                f"{clean(row.get('vulnerability_name'))} {clean(row.get('affected_component'))}".split()
            )
            scored = [(len(words & haystack), action) for words, action in hints]
            top_score, action = max(scored, default=(0, ""))
            return action if top_score > 0 else ""

        return df.apply(best, axis=1)

    def _evaluate(self, row: pd.Series) -> pd.Series:
        reasons: List[str] = []
        gaps: List[str] = []

        try:
            cvss = float(row.get("cvss"))
        except (TypeError, ValueError):
            cvss = 5.0
            gaps.append("CVSS not recorded, defaulted to 5.0")
        cvss_score = min(100.0, max(0.0, (cvss / 10.0) * 100.0))

        asset_exp = row.get("internet_exposed")
        vuln_exp = row.get("asset_exposure")

        if clean(asset_exp):
            exposed = is_true(asset_exp)
            source = "assets.csv"
            exp_base = 100.0 if exposed else 25.0
        elif clean(vuln_exp):
            exposed = is_true(vuln_exp)
            source = "vulnerabilities.csv (fallback)"
            exp_base = 100.0 if exposed else 25.0
            gaps.append("Exposure resolved from vulnerability feed")
        else:
            exposed = False
            source = "unknown"
            exp_base = 50.0
            gaps.append("Exposure unknown, scored as 50.0")

        env = clean(row.get("environment"))
        env_adj = 10.0 if env == "production" else 0.0
        exposure_score = min(100.0, exp_base + env_adj)
        if exposed:
            reasons.append("Reachable from public internet")

        in_kev = bool(row.get("in_kev"))
        kev_rw_text = clean(row.get("knownransomwarecampaignuse"))
        kev_ransomware = in_kev and (kev_rw_text == "known" or is_true(kev_rw_text))
        exploit_available = is_true(row.get("exploit_available"))

        if in_kev and kev_ransomware:
            exploit_score = 100.0
            reasons.append("Active in-the-wild exploitation + confirmed ransomware (CISA KEV)")
        elif in_kev:
            exploit_score = 90.0
            reasons.append("Listed in CISA KEV (active in-the-wild exploitation)")
        elif exploit_available:
            exploit_score = 75.0
            reasons.append("Functional exploit publicly available")
        else:
            exploit_score = 20.0

        ti_match = row.get("ti_match_count", 0) > 0
        ti_score_raw = 0.0
        conf_mult = 0.0

        if ti_match:
            ti_score_raw += 40.0
            campaigns = row.get("ti_campaigns", [])
            if campaigns:
                reasons.append(f"Targeted in campaign(s): {', '.join(campaigns)}")

            sectors = clean(row.get("ti_sectors"))
            if any(s in sectors for s in SECTOR_TOKENS):
                ti_score_raw += 20.0
                reasons.append("Sector target: Fintech/Banking")

            regions = clean(row.get("ti_regions"))
            if any(r in regions for r in REGIONAL_TOKENS):
                ti_score_raw += 15.0
                reasons.append("Regional target: Middle East/Gulf")

            if is_true(row.get("ti_ransomware")):
                ti_score_raw += 15.0
                reasons.append("Ransomware association confirmed in threat intel")

            maturity = clean(row.get("ti_exploit_maturity"))
            if maturity in {"high", "weaponized", "functional"}:
                ti_score_raw += 10.0

            conf_key = clean(row.get("ti_confidence"))
            conf_mult = CONFIDENCE_MAP.get(conf_key, 0.4)
            threat_intel_score = min(100.0, ti_score_raw * conf_mult)
        else:
            threat_intel_score = 0.0

        if row.get("report_ransomware") is True and not is_true(row.get("ti_ransomware")):
            reasons.append("Ransomware campaign cited in regional MDR advisory")

        crit_key = clean(row.get("criticality"))
        crit_score = CRITICALITY_MAP.get(crit_key, 25.0)

        cust_score = 15.0 if is_true(row.get("customer_facing")) else 0.0
        rev_val = clean(row.get("revenue_impact"))
        rev_score = REVENUE_MAP.get(rev_val, 0.0)

        scope = clean(row.get("compliance_scope"))
        comp_score = 0.0
        if scope:
            for token, pts in COMPLIANCE_MAP.items():
                if token in scope:
                    comp_score += pts
            reasons.append(f"Compliance scope: {row.get('compliance_scope')}")

        business_impact_score = min(100.0, crit_score + cust_score + rev_score + comp_score)
        if crit_score >= 80.0:
            reasons.append(f"Supports critical business service '{row.get('business_service')}'")

        edr = clean(row.get("edr_installed"))
        if not edr:
            control_gap_score = 50.0
            gaps.append("EDR status not recorded")
        elif not is_true(edr):
            control_gap_score = 100.0
            reasons.append("Compensating control missing (No EDR installed)")
        else:
            control_gap_score = 10.0

        raw_composite = (
            (0.25 * cvss_score)
            + (0.20 * exposure_score)
            + (0.20 * exploit_score)
            + (0.15 * threat_intel_score)
            + (0.15 * business_impact_score)
            + (0.05 * control_gap_score)
        )

        composite_display = round(raw_composite, 3)

        breakdown = (
            f"Score: {composite_display:.3f} | "
            f"CVSS(25%): {cvss_score:.3f}, "
            f"Exposure(20%): {exposure_score:.3f}, "
            f"Exploit(20%): {exploit_score:.3f}, "
            f"ThreatIntel(15%): {threat_intel_score:.3f}, "
            f"BizImpact(15%): {business_impact_score:.3f}, "
            f"ControlGap(5%): {control_gap_score:.3f}"
        )

        try:
            days_open = float(row.get("days_open", 0.0))
        except (TypeError, ValueError):
            days_open = 0.0

        tie_conf_val = {"high": 3, "medium": 2, "low": 1}.get(clean(row.get("ti_confidence")), 0)
        is_rw = 1 if (kev_ransomware or is_true(row.get("ti_ransomware")) or row.get("report_ransomware") is True) else 0
        is_pci = 1 if "pci" in scope else 0

        return pd.Series(
            [
                composite_display,
                round(cvss_score, 3),
                round(exposure_score, 3),
                round(exploit_score, 3),
                round(threat_intel_score, 3),
                round(business_impact_score, 3),
                round(control_gap_score, 3),
                "; ".join(reasons) if reasons else "Ranked on baseline characteristics",
                breakdown,
                source,
                "; ".join(gaps),
                1 if in_kev else 0,
                is_rw,
                1 if exposed else 0,
                CRITICALITY_RANK.get(crit_key, 1),
                is_pci,
                rev_score,
                tie_conf_val,
                days_open,
                cvss,
            ]
        )