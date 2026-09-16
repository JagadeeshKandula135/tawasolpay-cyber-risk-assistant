"""Loads the TawasolPay data pack and public reference catalogs."""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List

import pandas as pd

log = logging.getLogger(__name__)

CVE_PATTERN = re.compile(
    r"(CVE-\d{4}-\d{4,7}|CVE-SYN-\d{4}-\d{4}|CICD-SYN-\d{3}|CLOUD-SYN-\d{3}"
    r"|CTRL-SYN-\d{3}|K8S-SYN-\d{3})"
)
SECTION_PATTERN = re.compile(
    r"###\s*\d+\.\s*([^\n]+)\n(.*?)(?=(?:###|\Z|## Threat Intelligence))", re.DOTALL
)

CSV_SPEC = {
    "assets.csv": ("assets", ["asset_id"]),
    "vulnerabilities.csv": ("vulnerabilities", ["asset_id", "cve"]),
    "business_services.csv": ("biz_services", []),
    "threat_intelligence.csv": ("threat_intel", ["matched_cve_or_control"]),
    "remediation_guidance.csv": ("remediation_hints", []),
    "known_exploited_vulnerabilities.csv": ("cisa_kev", ["cveid"]),
}

NIST_FILE = "NIST_SP-800-53_rev5_catalog_load.csv"
REPORT_FILE = "synthetic_threat_report.md"


class DataPackError(FileNotFoundError):
    """A required data pack file is missing."""


class DataPackIngestion:
    def __init__(self, data_dir: str = "data") -> None:
        self.data_dir = data_dir
        self.frames: Dict[str, pd.DataFrame] = {}
        self.nist_catalog_df = pd.DataFrame()
        self.threat_report_raw = ""
        self.threat_campaigns: List[Dict[str, Any]] = []

    def _find_path(self, filename: str, required: bool = True) -> str | None:
        for candidate in (os.path.join(self.data_dir, filename), os.path.join(".", filename)):
            if os.path.exists(candidate):
                return candidate
        if required:
            raise DataPackError(
                f"{filename} not found in '{self.data_dir}/' or current working directory."
            )
        return None

    @staticmethod
    def _read(path: str) -> pd.DataFrame:
        df = pd.read_csv(path, low_memory=False, encoding="utf-8-sig")
        df.columns = [str(c).strip().lower().replace(" ", "_").replace("-", "_") for c in df.columns]
        return df

    def load_data(self) -> None:
        for filename, (key, join_cols) in CSV_SPEC.items():
            df = self._read(self._find_path(filename))
            for col in join_cols:
                if col in df.columns:
                    df[col] = df[col].astype(str).str.strip().str.upper()
            self.frames[key] = df

        self.nist_catalog_df = self._read(self._find_path(NIST_FILE))
        self._load_threat_report()
        self._log_coverage()

    def _load_threat_report(self) -> None:
        path = self._find_path(REPORT_FILE, required=False)
        if not path:
            log.warning("%s not found; skipping campaign ingestion.", REPORT_FILE)
            return

        with open(path, encoding="utf-8") as f:
            self.threat_report_raw = f.read()

        for name, details in SECTION_PATTERN.findall(self.threat_report_raw):
            lowered = details.lower()
            self.threat_campaigns.append(
                {
                    "campaign_name": name.strip(),
                    "cves": sorted({c.upper() for c in CVE_PATTERN.findall(details)}),
                    "ransomware": "ransomware: yes" in lowered,
                    "text": details.strip(),
                }
            )

    def _log_coverage(self) -> None:
        vulns, assets = self.frames["vulnerabilities"], self.frames["assets"]
        kev, intel = self.frames["cisa_kev"], self.frames["threat_intel"]

        cves = set(vulns["cve"].dropna())
        orphans = set(vulns["asset_id"]) - set(assets["asset_id"])
        report_cves = {c for camp in self.threat_campaigns for c in camp["cves"]}

        log.info(
            "Loaded %d vulns / %d assets. KEV: %d/%d, Intel: %d/%d, Report: %d/%d. Orphan assets: %d.",
            len(vulns),
            len(assets),
            len(cves & set(kev["cveid"].dropna())),
            len(cves),
            len(cves & set(intel["matched_cve_or_control"].dropna())),
            len(cves),
            len(cves & report_cves),
            len(cves),
            len(orphans),
        )

    def run(self) -> Dict[str, Any]:
        self.load_data()
        return {
            **self.frames,
            "nist_catalog": self.nist_catalog_df,
            "threat_campaigns": self.threat_campaigns,
            "threat_report_raw": self.threat_report_raw,
        }