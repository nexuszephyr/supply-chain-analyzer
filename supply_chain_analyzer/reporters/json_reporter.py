"""JSON output reporter."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..core.models import ScanResult


class JsonReporter:
    """Reporter that outputs results as JSON."""
    
    def report(self, result: ScanResult, output_path: Optional[Path] = None) -> str:
        """
        Generate a JSON report from scan results.
        
        Args:
            result: The scan results
            output_path: Optional file path to write the report to
            
        Returns:
            JSON string of the report
        """
        report_data = self._build_report(result)
        json_output = json.dumps(report_data, indent=2, default=str)
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(json_output)
        
        return json_output
    
    def _build_report(self, result: ScanResult) -> dict:
        """Build the report dictionary."""
        return {
            "metadata": {
                "project_path": result.project_path,
                "scan_time": result.scan_time.isoformat(),
                "tool": "supply-chain-analyzer",
                "version": "0.1.0",
            },
            "summary": {
                "total_dependencies": result.total_dependencies,
                "total_vulnerabilities": result.total_vulnerabilities,
                "critical_vulnerabilities": result.critical_vulnerabilities,
                "typosquatting_alerts": len(result.typosquat_matches),
                "license_issues": len(result.license_issues),
                "has_issues": result.has_issues,
            },
            "dependencies": [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem.value,
                    "source_file": dep.source_file,
                    "is_direct": dep.is_direct,
                }
                for dep in result.dependencies
            ],
            "vulnerabilities": {
                dep_id: [
                    {
                        "id": vuln.id,
                        "summary": vuln.summary,
                        "description": vuln.description,
                        "severity": vuln.severity.value,
                        "cvss_score": vuln.cvss_score,
                        "affected_versions": vuln.affected_versions,
                        "fixed_versions": vuln.fixed_versions,
                        "references": vuln.references,
                        "published": vuln.published.isoformat() if vuln.published else None,
                    }
                    for vuln in vulns
                ]
                for dep_id, vulns in result.vulnerabilities.items()
            },
            "typosquatting": [
                {
                    "suspicious_package": match.suspicious_package,
                    "legitimate_package": match.legitimate_package,
                    "similarity_score": match.similarity_score,
                    "detection_method": match.detection_method,
                    "risk_level": match.risk_level,
                }
                for match in result.typosquat_matches
            ],
            "license_issues": [
                {
                    "package": f"{dep.name}@{dep.version}",
                    "license": license_info.spdx_id,
                    "is_permissive": license_info.is_permissive,
                    "is_copyleft": license_info.is_copyleft,
                }
                for dep, license_info in result.license_issues
            ],
            "reputation_scores": {
                name: {
                    "overall_score": score.overall_score,
                    "risk_level": score.risk_level,
                    "factors": score.factors,
                    "details": score.details,
                }
                for name, score in result.reputation_scores.items()
            } if result.reputation_scores else {},
        }

