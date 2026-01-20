"""Data models for the Supply Chain Security Analyzer."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Ecosystem(Enum):
    """Supported package ecosystems."""
    PIP = "pip"
    NPM = "npm"
    MAVEN = "maven"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.UNKNOWN


@dataclass
class Dependency:
    """Represents a package dependency."""
    name: str
    version: str
    ecosystem: Ecosystem = Ecosystem.PIP
    source_file: Optional[str] = None
    is_direct: bool = True
    dependencies: list["Dependency"] = field(default_factory=list)
    
    @property
    def identifier(self) -> str:
        """Unique identifier for this dependency."""
        return f"{self.ecosystem.value}:{self.name}@{self.version}"
    
    def __hash__(self):
        return hash(self.identifier)
    
    def __eq__(self, other):
        if not isinstance(other, Dependency):
            return False
        return self.identifier == other.identifier


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    id: str  # CVE ID or OSV ID
    summary: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published: Optional[datetime] = None
    
    @property
    def is_critical(self) -> bool:
        """Check if this is a critical vulnerability."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


@dataclass
class LicenseInfo:
    """Represents license information for a package."""
    spdx_id: str
    name: str
    is_permissive: bool = True
    is_copyleft: bool = False
    is_weak_copyleft: bool = False
    impact_note: str = ""
    
    # Known permissive licenses
    PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0"}
    
    # Weak copyleft - file-level only, often enterprise-acceptable
    WEAK_COPYLEFT_LICENSES = {"MPL-2.0", "LGPL-2.1", "LGPL-3.0"}
    
    # Strong copyleft - requires full source disclosure
    STRONG_COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0"}
    
    @classmethod
    def from_spdx(cls, spdx_id: str) -> "LicenseInfo":
        """Create LicenseInfo from SPDX identifier."""
        is_permissive = spdx_id in cls.PERMISSIVE_LICENSES
        is_weak_copyleft = spdx_id in cls.WEAK_COPYLEFT_LICENSES
        is_copyleft = spdx_id in cls.STRONG_COPYLEFT_LICENSES
        
        # Set impact note for context
        impact_note = ""
        if is_weak_copyleft:
            if spdx_id == "MPL-2.0":
                impact_note = "Requires disclosure of modified MPL-covered files only"
            elif spdx_id.startswith("LGPL"):
                impact_note = "Allows linking without source disclosure"
        elif is_copyleft:
            impact_note = "Requires full source disclosure if distributed"
        
        return cls(
            spdx_id=spdx_id,
            name=spdx_id,
            is_permissive=is_permissive,
            is_copyleft=is_copyleft,
            is_weak_copyleft=is_weak_copyleft,
            impact_note=impact_note,
        )


@dataclass
class TyposquatMatch:
    """Represents a potential typosquatting match."""
    suspicious_package: str
    legitimate_package: str
    similarity_score: float
    detection_method: str  # "levenshtein", "homoglyph", "swap", etc.
    risk_level: str  # "high", "medium", "low"


@dataclass
class ScanResult:
    """Aggregated results from a security scan."""
    project_path: str
    scan_time: datetime
    dependencies: list[Dependency] = field(default_factory=list)
    vulnerabilities: dict[str, list[Vulnerability]] = field(default_factory=dict)  # dep_id -> vulns
    typosquat_matches: list[TyposquatMatch] = field(default_factory=list)
    license_issues: list[tuple[Dependency, LicenseInfo]] = field(default_factory=list)
    maturity_scores: dict = field(default_factory=dict)  # package_name -> MaturityScore
    ses_scores: dict = field(default_factory=dict)  # package_name -> SecurityExposureScore
    
    @property
    def reputation_scores(self) -> dict:
        """Backwards compatibility alias for maturity_scores."""
        return self.maturity_scores
    
    @property
    def total_dependencies(self) -> int:
        """Total number of dependencies scanned."""
        return len(self.dependencies)
    
    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities found."""
        return sum(len(v) for v in self.vulnerabilities.values())
    
    @property
    def critical_vulnerabilities(self) -> int:
        """Number of critical/high severity vulnerabilities."""
        count = 0
        for vulns in self.vulnerabilities.values():
            count += sum(1 for v in vulns if v.is_critical)
        return count
    
    @property
    def has_issues(self) -> bool:
        """Check if any security issues were found."""
        return (
            self.total_vulnerabilities > 0 
            or len(self.typosquat_matches) > 0 
            or len(self.license_issues) > 0
        )
