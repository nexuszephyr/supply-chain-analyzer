"""Security Exposure Score (SES) based on vulnerability data."""

from dataclasses import dataclass, field
from typing import Optional

from ..core.config import Config
from ..core.models import Dependency, Vulnerability


@dataclass
class SecurityExposureScore:
    """Security Exposure Score for a package."""
    package_name: str
    ses_score: float  # 0-10 scale
    ses_level: str  # "minimal", "low", "moderate", "high", "critical"
    components: dict[str, float] = field(default_factory=dict)
    vulnerabilities: list[str] = field(default_factory=list)  # CVE IDs
    action: str = ""
    
    @classmethod
    def from_components(cls, package_name: str, severity: float, exploitability: float,
                        exposure: float = 5.0, mitigations: float = 0.0, 
                        update_status: float = 0.0, vulnerabilities: list = None) -> "SecurityExposureScore":
        """Create SES from weighted components.
        
        Formula:
        SES = (0.30 × Severity) + (0.25 × Exploitability) + (0.25 × Exposure)
            - (0.15 × Mitigations) - (0.15 × UpdateStatus)
        """
        ses = (
            0.30 * severity +
            0.25 * exploitability +
            0.25 * exposure -
            0.15 * mitigations -
            0.15 * update_status
        )
        
        # Clamp to 0-10
        ses = max(0.0, min(10.0, ses))
        
        # Determine level and action
        if ses < 2:
            level = "minimal"
            action = "No action needed"
        elif ses < 4:
            level = "low"
            action = "Monitor"
        elif ses < 6:
            level = "moderate"
            action = "Harden or patch"
        elif ses < 8:
            level = "high"
            action = "Patch urgently"
        else:
            level = "critical"
            action = "Immediate action"
        
        return cls(
            package_name=package_name,
            ses_score=round(ses, 1),
            ses_level=level,
            components={
                "severity": severity,
                "exploitability": exploitability,
                "exposure": exposure,
                "mitigations": mitigations,
                "update_status": update_status,
            },
            vulnerabilities=vulnerabilities or [],
            action=action
        )


class SecurityExposureScorer:
    """Calculate Security Exposure Score based on vulnerability data."""
    
    # CVSS to severity score mapping
    CVSS_TO_SEVERITY = {
        (9.0, 10.0): 10,
        (7.0, 8.9): 7,
        (4.0, 6.9): 4,
        (0.0, 3.9): 1,
    }
    
    # Attack vector to exploitability mapping
    ATTACK_VECTOR_SCORE = {
        "NETWORK": 10,      # Remote, unauthenticated
        "ADJACENT": 7,      # Remote, authenticated
        "LOCAL": 4,
        "PHYSICAL": 1,
    }
    
    # Role-based exposure multipliers
    ROLE_MULTIPLIERS = {
        "network": 1.3,    # Network-facing packages get higher exposure
        "crypto": 1.2,     # Crypto packages are high-value targets
        "parser": 1.1,     # Parsers can have edge-case exploits
        "database": 1.2,   # Database access is sensitive
        "auth": 1.3,       # Auth is critical
        "file": 1.0,       # File I/O is moderate
        "system": 1.1,     # System access is sensitive
        "template": 0.9,   # Templates require specific misuse
        "markup": 0.8,     # Markup is lower risk
        "wsgi": 0.9,       # WSGI depends on deployment
        "signaling": 0.7,  # Signaling is low risk
        "typing": 0.5,     # Typing is minimal risk
        "docs": 0.4,       # Docs are minimal risk
        "testing": 0.5,    # Testing is minimal risk
        "dev": 0.4,        # Dev tools are minimal risk
        "cli": 0.6,        # CLI tools are low risk
        "utility": 0.5,    # Utilities are low risk
        "unknown": 0.8,    # Unknown defaults to moderate
    }
    
    def __init__(self, config: Config):
        """Initialize the security exposure scorer."""
        self.config = config
        # Default exposure level (can be overridden in config)
        self.default_exposure = getattr(config, 'default_exposure', 5.0)
    
    def score(self, vulnerabilities: dict[str, list[Vulnerability]], 
              dependencies: list = None) -> dict[str, SecurityExposureScore]:
        """
        Calculate SES for packages based on their vulnerabilities.
        
        Args:
            vulnerabilities: Dict mapping package names to vulnerability lists
            dependencies: Optional list of Dependency objects for role classification
            
        Returns:
            Dict mapping package names to SecurityExposureScore
        """
        scores = {}
        
        # Build role map from dependencies if provided
        role_map = {}
        if dependencies:
            from .risk_classifier import PackageClassifier
            classifier = PackageClassifier()
            for dep in dependencies:
                classification = classifier.classify(dep.name)
                # Get the primary keyword (role)
                if classification.keywords:
                    role_map[dep.name.lower()] = classification.keywords[0]
        
        for package_name, vulns in vulnerabilities.items():
            if not vulns:
                # No vulnerabilities = minimal exposure
                scores[package_name] = SecurityExposureScore(
                    package_name=package_name,
                    ses_score=0.0,
                    ses_level="minimal",
                    components={},
                    vulnerabilities=[],
                    action="No action needed"
                )
                continue
            
            # Calculate aggregated severity (use max CVSS)
            max_cvss = max(v.cvss_score or 0 for v in vulns)
            severity = self._cvss_to_severity(max_cvss)
            
            # Calculate exploitability from attack vectors
            exploitability = self._calculate_exploitability(vulns)
            
            # Get role-based exposure adjustment
            # Handle package names like "pip:idna@2.5" or "idna@2.5" or "idna"
            pkg_key = package_name
            if ':' in pkg_key:
                pkg_key = pkg_key.split(':')[-1]  # Remove ecosystem prefix
            if '@' in pkg_key:
                pkg_key = pkg_key.split('@')[0]  # Remove version
            pkg_key = pkg_key.lower()
            
            role = role_map.get(pkg_key, "unknown")
            role_multiplier = self.ROLE_MULTIPLIERS.get(role, 0.8)
            
            # Exposure adjusted by role
            exposure = self.default_exposure * role_multiplier
            
            # Calculate update status (check if any vuln has fixed version)
            has_fix = any(getattr(v, 'fixed_versions', None) for v in vulns)
            update_status = 0 if not has_fix else 0  # 0 = patch available but not applied
            # Note: We can't tell if user has applied the patch, so we assume not
            
            # Mitigations default to 0 (would need config to specify)
            mitigations = 0.0
            
            # Get CVE IDs
            cve_ids = [v.id for v in vulns if v.id]
            
            scores[package_name] = SecurityExposureScore.from_components(
                package_name=package_name,
                severity=severity,
                exploitability=exploitability,
                exposure=exposure,
                mitigations=mitigations,
                update_status=update_status,
                vulnerabilities=cve_ids
            )
        
        return scores
    
    def _cvss_to_severity(self, cvss: float) -> float:
        """Convert CVSS score to severity component (0-10)."""
        if cvss >= 9.0:
            return 10
        elif cvss >= 7.0:
            return 7
        elif cvss >= 4.0:
            return 4
        else:
            return 1
    
    def _calculate_exploitability(self, vulns: list[Vulnerability]) -> float:
        """Calculate max exploitability from vulnerability attack vectors."""
        max_exploitability = 1  # Default: theoretical
        
        for vuln in vulns:
            # Try to get attack vector from vulnerability metadata
            # OSV vulnerabilities often have this in severity details
            severity_details = getattr(vuln, 'severity', None) or {}
            
            # Check for attack vector in different possible locations
            attack_vector = None
            if isinstance(severity_details, dict):
                attack_vector = severity_details.get('attack_vector', '').upper()
            elif isinstance(severity_details, str) and ':' in severity_details:
                # Try to parse CVSS vector string like "CVSS:3.1/AV:N/AC:L/..."
                parts = severity_details.upper().split('/')
                for part in parts:
                    if part.startswith('AV:'):
                        av_code = part[3:]
                        if av_code == 'N':
                            attack_vector = 'NETWORK'
                        elif av_code == 'A':
                            attack_vector = 'ADJACENT'
                        elif av_code == 'L':
                            attack_vector = 'LOCAL'
                        elif av_code == 'P':
                            attack_vector = 'PHYSICAL'
            
            # If we found attack vector, map to score
            if attack_vector and attack_vector in self.ATTACK_VECTOR_SCORE:
                score = self.ATTACK_VECTOR_SCORE[attack_vector]
                max_exploitability = max(max_exploitability, score)
            elif vuln.cvss_score:
                # Fallback: assume network-exploitable if high CVSS
                if vuln.cvss_score >= 7.0:
                    max_exploitability = max(max_exploitability, 7)
        
        return max_exploitability
