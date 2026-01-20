"""Security scanners for the Supply Chain Security Analyzer."""

from .vulnerability import VulnerabilityScanner
from .typosquat import TyposquatScanner
from .license import LicenseScanner
from .dependency_tree import DependencyTreeScanner
from .ml_scorer import MLRiskScorer
from .maturity import MaturityScorer, MaturityScore, ReputationScorer, ReputationScore
from .security_exposure import SecurityExposureScorer, SecurityExposureScore
from .risk_classifier import PackageClassifier, RiskCategory, PackageClassification

__all__ = [
    "VulnerabilityScanner", 
    "TyposquatScanner", 
    "LicenseScanner", 
    "DependencyTreeScanner",
    "MLRiskScorer",
    "MaturityScorer",
    "MaturityScore",
    "SecurityExposureScorer",
    "SecurityExposureScore",
    "PackageClassifier",
    "RiskCategory",
    "PackageClassification",
    # Backwards compatibility
    "ReputationScorer",
    "ReputationScore",
]
