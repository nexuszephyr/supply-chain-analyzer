"""Project Maturity Index (PMI) scoring based on package metadata."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import httpx

from ..core.config import Config
from ..core.models import Dependency


@dataclass
class MaturityScore:
    """Maturity score for a package."""
    package_name: str
    overall_score: float  # 0-100
    maturity_level: str  # "mature", "established", "emerging", "early-stage"
    factors: dict[str, float] = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    
    @classmethod
    def from_factors(cls, package_name: str, factors: dict[str, float], 
                     weights: dict[str, float], details: dict = None) -> "MaturityScore":
        """Create maturity score from weighted factors."""
        # Calculate weighted average
        total_weight = sum(weights.values())
        overall = sum(factors.get(k, 0) * w for k, w in weights.items()) / total_weight
        
        # Determine maturity level (non-security labels)
        if overall >= 80:
            maturity_level = "mature"
        elif overall >= 60:
            maturity_level = "established"
        elif overall >= 40:
            maturity_level = "emerging"
        else:
            maturity_level = "early-stage"
        
        return cls(
            package_name=package_name,
            overall_score=round(overall, 1),
            maturity_level=maturity_level,
            factors=factors,
            details=details or {}
        )


class MaturityScorer:
    """Score package maturity based on PyPI metadata (Project Maturity Index)."""
    
    # PMI weights: Age 30%, Docs 20%, Activity 30%, Adoption 20%
    WEIGHTS = {
        "age": 0.30,
        "documentation": 0.20,
        "activity": 0.30,
        "adoption": 0.20,  # versions + downloads + stars combined
    }
    
    def __init__(self, config: Config):
        """Initialize the maturity scorer."""
        self.config = config
        self._client = None
    
    def scan(self, dependencies: list[Dependency]) -> dict[str, MaturityScore]:
        """
        Score maturity for all dependencies.
        
        Args:
            dependencies: List of dependencies to score
            
        Returns:
            Dictionary mapping package names to maturity scores
        """
        scores = {}
        
        with httpx.Client(timeout=15.0) as client:
            self._client = client
            for dep in dependencies:
                try:
                    score = self._score_package(dep.name)
                    if score:
                        scores[dep.name] = score
                    else:
                        # Create default score when metadata unavailable
                        scores[dep.name] = MaturityScore(
                            package_name=dep.name,
                            overall_score=50.0,
                            maturity_level="emerging",
                            factors={},
                            details={"error": "Could not fetch metadata"}
                        )
                except Exception:
                    # Create default score on error
                    scores[dep.name] = MaturityScore(
                        package_name=dep.name,
                        overall_score=50.0,
                        maturity_level="emerging",
                        factors={},
                        details={"error": "Could not fetch metadata"}
                    )
            self._client = None
        
        return scores
    
    def _score_package(self, package_name: str) -> Optional[MaturityScore]:
        """Score a single package."""
        # Fetch PyPI metadata
        metadata = self._fetch_pypi_metadata(package_name)
        if not metadata:
            return None
        
        info = metadata.get("info", {})
        releases = metadata.get("releases", {})
        
        # Calculate individual factors
        factors = {}
        details = {"package": package_name}
        
        # 1. Package age (days since first release) - 30%
        age_days = self._calculate_age(releases)
        details["age_days"] = age_days
        if age_days >= 365 * 3:  # 3+ years
            factors["age"] = 100
        elif age_days >= 365:  # 1+ year
            factors["age"] = 75
        elif age_days >= 180:  # 6+ months
            factors["age"] = 50
        elif age_days >= 30:  # 1+ month
            factors["age"] = 25
        else:
            factors["age"] = 10  # Very new package
        
        # 2. Documentation quality - 20%
        description = info.get("description", "") or ""
        summary = info.get("summary", "") or ""
        doc_length = len(description) + len(summary)
        details["doc_length"] = doc_length
        has_license = bool((info.get("license") or "").strip())
        has_repo = bool(
            info.get("project_urls", {}).get("Repository") or 
            info.get("project_urls", {}).get("Source") or
            info.get("home_page", "")
        )
        
        doc_score = 0
        if doc_length >= 2000:
            doc_score += 50
        elif doc_length >= 500:
            doc_score += 35
        elif doc_length >= 100:
            doc_score += 20
        else:
            doc_score += 5
        
        if has_license:
            doc_score += 25
        if has_repo:
            doc_score += 25
        
        factors["documentation"] = min(doc_score, 100)
        details["has_license"] = has_license
        details["has_repository"] = has_repo
        
        # 3. Recent activity - 30%
        last_release_days = self._days_since_last_release(releases)
        details["days_since_last_release"] = last_release_days
        if last_release_days <= 90:
            factors["activity"] = 100
        elif last_release_days <= 180:
            factors["activity"] = 75
        elif last_release_days <= 365:
            factors["activity"] = 50
        elif last_release_days <= 730:
            factors["activity"] = 25
        else:
            factors["activity"] = 10  # Abandoned
        
        # 4. Adoption (versions + downloads + stars) - 20%
        version_count = len(releases)
        details["version_count"] = version_count
        
        # Get GitHub stars if available
        github_url = self._extract_github_url(info)
        stars = 0
        if github_url:
            stars = self._fetch_github_stars(github_url)
            details["github_stars"] = stars
        
        adoption_score = 0
        # Version count contribution
        if version_count >= 20:
            adoption_score += 40
        elif version_count >= 10:
            adoption_score += 30
        elif version_count >= 5:
            adoption_score += 20
        else:
            adoption_score += 10
        
        # Stars contribution
        if stars >= 1000:
            adoption_score += 60
        elif stars >= 100:
            adoption_score += 45
        elif stars >= 10:
            adoption_score += 30
        else:
            adoption_score += 15
        
        factors["adoption"] = min(adoption_score, 100)
        
        return MaturityScore.from_factors(
            package_name=package_name,
            factors=factors,
            weights=self.WEIGHTS,
            details=details
        )
    
    def _fetch_pypi_metadata(self, package_name: str) -> Optional[dict]:
        """Fetch package metadata from PyPI."""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            response = self._client.get(url)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None
    
    def _calculate_age(self, releases: dict) -> int:
        """Calculate package age in days from first release."""
        if not releases:
            return 0
        
        earliest_date = None
        for version, files in releases.items():
            if not files:
                continue
            for f in files:
                upload_time = f.get("upload_time")
                if upload_time:
                    try:
                        # Parse the datetime string
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        # If naive (no timezone), assume UTC
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if earliest_date is None or dt < earliest_date:
                            earliest_date = dt
                    except Exception:
                        pass
        
        if earliest_date:
            now = datetime.now(timezone.utc)
            return (now - earliest_date).days
        return 0
    
    def _days_since_last_release(self, releases: dict) -> int:
        """Calculate days since the most recent release."""
        if not releases:
            return 9999
        
        latest_date = None
        for version, files in releases.items():
            if not files:
                continue
            for f in files:
                upload_time = f.get("upload_time")
                if upload_time:
                    try:
                        # Parse the datetime string
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        # If naive (no timezone), assume UTC
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if latest_date is None or dt > latest_date:
                            latest_date = dt
                    except Exception:
                        pass
        
        if latest_date:
            now = datetime.now(timezone.utc)
            return (now - latest_date).days
        return 9999
    
    def _extract_github_url(self, info: dict) -> Optional[str]:
        """Extract GitHub repository URL from package info."""
        project_urls = info.get("project_urls", {}) or {}
        
        # Check common URL fields
        for key in ["Repository", "Source", "GitHub", "Homepage", "Home"]:
            url = project_urls.get(key, "")
            if url and "github.com" in url:
                return url
        
        # Check home_page
        home_page = info.get("home_page", "")
        if home_page and "github.com" in home_page:
            return home_page
        
        return None
    
    def _fetch_github_stars(self, github_url: str) -> int:
        """Fetch star count from GitHub API."""
        try:
            # Parse owner/repo from URL
            # e.g., https://github.com/owner/repo
            parts = github_url.rstrip("/").split("/")
            if "github.com" in parts:
                idx = parts.index("github.com")
                if len(parts) > idx + 2:
                    owner = parts[idx + 1]
                    repo = parts[idx + 2].replace(".git", "")
                    
                    api_url = f"https://api.github.com/repos/{owner}/{repo}"
                    response = self._client.get(api_url, headers={
                        "Accept": "application/vnd.github.v3+json"
                    })
                    if response.status_code == 200:
                        data = response.json()
                        return data.get("stargazers_count", 0)
        except Exception:
            pass
        return 0


# Backwards compatibility aliases
ReputationScore = MaturityScore
ReputationScorer = MaturityScorer
