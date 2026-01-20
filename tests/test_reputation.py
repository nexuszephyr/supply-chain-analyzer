"""Tests for the reputation scoring module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta

from supply_chain_analyzer.scanners.reputation import ReputationScorer, ReputationScore
from supply_chain_analyzer.core.config import Config
from supply_chain_analyzer.core.models import Dependency, Ecosystem


class TestReputationScore:
    """Tests for ReputationScore dataclass."""
    
    def test_from_factors_high_score(self):
        """Test creating a high reputation score."""
        factors = {
            "age": 100,
            "versions": 75,
            "downloads": 80,
            "activity": 90,
            "documentation": 85,
            "maintainer": 70,
            "has_license": 100,
            "has_repository": 100,
            "github_stars": 100,
        }
        weights = {
            "age": 0.15,
            "versions": 0.10,
            "downloads": 0.15,
            "activity": 0.10,
            "documentation": 0.10,
            "maintainer": 0.15,
            "has_license": 0.05,
            "has_repository": 0.05,
            "github_stars": 0.15,
        }
        
        score = ReputationScore.from_factors("test-package", factors, weights)
        
        assert score.package_name == "test-package"
        assert score.overall_score >= 70
        assert score.risk_level == "low"
    
    def test_from_factors_medium_score(self):
        """Test creating a medium reputation score."""
        factors = {
            "age": 50,
            "versions": 50,
            "downloads": 50,
            "activity": 50,
            "documentation": 50,
            "maintainer": 50,
            "has_license": 50,
            "has_repository": 50,
            "github_stars": 50,
        }
        weights = {k: 0.11 for k in factors}
        
        score = ReputationScore.from_factors("test-package", factors, weights)
        
        assert score.overall_score == 50
        assert score.risk_level == "medium"
    
    def test_from_factors_low_score(self):
        """Test creating a low (high risk) reputation score."""
        factors = {
            "age": 10,
            "versions": 10,
            "downloads": 10,
            "activity": 10,
            "documentation": 10,
            "maintainer": 10,
            "has_license": 0,
            "has_repository": 0,
            "github_stars": 10,
        }
        weights = {k: 0.11 for k in factors}
        
        score = ReputationScore.from_factors("sketchy-package", factors, weights)
        
        assert score.overall_score < 40
        assert score.risk_level == "high"


class TestReputationScorer:
    """Tests for ReputationScorer class."""
    
    @pytest.fixture
    def config(self):
        """Create a test config."""
        return Config()
    
    @pytest.fixture
    def scorer(self, config):
        """Create a reputation scorer."""
        return ReputationScorer(config)
    
    def test_init(self, scorer):
        """Test scorer initialization."""
        assert scorer.config is not None
        assert scorer.WEIGHTS is not None
        # Weights should sum to 1.0
        assert abs(sum(scorer.WEIGHTS.values()) - 1.0) < 0.01
    
    def test_scan_with_mock_pypi(self, scorer):
        """Test scanning with mocked PyPI response."""
        deps = [
            Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PIP),
        ]
        
        # Create a mock score for a well-established package
        mock_score = ReputationScore(
            package_name="requests",
            overall_score=85.0,
            risk_level="low",
            factors={"age": 100, "versions": 100, "github_stars": 100},
            details={"author": "Kenneth Reitz"}
        )
        
        with patch.object(scorer, '_score_package', return_value=mock_score):
            scores = scorer.scan(deps)
        
        assert "requests" in scores
        score = scores["requests"]
        assert score.overall_score >= 70  # Well-established package
        assert score.risk_level == "low"
    
    def test_scan_new_package(self, scorer):
        """Test scoring a new suspicious package."""
        deps = [
            Dependency(name="new-sketchy-pkg", version="0.1.0", ecosystem=Ecosystem.PIP),
        ]
        
        # Create a mock score for a suspicious package
        mock_score = ReputationScore(
            package_name="new-sketchy-pkg",
            overall_score=25.0,
            risk_level="high",
            factors={"age": 10, "versions": 10, "has_license": 0},
            details={}
        )
        
        with patch.object(scorer, '_score_package', return_value=mock_score):
            scores = scorer.scan(deps)
        
        assert "new-sketchy-pkg" in scores
        score = scores["new-sketchy-pkg"]
        # New package with no docs/license should score lower
        assert score.overall_score < 50
    
    def test_scan_api_error(self, scorer):
        """Test handling API errors gracefully."""
        deps = [
            Dependency(name="nonexistent-package", version="1.0.0", ecosystem=Ecosystem.PIP),
        ]
        
        with patch.object(scorer, '_fetch_pypi_metadata', return_value=None):
            scores = scorer.scan(deps)
        
        # Should still return a score with error info
        assert "nonexistent-package" in scores
        score = scores["nonexistent-package"]
        assert score.risk_level == "medium"  # Default for errors


class TestReputationScorerHelpers:
    """Tests for helper methods."""
    
    @pytest.fixture
    def scorer(self):
        return ReputationScorer(Config())
    
    def test_calculate_age_no_releases(self, scorer):
        """Test age calculation with no releases."""
        age = scorer._calculate_age({})
        assert age == 0
    
    def test_calculate_age_with_releases(self, scorer):
        """Test age calculation with releases."""
        old_date = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        releases = {
            "1.0.0": [{"upload_time": old_date}],
        }
        
        age = scorer._calculate_age(releases)
        assert 360 <= age <= 370  # Approximately 1 year
    
    def test_extract_github_url(self, scorer):
        """Test GitHub URL extraction."""
        info = {
            "project_urls": {
                "Repository": "https://github.com/user/repo",
            },
        }
        
        url = scorer._extract_github_url(info)
        assert url == "https://github.com/user/repo"
    
    def test_extract_github_url_from_homepage(self, scorer):
        """Test GitHub URL extraction from home_page."""
        info = {
            "project_urls": {},
            "home_page": "https://github.com/user/repo",
        }
        
        url = scorer._extract_github_url(info)
        assert url == "https://github.com/user/repo"
    
    def test_extract_github_url_not_found(self, scorer):
        """Test GitHub URL not found."""
        info = {
            "project_urls": {},
            "home_page": "https://example.com",
        }
        
        url = scorer._extract_github_url(info)
        assert url is None
