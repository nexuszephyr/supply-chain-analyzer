"""Tests for typosquatting scanner."""

import pytest

from supply_chain_analyzer.scanners.typosquat import TyposquatScanner
from supply_chain_analyzer.core.config import Config
from supply_chain_analyzer.core.models import Dependency, Ecosystem


class TestTyposquatScanner:
    """Tests for TyposquatScanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()
        self.scanner = TyposquatScanner(self.config)
    
    def test_levenshtein_similarity(self):
        """Test Levenshtein similarity calculation."""
        # Exact match
        assert self.scanner._levenshtein_similarity("numpy", "numpy") == 1.0
        
        # One character difference
        sim = self.scanner._levenshtein_similarity("numpy", "numpi")
        assert 0.7 < sim < 1.0
        
        # Completely different
        sim = self.scanner._levenshtein_similarity("numpy", "flask")
        assert sim < 0.5
    
    def test_char_swap_detection(self):
        """Test character swap detection."""
        assert self.scanner._is_char_swap("reqeusts", "requests")
        assert self.scanner._is_char_swap("nupmy", "numpy")
        assert not self.scanner._is_char_swap("numpy", "numpy")
        assert not self.scanner._is_char_swap("np", "numpy")  # Different lengths
    
    def test_detect_typosquat(self):
        """Test detecting a typosquatting package."""
        deps = [
            Dependency(name="reqeusts", version="1.0.0", ecosystem=Ecosystem.PIP),  # typosquat of requests
        ]
        
        matches = self.scanner.scan(deps)
        
        assert len(matches) == 1
        assert matches[0].suspicious_package == "reqeusts"
        assert matches[0].legitimate_package == "requests"
        assert matches[0].detection_method == "character_swap"
    
    def test_no_false_positive_for_popular_packages(self):
        """Test that popular packages don't trigger false positives."""
        deps = [
            Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PIP),
            Dependency(name="numpy", version="1.21.0", ecosystem=Ecosystem.PIP),
        ]
        
        matches = self.scanner.scan(deps)
        
        assert len(matches) == 0
    
    def test_prefix_suffix_attack(self):
        """Test detection of prefix/suffix typosquatting."""
        deps = [
            Dependency(name="python-requests", version="1.0.0", ecosystem=Ecosystem.PIP),
        ]
        
        matches = self.scanner.scan(deps)
        
        assert len(matches) == 1
        assert matches[0].detection_method == "prefix_suffix"
