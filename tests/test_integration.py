"""Integration tests for end-to-end scanning workflows."""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from supply_chain_analyzer.core.analyzer import Analyzer
from supply_chain_analyzer.core.config import Config


class TestIntegration:
    """Integration tests for the full scanning workflow."""
    
    @pytest.fixture
    def sample_project(self):
        """Create a temporary project with dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # Create requirements.txt
            (project / "requirements.txt").write_text(
                "requests==2.28.0\n"
                "numpy>=1.21.0\n"
                "flask==2.0.0\n"
            )
            
            yield project
    
    @pytest.fixture
    def sample_project_with_pyproject(self):
        """Create a temporary project with pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # Create pyproject.toml
            (project / "pyproject.toml").write_text('''
[project]
name = "test-project"
version = "1.0.0"
dependencies = [
    "httpx>=0.24.0",
    "click>=8.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
]
''')
            
            yield project
    
    def test_scan_project_with_requirements(self, sample_project):
        """Test scanning a project with requirements.txt."""
        config = Config()
        config.check_typosquatting = False  # Speed up test
        
        analyzer = Analyzer(config)
        result = analyzer.scan(sample_project)
        
        assert result.total_dependencies == 3
        assert "requests" in [d.name for d in result.dependencies]
        assert "numpy" in [d.name for d in result.dependencies]
        assert "flask" in [d.name for d in result.dependencies]
    
    def test_scan_project_with_pyproject(self, sample_project_with_pyproject):
        """Test scanning a project with pyproject.toml."""
        config = Config()
        config.check_typosquatting = False
        
        analyzer = Analyzer(config)
        result = analyzer.scan(sample_project_with_pyproject)
        
        assert result.total_dependencies >= 2
        dep_names = [d.name for d in result.dependencies]
        assert "httpx" in dep_names
        assert "click" in dep_names
    
    def test_scan_nonexistent_project(self):
        """Test scanning a nonexistent project."""
        config = Config()
        analyzer = Analyzer(config)
        
        with pytest.raises(FileNotFoundError):
            analyzer.scan("/nonexistent/path")
    
    def test_scan_empty_project(self):
        """Test scanning a project with no dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Config()
            analyzer = Analyzer(config)
            result = analyzer.scan(tmpdir)
            
            assert result.total_dependencies == 0
            assert result.has_issues == False
    
    def test_vulnerability_only_scan(self, sample_project):
        """Test vulnerability-only scan mode."""
        config = Config()
        analyzer = Analyzer(config)
        
        result = analyzer.scan_vulnerabilities_only(sample_project)
        
        assert result.total_dependencies == 3
        # Typosquat should not be checked
        assert result.typosquat_matches == []
    
    def test_typosquatting_only_scan(self, sample_project):
        """Test typosquatting-only scan mode."""
        config = Config()
        analyzer = Analyzer(config)
        
        result = analyzer.scan_typosquatting_only(sample_project)
        
        assert result.total_dependencies == 3
        # Vulnerabilities should not be checked
        assert result.vulnerabilities == {}
    
    def test_license_only_scan(self, sample_project):
        """Test license-only scan mode."""
        config = Config()
        config.allowed_licenses = {"MIT", "Apache-2.0", "BSD-3-Clause"}
        
        analyzer = Analyzer(config)
        result = analyzer.scan_licenses_only(sample_project)
        
        assert result.total_dependencies == 3


class TestTyposquatIntegration:
    """Integration tests specifically for typosquatting detection."""
    
    def test_detect_suspicious_package(self):
        """Test detecting a typosquatting package."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # Create requirements with suspicious package
            (project / "requirements.txt").write_text(
                "reqeusts==1.0.0\n"  # Typo of 'requests'
            )
            
            config = Config()
            config.typosquat_threshold = 0.8
            
            analyzer = Analyzer(config)
            result = analyzer.scan_typosquatting_only(project)
            
            assert len(result.typosquat_matches) >= 1
            suspicious_names = [m.suspicious_package for m in result.typosquat_matches]
            assert "reqeusts" in suspicious_names
    
    def test_no_false_positives_for_legitimate(self):
        """Test that legitimate packages don't trigger alerts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            
            # Create requirements with legitimate packages
            (project / "requirements.txt").write_text(
                "requests==2.28.0\n"
                "numpy==1.21.0\n"
                "pandas==1.4.0\n"
            )
            
            config = Config()
            analyzer = Analyzer(config)
            result = analyzer.scan_typosquatting_only(project)
            
            # These are legitimate packages, should not trigger
            assert len(result.typosquat_matches) == 0
