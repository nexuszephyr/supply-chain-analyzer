"""Tests for core data models."""

import pytest
from datetime import datetime

from supply_chain_analyzer.core.models import (
    Dependency, Vulnerability, LicenseInfo, TyposquatMatch, 
    ScanResult, Ecosystem, Severity
)


class TestDependency:
    """Tests for Dependency model."""
    
    def test_create_dependency(self):
        """Test creating a dependency."""
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem=Ecosystem.PIP,
            source_file="requirements.txt"
        )
        
        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.ecosystem == Ecosystem.PIP
        assert dep.is_direct == True
    
    def test_dependency_identifier(self):
        """Test dependency identifier generation."""
        dep = Dependency(name="numpy", version="1.21.0", ecosystem=Ecosystem.PIP)
        assert dep.identifier == "pip:numpy@1.21.0"
    
    def test_dependency_hash(self):
        """Test dependency hashing for set operations."""
        dep1 = Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PIP)
        dep2 = Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PIP)
        dep3 = Dependency(name="requests", version="2.29.0", ecosystem=Ecosystem.PIP)
        
        assert hash(dep1) == hash(dep2)
        assert hash(dep1) != hash(dep3)
        assert dep1 == dep2
        assert dep1 != dep3


class TestVulnerability:
    """Tests for Vulnerability model."""
    
    def test_create_vulnerability(self):
        """Test creating a vulnerability."""
        vuln = Vulnerability(
            id="CVE-2021-1234",
            summary="Test vulnerability",
            description="A test description",
            severity=Severity.HIGH,
            cvss_score=7.5
        )
        
        assert vuln.id == "CVE-2021-1234"
        assert vuln.severity == Severity.HIGH
        assert vuln.is_critical == True
    
    def test_vulnerability_is_critical(self):
        """Test is_critical property."""
        critical = Vulnerability(id="1", summary="", description="", severity=Severity.CRITICAL)
        high = Vulnerability(id="2", summary="", description="", severity=Severity.HIGH)
        medium = Vulnerability(id="3", summary="", description="", severity=Severity.MEDIUM)
        low = Vulnerability(id="4", summary="", description="", severity=Severity.LOW)
        
        assert critical.is_critical == True
        assert high.is_critical == True
        assert medium.is_critical == False
        assert low.is_critical == False


class TestScanResult:
    """Tests for ScanResult model."""
    
    def test_create_empty_result(self):
        """Test creating an empty scan result."""
        result = ScanResult(
            project_path="/test/project",
            scan_time=datetime.now()
        )
        
        assert result.total_dependencies == 0
        assert result.total_vulnerabilities == 0
        assert result.has_issues == False
    
    def test_result_with_vulnerabilities(self):
        """Test scan result with vulnerabilities."""
        vuln = Vulnerability(id="CVE-1", summary="Test", description="", severity=Severity.HIGH)
        
        result = ScanResult(
            project_path="/test",
            scan_time=datetime.now(),
            vulnerabilities={"pkg:test@1.0": [vuln]}
        )
        
        assert result.total_vulnerabilities == 1
        assert result.critical_vulnerabilities == 1
        assert result.has_issues == True
    
    def test_result_with_typosquats(self):
        """Test scan result with typosquatting matches."""
        match = TyposquatMatch(
            suspicious_package="reqeusts",
            legitimate_package="requests",
            similarity_score=0.95,
            detection_method="levenshtein",
            risk_level="high"
        )
        
        result = ScanResult(
            project_path="/test",
            scan_time=datetime.now(),
            typosquat_matches=[match]
        )
        
        assert len(result.typosquat_matches) == 1
        assert result.has_issues == True
    
    def test_result_with_license_issues(self):
        """Test scan result with license issues."""
        dep = Dependency(name="gpl-pkg", version="1.0", ecosystem=Ecosystem.PIP)
        license_info = LicenseInfo.from_spdx("GPL-3.0")
        
        result = ScanResult(
            project_path="/test",
            scan_time=datetime.now(),
            license_issues=[(dep, license_info)]
        )
        
        assert len(result.license_issues) == 1
        assert result.has_issues == True


class TestSeverity:
    """Tests for Severity enum."""
    
    def test_from_cvss_critical(self):
        """Test CVSS to severity for critical."""
        assert Severity.from_cvss(10.0) == Severity.CRITICAL
        assert Severity.from_cvss(9.0) == Severity.CRITICAL
    
    def test_from_cvss_high(self):
        """Test CVSS to severity for high."""
        assert Severity.from_cvss(8.9) == Severity.HIGH
        assert Severity.from_cvss(7.0) == Severity.HIGH
    
    def test_from_cvss_medium(self):
        """Test CVSS to severity for medium."""
        assert Severity.from_cvss(6.9) == Severity.MEDIUM
        assert Severity.from_cvss(4.0) == Severity.MEDIUM
    
    def test_from_cvss_low(self):
        """Test CVSS to severity for low."""
        assert Severity.from_cvss(3.9) == Severity.LOW
        assert Severity.from_cvss(0.1) == Severity.LOW
