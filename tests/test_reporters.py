"""Tests for reporters."""

import pytest
import json
from datetime import datetime
from pathlib import Path
import tempfile

from supply_chain_analyzer.reporters.json_reporter import JsonReporter
from supply_chain_analyzer.reporters.html_reporter import HtmlReporter
from supply_chain_analyzer.core.models import (
    ScanResult, Dependency, Vulnerability, TyposquatMatch,
    Ecosystem, Severity
)


class TestJsonReporter:
    """Tests for JsonReporter."""
    
    def test_report_empty_result(self):
        """Test JSON report with empty result."""
        result = ScanResult(
            project_path="/test/project",
            scan_time=datetime.now()
        )
        
        reporter = JsonReporter()
        output = reporter.report(result)
        
        data = json.loads(output)
        assert data["summary"]["total_dependencies"] == 0
        assert data["summary"]["has_issues"] == False
    
    def test_report_with_vulnerabilities(self):
        """Test JSON report with vulnerabilities."""
        vuln = Vulnerability(
            id="CVE-2021-1234",
            summary="Test vuln",
            description="Description",
            severity=Severity.HIGH
        )
        
        result = ScanResult(
            project_path="/test",
            scan_time=datetime.now(),
            vulnerabilities={"pip:test@1.0": [vuln]}
        )
        
        reporter = JsonReporter()
        output = reporter.report(result)
        
        data = json.loads(output)
        assert data["summary"]["total_vulnerabilities"] == 1
        assert "pip:test@1.0" in data["vulnerabilities"]
    
    def test_report_to_file(self):
        """Test writing JSON report to file."""
        result = ScanResult(
            project_path="/test",
            scan_time=datetime.now()
        )
        
        reporter = JsonReporter()
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = Path(f.name)
        
        try:
            reporter.report(result, output_path)
            
            with open(output_path) as f:
                data = json.load(f)
            
            assert data["metadata"]["project_path"] == "/test"
        finally:
            output_path.unlink()


class TestHtmlReporter:
    """Tests for HtmlReporter."""
    
    def test_report_generates_html(self):
        """Test HTML report generation."""
        result = ScanResult(
            project_path="/test/project",
            scan_time=datetime.now()
        )
        
        reporter = HtmlReporter()
        output = reporter.report(result)
        
        assert "<!DOCTYPE html>" in output
        assert "Supply Chain Security Report" in output
        assert "/test/project" in output
    
    def test_report_with_vulnerabilities(self):
        """Test HTML report includes vulnerabilities."""
        vuln = Vulnerability(
            id="CVE-2021-1234",
            summary="Test vulnerability",
            description="Description",
            severity=Severity.HIGH
        )
        
        result = ScanResult(
            project_path="/test",
            scan_time=datetime.now(),
            vulnerabilities={"pip:test@1.0": [vuln]}
        )
        
        reporter = HtmlReporter()
        output = reporter.report(result)
        
        assert "CVE-2021-1234" in output
        assert "Vulnerabilities" in output
    
    def test_report_with_typosquats(self):
        """Test HTML report includes typosquatting alerts."""
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
        
        reporter = HtmlReporter()
        output = reporter.report(result)
        
        assert "reqeusts" in output
        assert "Typosquatting" in output
    
    def test_report_to_file(self):
        """Test writing HTML report to file."""
        result = ScanResult(
            project_path="/test",
            scan_time=datetime.now()
        )
        
        reporter = HtmlReporter()
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            output_path = Path(f.name)
        
        try:
            reporter.report(result, output_path)
            
            with open(output_path, encoding="utf-8") as f:
                content = f.read()
            
            assert "<!DOCTYPE html>" in content
        finally:
            output_path.unlink()
