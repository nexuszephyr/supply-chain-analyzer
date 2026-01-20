"""Main analyzer orchestrator for the Supply Chain Security Analyzer."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import Config
from .models import Dependency, ScanResult, Ecosystem


class Analyzer:
    """Main orchestrator for security analysis."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the analyzer with optional configuration."""
        self.config = config or Config()
        self._parsers = {}
        self._scanners = {}
        self._setup_components()
    
    def _setup_components(self) -> None:
        """Initialize parsers and scanners."""
        # Import here to avoid circular imports
        from ..parsers import PipParser
        from ..scanners import VulnerabilityScanner, TyposquatScanner, LicenseScanner, MaturityScorer, SecurityExposureScorer
        
        # Register parsers
        self._parsers[Ecosystem.PIP] = PipParser()
        
        # Register scanners
        self._scanners["vulnerability"] = VulnerabilityScanner(self.config)
        self._scanners["typosquat"] = TyposquatScanner(self.config)
        self._scanners["license"] = LicenseScanner(self.config)
        self._scanners["maturity"] = MaturityScorer(self.config)
        self._scanners["ses"] = SecurityExposureScorer(self.config)
    
    def scan(self, project_path: str | Path) -> ScanResult:
        """
        Perform a full security scan on a project.
        
        Args:
            project_path: Path to the project directory
            
        Returns:
            ScanResult containing all findings
        """
        project_path = Path(project_path)
        if not project_path.exists():
            raise FileNotFoundError(f"Project path not found: {project_path}")
        
        result = ScanResult(
            project_path=str(project_path),
            scan_time=datetime.now(),
        )
        
        # Parse dependencies
        dependencies = self._parse_dependencies(project_path)
        result.dependencies = dependencies
        
        # Run vulnerability scanner
        vuln_scanner = self._scanners["vulnerability"]
        result.vulnerabilities = vuln_scanner.scan(dependencies)
        
        # Run typosquatting scanner
        if self.config.check_typosquatting:
            typosquat_scanner = self._scanners["typosquat"]
            result.typosquat_matches = typosquat_scanner.scan(dependencies)
        
        # Run license scanner
        license_scanner = self._scanners["license"]
        result.license_issues = license_scanner.scan(dependencies)
        
        # Run maturity scanner (PMI)
        if self.config.check_reputation:
            maturity_scanner = self._scanners["maturity"]
            result.maturity_scores = maturity_scanner.scan(dependencies)
        
        # Calculate Security Exposure Scores from vulnerabilities
        if result.vulnerabilities:
            ses_scorer = self._scanners["ses"]
            result.ses_scores = ses_scorer.score(result.vulnerabilities, result.dependencies)
        
        return result
    
    def _parse_dependencies(self, project_path: Path) -> list[Dependency]:
        """Parse dependencies from project files."""
        dependencies = []
        
        # Check for requirements.txt (pip)
        requirements_file = project_path / "requirements.txt"
        if requirements_file.exists():
            pip_parser = self._parsers[Ecosystem.PIP]
            deps = pip_parser.parse(requirements_file)
            dependencies.extend(deps)
        
        # Check for pyproject.toml
        pyproject_file = project_path / "pyproject.toml"
        if pyproject_file.exists():
            pip_parser = self._parsers[Ecosystem.PIP]
            deps = pip_parser.parse_pyproject(pyproject_file)
            dependencies.extend(deps)
        
        # Check for setup.py (legacy projects)
        setup_py_file = project_path / "setup.py"
        if setup_py_file.exists():
            pip_parser = self._parsers[Ecosystem.PIP]
            deps = pip_parser.parse_setup_py(setup_py_file)
            dependencies.extend(deps)
        
        return dependencies
    
    def scan_vulnerabilities_only(self, project_path: str | Path) -> ScanResult:
        """Scan only for vulnerabilities."""
        project_path = Path(project_path)
        result = ScanResult(
            project_path=str(project_path),
            scan_time=datetime.now(),
        )
        
        dependencies = self._parse_dependencies(project_path)
        result.dependencies = dependencies
        
        vuln_scanner = self._scanners["vulnerability"]
        result.vulnerabilities = vuln_scanner.scan(dependencies)
        
        return result
    
    def scan_typosquatting_only(self, project_path: str | Path) -> ScanResult:
        """Scan only for typosquatting."""
        project_path = Path(project_path)
        result = ScanResult(
            project_path=str(project_path),
            scan_time=datetime.now(),
        )
        
        dependencies = self._parse_dependencies(project_path)
        result.dependencies = dependencies
        
        typosquat_scanner = self._scanners["typosquat"]
        result.typosquat_matches = typosquat_scanner.scan(dependencies)
        
        return result
    
    def scan_licenses_only(self, project_path: str | Path) -> ScanResult:
        """Scan only for license compliance."""
        project_path = Path(project_path)
        result = ScanResult(
            project_path=str(project_path),
            scan_time=datetime.now(),
        )
        
        dependencies = self._parse_dependencies(project_path)
        result.dependencies = dependencies
        
        license_scanner = self._scanners["license"]
        result.license_issues = license_scanner.scan(dependencies)
        
        return result
    
    def scan_maturity_only(self, project_path: str | Path) -> ScanResult:
        """Scan only for package maturity (PMI)."""
        project_path = Path(project_path)
        result = ScanResult(
            project_path=str(project_path),
            scan_time=datetime.now(),
        )
        
        dependencies = self._parse_dependencies(project_path)
        result.dependencies = dependencies
        
        maturity_scanner = self._scanners["maturity"]
        result.maturity_scores = maturity_scanner.scan(dependencies)
        
        return result
    
    # Backwards compatibility
    def scan_reputation_only(self, project_path: str | Path) -> ScanResult:
        """Deprecated: Use scan_maturity_only instead."""
        return self.scan_maturity_only(project_path)
