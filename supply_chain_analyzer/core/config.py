"""Configuration management for the Supply Chain Security Analyzer."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml


@dataclass
class Config:
    """Configuration settings for the analyzer."""
    
    # Scanning options
    scan_dev_dependencies: bool = True
    max_depth: int = 10  # Maximum dependency tree depth
    timeout_seconds: int = 30
    
    # Vulnerability settings
    min_severity: str = "low"  # Minimum severity to report
    ignore_vulnerabilities: list[str] = field(default_factory=list)  # CVE IDs to ignore
    
    # License settings
    allowed_licenses: set[str] = field(default_factory=lambda: {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"})
    blocked_licenses: set[str] = field(default_factory=lambda: {"GPL-3.0", "AGPL-3.0"})
    
    # Typosquatting settings
    typosquat_threshold: float = 0.85  # Similarity threshold (0-1)
    check_typosquatting: bool = True
    
    # Reputation settings
    check_reputation: bool = True
    min_reputation_score: float = 40.0  # Minimum acceptable score (0-100)
    
    # Cache settings
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "supply-chain-analyzer")
    cache_ttl_hours: int = 24
    
    # Output settings
    output_format: str = "console"  # console, json, html, sarif
    verbose: bool = False
    
    # ML settings
    use_ml_scoring: bool = False
    model_path: Optional[Path] = None
    
    @classmethod
    def load_from_file(cls, path: Path) -> "Config":
        """Load configuration from a YAML file."""
        if not path.exists():
            return cls()
        
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        
        # Convert lists to sets where needed
        if "allowed_licenses" in data:
            data["allowed_licenses"] = set(data["allowed_licenses"])
        if "blocked_licenses" in data:
            data["blocked_licenses"] = set(data["blocked_licenses"])
        if "cache_dir" in data:
            data["cache_dir"] = Path(data["cache_dir"])
        if "model_path" in data and data["model_path"]:
            data["model_path"] = Path(data["model_path"])
            
        return cls(**data)
    
    def save_to_file(self, path: Path) -> None:
        """Save configuration to a YAML file."""
        data = {
            "scan_dev_dependencies": self.scan_dev_dependencies,
            "max_depth": self.max_depth,
            "timeout_seconds": self.timeout_seconds,
            "min_severity": self.min_severity,
            "ignore_vulnerabilities": self.ignore_vulnerabilities,
            "allowed_licenses": list(self.allowed_licenses),
            "blocked_licenses": list(self.blocked_licenses),
            "typosquat_threshold": self.typosquat_threshold,
            "check_typosquatting": self.check_typosquatting,
            "cache_dir": str(self.cache_dir),
            "cache_ttl_hours": self.cache_ttl_hours,
            "output_format": self.output_format,
            "verbose": self.verbose,
            "use_ml_scoring": self.use_ml_scoring,
            "model_path": str(self.model_path) if self.model_path else None,
        }
        
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
