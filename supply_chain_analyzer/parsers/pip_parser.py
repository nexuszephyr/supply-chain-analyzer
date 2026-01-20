"""Parser for pip/Python package files."""

import re
from pathlib import Path
from typing import Optional
import toml

from .base import BaseParser
from ..core.models import Dependency, Ecosystem


class PipParser(BaseParser):
    """Parser for Python package manifest files (requirements.txt, pyproject.toml)."""
    
    # Regex pattern for requirements.txt lines
    # Matches: package_name[extras]>=version,<version2 ; markers # comment
    REQUIREMENT_PATTERN = re.compile(
        r'^(?P<name>[a-zA-Z0-9][-a-zA-Z0-9._]*)'
        r'(?:\[(?P<extras>[^\]]+)\])?'
        r'(?P<specifier>[<>=!~][^;#\s]*)?'
        r'(?:\s*;\s*(?P<markers>[^#]*))?'
        r'(?:\s*#.*)?$'
    )
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the file."""
        return file_path.name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile")
    
    def parse(self, file_path: Path) -> list[Dependency]:
        """Parse a requirements.txt file."""
        if not file_path.exists():
            return []
        
        dependencies = []
        
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines, comments, and options
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                
                # Skip -r includes for now
                if line.startswith("-r "):
                    continue
                
                dep = self._parse_requirement_line(line, str(file_path))
                if dep:
                    dependencies.append(dep)
        
        return dependencies
    
    def _parse_requirement_line(self, line: str, source_file: str) -> Optional[Dependency]:
        """Parse a single requirement line."""
        match = self.REQUIREMENT_PATTERN.match(line)
        if not match:
            return None
        
        name = match.group("name")
        specifier = match.group("specifier") or ""
        
        # Extract version from specifier
        version = self._extract_version(specifier)
        
        return Dependency(
            name=name.lower(),  # Normalize package names to lowercase
            version=version,
            ecosystem=Ecosystem.PIP,
            source_file=source_file,
            is_direct=True,
        )
    
    def _extract_version(self, specifier: str) -> str:
        """Extract a version string from a specifier."""
        if not specifier:
            return "*"
        
        # Handle common cases: ==, >=, ~=
        # For ==, return exact version
        if specifier.startswith("=="):
            return specifier[2:].split(",")[0].strip()
        
        # For >=, return the minimum version
        if specifier.startswith(">="):
            return specifier[2:].split(",")[0].strip()
        
        # For ~=, return the base version
        if specifier.startswith("~="):
            return specifier[2:].split(",")[0].strip()
        
        # Return the full specifier for complex cases
        return specifier
    
    def parse_pyproject(self, file_path: Path) -> list[Dependency]:
        """Parse a pyproject.toml file for dependencies."""
        if not file_path.exists():
            return []
        
        try:
            # Use tomli for better TOML compatibility (supports modern pyproject.toml)
            import tomli
            with open(file_path, "rb") as f:
                data = tomli.load(f)
        except Exception:
            return []
        
        dependencies = []
        
        # PEP 621 format: [project.dependencies]
        project_deps = data.get("project", {}).get("dependencies", [])
        for dep_str in project_deps:
            dep = self._parse_requirement_line(dep_str, str(file_path))
            if dep:
                dependencies.append(dep)
        
        # Optional dependencies
        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        for group_deps in optional_deps.values():
            for dep_str in group_deps:
                dep = self._parse_requirement_line(dep_str, str(file_path))
                if dep:
                    dep.is_direct = False  # Mark optional deps
                    dependencies.append(dep)
        
        # Poetry format: [tool.poetry.dependencies]
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, version_info in poetry_deps.items():
            if name == "python":
                continue
            
            if isinstance(version_info, str):
                version = version_info.lstrip("^~>=<")
            elif isinstance(version_info, dict):
                version = version_info.get("version", "*").lstrip("^~>=<")
            else:
                version = "*"
            
            dependencies.append(Dependency(
                name=name.lower(),
                version=version,
                ecosystem=Ecosystem.PIP,
                source_file=str(file_path),
                is_direct=True,
            ))
        
        return dependencies
    
    def parse_setup_py(self, file_path: Path) -> list[Dependency]:
        """Parse a setup.py file for dependencies (best-effort, regex-based)."""
        if not file_path.exists():
            return []
        
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return []
        
        dependencies = []
        
        # Look for install_requires or requires lists
        # Pattern matches: install_requires = [...] or requires = [...]
        patterns = [
            r'install_requires\s*=\s*\[([^\]]+)\]',
            r'requires\s*=\s*\[([^\]]+)\]',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.DOTALL)
            if match:
                deps_block = match.group(1)
                # Extract quoted strings
                dep_strings = re.findall(r'["\']([^"\']+)["\']', deps_block)
                for dep_str in dep_strings:
                    dep = self._parse_requirement_line(dep_str.strip(), str(file_path))
                    if dep:
                        dependencies.append(dep)
        
        return dependencies

