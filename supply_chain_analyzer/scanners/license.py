"""License compliance scanner."""

import httpx
from typing import Optional

from ..core.config import Config
from ..core.models import Dependency, LicenseInfo


class LicenseScanner:
    """Scanner for license compliance checking."""
    
    PYPI_API_URL = "https://pypi.org/pypi/{package}/json"
    
    # Map common license strings to SPDX identifiers
    LICENSE_MAPPING = {
        "mit": "MIT",
        "mit license": "MIT",
        "apache 2.0": "Apache-2.0",
        "apache license 2.0": "Apache-2.0",
        "apache-2.0": "Apache-2.0",
        "apache software license": "Apache-2.0",
        "bsd": "BSD-3-Clause",
        "bsd license": "BSD-3-Clause",
        "bsd-2-clause": "BSD-2-Clause",
        "bsd-3-clause": "BSD-3-Clause",
        "gpl": "GPL-3.0",
        "gpl-3.0": "GPL-3.0",
        "gpl v3": "GPL-3.0",
        "gnu general public license v3": "GPL-3.0",
        "lgpl": "LGPL-3.0",
        "lgpl-3.0": "LGPL-3.0",
        "agpl": "AGPL-3.0",
        "agpl-3.0": "AGPL-3.0",
        "isc": "ISC",
        "isc license": "ISC",
        "mpl-2.0": "MPL-2.0",
        "mozilla public license 2.0": "MPL-2.0",
        "unlicense": "Unlicense",
        "public domain": "Unlicense",
        "cc0": "CC0-1.0",
    }
    
    def __init__(self, config: Config):
        """Initialize the license scanner."""
        self.config = config
        self._client = httpx.Client(timeout=config.timeout_seconds)
    
    def scan(self, dependencies: list[Dependency]) -> list[tuple[Dependency, LicenseInfo]]:
        """
        Scan dependencies for license compliance issues.
        
        Args:
            dependencies: List of dependencies to scan
            
        Returns:
            List of (dependency, license_info) tuples for packages with issues
        """
        issues = []
        
        for dep in dependencies:
            license_info = self._get_license_info(dep)
            if license_info and not self._is_license_allowed(license_info):
                issues.append((dep, license_info))
        
        return issues
    
    def _get_license_info(self, dependency: Dependency) -> Optional[LicenseInfo]:
        """Fetch license information for a dependency from PyPI."""
        try:
            url = self.PYPI_API_URL.format(package=dependency.name)
            response = self._client.get(url)
            response.raise_for_status()
            
            data = response.json()
            info = data.get("info", {})
            
            # Try to get license from classifier first (more reliable)
            classifiers = info.get("classifiers", [])
            for classifier in classifiers:
                if classifier.startswith("License :: OSI Approved ::"):
                    license_name = classifier.replace("License :: OSI Approved :: ", "")
                    spdx_id = self._normalize_license(license_name)
                    return LicenseInfo.from_spdx(spdx_id)
            
            # Fall back to license field
            license_str = info.get("license", "")
            if license_str:
                spdx_id = self._normalize_license(license_str)
                return LicenseInfo.from_spdx(spdx_id)
            
            return None
            
        except httpx.HTTPError:
            return None
        except Exception:
            return None
    
    def _normalize_license(self, license_str: str) -> str:
        """Normalize a license string to SPDX identifier."""
        normalized = license_str.lower().strip()
        return self.LICENSE_MAPPING.get(normalized, license_str)
    
    def _is_license_allowed(self, license_info: LicenseInfo) -> bool:
        """Check if a license is allowed based on configuration."""
        # If we have an allowed list, check against it
        if self.config.allowed_licenses:
            if license_info.spdx_id in self.config.allowed_licenses:
                return True
            # Not in allowed list = not allowed
            return False
        
        # If we only have a blocked list, check against it
        if self.config.blocked_licenses:
            if license_info.spdx_id in self.config.blocked_licenses:
                return False
        
        # Default: allow permissive, block copyleft
        return license_info.is_permissive and not license_info.is_copyleft
    
    def __del__(self):
        """Cleanup HTTP client."""
        if hasattr(self, "_client"):
            self._client.close()
