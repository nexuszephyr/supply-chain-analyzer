"""Tests for license scanner."""

import pytest
from unittest.mock import patch, MagicMock

from supply_chain_analyzer.scanners.license import LicenseScanner
from supply_chain_analyzer.core.config import Config
from supply_chain_analyzer.core.models import Dependency, Ecosystem, LicenseInfo


class TestLicenseScanner:
    """Tests for LicenseScanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()
        self.config.allowed_licenses = {"MIT", "Apache-2.0", "BSD-3-Clause"}
        self.scanner = LicenseScanner(self.config)
    
    def test_license_info_from_spdx(self):
        """Test LicenseInfo creation from SPDX identifier."""
        mit = LicenseInfo.from_spdx("MIT")
        assert mit.spdx_id == "MIT"
        assert mit.is_permissive == True
        assert mit.is_copyleft == False
        
        gpl = LicenseInfo.from_spdx("GPL-3.0")
        assert gpl.spdx_id == "GPL-3.0"
        assert gpl.is_copyleft == True
    
    def test_normalize_license(self):
        """Test license string normalization."""
        assert self.scanner._normalize_license("MIT License") == "MIT"
        assert self.scanner._normalize_license("Apache 2.0") == "Apache-2.0"
        assert self.scanner._normalize_license("BSD") == "BSD-3-Clause"
    
    def test_is_license_allowed_with_allowed_list(self):
        """Test license allowed check against allowed list."""
        mit_license = LicenseInfo.from_spdx("MIT")
        assert self.scanner._is_license_allowed(mit_license) == True
        
        gpl_license = LicenseInfo.from_spdx("GPL-3.0")
        assert self.scanner._is_license_allowed(gpl_license) == False
    
    def test_scan_empty_dependencies(self):
        """Test scanning with no dependencies."""
        result = self.scanner.scan([])
        assert result == []
    
    @patch("httpx.Client.get")
    def test_scan_with_allowed_license(self, mock_get):
        """Test scanning package with allowed license."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "license": "MIT",
                "classifiers": ["License :: OSI Approved :: MIT License"]
            }
        }
        mock_get.return_value = mock_response
        
        deps = [
            Dependency(name="good-package", version="1.0.0", ecosystem=Ecosystem.PIP)
        ]
        
        result = self.scanner.scan(deps)
        
        # MIT is allowed, so no issues
        assert result == []
    
    @patch("httpx.Client.get")
    def test_scan_with_blocked_license(self, mock_get):
        """Test scanning package with blocked license."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "license": "GPL-3.0",
                "classifiers": ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"]
            }
        }
        mock_get.return_value = mock_response
        
        deps = [
            Dependency(name="gpl-package", version="1.0.0", ecosystem=Ecosystem.PIP)
        ]
        
        result = self.scanner.scan(deps)
        
        # GPL is not in allowed list, so it's an issue
        assert len(result) == 1
        assert result[0][0].name == "gpl-package"
    
    @patch("httpx.Client.get")
    def test_scan_handles_api_error(self, mock_get):
        """Test that API errors are handled gracefully."""
        import httpx
        mock_get.side_effect = httpx.HTTPError("API Error")
        
        deps = [
            Dependency(name="test-package", version="1.0.0", ecosystem=Ecosystem.PIP)
        ]
        
        # Should not raise, should return empty
        result = self.scanner.scan(deps)
        assert result == []
