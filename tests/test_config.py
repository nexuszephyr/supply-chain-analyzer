"""Tests for configuration module."""

import pytest
import tempfile
from pathlib import Path

from supply_chain_analyzer.core.config import Config


class TestConfig:
    """Tests for Config class."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.scan_dev_dependencies == True
        assert config.max_depth == 10
        assert config.timeout_seconds == 30
        assert config.typosquat_threshold == 0.85
        assert "MIT" in config.allowed_licenses
    
    def test_modify_config(self):
        """Test modifying configuration."""
        config = Config()
        config.allowed_licenses = {"MIT", "BSD-3-Clause"}
        config.typosquat_threshold = 0.9
        
        assert config.allowed_licenses == {"MIT", "BSD-3-Clause"}
        assert config.typosquat_threshold == 0.9
    
    def test_save_and_load_config(self):
        """Test saving and loading configuration from file."""
        config = Config()
        config.allowed_licenses = {"MIT", "Apache-2.0"}
        config.typosquat_threshold = 0.8
        config.verbose = True
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_path = Path(f.name)
        
        try:
            # Save config
            config.save_to_file(config_path)
            
            # Load config
            loaded = Config.load_from_file(config_path)
            
            assert loaded.allowed_licenses == {"MIT", "Apache-2.0"}
            assert loaded.typosquat_threshold == 0.8
            assert loaded.verbose == True
        finally:
            config_path.unlink()
    
    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file returns defaults."""
        config = Config.load_from_file(Path("/nonexistent/path/config.yaml"))
        
        # Should return default config
        assert config.max_depth == 10
        assert config.timeout_seconds == 30
    
    def test_blocked_licenses(self):
        """Test blocked licenses configuration."""
        config = Config()
        config.blocked_licenses = {"GPL-3.0", "AGPL-3.0"}
        
        assert "GPL-3.0" in config.blocked_licenses
        assert "AGPL-3.0" in config.blocked_licenses
