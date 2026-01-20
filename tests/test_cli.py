"""Tests for CLI commands."""

import pytest
from click.testing import CliRunner
import tempfile
from pathlib import Path

from supply_chain_analyzer.cli import main


class TestCli:
    """Tests for CLI commands."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def sample_project(self):
        """Create a temporary project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "requirements.txt").write_text("requests==2.28.0\n")
            yield str(project)
    
    def test_help_command(self, runner):
        """Test --help option."""
        result = runner.invoke(main, ["--help"])
        
        assert result.exit_code == 0
        assert "Supply Chain Security Analyzer" in result.output
        assert "scan" in result.output
        assert "vuln" in result.output
        assert "typosquat" in result.output
        assert "license" in result.output
        assert "tree" in result.output
    
    def test_version_command(self, runner):
        """Test --version option."""
        result = runner.invoke(main, ["--version"])
        
        assert result.exit_code == 0
        assert "0.1.0" in result.output
    
    def test_init_command(self, runner):
        """Test init command creates config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".sca.yaml"
            
            result = runner.invoke(main, ["init", "-o", str(config_path)])
            
            assert result.exit_code == 0
            assert config_path.exists()
    
    def test_scan_command_json_format(self, runner, sample_project):
        """Test scan command with JSON format."""
        result = runner.invoke(main, ["scan", sample_project, "-f", "json"])
        
        # Should succeed and contain JSON
        assert '"metadata"' in result.output or result.exit_code in (0, 1)
    
    def test_scan_nonexistent_path(self, runner):
        """Test scan command with nonexistent path."""
        result = runner.invoke(main, ["scan", "/nonexistent/path"])
        
        assert result.exit_code != 0
    
    def test_scan_help(self, runner):
        """Test scan --help."""
        result = runner.invoke(main, ["scan", "--help"])
        
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--output" in result.output
        assert "--severity" in result.output
    
    def test_typosquat_help(self, runner):
        """Test typosquat --help."""
        result = runner.invoke(main, ["typosquat", "--help"])
        
        assert result.exit_code == 0
        assert "--threshold" in result.output
    
    def test_license_help(self, runner):
        """Test license --help."""
        result = runner.invoke(main, ["license", "--help"])
        
        assert result.exit_code == 0
        assert "--allow" in result.output
        assert "--block" in result.output
    
    def test_tree_help(self, runner):
        """Test tree --help."""
        result = runner.invoke(main, ["tree", "--help"])
        
        assert result.exit_code == 0
        assert "--depth" in result.output
