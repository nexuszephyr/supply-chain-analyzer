"""Tests for package parsers."""

import pytest
from pathlib import Path
import tempfile

from supply_chain_analyzer.parsers.pip_parser import PipParser
from supply_chain_analyzer.core.models import Ecosystem


class TestPipParser:
    """Tests for PipParser."""
    
    def test_parse_requirements_txt(self):
        """Test parsing a requirements.txt file."""
        parser = PipParser()
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests==2.28.0\n")
            f.write("numpy>=1.21.0\n")
            f.write("pandas~=1.4.0\n")
            f.write("# this is a comment\n")
            f.write("flask\n")
            f.name
        
        try:
            deps = parser.parse(Path(f.name))
            
            assert len(deps) == 4
            
            # Check requests
            requests_dep = next(d for d in deps if d.name == "requests")
            assert requests_dep.version == "2.28.0"
            assert requests_dep.ecosystem == Ecosystem.PIP
            
            # Check numpy
            numpy_dep = next(d for d in deps if d.name == "numpy")
            assert numpy_dep.version == "1.21.0"
            
            # Check flask (no version specified)
            flask_dep = next(d for d in deps if d.name == "flask")
            assert flask_dep.version == "*"
            
        finally:
            Path(f.name).unlink()
    
    def test_parse_empty_file(self):
        """Test parsing an empty requirements file."""
        parser = PipParser()
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("")
            f.name
        
        try:
            deps = parser.parse(Path(f.name))
            assert len(deps) == 0
        finally:
            Path(f.name).unlink()
    
    def test_parse_with_extras(self):
        """Test parsing packages with extras."""
        parser = PipParser()
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests[security]==2.28.0\n")
            f.name
        
        try:
            deps = parser.parse(Path(f.name))
            assert len(deps) == 1
            assert deps[0].name == "requests"
            assert deps[0].version == "2.28.0"
        finally:
            Path(f.name).unlink()
    
    def test_can_parse(self):
        """Test can_parse method."""
        parser = PipParser()
        
        assert parser.can_parse(Path("requirements.txt"))
        assert parser.can_parse(Path("requirements-dev.txt"))
        assert parser.can_parse(Path("pyproject.toml"))
        assert not parser.can_parse(Path("package.json"))
        assert not parser.can_parse(Path("pom.xml"))
