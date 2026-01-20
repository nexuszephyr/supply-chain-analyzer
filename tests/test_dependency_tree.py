"""Tests for dependency tree scanner."""

import pytest
from unittest.mock import patch, MagicMock

from supply_chain_analyzer.scanners.dependency_tree import DependencyTreeScanner
from supply_chain_analyzer.core.config import Config
from supply_chain_analyzer.core.models import Dependency, Ecosystem


class TestDependencyTreeScanner:
    """Tests for DependencyTreeScanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()
        self.scanner = DependencyTreeScanner(self.config)
    
    def test_build_tree_empty_dependencies(self):
        """Test building tree with no dependencies."""
        result = self.scanner.build_tree([])
        
        assert result["direct"] == []
        assert result["transitive"] == []
        assert len(result["all_packages"]) == 0
    
    def test_build_tree_single_dependency(self):
        """Test building tree with single dependency."""
        deps = [
            Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PIP)
        ]
        
        with patch.object(self.scanner, "_get_dependencies", return_value=[]):
            result = self.scanner.build_tree(deps, max_depth=1)
        
        assert len(result["direct"]) == 1
        assert result["direct"][0]["name"] == "requests"
        assert result["direct"][0]["version"] == "2.28.0"
    
    def test_build_tree_with_transitive_deps(self):
        """Test building tree with transitive dependencies."""
        deps = [
            Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PIP)
        ]
        
        # Mock transitive dependencies
        def mock_get_deps(package, version):
            if package == "requests":
                return [("urllib3", "*"), ("certifi", "*")]
            return []
        
        with patch.object(self.scanner, "_get_dependencies", side_effect=mock_get_deps):
            result = self.scanner.build_tree(deps, max_depth=2)
        
        assert len(result["direct"]) == 1
        assert len(result["direct"][0]["dependencies"]) == 2
    
    def test_format_tree_ascii(self):
        """Test ASCII tree formatting."""
        tree = {
            "direct": [
                {
                    "name": "requests",
                    "version": "2.28.0",
                    "depth": 0,
                    "dependencies": [
                        {
                            "name": "urllib3",
                            "version": "1.26.0",
                            "depth": 1,
                            "dependencies": []
                        }
                    ]
                }
            ]
        }
        
        ascii_output = self.scanner.format_tree_ascii(tree)
        
        assert "requests@2.28.0" in ascii_output
        assert "urllib3@1.26.0" in ascii_output
        assert "├──" in ascii_output or "└──" in ascii_output
    
    def test_find_vulnerable_paths(self):
        """Test finding paths to vulnerable packages."""
        tree = {
            "direct": [
                {
                    "name": "requests",
                    "version": "2.28.0",
                    "dependencies": [
                        {
                            "name": "urllib3",
                            "version": "1.26.0",
                            "dependencies": []
                        }
                    ]
                }
            ]
        }
        
        paths = self.scanner.find_vulnerable_paths(tree, {"urllib3"})
        
        assert len(paths) == 1
        assert paths[0] == ["requests@2.28.0", "urllib3@1.26.0"]
    
    def test_find_vulnerable_paths_no_matches(self):
        """Test finding paths when no vulnerable packages."""
        tree = {
            "direct": [
                {
                    "name": "requests",
                    "version": "2.28.0",
                    "dependencies": []
                }
            ]
        }
        
        paths = self.scanner.find_vulnerable_paths(tree, {"lodash"})
        
        assert paths == []
    
    def test_get_stats(self):
        """Test getting tree statistics."""
        tree = {
            "direct": [{"name": "pkg1"}, {"name": "pkg2"}],
            "transitive": [
                {"name": "trans1", "depth": 1},
                {"name": "trans2", "depth": 2},
                {"name": "trans3", "depth": 2}
            ],
            "all_packages": {"pkg1", "pkg2", "trans1", "trans2", "trans3"}
        }
        
        stats = self.scanner.get_stats(tree)
        
        assert stats["direct_count"] == 2
        assert stats["transitive_count"] == 3
        assert stats["total_packages"] == 5
        assert stats["max_depth"] == 2
