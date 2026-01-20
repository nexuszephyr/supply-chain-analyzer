"""Dependency tree analyzer for transitive dependency resolution and visualization."""

import httpx
from typing import Optional
from collections import defaultdict

from ..core.config import Config
from ..core.models import Dependency, Ecosystem


class DependencyTreeScanner:
    """Scanner for building and analyzing dependency trees."""
    
    PYPI_API_URL = "https://pypi.org/pypi/{package}/{version}/json"
    PYPI_LATEST_URL = "https://pypi.org/pypi/{package}/json"
    
    def __init__(self, config: Config):
        """Initialize the dependency tree scanner."""
        self.config = config
        self._client = httpx.Client(timeout=config.timeout_seconds)
        self._cache: dict[str, list[str]] = {}  # Cache package dependencies
    
    def build_tree(self, dependencies: list[Dependency], max_depth: int = 5) -> dict:
        """
        Build a complete dependency tree with transitive dependencies.
        
        Args:
            dependencies: List of direct dependencies
            max_depth: Maximum depth to traverse
            
        Returns:
            Dictionary representing the dependency tree
        """
        tree = {
            "direct": [],
            "transitive": [],
            "all_packages": set(),
            "depth_map": defaultdict(list),
        }
        
        for dep in dependencies:
            node = self._build_node(dep, depth=0, max_depth=max_depth, visited=set())
            tree["direct"].append(node)
            self._flatten_tree(node, tree["all_packages"], tree["transitive"], depth=0)
        
        return tree
    
    def _build_node(self, dep: Dependency, depth: int, max_depth: int, visited: set) -> dict:
        """Build a tree node for a dependency."""
        node = {
            "name": dep.name,
            "version": dep.version,
            "depth": depth,
            "dependencies": [],
        }
        
        # Avoid circular dependencies
        dep_key = f"{dep.name}@{dep.version}"
        if dep_key in visited or depth >= max_depth:
            return node
        
        visited.add(dep_key)
        
        # Fetch transitive dependencies
        trans_deps = self._get_dependencies(dep.name, dep.version)
        
        for trans_name, trans_version in trans_deps:
            trans_dep = Dependency(
                name=trans_name,
                version=trans_version or "*",
                ecosystem=Ecosystem.PIP,
                is_direct=False,
            )
            child_node = self._build_node(trans_dep, depth + 1, max_depth, visited.copy())
            node["dependencies"].append(child_node)
        
        return node
    
    def _get_dependencies(self, package: str, version: str) -> list[tuple[str, str]]:
        """Fetch dependencies for a package from PyPI."""
        cache_key = f"{package}@{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        try:
            if version and version != "*":
                url = self.PYPI_API_URL.format(package=package, version=version)
            else:
                url = self.PYPI_LATEST_URL.format(package=package)
            
            response = self._client.get(url)
            response.raise_for_status()
            
            data = response.json()
            requires = data.get("info", {}).get("requires_dist", []) or []
            
            deps = []
            for req in requires:
                # Parse requirement string (e.g., "requests>=2.0; extra == 'security'")
                # Skip extras and environment markers for now
                if ";" in req and "extra" in req:
                    continue
                
                # Extract package name
                name = req.split()[0].split("[")[0].split("<")[0].split(">")[0].split("=")[0].split("!")[0]
                deps.append((name.lower(), "*"))
            
            self._cache[cache_key] = deps
            return deps
            
        except Exception:
            return []
    
    def _flatten_tree(self, node: dict, all_packages: set, transitive: list, depth: int) -> None:
        """Flatten tree to collect all packages."""
        pkg_key = f"{node['name']}@{node['version']}"
        all_packages.add(pkg_key)
        
        if depth > 0:  # Skip direct dependencies
            transitive.append({
                "name": node["name"],
                "version": node["version"],
                "depth": depth,
            })
        
        for child in node.get("dependencies", []):
            self._flatten_tree(child, all_packages, transitive, depth + 1)
    
    def format_tree_ascii(self, tree: dict) -> str:
        """
        Format dependency tree as ASCII art.
        
        Returns:
            String representation of the tree
        """
        lines = []
        
        for i, node in enumerate(tree["direct"]):
            is_last = i == len(tree["direct"]) - 1
            self._format_node(node, lines, "", is_last)
        
        return "\n".join(lines)
    
    def _format_node(self, node: dict, lines: list, prefix: str, is_last: bool) -> None:
        """Format a single tree node."""
        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{node['name']}@{node['version']}")
        
        new_prefix = prefix + ("    " if is_last else "│   ")
        
        children = node.get("dependencies", [])
        for i, child in enumerate(children):
            child_is_last = i == len(children) - 1
            self._format_node(child, lines, new_prefix, child_is_last)
    
    def find_vulnerable_paths(self, tree: dict, vulnerable_packages: set[str]) -> list[list[str]]:
        """
        Find paths in the tree that lead to vulnerable packages.
        
        Args:
            tree: Dependency tree
            vulnerable_packages: Set of vulnerable package names
            
        Returns:
            List of paths (each path is a list of package names)
        """
        paths = []
        
        for node in tree["direct"]:
            self._find_paths(node, vulnerable_packages, [], paths)
        
        return paths
    
    def _find_paths(self, node: dict, targets: set[str], current_path: list, all_paths: list) -> None:
        """Recursively find paths to vulnerable packages."""
        current_path = current_path + [f"{node['name']}@{node['version']}"]
        
        if node["name"].lower() in targets:
            all_paths.append(current_path)
        
        for child in node.get("dependencies", []):
            self._find_paths(child, targets, current_path, all_paths)
    
    def get_stats(self, tree: dict) -> dict:
        """Get statistics about the dependency tree."""
        all_packages = tree["all_packages"]
        transitive = tree["transitive"]
        
        max_depth = max((t["depth"] for t in transitive), default=0)
        
        return {
            "direct_count": len(tree["direct"]),
            "transitive_count": len(transitive),
            "total_packages": len(all_packages),
            "max_depth": max_depth,
        }
    
    def __del__(self):
        """Cleanup HTTP client."""
        if hasattr(self, "_client"):
            self._client.close()
