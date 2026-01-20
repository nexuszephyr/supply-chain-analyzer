"""Package risk classifier for grouping dependencies by security relevance."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..core.models import Dependency


class RiskCategory(Enum):
    """Risk category for packages."""
    SECURITY_RELEVANT = "security_relevant"  # Network, parsers, crypto, auth
    CONDITIONALLY_RELEVANT = "conditionally_relevant"  # Depends on usage (jinja2, markupsafe)
    SUPPORT = "support"  # Typing, docs, utilities, dev tools


@dataclass
class PackageClassification:
    """Classification result for a package."""
    package_name: str
    category: RiskCategory
    reason: str
    keywords: list[str]


# Patterns for security-relevant packages
SECURITY_RELEVANT_PATTERNS = {
    # Network/HTTP
    "network": [
        "requests", "httpx", "aiohttp", "urllib3", "httplib2", 
        "tornado", "twisted", "socket", "websocket", "grpc",
        "fastapi", "flask", "django", "starlette", "uvicorn",
        "gunicorn", "hypercorn", "sanic", "bottle", "falcon",
    ],
    # Parsing/Serialization
    "parser": [
        "lxml", "beautifulsoup", "html5lib", "xml", "yaml", "pyyaml",
        "json", "ujson", "orjson", "msgpack", "pickle", "marshal",
        "csv", "pandas", "numpy", "pillow", "imageio",
    ],
    # Crypto/Security
    "crypto": [
        "cryptography", "pycryptodome", "hashlib", "ssl", "tls",
        "jwt", "pyjwt", "python-jose", "authlib", "oauthlib",
        "passlib", "bcrypt", "argon2", "scrypt", "secrets",
    ],
    # Auth/Identity
    "auth": [
        "auth", "oauth", "saml", "ldap", "kerberos", "sso",
        "login", "session", "token", "credential", "identity",
    ],
    # Database
    "database": [
        "sqlalchemy", "psycopg", "pymysql", "mysql", "postgres",
        "sqlite", "mongodb", "pymongo", "redis", "celery",
        "elasticsearch", "cassandra", "dynamodb", "firebase",
    ],
    # File/IO
    "file": [
        "pathlib", "shutil", "tempfile", "zipfile", "tarfile",
        "gzip", "bz2", "lzma", "io", "mmap",
    ],
    # Process/System
    "system": [
        "subprocess", "os", "sys", "multiprocessing", "threading",
        "asyncio", "concurrent", "signal", "ctypes", "cffi",
    ],
}

# Patterns for support libraries
SUPPORT_PATTERNS = {
    # Type hints
    "typing": [
        "typing", "typing-extensions", "mypy", "pyright", "types-",
        "typeguard", "pydantic", "attrs", "dataclasses",
    ],
    # Documentation
    "docs": [
        "sphinx", "mkdocs", "pdoc", "docutils", "readme",
        "changelog", "towncrier", "annotated",
    ],
    # Testing
    "testing": [
        "pytest", "unittest", "nose", "mock", "faker",
        "hypothesis", "coverage", "tox", "nox",
    ],
    # Dev tools
    "dev": [
        "black", "flake8", "pylint", "isort", "autopep8",
        "pre-commit", "commitizen", "bumpversion",
    ],
    # CLI utilities
    "cli": [
        "click", "argparse", "fire", "typer", "rich",
        "colorama", "termcolor", "tqdm", "progressbar",
    ],
    # Utilities (low risk)
    "utility": [
        "six", "future", "compat", "backports", "importlib",
        "functools", "itertools", "collections", "operator",
    ],
}

# Patterns for conditionally-relevant packages (depends on usage)
CONDITIONALLY_RELEVANT_PATTERNS = {
    # Template engines - only risky with untrusted input
    "template": [
        "jinja2", "jinja", "mako", "chameleon", "genshi",
    ],
    # Escape/markup - depends on usage
    "markup": [
        "markupsafe", "bleach", "html",
    ],
    # Signaling - only risky if exposed externally
    "signaling": [
        "blinker",
    ],
    # WSGI/ASGI utilities - depends on deployment
    "wsgi": [
        "werkzeug", "itsdangerous",
    ],
}


class PackageClassifier:
    """Classify packages by security relevance."""
    
    def __init__(self):
        """Initialize classifier with pattern maps."""
        self._security_patterns = SECURITY_RELEVANT_PATTERNS
        self._conditional_patterns = CONDITIONALLY_RELEVANT_PATTERNS
        self._support_patterns = SUPPORT_PATTERNS
    
    def classify(self, package_name: str) -> PackageClassification:
        """
        Classify a package as security-relevant, conditionally-relevant, or support.
        
        Args:
            package_name: Name of the package
            
        Returns:
            PackageClassification with category and reason
        """
        name_lower = package_name.lower().replace("-", "").replace("_", "")
        
        # Check conditionally-relevant patterns FIRST (these are often in other lists too)
        for category, patterns in self._conditional_patterns.items():
            for pattern in patterns:
                pattern_normalized = pattern.lower().replace("-", "").replace("_", "")
                if pattern_normalized in name_lower or name_lower in pattern_normalized:
                    return PackageClassification(
                        package_name=package_name,
                        category=RiskCategory.CONDITIONALLY_RELEVANT,
                        reason=f"{category.title()} - depends on usage",
                        keywords=[category]
                    )
        
        # Check security-relevant patterns
        for category, patterns in self._security_patterns.items():
            for pattern in patterns:
                pattern_normalized = pattern.lower().replace("-", "").replace("_", "")
                if pattern_normalized in name_lower or name_lower in pattern_normalized:
                    return PackageClassification(
                        package_name=package_name,
                        category=RiskCategory.SECURITY_RELEVANT,
                        reason=f"{category.title()} component",
                        keywords=[category]
                    )
        
        # Check support patterns
        for category, patterns in self._support_patterns.items():
            for pattern in patterns:
                pattern_normalized = pattern.lower().replace("-", "").replace("_", "")
                if pattern_normalized in name_lower or name_lower in pattern_normalized:
                    return PackageClassification(
                        package_name=package_name,
                        category=RiskCategory.SUPPORT,
                        reason=f"{category.title()} library",
                        keywords=[category]
                    )
        
        # Default: mark as unclassified (not automatically security-relevant)
        return PackageClassification(
            package_name=package_name,
            category=RiskCategory.CONDITIONALLY_RELEVANT,
            reason="Unclassified - review manually",
            keywords=["unknown"]
        )
    
    def classify_dependencies(self, dependencies: list[Dependency]) -> dict[str, list[tuple[Dependency, PackageClassification]]]:
        """
        Classify a list of dependencies into groups.
        
        Args:
            dependencies: List of Dependency objects
            
        Returns:
            Dict with 'security_relevant', 'conditionally_relevant', and 'support' keys
        """
        result = {
            "security_relevant": [],
            "conditionally_relevant": [],
            "support": [],
        }
        
        for dep in dependencies:
            classification = self.classify(dep.name)
            if classification.category == RiskCategory.SECURITY_RELEVANT:
                result["security_relevant"].append((dep, classification))
            elif classification.category == RiskCategory.CONDITIONALLY_RELEVANT:
                result["conditionally_relevant"].append((dep, classification))
            else:
                result["support"].append((dep, classification))
        
        return result

