"""Typosquatting detection scanner."""

from typing import Optional

from ..core.config import Config
from ..core.models import Dependency, TyposquatMatch


class TyposquatScanner:
    """Scanner for detecting potential typosquatting attacks in package names."""
    
    # Top popular PyPI packages to check against
    POPULAR_PACKAGES = {
        "requests", "numpy", "pandas", "matplotlib", "scipy", "django",
        "flask", "tensorflow", "torch", "keras", "pillow", "sqlalchemy",
        "beautifulsoup4", "selenium", "pytest", "boto3", "pyyaml", "redis",
        "celery", "cryptography", "httpx", "fastapi", "pydantic", "black",
        "mypy", "pylint", "setuptools", "pip", "wheel", "virtualenv",
        "tqdm", "click", "colorama", "rich", "typer", "poetry",
        "jupyter", "notebook", "ipython", "scikit-learn", "xgboost",
        "lightgbm", "opencv-python", "transformers", "huggingface-hub",
        "aiohttp", "asyncio", "uvicorn", "gunicorn", "werkzeug",
        "jinja2", "markdown", "pygments", "sphinx", "mkdocs",
        "psycopg2", "pymongo", "elasticsearch", "kafka-python",
        "paramiko", "fabric", "ansible", "docker", "kubernetes",
        "aws-cdk", "google-cloud-storage", "azure-storage-blob",
        # Flask/web framework dependencies
        "blinker", "itsdangerous", "markupsafe", "starlette", "anyio",
        "asgiref", "python-dotenv", "orjson", "ujson", "msgpack",
    }
    
    # Trusted packages that should NEVER be flagged as typosquats
    # These are well-known packages with long history
    TRUSTED_ALLOWLIST = {
        "blinker",      # Flask signaling library (since 2010)
        "itsdangerous", # Flask security (Pallets)
        "markupsafe",   # Jinja2 dependency (Pallets)
        "werkzeug",     # Flask WSGI (Pallets)
        "jinja2",       # Template engine (Pallets)
        "click",        # CLI framework (Pallets)
        "starlette",    # ASGI framework
        "anyio",        # Async compatibility
        "asgiref",      # ASGI reference
        "httpcore",     # HTTP transport
        "sniffio",      # Async library detection
        "h11",          # HTTP/1.1 parser
        "certifi",      # SSL certificates
        "charset-normalizer",
        "idna",         # Internationalized domain names
        "urllib3",      # HTTP library
        "six",          # Python 2/3 compatibility
        "typing-extensions",
    }
    
    # Common typosquatting techniques
    HOMOGLYPHS = {
        "a": ["а", "ɑ", "α"],  # Cyrillic а, Latin ɑ, Greek α
        "e": ["е", "ε"],       # Cyrillic е, Greek ε
        "o": ["о", "ο", "0"],  # Cyrillic о, Greek ο, zero
        "i": ["і", "ι", "1", "l"],  # Cyrillic і, Greek ι, one, lowercase L
        "c": ["с", "ϲ"],       # Cyrillic с, Greek ϲ
        "p": ["р", "ρ"],       # Cyrillic р, Greek ρ
        "s": ["ѕ", "ѕ"],       # Cyrillic ѕ
        "x": ["х", "χ"],       # Cyrillic х, Greek χ
        "y": ["у", "γ"],       # Cyrillic у, Greek γ
    }
    
    def __init__(self, config: Config):
        """Initialize the typosquatting scanner."""
        self.config = config
        self.threshold = config.typosquat_threshold
    
    def scan(self, dependencies: list[Dependency]) -> list[TyposquatMatch]:
        """
        Scan dependencies for potential typosquatting.
        
        Args:
            dependencies: List of dependencies to scan
            
        Returns:
            List of potential typosquatting matches
        """
        matches = []
        
        for dep in dependencies:
            match = self._check_typosquatting(dep.name)
            if match:
                matches.append(match)
        
        return matches
    
    def _check_typosquatting(self, package_name: str) -> Optional[TyposquatMatch]:
        """Check if a package name is potentially typosquatting a popular package."""
        # Normalize the name
        name = package_name.lower().replace("_", "-")
        
        # Skip if it's a known popular package
        if name in self.POPULAR_PACKAGES:
            return None
        
        # Skip trusted packages (prevent false positives on legitimate packages)
        if name in self.TRUSTED_ALLOWLIST:
            return None
        
        best_match = None
        best_score = 0.0
        best_method = ""
        
        for popular in self.POPULAR_PACKAGES:
            # Check Levenshtein distance
            lev_score = self._levenshtein_similarity(name, popular)
            if lev_score > best_score and lev_score >= self.threshold:
                best_score = lev_score
                best_match = popular
                best_method = "levenshtein"
            
            # Check for character swaps
            if self._is_char_swap(name, popular):
                best_score = 0.95
                best_match = popular
                best_method = "character_swap"
            
            # Check for homoglyphs
            if self._has_homoglyph(name, popular):
                best_score = 0.98
                best_match = popular
                best_method = "homoglyph"
            
            # Check for prefix/suffix attacks
            prefix_suffix_score = self._check_prefix_suffix(name, popular)
            if prefix_suffix_score > best_score:
                best_score = prefix_suffix_score
                best_match = popular
                best_method = "prefix_suffix"
        
        if best_match and best_score >= self.threshold:
            risk_level = "high" if best_score >= 0.95 else ("medium" if best_score >= 0.9 else "low")
            return TyposquatMatch(
                suspicious_package=package_name,
                legitimate_package=best_match,
                similarity_score=best_score,
                detection_method=best_method,
                risk_level=risk_level,
            )
        
        return None
    
    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Calculate Levenshtein similarity (1 - normalized distance)."""
        if s1 == s2:
            return 1.0
        
        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0
        
        # Create distance matrix
        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        
        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j
        
        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i-1] == s2[j-1] else 1
                matrix[i][j] = min(
                    matrix[i-1][j] + 1,      # deletion
                    matrix[i][j-1] + 1,      # insertion
                    matrix[i-1][j-1] + cost  # substitution
                )
        
        distance = matrix[len1][len2]
        max_len = max(len1, len2)
        return 1.0 - (distance / max_len)
    
    def _is_char_swap(self, s1: str, s2: str) -> bool:
        """Check if s1 is s2 with exactly two adjacent characters swapped."""
        if len(s1) != len(s2):
            return False
        
        diffs = [(i, s1[i], s2[i]) for i in range(len(s1)) if s1[i] != s2[i]]
        
        if len(diffs) != 2:
            return False
        
        i1, c1_s1, c1_s2 = diffs[0]
        i2, c2_s1, c2_s2 = diffs[1]
        
        return i2 == i1 + 1 and c1_s1 == c2_s2 and c2_s1 == c1_s2
    
    def _has_homoglyph(self, suspicious: str, legitimate: str) -> bool:
        """Check if suspicious contains homoglyphs of characters in legitimate."""
        if len(suspicious) != len(legitimate):
            return False
        
        for i, (s_char, l_char) in enumerate(zip(suspicious, legitimate)):
            if s_char == l_char:
                continue
            
            # Check if s_char is a homoglyph of l_char
            if l_char in self.HOMOGLYPHS:
                if s_char in self.HOMOGLYPHS[l_char]:
                    return True
        
        return False
    
    def _check_prefix_suffix(self, suspicious: str, legitimate: str) -> float:
        """Check for prefix/suffix typosquatting attacks."""
        # python-requests vs requests
        prefixes = ["python-", "py-", "python3-", "py3-", "lib", "the-"]
        suffixes = ["-python", "-py", "-lib", "-core", "-dev", "-utils"]
        
        for prefix in prefixes:
            if suspicious == prefix + legitimate:
                return 0.92
            if suspicious == legitimate + prefix.rstrip("-"):
                return 0.92
        
        for suffix in suffixes:
            if suspicious == legitimate + suffix:
                return 0.92
            if suspicious == suffix.lstrip("-") + legitimate:
                return 0.92
        
        return 0.0
