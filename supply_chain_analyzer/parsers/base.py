"""Base parser interface for package manifest files."""

from abc import ABC, abstractmethod
from pathlib import Path

from ..core.models import Dependency


class BaseParser(ABC):
    """Abstract base class for package manifest parsers."""
    
    @abstractmethod
    def parse(self, file_path: Path) -> list[Dependency]:
        """
        Parse a package manifest file and extract dependencies.
        
        Args:
            file_path: Path to the manifest file
            
        Returns:
            List of Dependency objects
        """
        pass
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if this parser can handle the file
        """
        pass
