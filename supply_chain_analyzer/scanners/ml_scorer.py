"""ML model integration for package risk scoring."""

from pathlib import Path
from typing import Optional
import json

from ..core.config import Config
from ..core.models import Dependency


class MLRiskScorer:
    """ML-based risk scorer for packages."""
    
    def __init__(self, config: Config):
        """Initialize the ML risk scorer."""
        self.config = config
        self._model = None
        self._scaler = None
        self._feature_columns = None
        self._loaded = False
        
        if config.use_ml_scoring and config.model_path:
            self._load_models(config.model_path)
    
    def _load_models(self, models_dir: Path) -> None:
        """Load trained models from disk."""
        try:
            import joblib
            
            models_dir = Path(models_dir)
            
            # Load model
            model_path = models_dir / "risk_scorer.joblib"
            if model_path.exists():
                self._model = joblib.load(model_path)
            
            # Load scaler (optional)
            scaler_path = models_dir / "scaler.joblib"
            if scaler_path.exists():
                self._scaler = joblib.load(scaler_path)
            
            # Load feature columns
            metadata_path = models_dir / "metadata.json"
            if metadata_path.exists():
                with open(metadata_path) as f:
                    metadata = json.load(f)
                    self._feature_columns = metadata.get("feature_columns", [])
            
            self._loaded = self._model is not None
            
        except ImportError:
            # joblib not installed
            self._loaded = False
        except Exception as e:
            self._loaded = False
    
    def is_available(self) -> bool:
        """Check if ML scoring is available."""
        return self._loaded
    
    def score_package(self, package_metadata: dict) -> Optional[float]:
        """
        Score a package's risk level using ML model.
        
        Args:
            package_metadata: Package metadata from PyPI
            
        Returns:
            Risk score between 0-1, or None if ML not available
        """
        if not self._loaded:
            return None
        
        try:
            features = self._extract_features(package_metadata)
            
            # Create feature vector
            feature_vector = [features.get(col, 0) for col in self._feature_columns]
            
            # Scale if scaler available
            if self._scaler:
                feature_vector = self._scaler.transform([feature_vector])
            else:
                feature_vector = [feature_vector]
            
            # Predict probability
            proba = self._model.predict_proba(feature_vector)[0]
            
            # Return probability of being malicious (class 1)
            return float(proba[1])
            
        except Exception:
            return None
    
    def _extract_features(self, metadata: dict) -> dict:
        """Extract features from package metadata."""
        info = metadata.get("info", {})
        releases = metadata.get("releases", {})
        
        # Calculate days since creation
        days_since_creation = 0
        # (simplified - in production would parse release dates)
        
        return {
            "days_since_creation": days_since_creation,
            "version_count": len(releases),
            "has_homepage": int(bool(info.get("home_page"))),
            "has_repository": int(bool(
                info.get("project_urls", {}).get("Repository") or 
                info.get("project_urls", {}).get("Source")
            )),
            "description_length": len(info.get("description", "") or ""),
            "classifiers_count": len(info.get("classifiers", [])),
            "is_very_new": 0,
            "is_established": 0,
            "is_few_versions": int(len(releases) <= 3),
            "doc_score": min(len(info.get("description", "") or "") / 1000, 1.0),
            "credibility_score": (
                int(bool(info.get("home_page"))) +
                int(bool(info.get("project_urls", {}).get("Repository"))) +
                int(bool(info.get("license"))) +
                int(len(info.get("classifiers", [])) > 0)
            ) / 4.0,
        }
    
    def score_dependencies(self, dependencies: list[Dependency]) -> dict[str, float]:
        """
        Score multiple dependencies.
        
        Args:
            dependencies: List of dependencies to score
            
        Returns:
            Dictionary mapping package names to risk scores
        """
        if not self._loaded:
            return {}
        
        import httpx
        
        scores = {}
        
        with httpx.Client(timeout=10.0) as client:
            for dep in dependencies:
                try:
                    url = f"https://pypi.org/pypi/{dep.name}/json"
                    response = client.get(url)
                    if response.status_code == 200:
                        metadata = response.json()
                        score = self.score_package(metadata)
                        if score is not None:
                            scores[dep.name] = score
                except Exception:
                    pass
        
        return scores
