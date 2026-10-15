"""
CyberShield AI — Machine Learning Subsystem
Contains feature extractors, anomaly detection models, and evaluation pipelines.
"""

import sys
from pathlib import Path

# Ensure local virtual environment packages are discoverable if present
_venv_site = Path(__file__).resolve().parent.parent.parent / ".venv" / "lib" / "python3.14" / "site-packages"
if _venv_site.exists() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

from backend.ml.anomaly import AnomalyDetectionPipeline
from backend.ml.features import SecurityFeatureExtractor

__all__ = ["SecurityFeatureExtractor", "AnomalyDetectionPipeline"]
