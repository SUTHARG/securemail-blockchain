"""Advisory anomaly detection package for SecureMailScope."""
from advisory.anomaly.features import extract_session_features, session_to_feature_vector, FEATURE_NAMES
from advisory.anomaly.detector import AnomalyDetector

__all__ = [
    "AnomalyDetector",
    "extract_session_features",
    "session_to_feature_vector",
    "FEATURE_NAMES",
]
