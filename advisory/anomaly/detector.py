"""Advisory Anomaly Detection using scikit-learn Isolation Forest (Tier 2 / Prompt T2.4).

CRITICAL NOTE:
Isolation Forest itself does not provide per-feature attribution or feature importances.
The 'top deviating features' list is a separate post-hoc heuristic comparing feature values
against empirical baseline frequencies, and is clearly marked as such.
This module is strictly ADVISORY: its output is never hashed and never sent on-chain.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import pickle
import sklearn
from sklearn.ensemble import IsolationForest

from engine.smscope.models import SessionRecord
from advisory.anomaly.features import (
    FEATURE_NAMES,
    session_to_feature_vector,
    extract_session_features,
)


class AnomalyDetector:
    """Trains and executes advisory anomaly detection on email session traffic."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        summary_path: Optional[Path] = None,
        threshold: float = -0.15,
    ):
        self.model: Optional[IsolationForest] = None
        self.threshold = threshold
        self.baseline_summary: Dict[str, Any] = {}
        self.baseline_ja3_counts: Dict[str, int] = {}
        self.baseline_server_certs: Dict[str, str] = {}
        self.feature_distributions: Dict[str, Dict[str, int]] = {}

        if model_path and model_path.exists():
            self.load_model(model_path)
        if summary_path and summary_path.exists():
            self.load_summary(summary_path)

    def train(
        self,
        sessions: List[SessionRecord],
        random_state: int = 42,
        contamination: float = 0.05,
    ) -> Dict[str, Any]:
        """
        Train IsolationForest model with fixed random_state for exact determinism.
        """
        # 1. Compute empirical baseline distributions
        ja3_counts: Dict[str, int] = {}
        server_certs: Dict[str, str] = {}
        feature_dists: Dict[str, Dict[str, int]] = {f: {} for f in FEATURE_NAMES}

        for s in sessions:
            if s.tls and s.tls.ja3:
                ja3_counts[s.tls.ja3] = ja3_counts.get(s.tls.ja3, 0) + 1
            if s.certificates and len(s.certificates) > 0:
                server_certs[s.serverEndpoint] = s.certificates[0].sha256

        self.baseline_ja3_counts = ja3_counts
        self.baseline_server_certs = server_certs

        # 2. Extract feature matrix
        X = []
        for s in sessions:
            vec = session_to_feature_vector(s, ja3_counts, server_certs)
            X.append(vec)
            feat_dict = extract_session_features(s, ja3_counts, server_certs)
            for k, v in feat_dict.items():
                str_v = str(v)
                feature_dists[k][str_v] = feature_dists[k].get(str_v, 0) + 1

        self.feature_distributions = feature_dists

        # 3. Fit IsolationForest
        # Deterministic with fixed random_state
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        self.model.fit(X)

        # 4. Calibration: evaluate threshold on training set scores
        scores = self.model.decision_function(X)
        sorted_scores = sorted(scores)
        # Select threshold at bottom 5th percentile
        thresh_idx = int(len(sorted_scores) * contamination)
        self.threshold = float(sorted_scores[thresh_idx]) if sorted_scores else -0.15

        self.baseline_summary = {
            "sklearn_version": sklearn.__version__,
            "random_state": random_state,
            "session_count": len(sessions),
            "threshold": self.threshold,
            "feature_names": FEATURE_NAMES,
            "ja3_count": len(ja3_counts),
            "server_endpoint_count": len(server_certs),
            "feature_distributions": feature_dists,
        }
        return self.baseline_summary

    def save(self, model_path: Path, summary_path: Path):
        """Save model and metadata summary to disk."""
        model_path.parent.mkdir(parents=True, exist_ok=True)
        with open(model_path, "wb") as f:
            pickle.dump(self.model, f)

        summary_data = {
            **self.baseline_summary,
            "baseline_ja3_counts": self.baseline_ja3_counts,
            "baseline_server_certs": self.baseline_server_certs,
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, sort_keys=True)

    def load_model(self, model_path: Path):
        """Load trained Isolation Forest model."""
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

    def load_summary(self, summary_path: Path):
        """Load baseline summary and reference metadata."""
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.baseline_summary = data
        self.threshold = data.get("threshold", -0.15)
        self.baseline_ja3_counts = data.get("baseline_ja3_counts", {})
        self.baseline_server_certs = data.get("baseline_server_certs", {})
        self.feature_distributions = data.get("feature_distributions", {})

    def score_session(self, session: SessionRecord) -> Dict[str, Any]:
        """
        Score a single session record.
        Returns:
            - anomaly_score: float score from decision_function
            - is_anomaly: bool flag indicating if score <= threshold
            - top_deviating_features: list of feature names with rare empirical baseline values
        """
        if self.model is None:
            raise RuntimeError("AnomalyDetector model is not trained or loaded.")

        vec = session_to_feature_vector(
            session, self.baseline_ja3_counts, self.baseline_server_certs
        )
        # decision_function: lower means more anomalous
        score = float(self.model.decision_function([vec])[0])
        is_anomaly = bool(score <= self.threshold)

        # Heuristic explanation: identify features that occur with frequency < 5% in baseline
        # Note: Isolation Forest does not provide per-feature attribution; this is an empirical heuristic.
        deviating_features = []
        feat_dict = extract_session_features(
            session, self.baseline_ja3_counts, self.baseline_server_certs
        )
        total_baseline = self.baseline_summary.get("session_count", 1)

        for feat_name, feat_val in feat_dict.items():
            dist = self.feature_distributions.get(feat_name, {})
            val_count = dist.get(str(feat_val), 0)
            freq = val_count / total_baseline if total_baseline > 0 else 0
            if freq < 0.05:
                deviating_features.append(f"{feat_name}={feat_val} (baseline_freq={freq:.1%})")

        sess_id = session.get("sessionId") if isinstance(session, dict) else session.sessionId
        server_ep = session.get("serverEndpoint", "") if isinstance(session, dict) else session.serverEndpoint

        return {
            "sessionId": sess_id,
            "serverEndpoint": server_ep,
            "anomalyScore": round(score, 4),
            "isAnomaly": is_anomaly,
            "topDeviatingFeatures": deviating_features,
            "explanationNote": "Isolation Forest does not provide per-feature attribution; deviating features are an empirical baseline heuristic.",
        }

    def score_capture(self, sessions: List[SessionRecord]) -> List[Dict[str, Any]]:
        """Score all sessions in a capture and return flagged sessions."""
        flagged = []
        for s in sessions:
            res = self.score_session(s)
            if res["isAnomaly"]:
                flagged.append(res)
        return flagged
