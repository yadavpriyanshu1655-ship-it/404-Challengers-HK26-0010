"""
CyberShield AI — Machine-Learning Anomaly Detection Pipeline

Reproducible Scikit-learn Isolation Forest pipeline for unsupervised
outlier and anomaly detection on enterprise security telemetry.

Guarantees:
- Fit-only-on-training data to strictly avoid data leakage.
- Reproducible random state for consistent evaluation.
- Safe joblib persistence and artifact reloading.
- Calibrated 0.0 - 1.0 anomaly score generation.
- Clear separation from rule-based findings.
- Explicit non-maliciousness disclaimer on all anomaly findings.
"""

from __future__ import annotations

import io
from pathlib import Path
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from backend.ml.features import SecurityFeatureExtractor
from backend.models.anomaly import AnomalyFinding, ModelEvaluationReport
from backend.models.event import IngestionResult, SecurityEvent


class AnomalyDetectionPipeline:
    """
    Scikit-learn Isolation Forest pipeline for security telemetry anomaly detection.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.08,
        random_state: int = 42,
    ):
        """
        Initialize the anomaly detection pipeline.
        
        Args:
            n_estimators: Number of isolation trees in the forest.
            contamination: Expected proportion of outliers in the data corpus.
            random_state: Fixed seed guaranteeing reproducibility.
        """
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state

        self.extractor = SecurityFeatureExtractor()
        self.preprocessor = SecurityFeatureExtractor.build_preprocessor()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )

        self.is_fitted: bool = False
        self.training_sample_size: int = 0
        self._finding_counter: int = 0

    # -----------------------------------------------------------------
    # Training (Leakage-Free)
    # -----------------------------------------------------------------

    def fit(self, events: Union[IngestionResult, Iterable[Union[SecurityEvent, Dict[str, Any]]]]) -> AnomalyDetectionPipeline:
        """
        Fit feature preprocessor and Isolation Forest on training data only.
        
        Avoids training/evaluation data leakage by strictly fitting scalers
        and encoders on the provided training corpus.
        """
        if isinstance(events, IngestionResult):
            raw_events = events.events
        else:
            raw_events = list(events)

        if not raw_events:
            raise ValueError("Cannot train anomaly detection pipeline on an empty event corpus.")

        df = self.extractor.extract_features(raw_events)
        self.training_sample_size = len(df)

        # Separate feature columns from metadata columns
        X_df = df[self.extractor.NUMERIC_COLUMNS + self.extractor.CATEGORICAL_COLUMNS]

        # 1. Fit preprocessor on training data only
        X_transformed = self.preprocessor.fit_transform(X_df)

        # 2. Fit Isolation Forest on transformed features
        self.model.fit(X_transformed)
        self.is_fitted = True
        return self

    # -----------------------------------------------------------------
    # Inference
    # -----------------------------------------------------------------

    def score(
        self, events: Union[IngestionResult, Iterable[Union[SecurityEvent, Dict[str, Any]]]]
    ) -> List[AnomalyFinding]:
        """
        Generate anomaly indicators and normalized scores for security events.
        
        Does not claim an anomaly is necessarily malicious; flags statistical
        deviations from the baseline distribution.
        """
        if not self.is_fitted:
            raise RuntimeError("AnomalyDetectionPipeline must be fitted before running inference.")

        if isinstance(events, IngestionResult):
            raw_events = events.events
        else:
            raw_events = list(events)

        if not raw_events:
            return []

        df = self.extractor.extract_features(raw_events)
        if df.empty:
            return []

        X_df = df[self.extractor.NUMERIC_COLUMNS + self.extractor.CATEGORICAL_COLUMNS]
        # Transform using pre-fitted transformers (no re-fitting / no leakage)
        X_transformed = self.preprocessor.transform(X_df)

        # Predict anomaly indicator: -1 for outlier/anomaly, 1 for inlier
        predictions = self.model.predict(X_transformed)
        # Decision function: negative values indicate outliers
        raw_scores = self.model.decision_function(X_transformed)

        findings: List[AnomalyFinding] = []

        for idx, (pred, raw_score) in enumerate(zip(predictions, raw_scores)):
            is_anomaly = bool(pred == -1)
            # Calibrate raw_score to 0.0 - 1.0 probability-like anomaly score
            # raw_score typically spans [-0.5, 0.5]; sigmoid calibration
            normalized_score = float(1.0 / (1.0 + np.exp(raw_score * 5.0)))
            normalized_score = max(0.0, min(1.0, round(normalized_score, 4)))

            self._finding_counter += 1
            finding_id = f"CS-ANOMALY-{self._finding_counter:04d}"

            # Derive contributing factors based on feature thresholds
            row_dict = df.iloc[idx].to_dict()
            contributing = self._identify_contributing_factors(row_dict, is_anomaly, normalized_score)

            finding = AnomalyFinding(
                finding_id=finding_id,
                event_fingerprint=str(row_dict.get("_fingerprint", "")),
                timestamp=str(row_dict.get("_timestamp", "")),
                entity=str(row_dict.get("_entity", "unknown")),
                is_anomaly=is_anomaly,
                anomaly_score=normalized_score,
                raw_score=round(float(raw_score), 4),
                contributing_factors=contributing,
                disclaimer="Statistical anomaly indicator only; does not necessarily indicate malicious intent.",
                metadata={
                    "event_type": row_dict.get("event_type"),
                    "is_failure": bool(row_dict.get("is_failure", 0)),
                    "is_external_ip": bool(row_dict.get("is_external_ip", 0)),
                    "is_privileged_user": bool(row_dict.get("is_privileged_user", 0)),
                    "source_ip": row_dict.get("_source_ip"),
                },
            )
            findings.append(finding)

        return findings

    # -----------------------------------------------------------------
    # Held-Out Evaluation
    # -----------------------------------------------------------------

    def evaluate_held_out(
        self, test_events: Union[IngestionResult, Iterable[Union[SecurityEvent, Dict[str, Any]]]]
    ) -> ModelEvaluationReport:
        """
        Evaluate the fitted pipeline on held-out synthetic test telemetry.
        """
        findings = self.score(test_events)
        eval_count = len(findings)
        if eval_count == 0:
            return ModelEvaluationReport(
                model_name="CyberShield IsolationForest",
                algorithm="Isolation Forest (Scikit-learn)",
                training_sample_count=self.training_sample_size,
                evaluation_sample_count=0,
                contamination_rate=self.contamination,
                detected_anomalies_count=0,
                anomaly_rate=0.0,
                mean_anomaly_score=0.0,
                limitations=[
                    "Evaluation dataset was empty.",
                ],
            )

        anomaly_count = sum(1 for f in findings if f.is_anomaly)
        mean_score = float(np.mean([f.anomaly_score for f in findings]))
        anomaly_rate = round(anomaly_count / eval_count, 4)

        report = ModelEvaluationReport(
            model_name="CyberShield IsolationForest",
            algorithm="Isolation Forest (Scikit-learn)",
            training_sample_count=self.training_sample_size,
            evaluation_sample_count=eval_count,
            contamination_rate=self.contamination,
            detected_anomalies_count=anomaly_count,
            anomaly_rate=anomaly_rate,
            mean_anomaly_score=round(mean_score, 4),
            limitations=[
                "Unsupervised model: detects statistical deviations from training distribution, not confirmed malice.",
                "Sensitivity is governed by the contamination hyperparameter, which requires domain tuning.",
                "Evaluated on synthetic telemetry; performance may differ on enterprise production data distributions.",
                "Categorical encoding ignores unseen event types via handle_unknown='ignore'.",
            ],
        )
        return report

    # -----------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------

    def save(self, filepath: Union[str, Path]) -> None:
        """
        Persist the trained pipeline and preprocessors to disk using joblib.
        """
        if not self.is_fitted:
            raise RuntimeError("Cannot save an unfitted AnomalyDetectionPipeline.")

        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)

        artifact = {
            "model": self.model,
            "preprocessor": self.preprocessor,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "training_sample_size": self.training_sample_size,
            "saved_at": time.time(),
        }
        joblib.dump(artifact, target)

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> AnomalyDetectionPipeline:
        """
        Load a persisted AnomalyDetectionPipeline from disk.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Model artifact not found at {path}")

        artifact = joblib.load(path)
        pipeline = cls(
            n_estimators=artifact.get("n_estimators", 100),
            contamination=artifact.get("contamination", 0.08),
            random_state=artifact.get("random_state", 42),
        )
        pipeline.model = artifact["model"]
        pipeline.preprocessor = artifact["preprocessor"]
        pipeline.training_sample_size = artifact.get("training_sample_size", 0)
        pipeline.is_fitted = True
        return pipeline

    # -----------------------------------------------------------------
    # Explainability Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _identify_contributing_factors(
        row: Dict[str, Any], is_anomaly: bool, score: float
    ) -> List[str]:
        factors: List[str] = []
        if not is_anomaly and score < 0.5:
            factors.append("Behavioral metrics align closely with baseline training distribution.")
            return factors

        if row.get("is_failure") == 1:
            factors.append("Authentication or action failed.")
        if row.get("is_external_ip") == 1:
            factors.append(f"Connection initiated from non-private external IP: '{row.get('_source_ip')}'.")
        if row.get("is_privileged_user") == 1:
            factors.append(f"Privileged user identity '{row.get('_entity')}'.")
        if row.get("is_privileged_resource") == 1:
            factors.append("Access to privileged or sensitive system resource.")
        if row.get("log_payload_size", 0) > 8.0:
            factors.append(f"Elevated payload transfer volume (log-size: {row.get('log_payload_size'):.2f}).")
        if row.get("is_weekend") == 1:
            factors.append("Activity occurred during weekend hours.")

        if not factors:
            factors.append("Unusual multidimensional feature correlation detected by isolation trees.")

        return factors
