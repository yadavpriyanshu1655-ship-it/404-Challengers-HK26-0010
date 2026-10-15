"""
Unit and integration tests for CyberShield AI Machine-Learning Anomaly Detection.

Covers:
- Feature extraction and categorical encoding.
- Preprocessing fit on training data only (data leakage prevention).
- Model persistence and safe artifact reloading (joblib).
- Reproducibility guarantees via fixed random_state.
- Anomaly scoring and calibrated probability output in [0.0, 1.0].
- Held-out evaluation reporting actual metrics and limitations.
- Strict separation of ML findings from rule-based findings.
- Explicit non-malicious disclaimer verification.
- Invalid, missing, and edge-case telemetry handling.
"""

from pathlib import Path
import tempfile
import numpy as np
import pandas as pd
import pytest

from backend.ingestion import SecurityLogIngestion
from backend.ml.anomaly import AnomalyDetectionPipeline
from backend.ml.features import SecurityFeatureExtractor
from backend.models.alert import ThreatAlert
from backend.models.anomaly import AnomalyFinding, ModelEvaluationReport
from backend.models.event import SecurityEvent


@pytest.fixture
def training_events():
    """Load training baseline telemetry."""
    path = Path(__file__).resolve().parent.parent / "data" / "training_telemetry.csv"
    ingestion = SecurityLogIngestion()
    return ingestion.process_file(path).events


@pytest.fixture
def held_out_events():
    """Load held-out evaluation telemetry."""
    path = Path(__file__).resolve().parent.parent / "data" / "held_out_telemetry.csv"
    ingestion = SecurityLogIngestion()
    return ingestion.process_file(path).events


# =====================================================================
# 1. Feature Extraction & Preprocessing Tests
# =====================================================================

def test_feature_extraction_structure(training_events):
    """Verify feature extractor generates expected numerical and categorical dimensions."""
    extractor = SecurityFeatureExtractor()
    df = extractor.extract_features(training_events)

    assert isinstance(df, pd.DataFrame)
    assert len(df) == len(training_events)
    for col in extractor.NUMERIC_COLUMNS:
        assert col in df.columns
    for col in extractor.CATEGORICAL_COLUMNS:
        assert col in df.columns

    # Verify cyclical hour encoding bounds
    assert df["hour_sin"].between(-1.0, 1.0).all()
    assert df["hour_cos"].between(-1.0, 1.0).all()
    # Verify external IP detection
    assert set(df["is_external_ip"].unique()).issubset({0, 1})


def test_preprocessing_fitted_on_training_only(training_events, held_out_events):
    """
    Requirement Check: Avoid training/evaluation data leakage.
    Ensure preprocessor fits solely on training data and transforms test data.
    """
    extractor = SecurityFeatureExtractor()
    train_df = extractor.extract_features(training_events)
    test_df = extractor.extract_features(held_out_events)

    preprocessor = extractor.build_preprocessor()

    X_train_cols = train_df[extractor.NUMERIC_COLUMNS + extractor.CATEGORICAL_COLUMNS]
    X_test_cols = test_df[extractor.NUMERIC_COLUMNS + extractor.CATEGORICAL_COLUMNS]

    # Fit on training data only
    X_train_trans = preprocessor.fit_transform(X_train_cols)
    # Transform test data without re-fitting
    X_test_trans = preprocessor.transform(X_test_cols)

    assert X_train_trans.shape[0] == len(training_events)
    assert X_test_trans.shape[0] == len(held_out_events)
    assert X_train_trans.shape[1] == X_test_trans.shape[1]


# =====================================================================
# 2. Pipeline Training, Scoring & Inference Tests
# =====================================================================

def test_pipeline_fit_and_inference(training_events, held_out_events):
    """Verify end-to-end training and anomaly scoring."""
    pipeline = AnomalyDetectionPipeline(n_estimators=50, contamination=0.1, random_state=42)
    assert not pipeline.is_fitted

    pipeline.fit(training_events)
    assert pipeline.is_fitted
    assert pipeline.training_sample_size == len(training_events)

    findings = pipeline.score(held_out_events)
    assert len(findings) == len(held_out_events)

    for f in findings:
        assert isinstance(f, AnomalyFinding)
        assert f.finding_id.startswith("CS-ANOMALY-")
        assert 0.0 <= f.anomaly_score <= 1.0
        assert isinstance(f.is_anomaly, bool)
        assert len(f.contributing_factors) > 0


def test_anomalies_score_higher_than_normal(training_events, held_out_events):
    """Verify that clear outliers receive higher anomaly scores than conforming events."""
    pipeline = AnomalyDetectionPipeline(n_estimators=100, contamination=0.15, random_state=42)
    pipeline.fit(training_events)

    findings = pipeline.score(held_out_events)

    # First event in held-out is normal daytime login by alice
    normal_finding = findings[0]
    # Late event in held-out is root exfiltration of /etc/shadow at 03:00 AM from external IP
    outlier_finding = next(f for f in findings if f.entity == "root")

    assert outlier_finding.anomaly_score > normal_finding.anomaly_score
    assert outlier_finding.is_anomaly is True


# =====================================================================
# 3. Persistence and Safe Reload Tests
# =====================================================================

def test_model_persistence_and_reload(training_events, held_out_events):
    """Verify that saving and reloading preserves exact predictions and scores."""
    pipeline = AnomalyDetectionPipeline(n_estimators=50, contamination=0.1, random_state=42)
    pipeline.fit(training_events)

    original_findings = pipeline.score(held_out_events)

    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = Path(tmpdir) / "anomaly_model.joblib"
        pipeline.save(model_path)
        assert model_path.exists()

        loaded_pipeline = AnomalyDetectionPipeline.load(model_path)
        assert loaded_pipeline.is_fitted
        assert loaded_pipeline.training_sample_size == pipeline.training_sample_size

        reloaded_findings = loaded_pipeline.score(held_out_events)

        assert len(reloaded_findings) == len(original_findings)
        for orig, reloaded in zip(original_findings, reloaded_findings):
            assert orig.is_anomaly == reloaded.is_anomaly
            assert np.isclose(orig.anomaly_score, reloaded.anomaly_score, atol=1e-4)
            assert np.isclose(orig.raw_score, reloaded.raw_score, atol=1e-4)


# =====================================================================
# 4. Reproducibility Tests
# =====================================================================

def test_reproducibility_with_fixed_seed(training_events, held_out_events):
    """Verify that identical random_state produces identical anomaly scores."""
    pipeline1 = AnomalyDetectionPipeline(n_estimators=50, contamination=0.1, random_state=42)
    pipeline1.fit(training_events)
    scores1 = [f.anomaly_score for f in pipeline1.score(held_out_events)]

    pipeline2 = AnomalyDetectionPipeline(n_estimators=50, contamination=0.1, random_state=42)
    pipeline2.fit(training_events)
    scores2 = [f.anomaly_score for f in pipeline2.score(held_out_events)]

    assert np.allclose(scores1, scores2)


# =====================================================================
# 5. Held-Out Evaluation Report & Limitations
# =====================================================================

def test_held_out_evaluation_report(training_events, held_out_events):
    """Verify evaluation metrics generation and documented limitations."""
    pipeline = AnomalyDetectionPipeline(n_estimators=50, contamination=0.1, random_state=42)
    pipeline.fit(training_events)

    report = pipeline.evaluate_held_out(held_out_events)
    assert isinstance(report, ModelEvaluationReport)
    assert report.training_sample_count == len(training_events)
    assert report.evaluation_sample_count == len(held_out_events)
    assert report.detected_anomalies_count >= 1
    assert 0.0 <= report.anomaly_rate <= 1.0
    assert 0.0 <= report.mean_anomaly_score <= 1.0
    assert len(report.limitations) >= 3


# =====================================================================
# 6. Separation from Rule-Based Findings & Non-Maliciousness
# =====================================================================

def test_separation_from_rule_findings(training_events, held_out_events):
    """
    Requirement Check:
    1. Keep ML findings separate from rule-based findings.
    2. Do not claim an anomaly is necessarily malicious.
    """
    pipeline = AnomalyDetectionPipeline(n_estimators=50, contamination=0.1, random_state=42)
    pipeline.fit(training_events)

    findings = pipeline.score(held_out_events)
    for f in findings:
        assert isinstance(f, AnomalyFinding)
        assert not isinstance(f, ThreatAlert)
        assert not hasattr(f, "rule_name")
        assert not hasattr(f, "mitre_technique")
        # Verify explicit disclaimer
        assert "does not necessarily indicate malicious intent" in f.disclaimer.lower()


# =====================================================================
# 7. Edge Cases & Error Handling
# =====================================================================

def test_fit_on_empty_raises():
    """Fitting on empty telemetry raises ValueError."""
    pipeline = AnomalyDetectionPipeline()
    with pytest.raises(ValueError):
        pipeline.fit([])


def test_score_unfitted_raises(held_out_events):
    """Scoring prior to fitting raises RuntimeError."""
    pipeline = AnomalyDetectionPipeline()
    with pytest.raises(RuntimeError):
        pipeline.score(held_out_events)


def test_score_empty_returns_empty(training_events):
    """Scoring an empty list returns empty findings."""
    pipeline = AnomalyDetectionPipeline(n_estimators=20)
    pipeline.fit(training_events)
    assert pipeline.score([]) == []


def test_corrupt_payload_size_handled(training_events):
    """Event with non-numeric or negative payload handled without crashing."""
    pipeline = AnomalyDetectionPipeline(n_estimators=20)
    pipeline.fit(training_events)

    corrupt_event = {
        "timestamp": "2026-10-15T12:00:00Z",
        "source_ip": "10.0.0.5",
        "username": "tester",
        "event_type": "custom_event",
        "status": "success",
        "payload_size": "INVALID_NUMBER",
    }
    findings = pipeline.score([corrupt_event])
    assert len(findings) == 1
    assert findings[0].finding_id.startswith("CS-ANOMALY-")
