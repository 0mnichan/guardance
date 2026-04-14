"""
SVM-based device role classifier for Guardance.

Builds on the behavioral feature vector produced by :class:`DeviceProfile`
to train a scikit-learn SVM and infer device roles with confidence scores.

When scikit-learn is unavailable, the classifier gracefully falls back to
the rule-based :class:`ProtocolFingerprinter`.

IP2Vec embedding:
    A simplified IP2Vec approach is used where protocol usage patterns
    (the one-hot/count fields in the feature vector) act as the
    "embedding" — capturing behavioral similarity between devices.
    A full word2vec model over IP address sequences would require
    substantially more data than a single PCAP capture provides.

Confidence:
    Reported as the SVM decision function score normalised into [0, 1]
    via a sigmoid transform, capped at 0.99.
"""

from __future__ import annotations

import logging
import math
from typing import Any

from src.roles.fingerprint import FingerprintResult, ProtocolFingerprinter, ROLE_UNKNOWN
from src.roles.profiler import DeviceProfile

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sigmoid normalisation
# ---------------------------------------------------------------------------

def _sigmoid(x: float) -> float:
    """Sigmoid function mapping any real to (0, 1)."""
    return 1.0 / (1.0 + math.exp(-x))


# ---------------------------------------------------------------------------
# RoleClassifier
# ---------------------------------------------------------------------------

class RoleClassifier:
    """
    Trains an SVM classifier on labelled :class:`DeviceProfile` data and
    predicts device roles with confidence scores.

    Falls back to rule-based fingerprinting when sklearn is unavailable
    or when fewer than two labelled examples are available.

    Usage::

        classifier = RoleClassifier()
        # Optionally train on labelled profiles
        labelled = [(profile1, "plc"), (profile2, "hmi"), ...]
        classifier.fit(labelled)
        # Predict
        role, confidence = classifier.predict(profile)
    """

    def __init__(self) -> None:
        """Initialise with no trained model (falls back to fingerprinting)."""
        self._model: Any = None
        self._label_encoder: Any = None
        self._fingerprinter = ProtocolFingerprinter()
        self._is_trained = False

    def fit(self, labelled: list[tuple[DeviceProfile, str]]) -> None:
        """
        Train the SVM on a list of (profile, role_label) pairs.

        Requires scikit-learn.  If sklearn is not installed or there are
        fewer than two examples, training is silently skipped and the
        classifier will use fingerprinting as fallback.

        Args:
            labelled: List of (DeviceProfile, role_string) tuples.
        """
        if len(labelled) < 2:
            logger.warning("Not enough labelled data to train SVM (%d examples)", len(labelled))
            return

        try:
            from sklearn.preprocessing import LabelEncoder
            from sklearn.svm import SVC

            X = [p.to_feature_vector() for p, _ in labelled]
            y_raw = [label for _, label in labelled]

            le = LabelEncoder()
            y = le.fit_transform(y_raw)

            svm = SVC(kernel="rbf", probability=True, C=1.0, gamma="scale")
            svm.fit(X, y)

            self._model = svm
            self._label_encoder = le
            self._is_trained = True
            logger.info(
                "Trained SVM classifier on %d examples, %d classes",
                len(labelled),
                len(le.classes_),
            )
        except ImportError:
            logger.warning("scikit-learn not available — SVM training skipped")
        except Exception as exc:
            logger.error("SVM training failed: %s", exc)

    def predict(self, profile: DeviceProfile) -> tuple[str, float]:
        """
        Predict the device role for a given behavioral profile.

        If the SVM is trained, uses it with probability calibration.
        Otherwise falls back to protocol fingerprinting.

        Args:
            profile: A :class:`DeviceProfile` built from graph data.

        Returns:
            Tuple of (role_string, confidence_float) where confidence is
            in (0.0, 1.0].
        """
        if self._is_trained and self._model is not None:
            return self._predict_svm(profile)
        return self._predict_fingerprint(profile)

    def _predict_svm(self, profile: DeviceProfile) -> tuple[str, float]:
        """Use the trained SVM to predict role and confidence."""
        try:
            fv = [profile.to_feature_vector()]
            proba = self._model.predict_proba(fv)[0]
            best_idx = int(proba.argmax())
            confidence = float(proba[best_idx])
            role = self._label_encoder.inverse_transform([best_idx])[0]
            return role, min(confidence, 0.99)
        except Exception as exc:
            logger.error("SVM prediction failed: %s — falling back to fingerprint", exc)
            return self._predict_fingerprint(profile)

    def _predict_fingerprint(self, profile: DeviceProfile) -> tuple[str, float]:
        """Use rule-based fingerprinting to predict role and confidence."""
        observations = [
            (proto, next(iter(profile.ports), 0), None)
            for proto in profile.protocols
        ]
        if not observations:
            return ROLE_UNKNOWN, 0.0
        result: FingerprintResult = self._fingerprinter.infer(observations)
        return result.role, result.confidence


# ---------------------------------------------------------------------------
# Graph write-back
# ---------------------------------------------------------------------------

_UPDATE_DEVICE_ROLE = """
MATCH (d:Device {ip: $ip})
SET d.role                 = $role,
    d.inferred_purdue_level = $purdue_level,
    d.role_confidence      = $confidence
"""


def write_role_to_graph(
    session: Any,
    ip: str,
    role: str,
    confidence: float,
    purdue_level: int,
) -> None:
    """
    Write an inferred role back to the Device node in Neo4j.

    Args:
        session:      An active Neo4j session.
        ip:           Device IP address.
        role:         Inferred role string.
        confidence:   Confidence in the inference (0.0–1.0).
        purdue_level: Inferred Purdue level (0–5).
    """
    try:
        session.run(
            _UPDATE_DEVICE_ROLE,
            ip=ip,
            role=role,
            confidence=confidence,
            purdue_level=purdue_level,
        )
        logger.debug(
            "Wrote role to graph: %s → %s (%.2f, Level %d)",
            ip, role, confidence, purdue_level,
        )
    except Exception as exc:
        logger.error("Failed to write role for %s: %s", ip, exc)


# ---------------------------------------------------------------------------
# Batch inference runner
# ---------------------------------------------------------------------------

def run_role_inference(
    session: Any,
    classifier: RoleClassifier,
) -> list[dict]:
    """
    Run role inference across all Device nodes and write results back.

    Args:
        session:    An active Neo4j session.
        classifier: A :class:`RoleClassifier` instance (trained or fallback).

    Returns:
        List of dicts: ip, role, confidence, purdue_level.
    """
    from src.roles.profiler import GraphProfiler
    from src.ontology.auto_assign import infer_purdue_level

    profiler = GraphProfiler(None)  # driver not used when session passed in
    profiles = profiler.build_all_profiles(session)

    results = []
    for profile in profiles:
        # Skip devices that already have a manually-set role
        if profile.role and profile.role != ROLE_UNKNOWN:
            logger.debug("Skipping %s — already has role %s", profile.ip, profile.role)
            continue

        role, confidence = classifier.predict(profile)
        proto_port_pairs = [
            (proto, next(iter(profile.ports), 0)) for proto in profile.protocols
        ]
        purdue_level = infer_purdue_level(proto_port_pairs) if proto_port_pairs else 3

        write_role_to_graph(session, profile.ip, role, confidence, purdue_level)
        results.append({
            "ip": profile.ip,
            "role": role,
            "confidence": confidence,
            "purdue_level": purdue_level,
        })

    logger.info("Role inference complete: %d devices updated", len(results))
    return results
