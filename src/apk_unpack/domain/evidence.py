from __future__ import annotations

import copy
from typing import Any

from .jsonutil import canonical_json, sha256_text

CONFIDENCE_LEVELS = ("observed", "derived", "inferred")
AUTHORITY_LEVELS = (
    "shipped-artifact",
    "live-device",
    "controlled-replay",
    "historical-reference",
    "analyst-inference",
)

_PROVIDER_DEFAULT = {"id": "apk-unpack", "name": "APK Unpack Agents", "version": "0.1.0"}


def create_evidence(
    *,
    operation: str,
    normalized_result: dict[str, Any],
    subject: dict[str, Any] | None = None,
    provider: dict[str, Any] | None = None,
    predicate_type: str | None = None,
    parameters: dict[str, Any] | None = None,
    raw_result: dict[str, Any] | None = None,
    confidence: str = "observed",
    authority: str = "live-device",
    environment: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
    relationship_coverage: dict[str, Any] | None = None,
    locations: list[dict[str, Any]] | None = None,
    evidence_links: list[str] | None = None,
) -> dict[str, Any]:
    """Build one REA-shaped Evidence record with a content-addressed id.

    The identity deliberately excludes subject name/local_path so moving an
    artifact does not create a new identity. Everything else participates.
    """

    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError(f"unknown confidence: {confidence}")
    if authority not in AUTHORITY_LEVELS:
        raise ValueError(f"unknown authority: {authority}")

    subject_copy = copy.deepcopy(subject) if subject else None
    if isinstance(subject_copy, dict):
        subject_copy.pop("name", None)
        subject_copy.pop("local_path", None)

    body: dict[str, Any] = {
        "evidence_id": None,
        "subject": subject_copy,
        "provider": provider or dict(_PROVIDER_DEFAULT),
        "analysis_profile": None,
        "predicate_type": predicate_type or operation.replace("_", "."),
        "operation": operation,
        "parameters": parameters or {},
        "raw_result": raw_result,
        "normalized_result": normalized_result,
        "confidence": confidence,
        "authority": authority,
        "environment": environment,
        "limitations": limitations or [],
        "relationship_coverage": relationship_coverage,
        "locations": locations or [],
        "evidence_links": evidence_links or [],
    }
    semantic = {key: value for key, value in body.items() if key != "evidence_id"}
    body["evidence_id"] = "ev_" + sha256_text(canonical_json(semantic))
    return body


def evidence_digest(record: dict[str, Any]) -> str:
    semantic = {key: value for key, value in record.items() if key != "evidence_id"}
    return "ev_" + sha256_text(canonical_json(semantic))


def project_evidence(record: dict[str, Any]) -> dict[str, Any]:
    """Compact projection used when an evidence record is too large."""

    normalized = record.get("normalized_result") or {}
    return {
        "evidence_id": record.get("evidence_id"),
        "subject": record.get("subject"),
        "provider": record.get("provider"),
        "operation": record.get("operation"),
        "parameters": record.get("parameters"),
        "confidence": record.get("confidence"),
        "authority": record.get("authority"),
        "limitations": record.get("limitations"),
        "locations": record.get("locations"),
        "evidence_links": record.get("evidence_links"),
        "normalized_result_summary": {
            "keys": sorted(normalized.keys()) if isinstance(normalized, dict) else None,
            "size": len(canonical_json(normalized)) if isinstance(normalized, dict) else None,
        },
    }
