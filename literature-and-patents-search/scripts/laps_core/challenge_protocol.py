from __future__ import annotations

"""Bound verification request/response protocol shared by search and download.

The module intentionally has no dependency on either CLI.  It provides the
cryptographic binding, strict response-pointer handling and validation needed
to keep an asynchronous browser response from being replayed for another
record, source, cursor or resume URL.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit, urlunsplit

from .network_safety import outbound_http_url_allowed


VERIFICATION_REQUEST_SCHEMA = "laps_verification_request_v2"
VERIFICATION_RESPONSE_SCHEMA = "laps_verification_response_v2"
VERIFICATION_RESPONSE_POINTER_SCHEMA = "laps_verification_response_pointer_v2"
VERIFICATION_PROTOCOL_VERSION = 2
VERIFICATION_EVENTS = frozenset(
    {"search_challenge", "auth_challenge", "security_challenge"}
)
VERIFICATION_ACTIONS = frozenset(
    {"retry", "skip", "cooldown", "manual_pending", "unhandled"}
)
PRODUCERS = frozenset({"search", "download"})
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_EVENT_ID_LENGTH = 160

BINDING_FIELDS = (
    "producer",
    "run_id",
    "search_job_id",
    "auth_check_id",
    "record_id",
    "record_type",
    "source",
    "planned_channel",
    "auth_state_scope",
    "auth_mode",
    "principal_digest",
    "access_mode",
    "query_variant",
    "query_digest",
    "cursor_digest",
    "candidate_id",
    "challenge_url_digest",
    "resume_url_digest",
)

EVIDENCE_FIELDS = (
    "candidate_urls",
    "final_url",
    "storage_state_path",
    "storage_state_sha256",
    "external_browser_session",
    "browser_transport",
    "external_session_attestation",
    "capability_attestation",
    "sanitized_search_snapshot_paths",
    "challenge_resolution",
)


class VerificationReplayStore(Protocol):
    def mark_verification_responded(
        self,
        request: Mapping[str, Any],
        *,
        response_sha256: str,
        responded_at: str,
        reason_code: str,
    ) -> tuple[bool, str]: ...

    def consume_verification_response(
        self,
        request: Mapping[str, Any],
        *,
        response_sha256: str,
        responded_at: str,
        final_reason_code: str,
    ) -> tuple[bool, str]: ...

    def mark_verification_rejected(
        self,
        request: Mapping[str, Any],
        reason_code: str,
        *,
        response_sha256: str = "",
        responded_at: str = "",
    ) -> tuple[bool, str]: ...

    def mark_verification_expired(
        self,
        request: Mapping[str, Any],
        reason_code: str = "challenge_response_expired",
    ) -> tuple[bool, str]: ...


@dataclass(frozen=True)
class ProtocolValidation:
    valid: bool
    reason_code: str
    payload: dict[str, Any] | None = None
    response_sha256: str = ""


@dataclass(frozen=True)
class ResponseReadResult:
    payload: dict[str, Any] | None
    reason_code: str
    path: Path | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verification_file_audit_evidence(
    path: str | Path | None,
) -> tuple[str, str]:
    """Return a byte digest and claimed response time without trusting a file.

    Waiters use this only when the strict reader has already rejected a file.
    Symlinks are never followed, oversized/non-JSON data is still hashed for
    audit, and an unparseable timestamp remains empty rather than fabricated.
    """

    if path is None:
        return "", ""
    selected = Path(path)
    try:
        if selected.is_symlink() or not selected.is_file():
            return "", ""
        size = selected.stat().st_size
        if size <= 0 or size > MAX_RESPONSE_BYTES:
            return "", ""
        raw = selected.read_bytes()
    except OSError:
        return "", ""
    if len(raw) <= 0 or len(raw) > MAX_RESPONSE_BYTES:
        return "", ""
    response_sha = sha256_bytes(raw)
    try:
        loaded = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError):
        return response_sha, ""
    responded_at = (
        str(loaded.get("responded_at") or "")
        if isinstance(loaded, Mapping)
        else ""
    )
    return response_sha, responded_at


def value_digest(value: object) -> str:
    """Hash a binding value without returning the value itself."""

    return sha256_bytes(str(value or "").encode("utf-8", "surrogatepass"))


def normalized_url_digest(url: object) -> str:
    """Return a digest of a normalized URL while never persisting the URL."""

    text = str(url or "").strip()
    if not text:
        return ""
    try:
        split = urlsplit(text)
        if split.scheme.casefold() not in {"http", "https"} or not split.hostname:
            return value_digest(text)
        host = split.hostname.casefold().rstrip(".")
        port = split.port
        default_port = (split.scheme.casefold() == "http" and port == 80) or (
            split.scheme.casefold() == "https" and port == 443
        )
        netloc = host if port is None or default_port else f"{host}:{port}"
        normalized = urlunsplit(
            (
                split.scheme.casefold(),
                netloc,
                split.path or "/",
                split.query,
                "",
            )
        )
    except (TypeError, ValueError):
        normalized = text
    return value_digest(normalized)


def _json_object(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    loaded = json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    if not isinstance(loaded, dict):  # pragma: no cover - guarded by Mapping
        raise TypeError("expected JSON object")
    return loaded


def normalize_binding(binding: Mapping[str, Any]) -> dict[str, str]:
    normalized = {field: str(binding.get(field) or "").strip() for field in BINDING_FIELDS}
    normalized["producer"] = normalized["producer"].casefold()
    normalized["record_type"] = normalized["record_type"].casefold()
    normalized["auth_mode"] = normalized["auth_mode"].casefold()
    normalized["access_mode"] = normalized["access_mode"].casefold()
    return normalized


def binding_digest(binding: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(normalize_binding(binding)))


def _request_digest_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": str(request.get("schema") or ""),
        "event_id": str(request.get("event_id") or ""),
        "event": str(request.get("event") or ""),
        "created_at": str(request.get("created_at") or ""),
        "expires_at": str(request.get("expires_at") or ""),
        "request_nonce": str(request.get("request_nonce") or ""),
        "binding": normalize_binding(
            request.get("binding") if isinstance(request.get("binding"), Mapping) else {}
        ),
        "binding_digest": str(request.get("binding_digest") or ""),
    }


def request_digest(request: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(_request_digest_payload(request)))


def _valid_event_id(value: object) -> bool:
    text = str(value or "")
    return bool(
        text
        and len(text) <= MAX_EVENT_ID_LENGTH
        and text not in {".", ".."}
        and all(character.isalnum() or character in "-_" for character in text)
    )


def _validate_binding_subject(event: str, binding: Mapping[str, str]) -> str:
    producer = binding["producer"]
    if producer not in PRODUCERS:
        return "challenge_request_producer_invalid"
    if event == "search_challenge" and producer != "search":
        return "challenge_request_producer_invalid"
    if producer == "search" and not (
        binding["search_job_id"] or binding["auth_check_id"]
    ):
        return "challenge_request_subject_missing"
    if producer == "download" and not binding["run_id"]:
        return "challenge_request_subject_missing"
    if producer == "download" and not (
        binding["record_id"] or binding["auth_check_id"]
    ):
        return "challenge_request_subject_missing"
    if not (binding["source"] or binding["planned_channel"]):
        return "challenge_request_source_missing"
    return "challenge_request_valid"


def build_verification_request(
    *,
    event: str,
    event_id: str,
    producer: str,
    binding: Mapping[str, Any],
    ttl_seconds: int,
    public_fields: Mapping[str, Any] | None = None,
    created_at: str | None = None,
    request_nonce: str | None = None,
    challenge_url: str = "",
    resume_url: str = "",
) -> dict[str, Any]:
    """Build a v2 request while retaining safe legacy top-level fields.

    ``public_fields`` is deliberately outside the immutable digest envelope.
    This permits a trusted bundled hook to receive legacy runtime-only fields
    (including brokered credentials) without putting secrets into the binding.
    All authorization-relevant identity belongs in ``binding``.
    """

    selected_event = str(event or "").strip()
    if selected_event not in VERIFICATION_EVENTS:
        raise ValueError("challenge_request_event_invalid")
    if not _valid_event_id(event_id):
        raise ValueError("challenge_request_event_id_invalid")
    if int(ttl_seconds) <= 0:
        raise ValueError("challenge_request_ttl_invalid")
    created = _parse_utc(created_at or utc_now())
    if created is None:
        raise ValueError("challenge_request_timestamp_invalid")
    expires = created + timedelta(seconds=int(ttl_seconds))
    selected_binding = dict(binding)
    selected_binding["producer"] = producer
    if challenge_url:
        selected_binding["challenge_url_digest"] = normalized_url_digest(challenge_url)
    if resume_url:
        selected_binding["resume_url_digest"] = normalized_url_digest(resume_url)
    normalized_binding = normalize_binding(selected_binding)
    subject_reason = _validate_binding_subject(selected_event, normalized_binding)
    if subject_reason != "challenge_request_valid":
        raise ValueError(subject_reason)

    request = _json_object(public_fields)
    request.update(
        {
            "schema": VERIFICATION_REQUEST_SCHEMA,
            "event_id": event_id,
            "event": selected_event,
            "created_at": created.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": expires.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "request_nonce": request_nonce or secrets.token_urlsafe(24),
            "binding": normalized_binding,
        }
    )
    request["binding_digest"] = binding_digest(normalized_binding)
    request["request_digest"] = request_digest(request)
    return request


def validate_verification_request(
    request: Mapping[str, Any],
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> ProtocolValidation:
    if request.get("schema") != VERIFICATION_REQUEST_SCHEMA:
        return ProtocolValidation(False, "challenge_request_schema_invalid")
    event_id = str(request.get("event_id") or "")
    if not _valid_event_id(event_id):
        return ProtocolValidation(False, "challenge_request_event_id_invalid")
    event = str(request.get("event") or "")
    if event not in VERIFICATION_EVENTS:
        return ProtocolValidation(False, "challenge_request_event_invalid")
    binding_value = request.get("binding")
    if not isinstance(binding_value, Mapping):
        return ProtocolValidation(False, "challenge_request_binding_invalid")
    normalized = normalize_binding(binding_value)
    if dict(binding_value) != normalized:
        return ProtocolValidation(False, "challenge_request_binding_invalid")
    reason = _validate_binding_subject(event, normalized)
    if reason != "challenge_request_valid":
        return ProtocolValidation(False, reason)
    expected_binding = binding_digest(normalized)
    if not hmac.compare_digest(
        str(request.get("binding_digest") or ""), expected_binding
    ):
        return ProtocolValidation(False, "challenge_request_binding_digest_invalid")
    expected_request = request_digest(request)
    if not hmac.compare_digest(
        str(request.get("request_digest") or ""), expected_request
    ):
        return ProtocolValidation(False, "challenge_request_digest_invalid")
    created = _parse_utc(request.get("created_at"))
    expires = _parse_utc(request.get("expires_at"))
    if created is None or expires is None or expires <= created:
        return ProtocolValidation(False, "challenge_request_timestamp_invalid")
    selected_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if created > selected_now + timedelta(minutes=5):
        return ProtocolValidation(False, "challenge_request_timestamp_in_future")
    if not allow_expired and expires < selected_now:
        return ProtocolValidation(False, "challenge_response_expired")
    return ProtocolValidation(True, "challenge_request_valid", dict(request))


def _normalized_evidence(evidence: Mapping[str, Any] | None) -> dict[str, Any]:
    source = evidence or {}
    urls = source.get("candidate_urls") or []
    if isinstance(urls, str):
        urls = [urls]
    snapshots = source.get("sanitized_search_snapshot_paths") or []
    if isinstance(snapshots, str):
        snapshots = [snapshots]
    return {
        "candidate_urls": [str(value) for value in urls if str(value).strip()],
        "final_url": str(source.get("final_url") or "").strip(),
        "storage_state_path": str(source.get("storage_state_path") or "").strip(),
        "storage_state_sha256": str(source.get("storage_state_sha256") or "").strip().casefold(),
        "external_browser_session": source.get("external_browser_session") is True,
        "browser_transport": str(source.get("browser_transport") or "").strip(),
        "external_session_attestation": _json_object(
            source.get("external_session_attestation")
            if isinstance(source.get("external_session_attestation"), Mapping)
            else None
        ),
        "capability_attestation": _json_object(
            source.get("capability_attestation")
            if isinstance(source.get("capability_attestation"), Mapping)
            else None
        ),
        "sanitized_search_snapshot_paths": [
            str(value) for value in snapshots if str(value).strip()
        ],
        "challenge_resolution": _json_object(
            source.get("challenge_resolution")
            if isinstance(source.get("challenge_resolution"), Mapping)
            else None
        ),
    }


def build_verification_response(
    request: Mapping[str, Any],
    *,
    action: str,
    reason_code: str = "",
    category: str = "",
    retryable: bool = False,
    retry_at: str = "",
    evidence: Mapping[str, Any] | None = None,
    responded_at: str | None = None,
) -> dict[str, Any]:
    request_validation = validate_verification_request(request, allow_expired=True)
    if not request_validation.valid:
        raise ValueError(request_validation.reason_code)
    normalized_action = str(action or "").strip().casefold()
    if normalized_action not in VERIFICATION_ACTIONS:
        raise ValueError("challenge_response_action_invalid")
    return {
        "schema": VERIFICATION_RESPONSE_SCHEMA,
        "event_id": str(request.get("event_id") or ""),
        "request_digest": str(request.get("request_digest") or ""),
        "binding_digest": str(request.get("binding_digest") or ""),
        "action": normalized_action,
        "reason_code": str(reason_code or "").strip(),
        "category": str(category or "").strip(),
        "retryable": bool(retryable),
        "retry_at": str(retry_at or "").strip(),
        "responded_at": responded_at or utc_now(),
        "evidence": _normalized_evidence(evidence),
    }


def _contained_file(
    path_value: str,
    roots: Sequence[str | Path],
    *,
    expected_sha256: str = "",
) -> tuple[bool, str]:
    if not path_value:
        return False, "challenge_evidence_path_missing"
    raw = Path(path_value).expanduser()
    try:
        if raw.is_symlink():
            return False, "challenge_evidence_symlink_forbidden"
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError):
        return False, "challenge_evidence_path_invalid"
    if not resolved.is_file():
        return False, "challenge_evidence_path_invalid"
    allowed = False
    for root_value in roots:
        try:
            resolved.relative_to(Path(root_value).expanduser().resolve(strict=True))
            allowed = True
            break
        except (OSError, RuntimeError, ValueError):
            continue
    if not allowed:
        return False, "challenge_evidence_path_outside_controlled_root"
    if expected_sha256:
        if len(expected_sha256) != 64:
            return False, "challenge_evidence_digest_invalid"
        try:
            actual = sha256_file(resolved)
        except OSError:
            return False, "challenge_evidence_path_invalid"
        if not hmac.compare_digest(actual, expected_sha256.casefold()):
            return False, "challenge_evidence_digest_mismatch"
    return True, "challenge_evidence_path_valid"


def _default_url_validator(url: str) -> bool:
    return outbound_http_url_allowed(url)


def _validate_action_evidence(
    event: str,
    action: str,
    evidence: Mapping[str, Any],
) -> str:
    if action == "cooldown":
        return "challenge_response_valid"
    if action != "retry":
        return "challenge_response_valid"
    has_state = bool(
        evidence.get("storage_state_path") and evidence.get("storage_state_sha256")
    )
    has_external_session = bool(
        evidence.get("external_browser_session") is True
        and isinstance(evidence.get("external_session_attestation"), Mapping)
        and evidence.get("external_session_attestation")
    )
    if event == "auth_challenge" and not (has_state or has_external_session):
        return "challenge_response_auth_evidence_missing"
    if event == "search_challenge" and not (
        has_state or evidence.get("sanitized_search_snapshot_paths")
    ):
        return "challenge_response_search_evidence_missing"
    if event == "security_challenge":
        resolution = evidence.get("challenge_resolution")
        explicit_resolution = isinstance(resolution, Mapping) and any(
            resolution.get(key) is True
            for key in (
                "pdf_anchor_observed",
                "pdf_response_captured",
                "candidate_response_observed",
            )
        )
        if not (evidence.get("candidate_urls") or explicit_resolution):
            return "challenge_response_security_evidence_missing"
    return "challenge_response_valid"


def _validate_capability_attestation(
    evidence: Mapping[str, Any],
) -> str:
    attestation = evidence.get("capability_attestation")
    external = evidence.get("external_browser_session") is True
    if not attestation:
        return (
            "challenge_response_capability_missing"
            if external
            else "challenge_response_valid"
        )
    if not isinstance(attestation, Mapping) or not (
        attestation.get("ordinary_chrome_extension_connected") is True
        and attestation.get("full_cdp_access") is True
        and str(attestation.get("readonly_cdp_probe_method") or "")
        == "Page.getFrameTree"
        and attestation.get("readonly_cdp_probe_succeeded") is True
    ):
        return "challenge_response_capability_invalid"
    return "challenge_response_valid"


def _validate_external_session_attestation(
    request: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> str:
    if evidence.get("external_browser_session") is not True:
        return "challenge_response_valid"
    if str(evidence.get("browser_transport") or "") != "ordinary_chrome_cdp":
        return "challenge_response_external_session_transport_invalid"
    attestation = evidence.get("external_session_attestation")
    if not isinstance(attestation, Mapping):
        return "challenge_response_external_session_attestation_invalid"
    binding = request.get("binding")
    if not isinstance(binding, Mapping):
        return "challenge_response_external_session_attestation_invalid"
    expected_source = str(
        binding.get("source") or binding.get("planned_channel") or ""
    )
    expected_scope = str(binding.get("auth_state_scope") or "")
    if (
        attestation.get("schema")
        != "laps_ordinary_chrome_session_attestation_v1"
        or str(attestation.get("event_id") or "")
        != str(request.get("event_id") or "")
        or (
            expected_source
            and str(attestation.get("source") or "") != expected_source
        )
        or (
            expected_scope
            and str(attestation.get("auth_state_scope") or "")
            != expected_scope
        )
        or not str(attestation.get("institution_identity_digest") or "")
    ):
        return "challenge_response_external_session_attestation_invalid"
    event = str(request.get("event") or "")
    if event == "auth_challenge" and attestation.get("authenticated") is not True:
        return "challenge_response_external_session_attestation_invalid"
    if event == "search_challenge" and not (
        attestation.get("authenticated") is True
        or attestation.get("page_access_confirmed") is True
    ):
        return "challenge_response_external_session_attestation_invalid"
    return "challenge_response_valid"


def _validate_challenge_action_attestation(
    request: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> str:
    authorization = request.get("challenge_action_authorization")
    legacy_authorization = request.get("challenge_action_confirmation")
    contract = (
        authorization
        if isinstance(authorization, Mapping)
        else legacy_authorization
        if isinstance(legacy_authorization, Mapping)
        else {}
    )
    if contract.get("required") is not True:
        return "challenge_response_valid"
    resolution = evidence.get("challenge_resolution")
    if not isinstance(resolution, Mapping):
        return "challenge_response_action_attestation_missing"
    if (
        str(resolution.get("event_id") or "")
        != str(contract.get("event_id") or "")
        or str(resolution.get("challenge_fingerprint") or "")
        != str(contract.get("challenge_fingerprint") or "")
    ):
        return "challenge_response_action_attestation_unbound"
    actor = str(resolution.get("resolved_by") or "").strip().casefold()
    if actor in {
        "authorized_user",
        "page_progress_without_control_action",
        "already_resolved_before_control",
    }:
        return "challenge_response_valid"
    if actor not in {"codex_chrome_extension", "codex_computer_use"}:
        return "challenge_response_action_actor_invalid"
    if int(resolution.get("action_count") or 0) != 1:
        return "challenge_response_action_count_invalid"
    if isinstance(authorization, Mapping):
        attestation = resolution.get("action_attestation")
        if not isinstance(attestation, Mapping) or not (
            attestation.get("schema")
            == "laps_codex_challenge_action_attestation_v1"
            and attestation.get("authorization_source")
            == "run_preauthorization"
            and attestation.get("target_url_attested") is True
            and attestation.get("unique_visible_target") is True
            and attestation.get("page_progress_observed") is True
            and str(attestation.get("action_type") or "").casefold()
            in {"click", "drag"}
            and str(attestation.get("event_id") or "")
            == str(contract.get("event_id") or "")
            and str(attestation.get("challenge_fingerprint") or "")
            == str(contract.get("challenge_fingerprint") or "")
        ):
            return "challenge_response_action_attestation_invalid"
    else:
        confirmation = resolution.get("challenge_action_confirmation")
        if not isinstance(confirmation, Mapping) or not (
            confirmation.get("schema")
            == "laps_codex_challenge_action_confirmation_v1"
            and confirmation.get("decision") == "allow"
            and confirmation.get("confirmed_for_current_event") is True
            and str(confirmation.get("event_id") or "")
            == str(contract.get("event_id") or "")
            and str(confirmation.get("challenge_fingerprint") or "")
            == str(contract.get("challenge_fingerprint") or "")
        ):
            return "challenge_response_action_attestation_invalid"
    return "challenge_response_valid"


def validate_verification_response(
    request: Mapping[str, Any],
    response: object,
    *,
    controlled_roots: Sequence[str | Path] = (),
    url_validator: Callable[[str], bool] | None = None,
    replay_store: VerificationReplayStore | None = None,
    consume: bool = True,
    now: datetime | None = None,
) -> ProtocolValidation:
    """Validate and, when requested, consume one event-bound response.

    The response is first treated as untrusted JSON.  Ledger rejection is
    best-effort for invalid input, but terminal rows are immutable in the
    authority store.  A valid response is durably recorded as ``responded``
    before the separate consume transition, so a crash between the two can be
    audited and safely completed with the exact same response.
    """

    response_sha = ""
    responded_at = ""

    def audit_failure(reason_code: str) -> None:
        if replay_store is None or not isinstance(request, Mapping):
            return
        try:
            if reason_code == "challenge_response_expired":
                marker = getattr(replay_store, "mark_verification_expired", None)
                if callable(marker):
                    marker(request, reason_code)
                return
            marker = getattr(replay_store, "mark_verification_rejected", None)
            if callable(marker):
                marker(
                    request,
                    reason_code,
                    response_sha256=response_sha,
                    responded_at=responded_at,
                )
        except Exception:
            # Malformed external input must never turn validation into an
            # exception path. Store/I/O health is checked separately by the
            # callers that create the shared authority.
            return

    def rejected(reason_code: str) -> ProtocolValidation:
        audit_failure(reason_code)
        return ProtocolValidation(False, reason_code, response_sha256=response_sha)

    # Step 1: the response must be a bounded, canonically serializable JSON
    # object before any field, digest, path or URL is inspected.
    if not isinstance(response, Mapping):
        return rejected("challenge_response_json_invalid")
    try:
        response_object = dict(response)
        response_bytes = canonical_json_bytes(response_object)
    except (TypeError, ValueError, OverflowError):
        return rejected("challenge_response_json_invalid")
    response_sha = sha256_bytes(response_bytes)
    responded_at = str(response_object.get("responded_at") or "")
    if len(response_bytes) > MAX_RESPONSE_BYTES:
        return rejected("challenge_response_too_large")

    if not isinstance(request, Mapping):
        return rejected("challenge_request_schema_invalid")
    try:
        request_validation = validate_verification_request(request, now=now)
    except (TypeError, ValueError, OverflowError):
        return rejected("challenge_request_schema_invalid")
    if not request_validation.valid:
        return rejected(request_validation.reason_code)
    if response_object.get("schema") != VERIFICATION_RESPONSE_SCHEMA:
        return rejected("challenge_response_unbound")
    event_id = str(request.get("event_id") or "")
    if str(response_object.get("event_id") or "") != event_id:
        return rejected("challenge_response_unbound")
    for field in ("request_digest", "binding_digest"):
        if not hmac.compare_digest(
            str(response_object.get(field) or ""), str(request.get(field) or "")
        ):
            return rejected("challenge_response_unbound")
    action = str(response_object.get("action") or "").strip().casefold()
    if action not in VERIFICATION_ACTIONS:
        return rejected("challenge_response_action_invalid")
    responded = _parse_utc(response_object.get("responded_at"))
    created = _parse_utc(request.get("created_at"))
    expires = _parse_utc(request.get("expires_at"))
    selected_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if responded is None or created is None or expires is None:
        return rejected("challenge_response_timestamp_invalid")
    if (
        responded < created - timedelta(minutes=5)
        or responded > selected_now + timedelta(minutes=5)
    ):
        return rejected("challenge_response_timestamp_invalid")
    if responded > expires or selected_now > expires:
        return rejected("challenge_response_expired")
    retry_at = str(response_object.get("retry_at") or "").strip()
    if action == "cooldown":
        parsed_retry = _parse_utc(retry_at)
        if parsed_retry is None or parsed_retry <= selected_now:
            return rejected("challenge_response_retry_at_invalid")

    evidence_value = response_object.get("evidence")
    if not isinstance(evidence_value, Mapping):
        return rejected("challenge_response_evidence_invalid")
    normalized_evidence = _normalized_evidence(evidence_value)
    if dict(evidence_value) != normalized_evidence:
        return rejected("challenge_response_evidence_invalid")
    evidence_reason = _validate_action_evidence(
        str(request.get("event") or ""), action, normalized_evidence
    )
    if evidence_reason != "challenge_response_valid":
        return rejected(evidence_reason)

    if normalized_evidence["storage_state_path"]:
        valid, reason = _contained_file(
            normalized_evidence["storage_state_path"],
            controlled_roots,
            expected_sha256=normalized_evidence["storage_state_sha256"],
        )
        if not valid:
            return rejected(reason)
    for snapshot in normalized_evidence["sanitized_search_snapshot_paths"]:
        valid, reason = _contained_file(snapshot, controlled_roots)
        if not valid:
            return rejected(reason)

    for attestation_reason in (
        _validate_external_session_attestation(request, normalized_evidence),
        _validate_capability_attestation(normalized_evidence),
        _validate_challenge_action_attestation(request, normalized_evidence),
    ):
        if attestation_reason != "challenge_response_valid":
            return rejected(attestation_reason)

    selected_url_validator = url_validator or _default_url_validator
    for candidate in (
        *normalized_evidence["candidate_urls"],
        normalized_evidence["final_url"],
    ):
        if candidate:
            try:
                allowed = bool(selected_url_validator(candidate))
            except Exception:
                allowed = False
            if not allowed:
                return rejected("challenge_response_url_unsafe")

    # skip/unhandled evidence is retained for audit but explicitly neutralized
    # in the payload returned to callers so that it cannot be executed.
    normalized_response = response_object
    normalized_response["action"] = action
    normalized_response["evidence"] = normalized_evidence
    if action in {"skip", "unhandled"}:
        normalized_response["evidence"] = _normalized_evidence(None)
    if replay_store is not None and consume:
        final_reason = str(
            response_object.get("reason_code") or "challenge_response_valid"
        )
        marker = getattr(replay_store, "mark_verification_responded", None)
        if callable(marker):
            recorded, reason = marker(
                request,
                response_sha256=response_sha,
                responded_at=responded_at,
                reason_code=final_reason,
            )
            if not recorded:
                return ProtocolValidation(
                    False, reason, response_sha256=response_sha
                )
        consumed, reason = replay_store.consume_verification_response(
            request,
            response_sha256=response_sha,
            responded_at=responded_at,
            final_reason_code=final_reason,
        )
        if not consumed:
            return ProtocolValidation(False, reason, response_sha256=response_sha)
    return ProtocolValidation(
        True,
        "challenge_response_valid",
        normalized_response,
        response_sha,
    )


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def atomic_write_json(path: str | Path, payload: Mapping[str, Any]) -> Path:
    selected = Path(path)
    _atomic_write_bytes(selected, canonical_json_bytes(dict(payload)) + b"\n")
    return selected


def build_response_pointer(
    request: Mapping[str, Any],
    response_path: str | Path,
    *,
    response_sha256: str | None = None,
) -> dict[str, Any]:
    validation = validate_verification_request(request, allow_expired=True)
    if not validation.valid:
        raise ValueError(validation.reason_code)
    selected = Path(response_path)
    expected_name = f"{request['event_id']}.json"
    if selected.name != expected_name:
        raise ValueError("challenge_response_pointer_file_invalid")
    digest = response_sha256 or sha256_file(selected)
    return {
        "schema": VERIFICATION_RESPONSE_POINTER_SCHEMA,
        "event_id": str(request.get("event_id") or ""),
        "request_digest": str(request.get("request_digest") or ""),
        "response_file": expected_name,
        "response_sha256": digest,
        "updated_at": utc_now(),
    }


def write_verification_response_atomic(
    response_root: str | Path,
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> tuple[Path, Path]:
    """Publish an event response first and ``latest.json`` pointer second."""

    request_validation = validate_verification_request(request, allow_expired=True)
    if not request_validation.valid:
        raise ValueError(request_validation.reason_code)
    if response.get("schema") != VERIFICATION_RESPONSE_SCHEMA:
        raise ValueError("challenge_response_schema_invalid")
    if str(response.get("event_id") or "") != str(request.get("event_id") or ""):
        raise ValueError("challenge_response_unbound")
    if not hmac.compare_digest(
        str(response.get("request_digest") or ""),
        str(request.get("request_digest") or ""),
    ) or not hmac.compare_digest(
        str(response.get("binding_digest") or ""),
        str(request.get("binding_digest") or ""),
    ):
        raise ValueError("challenge_response_unbound")
    root = Path(response_root)
    root.mkdir(parents=True, exist_ok=True)
    response_path = root / f"{request['event_id']}.json"
    response_bytes = canonical_json_bytes(dict(response)) + b"\n"
    _atomic_write_bytes(response_path, response_bytes)
    response_sha = sha256_bytes(response_bytes)
    pointer = build_response_pointer(
        request, response_path, response_sha256=response_sha
    )
    pointer_path = root / "latest.json"
    atomic_write_json(pointer_path, pointer)
    return response_path, pointer_path


def _load_json_file(path: Path, *, max_bytes: int = MAX_RESPONSE_BYTES) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        size = path.stat().st_size
        if size <= 0 or size > max_bytes:
            return None
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def read_verification_response(
    response_root: str | Path,
    request: Mapping[str, Any],
    *,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> ResponseReadResult:
    """Read only an event-bound v2 response or a strict ``latest`` pointer."""

    request_validation = validate_verification_request(request, allow_expired=True)
    if not request_validation.valid:
        return ResponseReadResult(None, request_validation.reason_code)
    root = Path(response_root)
    event_id = str(request.get("event_id") or "")
    event_path = root / f"{event_id}.json"
    if event_path.exists():
        loaded = _load_json_file(event_path, max_bytes=max_bytes)
        if loaded is None:
            return ResponseReadResult(None, "challenge_response_unreadable", event_path)
        if loaded.get("schema") != VERIFICATION_RESPONSE_SCHEMA:
            return ResponseReadResult(None, "challenge_response_unbound", event_path)
        if (
            str(loaded.get("event_id") or "") != event_id
            or not hmac.compare_digest(
                str(loaded.get("request_digest") or ""),
                str(request.get("request_digest") or ""),
            )
            or not hmac.compare_digest(
                str(loaded.get("binding_digest") or ""),
                str(request.get("binding_digest") or ""),
            )
        ):
            return ResponseReadResult(None, "challenge_response_unbound", event_path)
        return ResponseReadResult(loaded, "challenge_response_loaded", event_path)

    pointer_path = root / "latest.json"
    if not pointer_path.exists():
        return ResponseReadResult(None, "challenge_response_missing")
    pointer = _load_json_file(pointer_path, max_bytes=max_bytes)
    if pointer is None:
        return ResponseReadResult(None, "challenge_response_pointer_unreadable", pointer_path)
    if pointer.get("schema") != VERIFICATION_RESPONSE_POINTER_SCHEMA:
        return ResponseReadResult(None, "challenge_response_unbound", pointer_path)
    expected_name = f"{event_id}.json"
    if (
        str(pointer.get("event_id") or "") != event_id
        or not hmac.compare_digest(
            str(pointer.get("request_digest") or ""),
            str(request.get("request_digest") or ""),
        )
        or str(pointer.get("response_file") or "") != expected_name
        or Path(str(pointer.get("response_file") or "")).name != expected_name
    ):
        return ResponseReadResult(None, "challenge_response_unbound", pointer_path)
    pointed_path = root / expected_name
    loaded = _load_json_file(pointed_path, max_bytes=max_bytes)
    if loaded is None:
        return ResponseReadResult(None, "challenge_response_pointer_target_invalid", pointed_path)
    expected_sha = str(pointer.get("response_sha256") or "").casefold()
    try:
        actual_sha = sha256_file(pointed_path)
    except OSError:
        return ResponseReadResult(None, "challenge_response_pointer_target_invalid", pointed_path)
    if len(expected_sha) != 64 or not hmac.compare_digest(expected_sha, actual_sha):
        return ResponseReadResult(None, "challenge_response_pointer_digest_mismatch", pointed_path)
    if (
        loaded.get("schema") != VERIFICATION_RESPONSE_SCHEMA
        or str(loaded.get("event_id") or "") != event_id
        or not hmac.compare_digest(
            str(loaded.get("request_digest") or ""),
            str(request.get("request_digest") or ""),
        )
        or not hmac.compare_digest(
            str(loaded.get("binding_digest") or ""),
            str(request.get("binding_digest") or ""),
        )
    ):
        return ResponseReadResult(None, "challenge_response_unbound", pointed_path)
    return ResponseReadResult(loaded, "challenge_response_loaded", pointed_path)


__all__ = [name for name in globals() if not name.startswith("_")]
