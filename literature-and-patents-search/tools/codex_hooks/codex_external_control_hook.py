from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shlex
import subprocess
import shutil
import sys
import threading
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


_SHARED_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
if str(_SHARED_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SHARED_SCRIPTS_DIR))

from laps_core.challenge_protocol import (  # noqa: E402
    MAX_RESPONSE_BYTES,
    VERIFICATION_REQUEST_SCHEMA,
    VERIFICATION_RESPONSE_POINTER_SCHEMA,
    VERIFICATION_RESPONSE_SCHEMA,
    build_verification_request,
    build_verification_response,
    read_verification_response as read_bound_verification_response,
    sha256_file as protocol_sha256_file,
    validate_verification_request,
    validate_verification_response,
    value_digest as protocol_value_digest,
    write_verification_response_atomic,
)
from laps_core.network_safety import outbound_http_url_allowed  # noqa: E402


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def truthy(value: str | None) -> bool:
    return (value or "").strip().casefold() in {"1", "true", "yes", "on"}


def env_int(names: tuple[str, ...], default: int, minimum: int = 1) -> int:
    for name in names:
        raw = os.getenv(name, "").strip()
        if not raw:
            continue
        try:
            return max(minimum, int(raw))
        except ValueError:
            continue
    return default


def env_is_set(name: str) -> bool:
    return os.getenv(name) is not None


def chrome_fallback_enabled() -> bool:
    if truthy(os.getenv("CODEX_HOOK_DISABLE_CHROME_FALLBACK")):
        return False
    if env_is_set("CODEX_HOOK_TRY_CHROME"):
        return truthy(os.getenv("CODEX_HOOK_TRY_CHROME"))
    return True


DEFAULT_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS = 180
DEFAULT_CODEX_CHROME_SETUP_CONFIRM_TIMEOUT_SECONDS = 300
DEFAULT_CODEX_CHROME_SETUP_POLL_INTERVAL_SECONDS = 300
DEFAULT_CODEX_CHROME_SETUP_SCAN_TIMEOUT_SECONDS = 1800
DEFAULT_CODEX_CHROME_CONNECT_SETTLE_SECONDS = 3
DEFAULT_EXTERNAL_HANDOFF_TIMEOUT_SECONDS = 900
HOOK_EVENT_ID_MAX_LENGTH = 48
CODEX_PAGE_CONTROL_REQUEST_SCHEMA = "laps_codex_page_control_request_v1"
CODEX_PAGE_CONTROL_RESPONSE_SCHEMA = "laps_codex_page_control_response_v1"
CODEX_CHROME_PREFLIGHT_SCHEMA = "laps_codex_chrome_preflight_v1"
CODEX_CHROME_OPEN_MARKER_SCHEMA = "laps_codex_ordinary_chrome_open_v1"
CODEX_CHROME_HANDOFF_CONFIRMATION_SCHEMA = (
    "laps_codex_ordinary_chrome_handoff_confirmation_v1"
)
CODEX_COMPUTER_USE_REQUEST_SCHEMA = "laps_codex_computer_use_request_v1"
CODEX_COMPUTER_USE_RESPONSE_SCHEMA = "laps_codex_computer_use_response_v1"
CODEX_CHALLENGE_ACTION_CONFIRMATION_SCHEMA = (
    "laps_codex_challenge_action_confirmation_v1"
)
CODEX_CHALLENGE_ACTION_AUTHORIZATION_SCHEMA = (
    "laps_codex_challenge_action_authorization_v2"
)
CODEX_CHALLENGE_ACTION_ATTESTATION_SCHEMA = (
    "laps_codex_challenge_action_attestation_v1"
)
CODEX_INTERACTION_LEARNING_SCHEMA = "laps_codex_interaction_learning_v1"
BROWSER_ESCALATION_POLICY_SCHEMA = "laps_browser_escalation_policy_v1"
BROWSER_ESCALATION_LAYERS = (
    "bundled_chromium",
    "playwright_chrome",
    "ordinary_chrome_cdp",
    "codex_windows_control",
)
BROWSER_CONTROL_AUTHORIZATION_SCHEMA = "laps_browser_control_authorization_v1"
BROWSER_CONTROL_ACTION_CLASSES = (
    "routine_navigation",
    "institution_selection",
    "configured_login",
    "consent_and_cookie",
    "search_and_pagination",
    "pdf_action",
    "single_bound_verification_action",
)
ORDINARY_CHROME_EXTERNAL_SESSION_ATTESTATION_SCHEMA = (
    "laps_ordinary_chrome_session_attestation_v1"
)
ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT = "ordinary_chrome_cdp"
RUNTIME_CREDENTIAL_FILL_SCHEMA = "laps_runtime_credential_fill_v1"
RUNTIME_CREDENTIAL_BROKER_DESCRIPTOR_SCHEMA = (
    "laps_runtime_credential_broker_descriptor_v1"
)
RUNTIME_CREDENTIAL_BROKER_REQUEST_SCHEMA = (
    "laps_runtime_credential_broker_request_v1"
)
CODEX_CHROME_READONLY_CDP_PROBE_METHOD = "Page.getFrameTree"
CODEX_PAGE_CONTROL_MAX_ACTIONS = 1
VERIFICATION_CHALLENGE_TYPES = frozenset(
    {"captcha_required", "robot_check", "cloudflare_or_waf"}
)
CODEX_COMPUTER_USE_STATUSES = frozenset(
    {
        "computer_use_requested",
        "computer_use_ready",
        "computer_use_url_unverified",
        "computer_use_stopped",
        "computer_use_challenge_unresolved",
        "computer_use_external_session_ready",
    }
)

CODEX_EXTENSION_FORBIDDEN_ACTIONS = (
    "Do not use proxy pools, IP rotation, third-party CAPTCHA services, token forgery, or hidden anti-bot script injection.",
    "Do not read or export browser cookies, passwords, local storage, profile databases, API keys, or account passwords.",
    "Do not submit one-time secrets such as SMS, email, OTP, or QR confirmations unless the authorized user has supplied that value for this exact flow.",
    "Do not continue high-frequency retries after access_denied, subscription_required, rate_limit, or cooldown classifications.",
)
CODEX_CHROME_PREFLIGHT_STATES = frozenset(
    {
        "ready",
        "local_chrome_not_found",
        "chrome_plugin_install_required",
        "chrome_plugin_connect_required",
        "full_cdp_enable_required",
        "workspace_policy_blocked",
        "codex_chrome_control_declined",
        "chrome_plugin_setup_timeout",
        "full_cdp_setup_timeout",
        "preflight_unavailable",
    }
)
CODEX_CHROME_SETUP_REQUIRED_STATES = frozenset(
    {
        "chrome_plugin_install_required",
        "chrome_plugin_connect_required",
        "full_cdp_enable_required",
    }
)
CODEX_CHROME_SKIP_STATES = frozenset(
    {
        "local_chrome_not_found",
        "workspace_policy_blocked",
        "codex_chrome_control_declined",
        "chrome_plugin_setup_timeout",
        "full_cdp_setup_timeout",
    }
)
CODEX_CHROME_SETUP_HELP = {
    "chrome_plugin_install_required": "Open Codex Plugins, add the Chrome plugin, finish extension setup, and confirm the extension shows Connected.",
    "chrome_plugin_connect_required": "Approve one selected-profile ordinary Chrome window, then reconnect the Codex Chrome extension for the current Codex task.",
    "full_cdp_enable_required": "Open Settings > Browser > Developer mode, enable full CDP access, approve the target host, and complete the read-only Page.getFrameTree probe.",
}


def chrome_executable_candidates() -> list[Path]:
    configured = os.getenv("CODEX_HOOK_CHROME_EXECUTABLE", "").strip()
    if configured:
        return [Path(configured).expanduser()]
    candidates: list[Path] = []
    for command in ("chrome", "chrome.exe", "google-chrome", "google-chrome-stable"):
        found = shutil.which(command)
        if found:
            candidates.append(Path(found))
    for env_name, suffix in (
        ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
        ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
        ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
    ):
        base = os.getenv(env_name, "").strip()
        if base:
            candidates.append(Path(base) / suffix)
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).casefold()
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def find_local_chrome() -> Path | None:
    for candidate in chrome_executable_candidates():
        try:
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()
        except Exception:
            continue
    return None


def codex_extension_control_enabled(payload: dict[str, Any] | None = None) -> bool:
    configured = os.getenv("LAPS_CODEX_EXTENSION_CONTROL_ENABLED")
    if configured is not None:
        return truthy(configured)
    if os.getenv("LAPS_CODEX_EXTENSION_CONTROL_HOOK", "").strip():
        return True
    if isinstance(payload, dict) and payload.get("codex_extension_control_enabled") is True:
        return True
    return codex_chrome_control_mode() == "required"


def ordinary_chrome_handoff_preauthorized(
    payload: dict[str, Any] | None = None,
) -> bool:
    if isinstance(payload, dict) and isinstance(
        payload.get("ordinary_chrome_preapproved"), bool
    ):
        return payload["ordinary_chrome_preapproved"]
    configured = os.getenv("LAPS_ORDINARY_CHROME_PREAUTHORIZED")
    return True if configured is None else truthy(configured)


def codex_windows_control_preauthorized(
    payload: dict[str, Any] | None = None,
) -> bool:
    if isinstance(payload, dict) and isinstance(
        payload.get("computer_use_preapproved"), bool
    ):
        return payload["computer_use_preapproved"]
    configured = os.getenv("LAPS_CODEX_WINDOWS_CONTROL_PREAUTHORIZED")
    return True if configured is None else truthy(configured)


def browser_escalation_policy_contract(
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    disabled_layers: list[str] = []
    if not chrome_fallback_enabled():
        disabled_layers.extend(BROWSER_ESCALATION_LAYERS[1:])
    return {
        "schema": BROWSER_ESCALATION_POLICY_SCHEMA,
        "layers": list(BROWSER_ESCALATION_LAYERS),
        "order_locked": True,
        "disabled_layers": disabled_layers,
        "current_browser": str(
            payload.get("parent_browser_name")
            or payload.get("browser_name")
            or ""
        ).strip().casefold(),
        "advance_on": [
            "verification_loop",
            "timeout",
            "transport_failure",
            "unsupported_browser",
        ],
        "final_failure_action": "cooldown_current_channel",
        "channel_order_unchanged": True,
    }


def control_authorization_contract(
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    return {
        "schema": BROWSER_CONTROL_AUTHORIZATION_SCHEMA,
        "scope": "literature_and_patent_browser_workflow",
        "preauthorized_action_classes": list(BROWSER_CONTROL_ACTION_CLASSES),
        "ordinary_chrome_preapproved": ordinary_chrome_handoff_preauthorized(
            payload
        ),
        "windows_control_preapproved": codex_windows_control_preauthorized(
            payload
        ),
        "verification_action_budget": 1,
        "event_bound": True,
        "requires_unique_visible_target": True,
        "refresh_or_repeat_forbidden": True,
        "user_completed_first_is_accepted": True,
        "user_held_one_time_secrets_remain_user_provided": True,
        "host_enforced_confirmation_may_still_apply": True,
    }


def source_deadline_remaining_seconds() -> int | None:
    raw = os.getenv("LAPS_SOURCE_DEADLINE_EPOCH_SECONDS", "").strip()
    if not raw:
        return None
    try:
        return max(0, int(float(raw) - time.time()))
    except ValueError:
        return None


def external_handoff_timeout_seconds(
    payload: dict[str, Any] | None = None,
) -> int:
    configured = DEFAULT_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS
    if isinstance(payload, dict) and payload.get(
        "external_handoff_timeout_seconds"
    ) not in {None, ""}:
        try:
            configured = max(
                1,
                int(payload.get("external_handoff_timeout_seconds")),
            )
        except (TypeError, ValueError):
            configured = DEFAULT_EXTERNAL_HANDOFF_TIMEOUT_SECONDS
    parent_remaining = source_deadline_remaining_seconds()
    if parent_remaining is None:
        return configured
    return max(1, min(configured, max(1, parent_remaining - 5)))


def codex_chrome_control_mode() -> str:
    raw = os.getenv("LAPS_CODEX_CHROME_CONTROL_MODE", "").strip().casefold()
    aliases = {
        "enabled": "auto",
        "on": "auto",
        "1": "auto",
        "disabled": "off",
        "declined": "off",
        "false": "off",
        "0": "off",
        "require": "required",
    }
    normalized = aliases.get(raw, raw)
    if normalized in {"auto", "off", "required"}:
        return normalized
    if env_is_set("LAPS_CODEX_EXTENSION_CONTROL_ENABLED") and not truthy(
        os.getenv("LAPS_CODEX_EXTENSION_CONTROL_ENABLED")
    ):
        return "off"
    return "auto"


def normalize_codex_chrome_preflight_state(value: Any) -> str:
    raw = str(value or "").strip().casefold().replace("-", "_")
    aliases = {
        "plugin_missing": "chrome_plugin_install_required",
        "plugin_install_required": "chrome_plugin_install_required",
        "plugin_disconnected": "chrome_plugin_connect_required",
        "plugin_disabled": "chrome_plugin_connect_required",
        "plugin_connect_required": "chrome_plugin_connect_required",
        "cdp_disabled": "full_cdp_enable_required",
        "full_cdp_disabled": "full_cdp_enable_required",
        "policy_blocked": "workspace_policy_blocked",
        "declined": "codex_chrome_control_declined",
        "plugin_setup_timeout": "chrome_plugin_setup_timeout",
        "cdp_setup_timeout": "full_cdp_setup_timeout",
        "unavailable": "preflight_unavailable",
    }
    normalized = aliases.get(raw, raw)
    return normalized if normalized in CODEX_CHROME_PREFLIGHT_STATES else ""


def codex_chrome_preflight_state() -> str:
    if codex_chrome_control_mode() == "off":
        return "codex_chrome_control_declined"
    configured = normalize_codex_chrome_preflight_state(
        os.getenv("LAPS_CODEX_CHROME_PREFLIGHT_STATE", "")
    )
    if configured:
        return configured
    diagnostics = codex_chrome_local_diagnostics()
    detected = normalize_codex_chrome_preflight_state(diagnostics.get("state"))
    return detected or "preflight_unavailable"


def codex_chrome_setup_reason(state: str) -> str:
    if state in CODEX_CHROME_SETUP_REQUIRED_STATES:
        return state
    if state == "preflight_unavailable":
        return "codex_chrome_capability_check_required"
    return state or "preflight_unavailable"


def codex_chrome_setup_confirm_timeout_seconds() -> int:
    return env_int(
        ("LAPS_CODEX_CHROME_SETUP_CONFIRM_TIMEOUT_SECONDS",),
        DEFAULT_CODEX_CHROME_SETUP_CONFIRM_TIMEOUT_SECONDS,
        1,
    )


def codex_chrome_handoff_confirm_timeout_seconds() -> int:
    return env_int(
        ("LAPS_CODEX_CHROME_HANDOFF_CONFIRM_TIMEOUT_SECONDS",),
        DEFAULT_CODEX_CHROME_SETUP_CONFIRM_TIMEOUT_SECONDS,
        1,
    )


def codex_chrome_setup_poll_interval_seconds() -> int:
    return env_int(
        ("LAPS_CODEX_CHROME_SETUP_POLL_INTERVAL_SECONDS",),
        DEFAULT_CODEX_CHROME_SETUP_POLL_INTERVAL_SECONDS,
        1,
    )


def codex_chrome_setup_scan_timeout_seconds() -> int:
    return env_int(
        ("LAPS_CODEX_CHROME_SETUP_SCAN_TIMEOUT_SECONDS",),
        DEFAULT_CODEX_CHROME_SETUP_SCAN_TIMEOUT_SECONDS,
        1,
    )


def codex_chrome_setup_stage(state: str) -> str:
    if state in {"chrome_plugin_install_required", "chrome_plugin_connect_required"}:
        return "chrome_plugin"
    if state == "full_cdp_enable_required":
        return "full_cdp"
    return ""


def codex_chrome_setup_timeout_state(stage: str) -> str:
    return (
        "full_cdp_setup_timeout"
        if stage == "full_cdp"
        else "chrome_plugin_setup_timeout"
    )


def codex_chrome_setup_max_wait_seconds(state: str) -> int:
    stage_seconds = (
        codex_chrome_setup_confirm_timeout_seconds()
        + codex_chrome_setup_scan_timeout_seconds()
    )
    stage = codex_chrome_setup_stage(state)
    if stage == "chrome_plugin":
        return stage_seconds * 2 + codex_chrome_connect_settle_seconds()
    if stage == "full_cdp":
        return stage_seconds
    return 0


def codex_page_control_enabled() -> bool:
    configured = os.getenv("LAPS_CODEX_PAGE_CONTROL_ENABLED")
    return True if configured is None else truthy(configured)


def automatic_verification_action_limit() -> int:
    if truthy(os.getenv("LAPS_DISABLE_AUTOMATIC_VERIFICATION_INTERACTION")):
        return 0
    return env_int(("LAPS_VERIFICATION_AUTOMATIC_ACTION_LIMIT",), 1, 1)


def verification_action_settle_seconds() -> int:
    return env_int(("LAPS_VERIFICATION_ACTION_SETTLE_SECONDS",), 45, 1)


def verification_control_stable_seconds() -> int:
    return env_int(("LAPS_VERIFICATION_CONTROL_STABLE_SECONDS",), 15, 1)


def verification_post_action_wait_seconds() -> int:
    return env_int(("LAPS_VERIFICATION_POST_ACTION_WAIT_SECONDS",), 180, 1)


def verification_resolution_stable_seconds() -> int:
    return env_int(("LAPS_VERIFICATION_RESOLUTION_STABLE_SECONDS",), 20, 1)


def institution_result_wait_seconds() -> int:
    return env_int(("LAPS_INSTITUTION_RESULT_WAIT_SECONDS",), 15, 1)


def institution_entry_transition_wait_seconds() -> int:
    return env_int(("LAPS_INSTITUTION_ENTRY_TRANSITION_WAIT_SECONDS",), 8, 1)


def codex_page_control_sequence_limit() -> int:
    return env_int(("LAPS_CODEX_PAGE_CONTROL_SEQUENCE_LIMIT",), 2, 1)


def verification_browser_fallback_cooldown_seconds() -> int:
    return env_int(("LAPS_VERIFICATION_BROWSER_FALLBACK_COOLDOWN_SECONDS",), 30, 1)


def verification_loop_stable_seconds() -> int:
    return env_int(("LAPS_VERIFICATION_LOOP_STABLE_SECONDS",), 60, 1)


def verification_action_same_node_is_stable(
    visible_since: float | None,
    *,
    now: float | None = None,
) -> bool:
    if visible_since is None:
        return False
    current = time.monotonic() if now is None else now
    return current - visible_since >= verification_loop_stable_seconds()


def verification_browser_transition_cooldown_seconds(
    previous_result: dict[str, Any] | None,
) -> int:
    del previous_result
    return verification_browser_fallback_cooldown_seconds()


def write_browser_layer_event(
    root: Path,
    event_name: str,
    browser_name: str,
    event_type: str,
    **details: Any,
) -> None:
    allowed_event_types = {
        "browser_layer_started",
        "browser_layer_finished",
        "browser_layer_advanced",
    }
    if event_type not in allowed_event_types:
        raise ValueError(f"Unsupported browser layer event: {event_type}")
    allowed_detail_keys = {
        "action",
        "challenge_type",
        "cooldown_seconds",
        "next_browser",
        "reason",
    }
    payload = {
        "schema": "laps_browser_layer_event_v1",
        "event_type": event_type,
        "browser": str(browser_name or ""),
        "created_at": utc_now(),
    }
    payload.update(
        {
            key: details[key]
            for key in allowed_detail_keys
            if key in details and details[key] not in (None, "")
        }
    )
    write_json(
        root
        / "browser_attempts"
        / f"{event_name}_{browser_name}_{event_type}.json",
        payload,
    )


def verification_document_reload_settle_seconds() -> int:
    return env_int(("LAPS_VERIFICATION_DOCUMENT_RELOAD_SETTLE_SECONDS",), 5, 1)


def verification_interaction_requires_same_browser_cooldown(
    interaction_observed: bool,
    initial_challenge: str,
    current_challenge: str,
) -> bool:
    return bool(
        interaction_observed
        and (
            initial_challenge in VERIFICATION_CHALLENGE_TYPES
            or current_challenge in VERIFICATION_CHALLENGE_TYPES
        )
    )


def verification_control_is_stable(visible_since: float | None, now: float | None = None) -> bool:
    if visible_since is None:
        return False
    current = time.monotonic() if now is None else now
    return current - visible_since >= verification_control_stable_seconds()


def verification_node_location_key(final_url: str) -> str:
    parsed = urlsplit(str(final_url or ""))
    host = (parsed.hostname or "").casefold()
    path = (parsed.path or "/").rstrip("/") or "/"
    return f"{host}|{path}"


def verification_node_key(final_url: str, challenge_type: str) -> str:
    return (
        f"{str(challenge_type or '').casefold()}|"
        f"{verification_node_location_key(final_url)}"
    )


def verification_node_fingerprint(node_key: str) -> str:
    return hashlib.sha256(str(node_key or "").encode("utf-8", "replace")).hexdigest()[:16]


def same_verification_document_reloaded(
    *,
    previous_epoch: str,
    current_epoch: str,
    previous_node: str,
    current_node: str,
    current_challenge: str,
) -> bool:
    return bool(
        previous_epoch
        and current_epoch
        and previous_epoch != current_epoch
        and previous_node
        and current_node == previous_node
        and current_challenge in VERIFICATION_CHALLENGE_TYPES
    )


AUTHENTICATION_PROGRESS_STAGES = frozenset(
    {"institution_entry", "institution_search", "idp_login", "mfa", "authenticated"}
)


def verification_loop_unresolved(
    *,
    interaction_observed: bool,
    action_node: str,
    current_node: str,
    stage_progress_observed: bool,
    navigation_progress_observed: bool,
    current_challenge: str,
) -> bool:
    return bool(
        interaction_observed
        and action_node
        and current_challenge in VERIFICATION_CHALLENGE_TYPES
        and current_node == action_node
        and not stage_progress_observed
        and not navigation_progress_observed
    )


def verification_loop_response(
    browser_name: str,
    *,
    has_later_browser: bool,
) -> tuple[str, str]:
    if browser_name == "chromium" and has_later_browser:
        return "unhandled", "verification_loop_unresolved"
    if browser_name == "chrome":
        return "cooldown", "verification_loop_after_chrome"
    return "cooldown", "verification_loop_unresolved"


def browser_internal_navigation_error(final_url: str) -> bool:
    lowered = str(final_url or "").strip().casefold()
    return lowered.startswith("chrome-error://") or lowered.startswith(
        "about:neterror"
    )


def browser_transport_unstable_exception(exc: BaseException) -> bool:
    surface = " ".join(
        (
            exc.__class__.__name__,
            str(exc),
            repr(exc),
        )
    ).casefold()
    return any(
        marker in surface
        for marker in (
            "transport error",
            "stream disconnected",
            "connection closed",
            "websocket is not open",
            "websocket closed",
            "targetclosederror",
            "target page, context or browser has been closed",
            "browser has been closed",
            "cdp session is closed",
            "error decoding response body",
        )
    )


def latest_external_interaction_sequence(trace: dict[str, Any] | None) -> int:
    if not trace:
        return 0
    try:
        last_external = trace.get("last_external") or {}
        return max(
            0,
            int(
                last_external.get("click_sequence")
                or last_external.get("sequence")
                or 0
            ),
        )
    except (TypeError, ValueError):
        return 0


def codex_extension_control_timeout_seconds() -> int:
    return env_int(
        ("LAPS_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS", "CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS"),
        DEFAULT_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS,
        1,
    )


def sanitize_url_for_extension(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        if not parts.scheme or not parts.netloc:
            return text[:500]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except Exception:
        return text.split("?", 1)[0].split("#", 1)[0][:500]


REDACTION_PLACEHOLDER = "***REDACTED***"
SENSITIVE_KEY_EXACT = {
    "account",
    "password",
    "school",
    "school_aliases",
    "raw_account",
    "raw_password",
    "parent_browser_cdp_endpoint",
    "parent_browser_target_id",
}
SENSITIVE_KEY_TOKENS = (
    "secret",
    "token",
    "cookie",
    "credential",
    "authorization",
    "session",
    "api_key",
    "apikey",
    "insttoken",
    "access_token",
    "refresh_token",
    "client_secret",
    "bearer",
)
URL_KEY_EXACT = {
    "url",
    "urls",
    "current_url",
    "entry_url",
    "candidate_url",
    "candidate_urls",
    "final_url",
    "source_url",
    "raw_current_url",
    "raw_entry_url",
    "raw_url",
    "raw_candidate_url",
}
SENSITIVE_VALUE_TOKENS = (
    "secret",
    "token",
    "cookie",
    "bearer",
    "password",
    "api_key",
    "apikey",
    "credential",
    "authorization",
    "session",
)
SAFE_SESSION_METADATA_KEYS = frozenset(
    {
        "external_browser_session",
        "external_session_attestation",
        "attestation_schema",
        "session_preauthorization",
        "session_preauthorization_is_sufficient",
        "challenge_action_authorization",
        "authorization_source",
        "browser_transport",
        "institution_identity_digest",
        "auth_state_scope",
        "authenticated",
        "page_access_confirmed",
        "snapshot_page_count",
        "explicit_no_results",
        "exhausted",
        "runtime_credential_fill",
        "model_blind_helper_path",
        "model_blind_helper_export",
        "broker_descriptor_path",
        "runtime_auth_values_available",
    }
)
SAFE_SESSION_METADATA_SCHEMAS = frozenset(
    {
        ORDINARY_CHROME_EXTERNAL_SESSION_ATTESTATION_SCHEMA,
        CODEX_CHALLENGE_ACTION_AUTHORIZATION_SCHEMA,
        CODEX_CHALLENGE_ACTION_ATTESTATION_SCHEMA,
        RUNTIME_CREDENTIAL_FILL_SCHEMA,
    }
)
URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>)}\]]+")


def normalized_key(key: str | None) -> str:
    return str(key or "").replace("-", "_").casefold()


def is_sensitive_key(key: str | None) -> bool:
    lowered = normalized_key(key)
    if lowered in SAFE_SESSION_METADATA_KEYS:
        return False
    if lowered in SENSITIVE_KEY_EXACT:
        return True
    return any(token in lowered for token in SENSITIVE_KEY_TOKENS)


def is_url_key(key: str | None) -> bool:
    lowered = normalized_key(key)
    return lowered in URL_KEY_EXACT or lowered.endswith("_url") or lowered.endswith("_urls")


def sanitize_url_for_event(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        if parts.scheme and parts.netloc:
            return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except Exception:
        pass
    return text.split("?", 1)[0].split("#", 1)[0]


def sanitize_search_result_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        if parts.scheme and parts.netloc:
            query = urlencode(
                [
                    (key, item_value)
                for key, item_value in parse_qsl(parts.query, keep_blank_values=True)
                if not is_sensitive_key(key)
                ]
            )
            return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    except Exception:
        pass
    return sanitize_url_for_event(text)


def contains_sensitive_value(text: str) -> bool:
    lowered = text.casefold()
    return any(token in lowered for token in SENSITIVE_VALUE_TOKENS)


def redact_persisted_string(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    without_url_secrets = URL_IN_TEXT_RE.sub(lambda match: sanitize_url_for_event(match.group(0)), text)
    if contains_sensitive_value(without_url_secrets):
        return REDACTION_PLACEHOLDER
    return without_url_secrets


def redact_payload_for_event(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            str(item_key): (
                REDACTION_PLACEHOLDER
                if is_sensitive_key(str(item_key))
                else redact_payload_for_event(item_value, str(item_key))
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_payload_for_event(item, key) for item in value]
    if isinstance(value, tuple):
        return [redact_payload_for_event(item, key) for item in value]
    if isinstance(value, str):
        if is_sensitive_key(key):
            return REDACTION_PLACEHOLDER
        if is_url_key(key):
            sanitized = sanitize_url_for_event(value)
            return REDACTION_PLACEHOLDER if contains_sensitive_value(sanitized) else sanitized
        if normalized_key(key) in SAFE_SESSION_METADATA_KEYS:
            return value[:500]
        if normalized_key(key) == "schema" and value in SAFE_SESSION_METADATA_SCHEMAS:
            return value
        return redact_persisted_string(value)
    if is_sensitive_key(key):
        return REDACTION_PLACEHOLDER
    return value


def parent_browser_attachment_requested(payload: dict[str, Any]) -> bool:
    endpoint = str(payload.get("parent_browser_cdp_endpoint") or "").strip()
    target_id = str(payload.get("parent_browser_target_id") or "").strip()
    browser_name = str(payload.get("parent_browser_name") or "").strip().casefold()
    if not endpoint or not target_id or browser_name not in {"chromium", "chrome"}:
        return False
    try:
        parsed = urlsplit(endpoint)
        return bool(
            parsed.scheme in {"http", "ws"}
            and parsed.hostname == "127.0.0.1"
            and parsed.port is not None
            and 0 < parsed.port < 65536
            and not parsed.username
            and not parsed.password
        )
    except (TypeError, ValueError):
        return False


def extension_raw_url_allowed() -> bool:
    return truthy(os.getenv("LAPS_CODEX_EXTENSION_CONTROL_ALLOW_RAW_URL"))


def configured_institution_identity_digest(payload: dict[str, Any]) -> str:
    values = [str(payload.get("school") or "")]
    aliases = payload.get("school_aliases")
    if isinstance(aliases, (list, tuple)):
        values.extend(str(value or "") for value in aliases)
    normalized = sorted(
        {
            " ".join(unicodedata.normalize("NFKC", value).casefold().split())
            for value in values
            if str(value or "").strip()
        }
    )
    if not normalized:
        return ""
    return hashlib.sha256(
        json.dumps(normalized, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def write_private_runtime_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    )
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def redact_rejected_response_artifact(
    path: Path | None,
    event_name: str,
    reason_code: str,
    *,
    require_embedded_event_id: bool = False,
) -> bool:
    """Replace one rejected response input with a non-secret audit envelope.

    Legacy asynchronous ``latest.json`` responses are no longer executable in
    protocol v2.  They may nevertheless contain cookies, signed URL queries or
    arbitrary nested secrets.  Once such a file is proven to belong to the
    current event, retaining its raw body serves no recovery purpose and turns
    the hook directory into a credential leak.  Event-specific rejected v2
    responses receive the same treatment.

    A v2 pointer is never rewritten here.  A shared ``latest.json`` without an
    exact embedded event ID is also left untouched so one process cannot alter
    another event's pointer or response.
    """

    if path is None:
        return False
    selected = Path(path)
    try:
        if not selected.exists() and not selected.is_symlink():
            return False
        if selected.is_symlink():
            loaded: Any = None
            raw = b""
            size = 0
        else:
            size = selected.stat().st_size
            if size <= 0 or size > MAX_RESPONSE_BYTES:
                loaded = None
                raw = b""
            else:
                raw = selected.read_bytes()
                loaded = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        loaded = None
        raw = b""
        try:
            size = selected.stat().st_size
        except OSError:
            size = 0

    embedded_event_id = (
        str(loaded.get("event_id") or "").strip()
        if isinstance(loaded, dict)
        else ""
    )
    if require_embedded_event_id and embedded_event_id != event_name:
        return False
    if isinstance(loaded, dict) and loaded.get("schema") in {
        VERIFICATION_RESPONSE_POINTER_SCHEMA,
    }:
        return False
    response_sha256 = hashlib.sha256(raw).hexdigest() if raw else ""
    audit = {
        "schema": "laps_rejected_verification_response_artifact_v1",
        "event_id": event_name,
        "reason_code": reason_code or "challenge_response_unbound",
        "response_sha256": response_sha256,
        "original_size_bytes": max(0, int(size)),
        "rejected_at": utc_now(),
    }
    write_private_runtime_json(
        selected,
        redact_payload_for_event(audit),
    )
    return True


def redact_preexisting_unbound_responses(root: Path, event_name: str) -> None:
    """Scrub only legacy response files that are bound to this invocation."""

    response_root = root / "responses"
    event_path = response_root / f"{event_name}.json"
    if event_path.exists() or event_path.is_symlink():
        try:
            loaded = (
                None
                if event_path.is_symlink()
                else json.loads(event_path.read_text(encoding="utf-8-sig"))
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            loaded = None
        if not (
            isinstance(loaded, dict)
            and loaded.get("schema") == VERIFICATION_RESPONSE_SCHEMA
        ):
            redact_rejected_response_artifact(
                event_path,
                event_name,
                "challenge_response_unbound",
            )
    latest_path = response_root / "latest.json"
    if latest_path.exists() or latest_path.is_symlink():
        try:
            loaded = (
                None
                if latest_path.is_symlink()
                else json.loads(latest_path.read_text(encoding="utf-8-sig"))
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            loaded = None
        if not (
            isinstance(loaded, dict)
            and loaded.get("schema") == VERIFICATION_RESPONSE_POINTER_SCHEMA
        ):
            redact_rejected_response_artifact(
                latest_path,
                event_name,
                "challenge_response_unbound",
                require_embedded_event_id=True,
            )


class RuntimeCredentialBroker:
    def __init__(
        self,
        payload: dict[str, Any],
        root: Path,
        event_name: str,
        timeout_seconds: int,
    ) -> None:
        self._account = str(payload.get("raw_account") or "")
        self._password = str(payload.get("raw_password") or "")
        self._school = str(payload.get("school") or "")
        self._school_aliases = payload_school_aliases(payload)
        self._credential_scope = str(payload.get("credential_scope") or "").strip().casefold()
        self._credential_allowed_hosts = tuple(
            str(value).strip().casefold().strip(".")
            for value in payload.get("credential_allowed_hosts", [])
            if str(value).strip()
        ) if isinstance(payload.get("credential_allowed_hosts"), list) else ()
        self.event_id = str(payload.get("event_id") or event_name)
        self.source = str(payload.get("source") or payload.get("channel") or "")
        self.auth_state_scope = str(payload.get("auth_state_scope") or "")
        self.institution_identity_digest = configured_institution_identity_digest(
            payload
        )
        self.expires_at_epoch_seconds = int(time.time()) + max(
            1, int(timeout_seconds)
        )
        self.descriptor_path = (
            root / "credential_brokers" / f"{event_name}.json"
        )
        self._capability = secrets.token_urlsafe(32)
        self._used = False
        self._closed = False
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._expiry_timer: threading.Timer | None = None

    @property
    def configured(self) -> bool:
        identity_bound = bool(self.institution_identity_digest)
        if self._credential_scope == "site_personal":
            identity_bound = bool(
                self.source == "度衍" and self._credential_allowed_hosts
            )
        return bool(
            self._account
            and self._password
            and self.event_id
            and self.source
            and self.auth_state_scope
            and identity_bound
        )

    def start(self) -> bool:
        if not self.configured:
            return False
        broker = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "LAPSRuntimeAuth/1"

            def log_message(self, format: str, *args: Any) -> None:
                del format, args

            def do_POST(self) -> None:
                if self.path != "/claim" or self.client_address[0] not in {
                    "127.0.0.1",
                    "::1",
                }:
                    self._send(404, {"status": "credential_broker_refused"})
                    return
                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    content_length = 0
                if content_length <= 0 or content_length > 16 * 1024:
                    self._send(400, {"status": "credential_request_invalid"})
                    return
                try:
                    loaded = json.loads(
                        self.rfile.read(content_length).decode("utf-8")
                    )
                except Exception:
                    self._send(400, {"status": "credential_request_invalid"})
                    return
                if not isinstance(loaded, dict):
                    self._send(400, {"status": "credential_request_invalid"})
                    return
                status, response = broker.claim(loaded)
                self._send(200 if status else 403, response)

            def _send(self, status_code: int, response: dict[str, Any]) -> None:
                body = json.dumps(response, ensure_ascii=False).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            self._server = server
            port = int(server.server_address[1])
            descriptor = {
                "schema": RUNTIME_CREDENTIAL_BROKER_DESCRIPTOR_SCHEMA,
                "endpoint": f"http://127.0.0.1:{port}/claim",
                "capability": self._capability,
                "event_id": self.event_id,
                "source": self.source,
                "auth_state_scope": self.auth_state_scope,
                "institution_identity_digest": self.institution_identity_digest,
                "credential_scope": self._credential_scope,
                "credential_allowed_hosts": list(self._credential_allowed_hosts),
                "expires_at_epoch_seconds": self.expires_at_epoch_seconds,
                "one_use": True,
            }
            write_private_runtime_json(self.descriptor_path, descriptor)
            self._server_thread = threading.Thread(
                target=server.serve_forever,
                name=f"laps-runtime-auth-{event_id({'event_id': self.event_id})}",
                daemon=True,
            )
            self._server_thread.start()
            delay = max(1.0, self.expires_at_epoch_seconds - time.time())
            self._expiry_timer = threading.Timer(delay, self.close)
            self._expiry_timer.daemon = True
            self._expiry_timer.start()
            return True
        except Exception:
            self.close()
            return False

    def claim(self, request: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        with self._lock:
            if self._closed:
                return False, {"status": "credential_broker_expired"}
            if time.time() >= self.expires_at_epoch_seconds:
                return False, {"status": "credential_broker_expired"}
            if self._used:
                return False, {"status": "credential_broker_already_used"}
            if request.get("schema") != RUNTIME_CREDENTIAL_BROKER_REQUEST_SCHEMA:
                return False, {"status": "credential_request_invalid"}
            supplied_capability = str(request.get("capability") or "")
            if not hmac.compare_digest(supplied_capability, self._capability):
                return False, {"status": "credential_capability_mismatch"}
            exact_fields = {
                "event_id": self.event_id,
                "source": self.source,
                "auth_state_scope": self.auth_state_scope,
                "institution_identity_digest": self.institution_identity_digest,
            }
            if any(
                str(request.get(key) or "") != expected
                for key, expected in exact_fields.items()
            ):
                return False, {"status": "credential_event_mismatch"}
            current_url = str(request.get("current_url") or "")
            try:
                parsed = urlsplit(current_url)
                local_fixture = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
                valid_scheme = parsed.scheme.casefold() == "https" or (
                    local_fixture and parsed.scheme.casefold() == "http"
                )
            except Exception:
                valid_scheme = False
            if not valid_scheme or not credential_scope_allows_url(
                self._credential_scope,
                self.source,
                current_url,
                self._credential_allowed_hosts,
                self._school,
                self._school_aliases,
            ):
                return False, {"status": "credential_host_not_allowed"}
            if (
                request.get("account_form_present") is not True
                or request.get("password_form_present") is not True
            ):
                return False, {"status": "credential_form_not_found"}
            self._used = True
            try:
                self.descriptor_path.unlink(missing_ok=True)
            except OSError:
                pass
            return True, {
                "status": "runtime_credentials_available",
                "account": self._account,
                "password": self._password,
            }

    def public_contract(self) -> dict[str, Any]:
        helper_path = Path(__file__).with_name(
            "codex_ordinary_chrome_credential_fill.mjs"
        )
        return {
            "schema": RUNTIME_CREDENTIAL_FILL_SCHEMA,
            "available": True,
            "model_blind_helper_path": str(helper_path.resolve()),
            "model_blind_helper_export": "fillRuntimeCredentials",
            "broker_descriptor_path": str(self.descriptor_path.resolve()),
            "event_id": self.event_id,
            "source": self.source,
            "auth_state_scope": self.auth_state_scope,
            "institution_identity_digest": self.institution_identity_digest,
            "expires_at_epoch_seconds": self.expires_at_epoch_seconds,
            "one_use": True,
        }

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._account = ""
            self._password = ""
            self._capability = ""
        timer = self._expiry_timer
        if timer is not None and timer is not threading.current_thread():
            timer.cancel()
        server = self._server
        if server is not None:
            server_thread = self._server_thread
            if server_thread is not None and server_thread.is_alive():
                try:
                    server.shutdown()
                except Exception:
                    pass
            try:
                server.server_close()
            except Exception:
                pass
        try:
            self.descriptor_path.unlink(missing_ok=True)
        except OSError:
            pass


_ACTIVE_RUNTIME_CREDENTIAL_BROKERS: dict[str, RuntimeCredentialBroker] = {}
_ACTIVE_RUNTIME_CREDENTIAL_BROKERS_LOCK = threading.Lock()


def start_runtime_credential_broker(
    payload: dict[str, Any],
    root: Path,
    event_name: str,
    timeout_seconds: int,
) -> RuntimeCredentialBroker | None:
    if str(payload.get("event") or "") != "auth_challenge":
        return None
    if (
        codex_extension_control_hook_command()
        and not truthy(
            os.getenv("LAPS_AUTH_CONTROL_HOOK_ALLOW_CREDENTIALS")
        )
    ):
        return None
    broker = RuntimeCredentialBroker(
        payload,
        root,
        event_name,
        timeout_seconds,
    )
    if not broker.start():
        return None
    with _ACTIVE_RUNTIME_CREDENTIAL_BROKERS_LOCK:
        previous = _ACTIVE_RUNTIME_CREDENTIAL_BROKERS.pop(event_name, None)
        _ACTIVE_RUNTIME_CREDENTIAL_BROKERS[event_name] = broker
    if previous is not None:
        previous.close()
    return broker


def stop_runtime_credential_broker(event_name: str) -> None:
    with _ACTIVE_RUNTIME_CREDENTIAL_BROKERS_LOCK:
        broker = _ACTIVE_RUNTIME_CREDENTIAL_BROKERS.pop(event_name, None)
    if broker is not None:
        broker.close()


def ordinary_chrome_snapshot_response_path(
    response_path: str,
    event_id: str,
) -> str:
    response = Path(response_path).expanduser().resolve()
    root = response.parent.parent
    raw_event_name = str(event_id or response.stem)
    safe_event_name = "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in raw_event_name
    ).strip("-_")
    event_name = compact_event_id(safe_event_name or "external_session")
    return str(
        root
        / "search_snapshots"
        / f"{event_name}.ordinary_chrome.sanitized.json"
    )


def challenge_action_authorization_contract(
    payload: dict[str, Any],
) -> dict[str, Any]:
    challenge_type = str(payload.get("challenge_type") or "").strip().casefold()
    source = str(payload.get("source") or payload.get("channel") or "")
    auth_state_scope = str(payload.get("auth_state_scope") or "")
    event_name = str(payload.get("event_id") or "")
    current_url = sanitize_url_for_extension(
        payload.get("current_url")
        or payload.get("final_url")
        or payload.get("raw_current_url")
    )
    node_key = verification_node_key(current_url, challenge_type)
    required = challenge_type in VERIFICATION_CHALLENGE_TYPES
    return {
        "schema": CODEX_CHALLENGE_ACTION_AUTHORIZATION_SCHEMA,
        "required": required,
        "authorized": required,
        "authorization_source": "run_preauthorization",
        "event_id": event_name,
        "source": source,
        "auth_state_scope": auth_state_scope,
        "challenge_type": challenge_type or "unknown_verification",
        "challenge_fingerprint": verification_node_fingerprint(node_key),
        "host_path": verification_node_location_key(current_url),
        "single_action_budget": 1,
        "reusable": False,
        "session_preauthorization_is_sufficient": True,
        "automatic_visible_action_allowed": required,
        "requires_unique_visible_target": True,
        "requires_target_url_attestation": True,
        "refresh_or_repeat_forbidden": True,
        "settle_seconds": verification_action_settle_seconds(),
        "post_action_observation_seconds": verification_post_action_wait_seconds(),
        "user_completed_first_is_accepted": True,
    }


def codex_interaction_learning_contract() -> dict[str, Any]:
    return {
        "schema": CODEX_INTERACTION_LEARNING_SCHEMA,
        "mode": "codex_user_parallel_observation",
        "ordinary_chrome_demonstration_supported": True,
        "monitor_user_completion": True,
        "pause_automation_after_external_input": True,
        "record_input_values": False,
        "record_browser_private_state": False,
        "record_stable_element_attributes": [
            "tag",
            "role",
            "id",
            "name",
            "aria_label",
            "test_id",
            "redacted_visible_text",
            "selector_candidates",
        ],
        "promotion_requires": [
            "observed_stage_progress",
            "stable_selector",
            "local_fixture",
            "focused_regression",
        ],
        "never_promote": [
            "coordinates_only",
            "nth_child_only",
            "one_time_secret",
            "browser_session_secret",
            "profile_state",
        ],
    }


def build_codex_extension_handoff_request(
    payload: dict[str, Any],
    response_path: str,
    storage_state_path: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    event = str(payload.get("event") or "")
    challenge_type = str(payload.get("challenge_type") or "")
    source = str(payload.get("source") or payload.get("channel") or "")
    keyword = str(payload.get("keyword") or payload.get("title") or "")
    event_id = str(payload.get("event_id") or "")
    institution_digest = configured_institution_identity_digest(payload)
    external_snapshot_path = ordinary_chrome_snapshot_response_path(
        response_path,
        event_id,
    )
    preflight_state = normalize_codex_chrome_preflight_state(
        payload.get("preflight_state")
    ) or codex_chrome_preflight_state()
    request: dict[str, Any] = {
        "event_id": event_id,
        "event": event,
        "challenge_type": challenge_type or "unknown_verification",
        "source": source,
        "channel": str(payload.get("channel") or source),
        "keyword": keyword,
        "auth_state_scope": str(payload.get("auth_state_scope") or ""),
        "reason": str(payload.get("reason") or "codex_extension_handoff_requested"),
        "record_type": str(payload.get("record_type") or ""),
        "search_record_type": str(payload.get("search_record_type") or "literature"),
        "title": str(payload.get("title") or ""),
        "doi": str(payload.get("doi") or ""),
        "access_mode": str(payload.get("access_mode") or ""),
        "current_url": sanitize_url_for_extension(payload.get("current_url") or payload.get("final_url") or payload.get("raw_current_url")),
        "candidate_url": sanitize_url_for_extension(payload.get("candidate_url") or payload.get("raw_candidate_url") or payload.get("raw_url")),
        "entry_url": sanitize_url_for_extension(payload.get("entry_url") or payload.get("raw_entry_url")),
        "source_url": sanitize_url_for_extension(payload.get("source_url") or payload.get("url")),
        "source_search_url": sanitize_search_result_url(
            payload.get("source_search_url")
        ),
        "final_url": sanitize_url_for_extension(payload.get("final_url")),
        "screenshot_path": str(payload.get("screenshot_path") or ""),
        "response_path": response_path,
        "storage_state_path": storage_state_path,
        "success_markers": [str(value) for value in payload.get("success_markers") or [] if str(value or "").strip()],
        "result_card_selectors": [
            str(value)
            for value in payload.get("result_card_selectors") or []
            if str(value or "").strip()
        ],
        "next_page_selectors": [
            str(value)
            for value in payload.get("next_page_selectors") or []
            if str(value or "").strip()
        ],
        "no_result_markers": [
            str(value)
            for value in payload.get("no_result_markers") or []
            if str(value or "").strip()
        ],
        "result_detail_enrichment": (
            dict(payload.get("result_detail_enrichment") or {})
            if isinstance(payload.get("result_detail_enrichment"), dict)
            else {}
        ),
        "result_patent_enrichment": (
            dict(payload.get("result_patent_enrichment") or {})
            if isinstance(payload.get("result_patent_enrichment"), dict)
            else {}
        ),
        "external_browser_resume": {
            "browser_transport": ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT,
            "attestation_schema": ORDINARY_CHROME_EXTERNAL_SESSION_ATTESTATION_SCHEMA,
            "event_id": event_id,
            "source": source,
            "keyword": keyword,
            "search_record_type": str(
                payload.get("search_record_type") or "literature"
            ),
            "auth_state_scope": str(payload.get("auth_state_scope") or ""),
            "institution_identity_digest": institution_digest,
            "snapshot_path": external_snapshot_path,
            "snapshot_schema": "laps_sanitized_search_snapshot_v1",
            "requires_authenticated_search_page": event == "auth_challenge",
            "requires_dedicated_parser_evidence": True,
        },
        "browser_preference": "codex_chrome_extension",
        "controller": "codex_chrome_extension",
        "timeout_seconds": max(1, int(timeout_seconds)),
        "session_preauthorization": {
            "ordinary_chrome": ordinary_chrome_handoff_preauthorized(payload),
            "windows_computer_use": codex_windows_control_preauthorized(payload),
            "visible_challenge_action": True,
        },
        "browser_escalation_policy": browser_escalation_policy_contract(payload),
        "control_authorization": control_authorization_contract(payload),
        "challenge_action_authorization": challenge_action_authorization_contract(
            payload
        ),
        "interaction_learning": codex_interaction_learning_contract(),
        "computer_use_fallback": {
            "available_after_ordinary_chrome": True,
            "preauthorized": codex_windows_control_preauthorized(payload),
            "same_ordinary_chrome_session_required": True,
            "target_url_attestation_required": True,
            "python_private_ui_automation_forbidden": True,
        },
        "runtime_auth_values_available": bool(
            payload.get("raw_account") and payload.get("raw_password")
        ),
        "created_at": utc_now(),
        "preflight": {
            "schema": CODEX_CHROME_PREFLIGHT_SCHEMA,
            "state": preflight_state,
            "ordinary_chrome_required": True,
            "current_task_connection_required": True,
            "open_ordinary_chrome_requires_explicit_approval": False,
            "open_ordinary_chrome_approved_for_current_run": True,
            "open_ordinary_chrome_once_per_run": True,
            "temporary_profile_extension_loading_supported": False,
            "required_capabilities": [
                "ordinary_chrome",
                "chrome_plugin_connected",
                "full_cdp_access",
                "readonly_cdp_probe_succeeded",
            ],
            "readonly_cdp_probe": {
                "method": CODEX_CHROME_READONLY_CDP_PROBE_METHOD,
                "mutates_page": False,
            },
            "pause_on_setup_required": True,
            "decline_scope": "codex_controlled_ordinary_chrome_only",
            "setup_help": dict(CODEX_CHROME_SETUP_HELP),
            "setup_timing": {
                "confirmation_timeout_seconds": codex_chrome_setup_confirm_timeout_seconds(),
                "poll_interval_seconds": codex_chrome_setup_poll_interval_seconds(),
                "scan_timeout_seconds": codex_chrome_setup_scan_timeout_seconds(),
                "connection_settle_seconds": codex_chrome_connect_settle_seconds(),
            },
        },
        "forbidden_actions": list(CODEX_EXTENSION_FORBIDDEN_ACTIONS),
        "expected_response": {
            "action": "retry|skip|cooldown|manual_pending|unhandled",
            "preflight_state": "ready|chrome_plugin_install_required|chrome_plugin_connect_required|full_cdp_enable_required|workspace_policy_blocked|codex_chrome_control_declined|chrome_plugin_setup_timeout|full_cdp_setup_timeout|preflight_unavailable",
            "reason": "codex_extension_handoff_succeeded|codex_extension_handoff_unavailable|codex_extension_handoff_timeout",
            "capability_attestation": {
                "ordinary_chrome_extension_connected": True,
                "full_cdp_access": True,
                "readonly_cdp_probe_method": CODEX_CHROME_READONLY_CDP_PROBE_METHOD,
                "readonly_cdp_probe_succeeded": True,
            },
            "storage_state_path": "required for institution/auth retry",
            "external_browser_session": (
                "true only for an independently owned ordinary Chrome/CDP "
                "session; requires external_session_attestation and sanitized "
                "search snapshot evidence instead of storage_state_path"
            ),
            "browser_transport": ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT,
            "external_session_attestation": {
                "schema": ORDINARY_CHROME_EXTERNAL_SESSION_ATTESTATION_SCHEMA,
                "event_id": event_id,
                "source": source,
                "auth_state_scope": str(payload.get("auth_state_scope") or ""),
                "institution_identity_digest": institution_digest,
                "authenticated": (
                    "true for auth_challenge; optional for a public "
                    "search_challenge"
                ),
                "page_access_confirmed": (
                    "true for search_challenge after the result page is "
                    "visibly loaded"
                ),
            },
            "sanitized_search_snapshot_paths": [external_snapshot_path],
            "candidate_urls": "required for PDF/security retry unless final_url is already a PDF",
            "final_url": "optional final browser URL",
            "challenge_resolution": (
                "required for retry when challenge_action_authorization.required; "
                "must identify authorized_user/page progress or one preauthorized "
                "Codex action bound to this event and fingerprint"
            ),
        },
    }
    if extension_raw_url_allowed():
        for key in ("raw_current_url", "raw_candidate_url", "raw_entry_url", "raw_url"):
            value = str(payload.get(key) or "").strip()
            if value:
                request[key] = value
    return request


def response_event_id(response: dict[str, Any]) -> str:
    direct = str(response.get("event_id") or "").strip()
    if direct:
        return direct
    for key in (
        "external_session_attestation",
        "challenge_action_authorization",
        "challenge_action_confirmation",
    ):
        nested = response.get(key)
        if isinstance(nested, dict):
            candidate = str(nested.get("event_id") or "").strip()
            if candidate:
                return candidate
    return ""


def response_matches_event(response: dict[str, Any], expected_event_id: str) -> bool:
    expected = str(expected_event_id or "").strip()
    return bool(expected and response_event_id(response) == expected)


def protocol_event_id_for_request(
    request: dict[str, Any] | None,
    internal_event_name: str,
) -> str:
    if isinstance(request, dict):
        configured = str(request.get("event_id") or "").strip()
        if configured:
            return configured
    return str(internal_event_name or "").strip()


def build_codex_computer_use_request(
    extension_request: dict[str, Any],
    attempt: dict[str, Any],
    *,
    response_path: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    event_name = str(extension_request.get("event_id") or "")
    source = str(
        extension_request.get("source")
        or extension_request.get("channel")
        or ""
    )
    current_url = sanitize_url_for_extension(
        attempt.get("final_url")
        or attempt.get("current_url")
        or extension_request.get("current_url")
    )
    challenge_contract = dict(
        extension_request.get("challenge_action_authorization")
        or extension_request.get("challenge_action_confirmation")
        or {}
    )
    return {
        "schema": CODEX_COMPUTER_USE_REQUEST_SCHEMA,
        "status": "computer_use_requested",
        "event_id": event_name,
        "event": str(extension_request.get("event") or ""),
        "source": source,
        "auth_state_scope": str(
            extension_request.get("auth_state_scope") or ""
        ),
        "challenge_type": str(
            attempt.get("challenge_type")
            or extension_request.get("challenge_type")
            or "unknown_verification"
        ),
        "current_url": current_url,
        "response_path": response_path,
        "timeout_seconds": max(1, int(timeout_seconds)),
        "preauthorized": True,
        "target_url_attestation_required": True,
        "same_ordinary_chrome_session_required": True,
        "single_action_budget": 1,
        "challenge_action_authorization": challenge_contract,
        "interaction_learning": dict(
            extension_request.get("interaction_learning") or {}
        ),
        "external_browser_resume": dict(
            extension_request.get("external_browser_resume") or {}
        ),
        "allowed_capabilities": [
            "identify_target_ordinary_chrome_window",
            "independently_attest_target_host_path",
            "perform_one_preauthorized_visible_click_or_drag",
            "observe_page_progress",
        ],
        "forbidden_capabilities": [
            "read_browser_private_state",
            "read_form_secret_values",
            "blind_coordinate_action_without_url_attestation",
            "repeat_or_refresh_challenge",
        ],
        "expected_response": {
            "schema": CODEX_COMPUTER_USE_RESPONSE_SCHEMA,
            "event_id": event_name,
            "status": "|".join(sorted(CODEX_COMPUTER_USE_STATUSES)),
            "target_url_attested": (
                "true before any Computer Use action"
            ),
            "action": "retry|cooldown|unhandled|manual_pending",
        },
        "created_at": utc_now(),
    }


def validate_codex_computer_use_response(
    response: dict[str, Any],
    request: dict[str, Any],
) -> tuple[bool, str]:
    if response.get("schema") != CODEX_COMPUTER_USE_RESPONSE_SCHEMA:
        return False, "computer_use_invalid_schema"
    event_name = str(request.get("event_id") or "")
    if not response_matches_event(response, event_name):
        return False, "computer_use_event_mismatch"
    status = str(response.get("status") or "").strip().casefold()
    if status not in CODEX_COMPUTER_USE_STATUSES:
        return False, "computer_use_invalid_status"
    action = str(response.get("action") or "").strip().casefold()
    if status in {"computer_use_requested", "computer_use_ready"}:
        if action not in {"", "manual_pending"}:
            return False, "computer_use_pending_status_invalid_action"
        return True, status
    if status == "computer_use_external_session_ready":
        if response.get("target_url_attested") is not True:
            return False, "computer_use_url_attestation_required"
        if action != "retry":
            return False, "computer_use_ready_requires_retry"
        return True, status
    if action not in {"cooldown", "unhandled"}:
        return False, "computer_use_terminal_status_invalid_action"
    return True, status


def challenge_action_attestation_matches_contract(
    attestation: Any,
    contract: dict[str, Any],
) -> bool:
    if not isinstance(attestation, dict):
        return False
    return bool(
        attestation.get("schema") == CODEX_CHALLENGE_ACTION_ATTESTATION_SCHEMA
        and attestation.get("authorization_source") == "run_preauthorization"
        and attestation.get("target_url_attested") is True
        and attestation.get("unique_visible_target") is True
        and attestation.get("page_progress_observed") is True
        and str(attestation.get("action_type") or "").casefold()
        in {"click", "drag"}
        and str(attestation.get("event_id") or "")
        == str(contract.get("event_id") or "")
        and str(attestation.get("challenge_fingerprint") or "")
        == str(contract.get("challenge_fingerprint") or "")
    )


def legacy_challenge_action_confirmation_matches_contract(
    confirmation: Any,
    contract: dict[str, Any],
) -> bool:
    if not isinstance(confirmation, dict):
        return False
    return bool(
        confirmation.get("schema")
        == CODEX_CHALLENGE_ACTION_CONFIRMATION_SCHEMA
        and confirmation.get("decision") == "allow"
        and confirmation.get("confirmed_for_current_event") is True
        and str(confirmation.get("event_id") or "")
        == str(contract.get("event_id") or "")
        and str(confirmation.get("challenge_fingerprint") or "")
        == str(contract.get("challenge_fingerprint") or "")
    )


def validate_challenge_resolution_attestation(
    response: dict[str, Any],
    request: dict[str, Any] | None,
) -> tuple[bool, str]:
    authorization_contract = (
        request.get("challenge_action_authorization")
        if isinstance(request, dict)
        and isinstance(request.get("challenge_action_authorization"), dict)
        else {}
    )
    legacy_contract = (
        request.get("challenge_action_confirmation")
        if isinstance(request, dict)
        and isinstance(request.get("challenge_action_confirmation"), dict)
        else {}
    )
    contract = authorization_contract or legacy_contract
    if contract.get("required") is not True:
        return True, "challenge_action_authorization_not_required"
    resolution = response.get("challenge_resolution")
    if not isinstance(resolution, dict):
        return False, "challenge_resolution_attestation_required"
    if (
        str(resolution.get("event_id") or "")
        != str(contract.get("event_id") or "")
        or str(resolution.get("challenge_fingerprint") or "")
        != str(contract.get("challenge_fingerprint") or "")
    ):
        return False, "challenge_resolution_event_mismatch"
    resolved_by = str(resolution.get("resolved_by") or "").strip().casefold()
    if resolved_by in {
        "authorized_user",
        "page_progress_without_control_action",
        "already_resolved_before_control",
    }:
        return True, "challenge_resolved_without_codex_action"
    if resolved_by not in {"codex_chrome_extension", "codex_computer_use"}:
        return False, "challenge_resolution_actor_invalid"
    if authorization_contract:
        if not challenge_action_attestation_matches_contract(
            resolution.get("action_attestation"),
            contract,
        ):
            return False, "challenge_action_attestation_invalid"
    elif not legacy_challenge_action_confirmation_matches_contract(
        resolution.get("challenge_action_confirmation"),
        contract,
    ):
        return False, "challenge_action_confirmation_invalid"
    if int(resolution.get("action_count") or 0) != 1:
        return False, "challenge_action_count_invalid"
    return True, "challenge_preauthorized_action_valid"


def codex_chrome_capability_attested(response: dict[str, Any]) -> bool:
    attestation = response.get("capability_attestation")
    if not isinstance(attestation, dict):
        return False
    return bool(
        attestation.get("ordinary_chrome_extension_connected") is True
        and attestation.get("full_cdp_access") is True
        and attestation.get("readonly_cdp_probe_method")
        == CODEX_CHROME_READONLY_CDP_PROBE_METHOD
        and attestation.get("readonly_cdp_probe_succeeded") is True
    )


def ordinary_chrome_external_snapshot_paths(
    response: dict[str, Any],
) -> list[str]:
    raw_paths = response.get("sanitized_search_snapshot_paths")
    if isinstance(raw_paths, list):
        paths = [str(value or "").strip() for value in raw_paths]
    else:
        paths = []
    singular = str(response.get("sanitized_search_snapshot_path") or "").strip()
    if singular and singular not in paths:
        paths.insert(0, singular)
    return [value for value in paths if value][:100]


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def validate_ordinary_chrome_snapshot_file(
    path_value: str,
    *,
    root: Path | None,
    expected_source: str,
    expected_keyword: str,
    expected_event_id: str,
    expected_scope: str,
    expected_record_type: str,
) -> tuple[bool, str]:
    try:
        path = Path(path_value).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return False, "ordinary_chrome_snapshot_path_invalid"
    if root is not None and not path_is_within(path, root / "search_snapshots"):
        return False, "ordinary_chrome_snapshot_outside_event_root"
    try:
        if not path.is_file() or path.stat().st_size > 25 * 1024 * 1024:
            return False, "ordinary_chrome_snapshot_missing_or_oversized"
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False, "ordinary_chrome_snapshot_invalid_json"
    if not isinstance(loaded, dict) or loaded.get("schema") != "laps_sanitized_search_snapshot_v1":
        return False, "ordinary_chrome_snapshot_invalid_schema"
    if expected_source and str(loaded.get("source") or "") != expected_source:
        return False, "ordinary_chrome_snapshot_source_mismatch"
    if expected_keyword and str(loaded.get("keyword") or "") != expected_keyword:
        return False, "ordinary_chrome_snapshot_keyword_mismatch"
    if expected_event_id and str(loaded.get("event_id") or "") != expected_event_id:
        return False, "ordinary_chrome_snapshot_event_mismatch"
    if expected_scope and str(loaded.get("auth_state_scope") or "") != expected_scope:
        return False, "ordinary_chrome_snapshot_scope_mismatch"
    if str(loaded.get("search_record_type") or "") != expected_record_type:
        return False, "ordinary_chrome_snapshot_record_type_mismatch"
    html_text = loaded.get("html")
    if not isinstance(html_text, str) or not html_text.strip():
        return False, "ordinary_chrome_snapshot_html_missing"
    if re.search(
        r"<(?:script|style|form|input|textarea|select|button|iframe|object|embed)\b",
        html_text,
        re.IGNORECASE,
    ):
        return False, "ordinary_chrome_snapshot_contains_forbidden_markup"
    final_url = str(loaded.get("final_url") or "")
    try:
        final_parts = urlsplit(final_url)
    except ValueError:
        return False, "ordinary_chrome_snapshot_final_url_invalid"
    if final_parts.scheme != "https" or not final_parts.hostname:
        return False, "ordinary_chrome_snapshot_final_url_invalid"
    return True, "ordinary_chrome_snapshot_valid"


def validate_ordinary_chrome_external_session_response(
    response: dict[str, Any],
    *,
    request: dict[str, Any] | None,
    root: Path | None,
) -> tuple[bool, str]:
    if response.get("external_browser_session") is not True:
        return False, "ordinary_chrome_external_session_flag_required"
    if str(response.get("browser_transport") or "") != ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT:
        return False, "ordinary_chrome_external_session_transport_invalid"
    if response.get("same_browser_handoff") is True:
        return False, "ordinary_chrome_external_session_cannot_be_parent_handoff"
    if str(response.get("storage_state_path") or "").strip():
        return False, "ordinary_chrome_external_session_must_not_claim_storage_state"
    attestation = response.get("external_session_attestation")
    if not isinstance(attestation, dict):
        return False, "ordinary_chrome_external_session_attestation_missing"
    if attestation.get("schema") != ORDINARY_CHROME_EXTERNAL_SESSION_ATTESTATION_SCHEMA:
        return False, "ordinary_chrome_external_session_attestation_invalid"
    event = str(request.get("event") or "").strip().casefold() if isinstance(request, dict) else ""
    if event == "auth_challenge" and attestation.get("authenticated") is not True:
        return False, "ordinary_chrome_external_session_attestation_invalid"
    if event == "search_challenge" and attestation.get("page_access_confirmed") is not True:
        return False, "ordinary_chrome_external_search_page_not_confirmed"

    expected = (
        request.get("external_browser_resume")
        if isinstance(request, dict)
        and isinstance(request.get("external_browser_resume"), dict)
        else {}
    )
    if not expected:
        return False, "ordinary_chrome_external_session_request_contract_missing"
    if not all(str(expected.get(key) or "").strip() for key in ("event_id", "source", "keyword")):
        return False, "ordinary_chrome_external_session_request_contract_invalid"
    if str(request.get("event") or "").casefold() == "auth_challenge" and not all(
        str(expected.get(key) or "").strip()
        for key in ("auth_state_scope", "institution_identity_digest")
    ):
        return False, "ordinary_chrome_external_session_request_contract_invalid"
    comparisons = {
        "event_id": "ordinary_chrome_external_session_event_mismatch",
        "source": "ordinary_chrome_external_session_source_mismatch",
        "auth_state_scope": "ordinary_chrome_external_session_scope_mismatch",
        "institution_identity_digest": (
            "ordinary_chrome_external_session_institution_mismatch"
        ),
    }
    for key, mismatch_reason in comparisons.items():
        expected_value = str(expected.get(key) or "")
        if expected_value and str(attestation.get(key) or "") != expected_value:
            return False, mismatch_reason

    snapshot_paths = ordinary_chrome_external_snapshot_paths(response)
    if not snapshot_paths:
        return False, "ordinary_chrome_external_session_snapshot_required"
    expected_source = str(expected.get("source") or "")
    expected_keyword = str(expected.get("keyword") or "")
    expected_event_id = str(expected.get("event_id") or "")
    expected_scope = str(expected.get("auth_state_scope") or "")
    expected_record_type = str(expected.get("search_record_type") or "literature")
    for path_value in snapshot_paths:
        valid, reason = validate_ordinary_chrome_snapshot_file(
            path_value,
            root=root,
            expected_source=expected_source,
            expected_keyword=expected_keyword,
            expected_event_id=expected_event_id,
            expected_scope=expected_scope,
            expected_record_type=expected_record_type,
        )
        if not valid:
            return False, reason
    return True, "ordinary_chrome_external_session_valid"


def validate_codex_extension_response(
    response: dict[str, Any],
    challenge_type: str = "",
    event: str = "",
    *,
    request: dict[str, Any] | None = None,
    root: Path | None = None,
) -> tuple[bool, str]:
    action = str(response.get("action") or "").strip().casefold()
    if action not in {"retry", "skip", "cooldown", "manual_pending", "unhandled"}:
        return False, "codex_extension_invalid_action"
    raw_preflight_state = response.get("preflight_state")
    preflight_state = normalize_codex_chrome_preflight_state(raw_preflight_state)
    if raw_preflight_state and not preflight_state:
        return False, "codex_chrome_preflight_invalid_state"
    if preflight_state in CODEX_CHROME_SETUP_REQUIRED_STATES and action != "manual_pending":
        return False, "codex_chrome_setup_requires_manual_pending"
    if preflight_state in CODEX_CHROME_SKIP_STATES and action != "skip":
        return False, "codex_chrome_unavailable_requires_skip"
    if preflight_state == "preflight_unavailable" and action not in {
        "manual_pending",
        "unhandled",
    }:
        return False, "codex_chrome_preflight_requires_capability_check"
    if action != "retry":
        return True, action
    challenge_attested, challenge_reason = (
        validate_challenge_resolution_attestation(response, request)
    )
    if not challenge_attested:
        return False, challenge_reason
    if not codex_chrome_capability_attested(response):
        return False, "codex_chrome_ready_requires_current_task_cdp_attestation"

    is_external_session = bool(
        response.get("external_browser_session") is True
        or str(response.get("browser_transport") or "")
        == ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT
    )
    if is_external_session:
        if str(event or "").casefold() not in {
            "auth_challenge",
            "search_challenge",
        }:
            return False, "ordinary_chrome_external_session_event_invalid"
        return validate_ordinary_chrome_external_session_response(
            response,
            request=request,
            root=root,
        )

    storage_path = str(response.get("storage_state_path") or "").strip()
    final_url = str(response.get("final_url") or "").strip()
    candidate_urls = response.get("candidate_urls") or response.get("urls") or []
    if not isinstance(candidate_urls, list):
        candidate_urls = []

    lowered_challenge = str(challenge_type or "").casefold()
    lowered_event = str(event or "").casefold()
    requires_auth_state = lowered_event == "auth_challenge" or lowered_challenge in {"institution_login", "mfa_required"}
    if requires_auth_state and not storage_path:
        return False, "codex_extension_retry_requires_storage_state"
    if lowered_event == "security_challenge" and not (storage_path or final_url or candidate_urls):
        return False, "codex_extension_retry_requires_pdf_or_state"
    if lowered_event == "search_challenge" and not (storage_path or final_url):
        return False, "codex_extension_retry_requires_state_or_final_url"
    return True, "retry"


def hook_root() -> Path:
    configured = os.getenv("CODEX_HOOK_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parent / "events"


def tools_root() -> Path:
    return Path(__file__).resolve().parents[1]


def add_local_package_paths() -> None:
    root = tools_root()
    candidates = [root / "python_packages"]
    venv = root / ".venv"
    candidates.extend((venv / "Lib").glob("site-packages"))
    candidates.extend((venv / "lib").glob("python*/site-packages"))
    for candidate in candidates:
        try:
            if candidate.exists():
                text = str(candidate.resolve())
                if text not in sys.path:
                    sys.path.insert(0, text)
        except Exception:
            continue


def chromium_installed(path: Path) -> bool:
    if not path.exists():
        return False
    markers = list(path.glob("chromium*/INSTALLATION_COMPLETE"))
    markers.extend(path.glob("chromium*/chrome-win*/chrome.exe"))
    markers.extend(path.glob("chromium*/chrome-linux*/chrome"))
    markers.extend(path.glob("chromium*/chrome-mac*/Chromium.app"))
    markers.extend(path.glob("chromium_headless_shell*/INSTALLATION_COMPLETE"))
    markers.extend(path.glob("chromium_headless_shell*/chrome-headless-shell-win64/chrome-headless-shell.exe"))
    return any(marker.exists() for marker in markers)


def configure_playwright_browsers_path() -> None:
    if os.getenv("PLAYWRIGHT_BROWSERS_PATH"):
        return
    for browser_dir in (tools_root() / "playwright-browsers", tools_root() / "ms-playwright"):
        if chromium_installed(browser_dir):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browser_dir)
            return


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact_payload_for_event(payload), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def codex_chrome_open_approved(response: dict[str, Any] | None = None) -> bool:
    if isinstance(response, dict) and response.get("allow_open_ordinary_chrome") is True:
        return True
    return truthy(os.getenv("LAPS_CODEX_CHROME_OPEN_APPROVED"))


def codex_chrome_connect_settle_seconds() -> int:
    return env_int(
        ("LAPS_CODEX_CHROME_CONNECT_SETTLE_SECONDS",),
        DEFAULT_CODEX_CHROME_CONNECT_SETTLE_SECONDS,
        1,
    )


def codex_home_path() -> Path:
    configured = os.getenv("CODEX_HOME", "").strip()
    return Path(configured).expanduser() if configured else Path.home() / ".codex"


def codex_chrome_plugin_root_candidates() -> list[Path]:
    configured = os.getenv("LAPS_CODEX_CHROME_PLUGIN_ROOT", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    cache_root = codex_home_path() / "plugins" / "cache" / "openai-bundled" / "chrome"
    try:
        candidates.extend(
            sorted(
                (path for path in cache_root.iterdir() if path.is_dir()),
                key=lambda path: path.name,
                reverse=True,
            )
        )
    except Exception:
        pass
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            continue
        key = str(resolved).casefold()
        if key not in seen:
            seen.add(key)
            unique.append(resolved)
    return unique


def find_codex_chrome_plugin_root() -> Path | None:
    required_scripts = (
        "check-extension-installed.js",
        "check-native-host-manifest.js",
        "open-chrome-window.js",
    )
    for candidate in codex_chrome_plugin_root_candidates():
        scripts = candidate / "scripts"
        try:
            if all((scripts / name).is_file() for name in required_scripts):
                return candidate
        except Exception:
            continue
    return None


def codex_chrome_node_executable() -> str:
    configured = os.getenv("LAPS_CODEX_CHROME_NODE_EXECUTABLE", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        try:
            if candidate.is_file():
                return str(candidate.resolve())
        except Exception:
            return ""
    return shutil.which("node") or ""


def run_codex_chrome_plugin_script(
    plugin_root: Path,
    script_name: str,
    *args: str,
    timeout_seconds: int = 15,
) -> tuple[int, dict[str, Any] | None, str]:
    node = codex_chrome_node_executable()
    script = plugin_root / "scripts" / script_name
    if not node:
        return -1, None, "node_not_found"
    if not script.is_file():
        return -1, None, "plugin_script_not_found"
    try:
        completed = subprocess.run(
            [node, str(script), *args],
            text=True,
            capture_output=True,
            timeout=max(1, timeout_seconds),
        )
    except subprocess.TimeoutExpired:
        return -1, None, "plugin_script_timeout"
    except Exception as exc:
        return -1, None, f"plugin_script_error:{exc.__class__.__name__}"
    stdout = (completed.stdout or "").strip()
    loaded: dict[str, Any] | None = None
    if stdout:
        try:
            parsed = json.loads(stdout)
            loaded = parsed if isinstance(parsed, dict) else None
        except Exception:
            loaded = None
    reason = "ok" if loaded is not None else "plugin_script_invalid_json"
    return completed.returncode, loaded, reason


def safe_chrome_profile_label(value: Any) -> str:
    label = str(value or "").strip()
    return label if label == "Default" or re.fullmatch(r"Profile \d+", label) else ""


def codex_chrome_local_diagnostics() -> dict[str, Any]:
    plugin_root = find_codex_chrome_plugin_root()
    if plugin_root is None:
        return {
            "state": "preflight_unavailable",
            "reason": "codex_chrome_plugin_tools_not_found",
        }
    extension_code, extension, extension_reason = run_codex_chrome_plugin_script(
        plugin_root,
        "check-extension-installed.js",
        "--json",
    )
    if extension is None:
        return {
            "state": "preflight_unavailable",
            "reason": extension_reason,
        }
    installed = extension.get("installed") is True
    enabled = extension.get("enabled") is True
    selected_profile = safe_chrome_profile_label(
        extension.get("selectedProfileDirectory")
    )
    if not installed or extension_code == 2:
        return {
            "state": "chrome_plugin_install_required",
            "reason": "codex_chrome_plugin_not_installed",
            "selected_profile": selected_profile,
        }
    if not enabled or extension_code != 0:
        return {
            "state": "chrome_plugin_connect_required",
            "reason": "codex_chrome_plugin_not_enabled",
            "selected_profile": selected_profile,
        }
    _, native_host, native_reason = run_codex_chrome_plugin_script(
        plugin_root,
        "check-native-host-manifest.js",
        "--json",
    )
    if native_host is None:
        return {
            "state": "chrome_plugin_connect_required",
            "reason": native_reason,
            "selected_profile": selected_profile,
        }
    if native_host.get("correct") is not True:
        return {
            "state": "chrome_plugin_connect_required",
            "reason": "codex_chrome_native_host_not_ready",
            "selected_profile": selected_profile,
        }
    return {
        "state": "chrome_plugin_connect_required",
        "reason": "ordinary_chrome_can_be_opened",
        "selected_profile": selected_profile,
        "plugin_root": plugin_root,
    }


def codex_ordinary_chrome_open_marker_path(root: Path) -> Path:
    return root / "control_state" / "codex_ordinary_chrome_open.json"


def open_ordinary_chrome_for_codex(
    root: Path,
    event_name: str,
    approval_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    marker_path = codex_ordinary_chrome_open_marker_path(root)
    if marker_path.exists():
        return {
            "opened": False,
            "already_opened": True,
            "reason": "ordinary_chrome_already_opened_for_current_run",
        }
    if not codex_chrome_open_approved(approval_response):
        return {
            "opened": False,
            "already_opened": False,
            "reason": "ordinary_chrome_open_approval_required",
        }
    if find_local_chrome() is None:
        return {
            "opened": False,
            "already_opened": False,
            "reason": "local_chrome_not_found",
            "preflight_state": "local_chrome_not_found",
        }
    diagnostics = codex_chrome_local_diagnostics()
    plugin_root = diagnostics.pop("plugin_root", None)
    if not isinstance(plugin_root, Path):
        return {
            "opened": False,
            "already_opened": False,
            **diagnostics,
        }
    returncode, opened, reason = run_codex_chrome_plugin_script(
        plugin_root,
        "open-chrome-window.js",
        "--json",
    )
    if returncode != 0 or opened is None:
        return {
            "opened": False,
            "already_opened": False,
            "reason": reason if opened is None else "ordinary_chrome_open_failed",
            "preflight_state": "chrome_plugin_connect_required",
        }
    selected_profile = safe_chrome_profile_label(
        opened.get("profileDirectory") or diagnostics.get("selected_profile")
    )
    marker = {
        "schema": CODEX_CHROME_OPEN_MARKER_SCHEMA,
        "opened": True,
        "reason": "ordinary_chrome_opened_for_codex_connection",
        "event_name": event_name,
        "selected_profile": selected_profile,
        "scope": "current_hook_root",
        "created_at": utc_now(),
    }
    write_json(marker_path, marker)
    return dict(marker)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(redact_payload_for_event(payload), ensure_ascii=False) + "\n")


INTERACTION_TRACE_SCHEMA = "laps_auth_interaction_trace_v1"
INTERACTION_TRACE_BINDING = "__lapsRecordInteraction"
INTERACTION_TRACE_INIT_SCRIPT = r"""
(() => {
  if (window.__lapsInteractionTraceInstalled) return;
  window.__lapsInteractionTraceInstalled = true;
  const clipped = (value, limit = 180) => String(value || "").trim().replace(/\s+/g, " ").slice(0, limit);
  const escaped = (value) => {
    try { return CSS.escape(String(value || "")); } catch (_) { return String(value || "").replace(/[^A-Za-z0-9_-]/g, "_"); }
  };
  const selectors = (element) => {
    const values = [];
    const tag = String(element.tagName || "").toLowerCase();
    const id = element.getAttribute("id") || "";
    const testId = element.getAttribute("data-testid") || element.getAttribute("data-test-id") || "";
    const name = element.getAttribute("name") || "";
    const aria = element.getAttribute("aria-label") || "";
    const role = element.getAttribute("role") || "";
    if (id) values.push(`#${escaped(id)}`);
    if (testId) values.push(`[data-testid="${clipped(testId, 100).replace(/"/g, '\\"')}"]`);
    if (tag && name) values.push(`${tag}[name="${clipped(name, 100).replace(/"/g, '\\"')}"]`);
    if (tag && aria) values.push(`${tag}[aria-label="${clipped(aria, 120).replace(/"/g, '\\"')}"]`);
    if (tag && role) values.push(`${tag}[role="${clipped(role, 60).replace(/"/g, '\\"')}"]`);
    const classes = Array.from(element.classList || []).filter(Boolean).slice(0, 3).map(escaped);
    if (tag && classes.length) values.push(`${tag}.${classes.join(".")}`);
    return Array.from(new Set(values)).slice(0, 6);
  };
  document.addEventListener("click", (event) => {
    const path = typeof event.composedPath === "function" ? event.composedPath() : [event.target];
    const element = path.find((candidate) => candidate && candidate.nodeType === 1);
    if (!element || typeof window["__lapsRecordInteraction"] !== "function") return;
    const now = Date.now();
    const marker = window.__lapsAutomationClickMarker;
    const automated = Boolean(marker && Number(marker.expires_at || 0) >= now);
    if (automated) window.__lapsAutomationClickMarker = null;
    const href = element.href || element.getAttribute("href") || "";
    Promise.resolve(window["__lapsRecordInteraction"]({
      event_type: "click",
      actor: automated ? "hook_automation" : "external_input",
      action_id: automated ? String(marker.action_id || "") : "",
      action_kind: automated ? String(marker.action_kind || "") : "",
      selector_hint: automated ? String(marker.selector_hint || "") : "",
      page_url: String(location.href || ""),
      element: {
        tag: String(element.tagName || "").toLowerCase(),
        role: element.getAttribute("role") || "",
        type: element.getAttribute("type") || "",
        id: element.getAttribute("id") || "",
        name: element.getAttribute("name") || "",
        aria_label: element.getAttribute("aria-label") || "",
        title: element.getAttribute("title") || "",
        test_id: element.getAttribute("data-testid") || element.getAttribute("data-test-id") || "",
        href: String(href || ""),
        text: clipped(element.innerText || element.textContent || ""),
        selector_candidates: selectors(element)
      }
    })).catch(() => {});
  }, true);
})();
"""


def interaction_trace_enabled(payload: dict[str, Any]) -> bool:
    event = str(payload.get("event") or "")
    enabled = os.getenv(
        "LAPS_VERIFICATION_INTERACTION_TRACE_ENABLED",
        os.getenv("LAPS_AUTH_INTERACTION_TRACE_ENABLED", ""),
    )
    return event in {"auth_challenge", "search_challenge", "security_challenge"} and truthy(enabled)


def interaction_trace_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def interaction_trace_text(value: Any, payload: dict[str, Any], limit: int = 180) -> str:
    text = " ".join(str(value or "").split())[:limit]
    school_values = [str(payload.get("school") or "")]
    if isinstance(payload.get("school_aliases"), (list, tuple)):
        school_values.extend(str(value or "") for value in payload["school_aliases"])
    replacements = (
        *((value, "<configured_school>") for value in school_values),
        (str(payload.get("raw_account") or ""), "<configured_account>"),
        (str(payload.get("raw_password") or ""), "<configured_password>"),
    )
    for secret, replacement in replacements:
        if secret:
            text = re.sub(re.escape(secret), replacement, text, flags=re.IGNORECASE)
    return redact_persisted_string(text)


def sanitized_interaction_element(value: Any, payload: dict[str, Any]) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    output: dict[str, Any] = {}
    for key in ("tag", "role", "type", "id", "name", "aria_label", "title", "test_id", "text"):
        output[key] = interaction_trace_text(raw.get(key), payload)
    output["href"] = sanitize_url_for_event(raw.get("href"))
    selectors = raw.get("selector_candidates") if isinstance(raw.get("selector_candidates"), list) else []
    output["selector_candidates"] = [
        interaction_trace_text(selector, payload, 220) for selector in selectors[:6]
    ]
    return output


def stable_external_auth_submit_interaction(element: Any, stage: str = "") -> bool:
    value = element if isinstance(element, dict) else {}
    element_id = str(value.get("id") or "").strip().casefold()
    element_name = str(value.get("name") or "").strip().casefold()
    selectors = {
        str(selector or "").strip().casefold()
        for selector in value.get("selector_candidates", [])
        if isinstance(selector, str)
    }
    stable_ids = {
        "login_submit",
        "login-submit",
        "loginbutton",
        "login-button",
    }
    if element_id in stable_ids or any(
        selector in {f"#{stable_id}" for stable_id in stable_ids}
        for selector in selectors
    ):
        return True
    if stage != "idp_login":
        return False
    element_type = str(value.get("type") or "").strip().casefold()
    label = " ".join(
        str(value.get(key) or "").strip()
        for key in ("text", "aria_label", "title")
    ).casefold()
    normalized_label = re.sub(r"\s+", " ", label).strip()
    return bool(
        element_type == "submit"
        and (
            element_name in {"login", "login_submit", "signin", "sign-in"}
            or normalized_label in {"login", "log in", "sign in", "登录", "登 录"}
        )
    )


def next_interaction_sequence(trace: dict[str, Any]) -> int:
    trace["sequence"] = int(trace.get("sequence") or 0) + 1
    return int(trace["sequence"])


def append_interaction_record(trace: dict[str, Any] | None, record: dict[str, Any]) -> None:
    if trace is None:
        return
    sequence = next_interaction_sequence(trace)
    if not trace.get("persist"):
        return
    payload = trace["payload"]
    base = {
        "schema": INTERACTION_TRACE_SCHEMA,
        "sequence": sequence,
        "created_at": interaction_trace_timestamp(),
        "event_id": trace["event_name"],
        "source": str(payload.get("source") or payload.get("channel") or ""),
        "auth_state_scope": str(payload.get("auth_state_scope") or ""),
        "auth_entry_id": str(payload.get("auth_entry_id") or ""),
        "browser": trace["browser_name"],
    }
    append_jsonl(trace["path"], {**base, **record})


def install_interaction_trace(
    context: Any,
    root: Path,
    event_name: str,
    payload: dict[str, Any],
    browser_name: str,
) -> dict[str, Any] | None:
    trace: dict[str, Any] = {
        "path": root / "interactions" / f"{event_name}_{browser_name}.jsonl",
        "event_name": event_name,
        "payload": payload,
        "browser_name": browser_name,
        "sequence": 0,
        "last_stage": "",
        "last_url": "",
        "last_external": None,
        "external_auth_form_submitted": False,
        "persist": interaction_trace_enabled(payload),
        "manual_pause_sequence": 0,
    }

    def receive(source: dict[str, Any], event: Any) -> None:
        raw = event if isinstance(event, dict) else {}
        actor = str(raw.get("actor") or "external_input")
        frame = source.get("frame") if isinstance(source, dict) else None
        frame_url = sanitize_url_for_event(getattr(frame, "url", ""))
        record = {
            "event_type": "click",
            "actor": actor,
            "action_id": interaction_trace_text(raw.get("action_id"), payload, 100),
            "action_kind": interaction_trace_text(raw.get("action_kind"), payload, 100),
            "selector_hint": interaction_trace_text(raw.get("selector_hint"), payload, 220),
            "page_url": sanitize_url_for_event(raw.get("page_url")),
            "frame_url": frame_url,
            "stage": str(trace.get("last_stage") or ""),
            "element": sanitized_interaction_element(raw.get("element"), payload),
        }
        append_interaction_record(trace, record)
        if actor == "external_input":
            if stable_external_auth_submit_interaction(record["element"], record["stage"]):
                trace["external_auth_form_submitted"] = True
            trace["last_external"] = {
                "monotonic": time.monotonic(),
                "before_stage": str(trace.get("last_stage") or ""),
                "before_url": str(trace.get("last_url") or ""),
                "click_sequence": int(trace.get("sequence") or 0),
                "element": record["element"],
                "effective": False,
            }

    try:
        context.expose_binding(INTERACTION_TRACE_BINDING, receive)
        context.add_init_script(INTERACTION_TRACE_INIT_SCRIPT)
        append_interaction_record(trace, {"event_type": "trace_started", "actor": "system"})
        return trace
    except Exception as exc:
        write_json(
            root / "errors" / f"{event_name}_{browser_name}_interaction_trace.json",
            {"error_type": exc.__class__.__name__, "error": repr(exc), "created_at": utc_now()},
        )
        return None


def record_untraced_verification_completion(
    trace: dict[str, Any] | None,
    challenge_type: str,
    final_url: str,
) -> None:
    if trace is None:
        return
    append_interaction_record(
        trace,
        {
            "event_type": "verification_cleared_without_traced_automation",
            "actor": "external_or_user_input",
            "challenge_type": challenge_type,
            "page_url": sanitize_url_for_event(final_url),
            "resolution_stable_seconds": verification_resolution_stable_seconds(),
        },
    )


def external_intervention_grace_seconds(payload: dict[str, Any]) -> float:
    raw = payload.get("external_intervention_grace_seconds")
    if raw is None:
        raw = os.getenv("LAPS_AUTH_EXTERNAL_INTERVENTION_GRACE_SECONDS", "10")
    try:
        return max(0.0, min(900.0, float(str(raw))))
    except Exception:
        return 10.0


def external_intervention_pause_remaining(
    trace: dict[str, Any] | None,
    *,
    now: float | None = None,
) -> float:
    if trace is None:
        return 0.0
    last_external = trace.get("last_external")
    if not isinstance(last_external, dict):
        return 0.0
    grace = external_intervention_grace_seconds(trace.get("payload") or {})
    current = time.monotonic() if now is None else now
    return max(0.0, grace - max(0.0, current - float(last_external.get("monotonic") or 0.0)))


def pause_for_external_intervention(page: Any, trace: dict[str, Any] | None) -> bool:
    if trace is None:
        return False
    remaining = external_intervention_pause_remaining(trace)
    last_external = trace.get("last_external") if isinstance(trace.get("last_external"), dict) else {}
    sequence = int(last_external.get("click_sequence") or 0)
    if remaining <= 0:
        active_sequence = int(trace.get("manual_pause_sequence") or 0)
        if active_sequence:
            append_interaction_record(
                trace,
                {
                    "event_type": "manual_control_pause_ended",
                    "actor": "system",
                    "click_sequence": active_sequence,
                },
            )
            trace["manual_pause_sequence"] = 0
        return False
    if int(trace.get("manual_pause_sequence") or 0) != sequence:
        append_interaction_record(
            trace,
            {
                "event_type": "manual_control_pause_started",
                "actor": "system",
                "click_sequence": sequence,
                "grace_seconds": external_intervention_grace_seconds(trace.get("payload") or {}),
            },
        )
        trace["manual_pause_sequence"] = sequence
    try:
        page.wait_for_timeout(min(500, max(100, int(remaining * 1000))))
    except Exception:
        time.sleep(min(0.5, remaining))
    return True


def mark_automation_click(locator: Any, action_kind: str, selector_hint: str = "") -> None:
    marker = {
        "action_id": f"{time.time_ns()}_{os.getpid()}",
        "action_kind": action_kind,
        "selector_hint": selector_hint,
        "expires_at": int(time.time() * 1000) + 2000,
    }
    try:
        locator.evaluate("(element, value) => { window.__lapsAutomationClickMarker = value; }", marker)
    except Exception:
        pass


def mark_page_automation_click(page: Any, action_kind: str, selector_hint: str = "") -> None:
    marker = {
        "action_id": f"{time.time_ns()}_{os.getpid()}",
        "action_kind": action_kind,
        "selector_hint": selector_hint,
        "expires_at": int(time.time() * 1000) + 2000,
    }
    for frame in getattr(page, "frames", []):
        try:
            frame.evaluate("value => { window.__lapsAutomationClickMarker = value; }", marker)
        except Exception:
            continue


def click_traced_locator(
    locator: Any,
    timeout_ms: int,
    action_kind: str,
    selector_hint: str = "",
    *,
    no_wait_after: bool = False,
) -> None:
    mark_automation_click(locator, action_kind, selector_hint)
    if no_wait_after:
        locator.click(timeout=timeout_ms, no_wait_after=True)
    else:
        locator.click(timeout=timeout_ms)


def classify_interaction_stage(text: str, final_url: str, challenge_type: str, event: str) -> str:
    if event != "auth_challenge":
        return challenge_type or "verification"
    lowered = " ".join((text or "", final_url or "")).casefold()
    if has_hard_access_blocker(text):
        return "blocked"
    if challenge_type == "mfa_required":
        return "mfa"
    if any(marker in lowered for marker in ("signed in", "sign out", "log out", "logout", "access provided by")):
        return "authenticated"
    if any(marker in lowered for marker in ("password", "authserver", "/saml", "idp", "single sign-on", "single sign on")):
        return "idp_login"
    if any(marker in lowered for marker in ("find your organization", "search institution", "search organization", "select your institution", "choose your institution")):
        return "institution_search"
    if any(marker in lowered for marker in ("institutional login", "access through your institution", "sign in via your organization", "openathens", "shibboleth", "carsi")):
        return "institution_entry"
    return "public_page"


def record_interaction_stage(
    trace: dict[str, Any] | None,
    stage: str,
    final_url: str,
    challenge_type: str,
) -> None:
    if trace is None:
        return
    sanitized_url = sanitize_url_for_event(final_url)
    previous_stage = str(trace.get("last_stage") or "")
    previous_url = str(trace.get("last_url") or "")
    changed = stage != previous_stage or sanitized_url != previous_url
    if changed:
        append_interaction_record(
            trace,
            {
                "event_type": "stage_transition",
                "actor": "system",
                "from_stage": previous_stage,
                "stage": stage,
                "page_url": sanitized_url,
                "challenge_type": challenge_type,
            },
        )
    external = trace.get("last_external")
    if (
        changed
        and isinstance(external, dict)
        and not external.get("effective")
        and time.monotonic() - float(external.get("monotonic") or 0) <= 10
        and (stage != external.get("before_stage") or sanitized_url != external.get("before_url"))
    ):
        external["effective"] = True
        append_interaction_record(
            trace,
            {
                "event_type": "effective_external_intervention",
                "actor": "external_input",
                "click_sequence": external.get("click_sequence"),
                "from_stage": external.get("before_stage"),
                "stage": stage,
                "page_url": sanitized_url,
                "element": external.get("element"),
            },
        )
    trace["last_stage"] = stage
    trace["last_url"] = sanitized_url


def read_payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    loaded = json.loads(raw)
    return loaded if isinstance(loaded, dict) else {}


def compact_event_id(value: str) -> str:
    safe = str(value or "").strip("-_")
    if len(safe) <= HOOK_EVENT_ID_MAX_LENGTH:
        return safe
    digest = hashlib.sha1(safe.encode("utf-8", "replace")).hexdigest()[:12]
    prefix_length = HOOK_EVENT_ID_MAX_LENGTH - len(digest) - 1
    prefix = safe[:prefix_length].rstrip("-_")
    return f"{prefix}_{digest}"


def event_id(payload: dict[str, Any]) -> str:
    configured = str(payload.get("event_id") or "").strip()
    if configured:
        safe_configured = redact_persisted_string(configured)
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in safe_configured)[:120]
        return compact_event_id(safe or "redacted_event")
    event_payload = redact_payload_for_event(payload)
    basis = json.dumps(event_payload, ensure_ascii=False, sort_keys=True) + utc_now() + str(os.getpid())
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]
    event = str(event_payload.get("event") or "hook")
    channel = str(event_payload.get("channel") or "unknown")
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in f"{event}_{channel}")[:80]
    return compact_event_id(f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe}_{digest}")


def _verification_request_binding(
    payload: dict[str, Any],
    event_name: str,
) -> tuple[str, dict[str, str]]:
    """Project a legacy request into the v2 binding without persisting secrets."""

    event = str(payload.get("event") or "").strip()
    configured_binding = payload.get("binding")
    binding = dict(configured_binding) if isinstance(configured_binding, dict) else {}
    producer = str(binding.get("producer") or payload.get("producer") or "").casefold()
    if producer not in {"search", "download"}:
        producer = "search" if event == "search_challenge" or payload.get("keyword") else "download"
    source = str(payload.get("source") or payload.get("channel") or "").strip()
    record_id = str(payload.get("record_id") or binding.get("record_id") or "").strip()
    run_id = str(payload.get("run_id") or binding.get("run_id") or "").strip()
    search_job_id = str(
        payload.get("search_job_id") or binding.get("search_job_id") or ""
    ).strip()
    auth_check_id = str(
        payload.get("auth_check_id") or binding.get("auth_check_id") or ""
    ).strip()
    if producer == "download" and not run_id:
        # Transitional identity for a v1 caller.  New callers supply the real
        # logical run ID; the event-bound fallback still prevents cross-event
        # replay while the CLI integration is being upgraded.
        run_id = f"hook-{event_name}"
    if producer == "download" and event != "auth_challenge" and not record_id:
        record_id = f"hook-{event_name}"
    if producer == "search" and not search_job_id and not auth_check_id:
        search_job_id = f"hook-{event_name}"
    if event == "auth_challenge" and not record_id and not auth_check_id:
        auth_check_id = f"hook-{event_name}"
    principal_basis = "|".join(
        str(payload.get(field) or "")
        for field in ("school", "account", "auth_entry_id", "auth_entry_mode")
    )
    keyword = str(payload.get("keyword") or payload.get("title") or "")
    cursor = payload.get("cursor") or payload.get("next_cursor") or payload.get("page") or ""
    selected_binding = {
        **{key: str(value or "") for key, value in binding.items()},
        "producer": producer,
        "run_id": run_id,
        "search_job_id": search_job_id,
        "auth_check_id": auth_check_id,
        "record_id": record_id,
        "record_type": str(
            payload.get("search_record_type")
            or payload.get("record_type")
            or binding.get("record_type")
            or ""
        ),
        "source": source,
        "planned_channel": str(
            payload.get("planned_channel")
            or payload.get("channel")
            or binding.get("planned_channel")
            or ""
        ),
        "auth_state_scope": str(
            payload.get("auth_state_scope") or binding.get("auth_state_scope") or ""
        ),
        "auth_mode": str(
            payload.get("auth_entry_mode")
            or payload.get("auth_path")
            or binding.get("auth_mode")
            or ""
        ),
        "principal_digest": str(
            binding.get("principal_digest")
            or payload.get("principal_digest")
            or protocol_value_digest(principal_basis)
        ),
        "access_mode": str(
            payload.get("access_mode") or binding.get("access_mode") or ""
        ),
        "query_variant": str(
            payload.get("query_variant") or binding.get("query_variant") or ""
        ),
        "query_digest": str(
            binding.get("query_digest")
            or payload.get("query_digest")
            or protocol_value_digest(keyword)
        ),
        "cursor_digest": str(
            binding.get("cursor_digest")
            or payload.get("cursor_digest")
            or protocol_value_digest(cursor)
        ),
        "candidate_id": str(
            payload.get("candidate_id") or binding.get("candidate_id") or ""
        ),
        "challenge_url_digest": str(
            binding.get("challenge_url_digest")
            or payload.get("challenge_url_digest")
            or ""
        ),
        "resume_url_digest": str(
            binding.get("resume_url_digest")
            or payload.get("resume_url_digest")
            or ""
        ),
    }
    return producer, selected_binding


def ensure_verification_request_v2(
    payload: dict[str, Any],
    event_name: str,
) -> dict[str, Any]:
    """Return a validated v2 request, upgrading a legacy synchronous input."""

    if payload.get("schema") == VERIFICATION_REQUEST_SCHEMA:
        validation = validate_verification_request(payload)
        if not validation.valid:
            raise ValueError(validation.reason_code)
        return dict(payload)
    producer, binding = _verification_request_binding(payload, event_name)
    timeout_values: list[int] = []
    for field in (
        "timeout_seconds",
        "manual_wait_seconds",
        "external_handoff_timeout_seconds",
    ):
        try:
            timeout_values.append(int(payload.get(field) or 0))
        except (TypeError, ValueError):
            continue
    ttl_seconds = max([10, *timeout_values])
    raw_challenge_url = str(
        payload.get("raw_current_url")
        or payload.get("raw_candidate_url")
        or payload.get("current_url")
        or payload.get("candidate_url")
        or ""
    )
    raw_resume_url = str(
        payload.get("raw_resume_url")
        or payload.get("resume_url")
        or payload.get("source_resume_url")
        or payload.get("source_search_url")
        or ""
    )
    return build_verification_request(
        event=str(payload.get("event") or ""),
        event_id=event_name,
        producer=producer,
        binding=binding,
        ttl_seconds=ttl_seconds,
        public_fields=payload,
        created_at=str(payload.get("created_at") or utc_now()),
        challenge_url=raw_challenge_url,
        resume_url=raw_resume_url,
    )


def _protocol_test_file_fixture_url(value: Any) -> bool:
    if not truthy(os.getenv("LAPS_VERIFICATION_PROTOCOL_TEST_MODE")):
        return False
    try:
        return urlsplit(str(value or "")).scheme.casefold() == "file"
    except ValueError:
        return False


def _legacy_response_evidence(response: dict[str, Any]) -> dict[str, Any]:
    urls = response.get("candidate_urls") or response.get("urls") or []
    if isinstance(urls, str):
        urls = [urls]
    snapshots = response.get("sanitized_search_snapshot_paths") or []
    if not snapshots and response.get("sanitized_search_snapshot_path"):
        snapshots = [response.get("sanitized_search_snapshot_path")]
    if isinstance(snapshots, str):
        snapshots = [snapshots]
    state_path = str(response.get("storage_state_path") or "").strip()
    state_sha = str(response.get("storage_state_sha256") or "").strip().casefold()
    if state_path and not state_sha:
        try:
            state_sha = protocol_sha256_file(Path(state_path).expanduser().resolve(strict=True))
        except (OSError, RuntimeError):
            state_sha = ""
    resolution = response.get("challenge_resolution")
    candidate_urls = [str(value) for value in urls if str(value).strip()]
    final_url = str(response.get("final_url") or "").strip()
    if truthy(os.getenv("LAPS_VERIFICATION_PROTOCOL_TEST_MODE")):
        # Local browser fixtures may start at file://, but a bound response
        # must never turn that fixture path into an executable URL.
        candidate_urls = [
            value
            for value in candidate_urls
            if not _protocol_test_file_fixture_url(value)
        ]
        if _protocol_test_file_fixture_url(final_url):
            final_url = ""
    return {
        "candidate_urls": candidate_urls,
        "final_url": final_url,
        "storage_state_path": state_path,
        "storage_state_sha256": state_sha,
        "external_browser_session": response.get("external_browser_session") is True,
        "browser_transport": str(response.get("browser_transport") or ""),
        "external_session_attestation": response.get("external_session_attestation")
        if isinstance(response.get("external_session_attestation"), dict)
        else {},
        "capability_attestation": response.get("capability_attestation")
        if isinstance(response.get("capability_attestation"), dict)
        else {},
        "sanitized_search_snapshot_paths": [
            str(value) for value in snapshots if str(value).strip()
        ],
        "challenge_resolution": resolution if isinstance(resolution, dict) else {},
    }


def bind_hook_response_v2(
    request: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, Any]:
    """Bind a hook result while retaining legacy top-level response fields."""

    if response.get("schema") == VERIFICATION_RESPONSE_SCHEMA:
        flattened = flatten_verification_response_v2(response)
        if not flattened.get("reason") or flattened.get("reason") == "codex_hook_response":
            flattened["reason"] = str(flattened.get("reason_code") or "")
        return flattened
    reason = str(response.get("reason_code") or response.get("reason") or "").strip()
    action = str(response.get("action") or "unhandled").strip().casefold()
    retry_at = str(response.get("retry_at") or "").strip()
    if action == "cooldown" and not retry_at:
        try:
            cooldown_seconds = max(
                1,
                int(
                    response.get("cooldown_seconds")
                    or verification_browser_fallback_cooldown_seconds()
                ),
            )
        except (TypeError, ValueError):
            cooldown_seconds = verification_browser_fallback_cooldown_seconds()
        retry_at = (
            datetime.now(timezone.utc) + timedelta(seconds=cooldown_seconds)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
    bound = build_verification_response(
        request,
        action=action,
        reason_code=reason,
        category=str(response.get("category") or ""),
        retryable=bool(response.get("retryable", action == "retry")),
        retry_at=retry_at,
        evidence=_legacy_response_evidence(response),
    )
    # Legacy top-level fields remain diagnostic compatibility output.  Only
    # the normalized v2 evidence below is executable by search/download.
    merged = dict(response)
    merged.update(bound)
    merged.setdefault("reason", reason)
    for key, value in bound["evidence"].items():
        merged.setdefault(key, value)
    return merged


def flatten_verification_response_v2(response: dict[str, Any]) -> dict[str, Any]:
    flattened = dict(response)
    evidence = response.get("evidence")
    if isinstance(evidence, dict):
        for key, value in evidence.items():
            flattened.setdefault(key, value)
    flattened.setdefault("reason", str(response.get("reason_code") or ""))
    return flattened


def wait_for_bound_verification_response(
    root: Path,
    request: dict[str, Any],
    seconds: int,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + max(0, seconds)
    while time.monotonic() < deadline:
        loaded = read_bound_verification_response(root / "responses", request)
        if loaded.payload is not None:
            validated, _ = validate_bound_hook_response(root, request, loaded.payload)
            if validated is not None:
                return validated
        time.sleep(1)
    return None


def verification_protocol_url_allowed(url: str) -> bool:
    # Response candidates/final URLs always use the production network
    # boundary.  The hook's separate initial file-fixture navigation path may
    # remain available in explicit test mode, but it cannot mint an executable
    # file:// challenge response.
    return outbound_http_url_allowed(url)


def validate_bound_hook_response(
    root: Path,
    request: dict[str, Any],
    response: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    validation = validate_verification_response(
        request,
        response,
        controlled_roots=[root],
        url_validator=verification_protocol_url_allowed,
        consume=False,
    )
    if not validation.valid or validation.payload is None:
        return None, validation.reason_code
    return flatten_verification_response_v2(validation.payload), validation.reason_code


def wait_for_response(root: Path, event_name: str, seconds: int) -> dict[str, Any] | None:
    candidates = [root / "responses" / f"{event_name}.json", root / "responses" / "latest.json"]
    return wait_for_response_paths(
        candidates,
        seconds,
        expected_event_id=event_name,
    )


def wait_for_response_paths(
    candidates: list[Path],
    seconds: int,
    ignored_fingerprints: set[str] | None = None,
    expected_event_id: str = "",
) -> dict[str, Any] | None:
    deadline = time.monotonic() + max(0, seconds)
    while time.monotonic() < deadline:
        response = read_response_candidates(
            candidates,
            expected_event_id=expected_event_id,
        )
        if response is not None and (
            not ignored_fingerprints
            or codex_chrome_response_fingerprint(response)
            not in ignored_fingerprints
        ):
            return response
        time.sleep(1)
    return None


def read_response_candidates(
    candidates: list[Path],
    *,
    expected_event_id: str = "",
) -> dict[str, Any] | None:
    for candidate in candidates:
        if candidate.exists():
            try:
                loaded = json.loads(candidate.read_text(encoding="utf-8-sig"))
                if isinstance(loaded, dict):
                    if expected_event_id and not response_matches_event(
                        loaded,
                        expected_event_id,
                    ):
                        continue
                    try:
                        write_json(candidate, loaded)
                    except Exception:
                        pass
                    return loaded
            except Exception:
                pass
    return None


def response_candidate_paths(root: Path, event_name: str, payload: dict[str, Any]) -> list[Path]:
    candidates: list[Path] = []
    configured = str(payload.get("response_path") or "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend([root / "responses" / f"{event_name}.json", root / "responses" / "latest.json"])
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def ordinary_chrome_handoff_confirmation_paths(
    root: Path,
    event_name: str,
) -> tuple[Path, Path]:
    request_path = (
        root
        / "extension_requests"
        / f"{event_name}.ordinary_chrome_confirmation.json"
    )
    response_path = (
        root
        / "extension_responses"
        / f"{event_name}.ordinary_chrome_confirmation.json"
    )
    return request_path, response_path


def wait_for_ordinary_chrome_handoff_confirmation(
    payload: dict[str, Any],
    root: Path,
    event_name: str,
    attempt: dict[str, Any],
) -> tuple[bool, str, dict[str, Any] | None]:
    request_path, response_path = ordinary_chrome_handoff_confirmation_paths(
        root,
        event_name,
    )
    timeout_seconds = codex_chrome_handoff_confirm_timeout_seconds()
    request = {
        "schema": CODEX_CHROME_HANDOFF_CONFIRMATION_SCHEMA,
        "event_id": event_name,
        "event": str(payload.get("event") or ""),
        "source": str(payload.get("source") or payload.get("channel") or ""),
        "challenge_type": str(
            attempt.get("challenge_type")
            or payload.get("challenge_type")
            or "unknown_verification"
        ),
        "current_url": sanitize_url_for_extension(
            attempt.get("final_url")
            or payload.get("current_url")
            or payload.get("raw_current_url")
        ),
        "playwright_result": str(
            attempt.get("reason") or "playwright_chrome_unresolved"
        ),
        "response_path": str(response_path),
        "requires_explicit_response": True,
        "confirmation_timeout_seconds": timeout_seconds,
        "prompt": (
            "Playwright Chrome could not resolve this verification. "
            "Allow this event to continue in ordinary Chrome with the Codex "
            "Chrome extension and full CDP?"
        ),
        "expected_response": {
            "schema": CODEX_CHROME_HANDOFF_CONFIRMATION_SCHEMA,
            "event_id": event_name,
            "decision": "allow|decline",
            "allow_ordinary_chrome_handoff": "true for allow; false for decline",
        },
        "created_at": utc_now(),
    }
    write_json(request_path, request)
    response = wait_for_response_paths([response_path], timeout_seconds)
    if response is None:
        return False, "ordinary_chrome_handoff_confirmation_timeout", None
    if response.get("schema") != CODEX_CHROME_HANDOFF_CONFIRMATION_SCHEMA:
        return False, "ordinary_chrome_handoff_confirmation_invalid_schema", response
    if str(response.get("event_id") or "") != event_name:
        return False, "ordinary_chrome_handoff_confirmation_event_mismatch", response
    decision = str(response.get("decision") or "").strip().casefold()
    allowed = response.get("allow_ordinary_chrome_handoff") is True
    declined = response.get("allow_ordinary_chrome_handoff") is False
    if decision == "allow" and allowed:
        approved_response = dict(response)
        approved_response.setdefault("allow_open_ordinary_chrome", True)
        return True, "ordinary_chrome_handoff_approved", approved_response
    if decision == "decline" and declined:
        return False, "ordinary_chrome_handoff_declined", response
    return False, "ordinary_chrome_handoff_confirmation_invalid_decision", response


def codex_extension_control_hook_command() -> list[str]:
    raw = os.getenv("LAPS_CODEX_EXTENSION_CONTROL_HOOK", "").strip()
    if not raw:
        return []
    return [
        part.strip('"')
        for part in shlex.split(raw, posix=os.name != "nt")
        if part.strip('"')
    ]


def run_codex_extension_control_hook(request: dict[str, Any], timeout_seconds: int) -> dict[str, Any] | None:
    command = codex_extension_control_hook_command()
    if not command:
        return None
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(request, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"action": "unhandled", "reason": "codex_extension_handoff_timeout"}
    except Exception as exc:
        return {"action": "skip", "reason": f"codex_extension_handoff_unavailable:{exc.__class__.__name__}"}
    if completed.returncode != 0:
        return {"action": "skip", "reason": f"codex_extension_handoff_unavailable:exit_{completed.returncode}"}
    stdout = (completed.stdout or "").strip()
    if not stdout:
        return None
    try:
        loaded = json.loads(stdout)
    except Exception:
        return {"action": "unhandled", "reason": "codex_extension_handoff_unhandled:non_json_stdout"}
    return loaded if isinstance(loaded, dict) else {"action": "unhandled", "reason": "codex_extension_handoff_unhandled:invalid_json"}


def codex_chrome_response_fingerprint(response: dict[str, Any]) -> str:
    try:
        return json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:
        return repr(response)


def codex_chrome_setup_latch_path(root: Path) -> Path:
    return root / "control_state" / "codex_chrome_preflight_latch.json"


def read_codex_chrome_setup_latch(root: Path) -> dict[str, Any] | None:
    path = codex_chrome_setup_latch_path(root)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(loaded, dict):
        return None
    state = normalize_codex_chrome_preflight_state(loaded.get("preflight_state"))
    if state not in CODEX_CHROME_SKIP_STATES:
        return None
    return {
        "action": "skip",
        "reason": str(loaded.get("reason") or state),
        "preflight_state": state,
    }


def write_codex_chrome_setup_latch(root: Path, state: str, reason: str) -> None:
    if state not in CODEX_CHROME_SKIP_STATES:
        return
    write_json(
        codex_chrome_setup_latch_path(root),
        {
            "schema": CODEX_CHROME_PREFLIGHT_SCHEMA,
            "action": "skip",
            "preflight_state": state,
            "reason": reason or state,
            "scope": "current_hook_root",
            "created_at": utc_now(),
        },
    )


def codex_chrome_setup_signal(
    response: dict[str, Any] | None,
) -> tuple[str, str, dict[str, Any] | None]:
    if not isinstance(response, dict):
        return "", "", None
    state = normalize_codex_chrome_preflight_state(
        response.get("preflight_state") or response.get("reason")
    )
    action = str(response.get("action") or "").strip().casefold()
    if state == "ready" and action in {"", "retry", "manual_pending", "unhandled"}:
        if codex_chrome_capability_attested(response):
            return "ready", state, response
        normalized = dict(response)
        normalized["action"] = "manual_pending"
        normalized["preflight_state"] = "full_cdp_enable_required"
        normalized["reason"] = "codex_chrome_current_task_cdp_probe_required"
        return "setup", "full_cdp_enable_required", normalized
    if state in CODEX_CHROME_SETUP_REQUIRED_STATES and action in {
        "",
        "manual_pending",
        "unhandled",
    }:
        return "setup", state, response
    if state in CODEX_CHROME_SKIP_STATES and action in {"", "skip", "unhandled"}:
        normalized = dict(response)
        normalized["action"] = "skip"
        normalized["preflight_state"] = state
        normalized.setdefault("reason", state)
        return "terminal", state, normalized
    return "", state, response


def wait_for_codex_chrome_setup(
    initial_state: str,
    request: dict[str, Any],
    request_path: Path,
    response_candidates: list[Path],
    root: Path,
    event_name: str,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    response_reader: Callable[[list[Path]], dict[str, Any] | None] = read_response_candidates,
    controller_runner: Callable[[dict[str, Any], int], dict[str, Any] | None] = run_codex_extension_control_hook,
    ordinary_chrome_opener: Callable[
        [Path, str, dict[str, Any] | None], dict[str, Any]
    ] = open_ordinary_chrome_for_codex,
    initial_approval_response: dict[str, Any] | None = None,
    confirm_timeout_seconds: int | None = None,
    poll_interval_seconds: int | None = None,
    scan_timeout_seconds: int | None = None,
    connect_settle_seconds: int | None = None,
) -> tuple[dict[str, Any], set[str]]:
    confirm_seconds = max(
        1,
        int(
            confirm_timeout_seconds
            if confirm_timeout_seconds is not None
            else codex_chrome_setup_confirm_timeout_seconds()
        ),
    )
    poll_seconds = max(
        1,
        int(
            poll_interval_seconds
            if poll_interval_seconds is not None
            else codex_chrome_setup_poll_interval_seconds()
        ),
    )
    scan_seconds = max(
        1,
        int(
            scan_timeout_seconds
            if scan_timeout_seconds is not None
            else codex_chrome_setup_scan_timeout_seconds()
        ),
    )
    settle_seconds = max(
        1,
        int(
            connect_settle_seconds
            if connect_settle_seconds is not None
            else codex_chrome_connect_settle_seconds()
        ),
    )
    current_state = normalize_codex_chrome_preflight_state(initial_state)
    expected_response_event_id = protocol_event_id_for_request(
        request,
        event_name,
    )
    seen_fingerprints: set[str] = set()
    started_stages: set[str] = set()

    def fresh_response() -> dict[str, Any] | None:
        response = (
            read_response_candidates(
                response_candidates,
                expected_event_id=expected_response_event_id,
            )
            if response_reader is read_response_candidates
            else response_reader(response_candidates)
        )
        if not isinstance(response, dict):
            return None
        fingerprint = codex_chrome_response_fingerprint(response)
        if fingerprint in seen_fingerprints:
            return None
        seen_fingerprints.add(fingerprint)
        return response

    def open_and_probe(
        approval_response: dict[str, Any] | None,
        stage_request: dict[str, Any],
    ) -> dict[str, Any] | None:
        open_result = ordinary_chrome_opener(root, event_name, approval_response)
        if open_result.get("opened") is not True:
            return None
        write_json(
            root
            / "browser_attempts"
            / f"{event_name}_codex_ordinary_chrome_opened.json",
            open_result,
        )
        sleeper(float(settle_seconds))
        response = fresh_response()
        if response is None:
            response = controller_runner(
                stage_request,
                codex_extension_control_timeout_seconds(),
            )
            if isinstance(response, dict):
                seen_fingerprints.add(codex_chrome_response_fingerprint(response))
        return response

    while current_state in CODEX_CHROME_SETUP_REQUIRED_STATES:
        stage = codex_chrome_setup_stage(current_state)
        if not stage or stage in started_stages:
            timeout_state = codex_chrome_setup_timeout_state(stage)
            reason = f"codex_chrome_setup_state_regressed:{current_state}"
            write_codex_chrome_setup_latch(root, timeout_state, reason)
            return {
                "action": "skip",
                "reason": reason,
                "preflight_state": timeout_state,
            }, seen_fingerprints
        started_stages.add(stage)

        stage_request = dict(request)
        stage_preflight = dict(request.get("preflight") or {})
        stage_preflight.update(
            {
                "state": current_state,
                "stage": stage,
                "phase": "awaiting_confirmation",
                "confirmation_timeout_seconds": confirm_seconds,
                "poll_interval_seconds": poll_seconds,
                "scan_timeout_seconds": scan_seconds,
            }
        )
        stage_request["preflight"] = stage_preflight
        write_json(request_path, stage_request)

        next_state = ""
        bootstrap_response = (
            open_and_probe(initial_approval_response, stage_request)
            if stage == "chrome_plugin"
            else None
        )
        initial_approval_response = None
        if bootstrap_response is not None:
            signal, response_state, normalized = codex_chrome_setup_signal(
                bootstrap_response
            )
            if signal == "ready":
                return {
                    "action": "continue",
                    "reason": "codex_chrome_preflight_ready",
                    "preflight_state": "ready",
                }, seen_fingerprints
            if signal == "terminal" and normalized is not None:
                write_codex_chrome_setup_latch(
                    root,
                    response_state,
                    str(normalized.get("reason") or response_state),
                )
                return normalized, seen_fingerprints
            if signal == "setup":
                response_stage = codex_chrome_setup_stage(response_state)
                if response_stage != stage:
                    current_state = response_state
                    continue
                current_state = response_state

        confirmation_deadline = monotonic() + confirm_seconds
        while monotonic() < confirmation_deadline:
            response = fresh_response()
            if (
                isinstance(response, dict)
                and stage == "chrome_plugin"
                and codex_chrome_open_approved(response)
            ):
                response = open_and_probe(response, stage_request)
            signal, response_state, normalized = codex_chrome_setup_signal(response)
            if signal == "ready":
                return {
                    "action": "continue",
                    "reason": "codex_chrome_preflight_ready",
                    "preflight_state": "ready",
                }, seen_fingerprints
            if signal == "terminal" and normalized is not None:
                write_codex_chrome_setup_latch(
                    root,
                    response_state,
                    str(normalized.get("reason") or response_state),
                )
                return normalized, seen_fingerprints
            if signal == "setup":
                response_stage = codex_chrome_setup_stage(response_state)
                if response_stage != stage:
                    next_state = response_state
                else:
                    current_state = response_state
                break
            remaining = confirmation_deadline - monotonic()
            if remaining <= 0:
                break
            sleeper(min(1.0, remaining))

        if next_state:
            current_state = next_state
            continue

        scan_deadline = monotonic() + scan_seconds
        scan_attempt = 0
        while monotonic() < scan_deadline:
            remaining = scan_deadline - monotonic()
            sleeper(min(float(poll_seconds), max(0.0, remaining)))
            scan_attempt += 1
            scan_request = dict(stage_request)
            scan_preflight = dict(stage_preflight)
            scan_preflight.update(
                {
                    "state": current_state,
                    "phase": "capability_scan",
                    "scan_attempt": scan_attempt,
                }
            )
            scan_request["preflight"] = scan_preflight
            write_json(request_path, scan_request)
            write_json(
                root
                / "browser_attempts"
                / f"{event_name}_codex_extension_setup_progress.json",
                {
                    "preflight_state": current_state,
                    "stage": stage,
                    "scan_attempt": scan_attempt,
                    "reason": "codex_chrome_setup_scan",
                    "created_at": utc_now(),
                },
            )

            response = fresh_response()
            if response is None and codex_extension_control_hook_command():
                remaining_after_sleep = max(1, int(scan_deadline - monotonic()))
                controller_timeout = min(
                    codex_extension_control_timeout_seconds(),
                    remaining_after_sleep,
                )
                response = controller_runner(scan_request, controller_timeout)
                if isinstance(response, dict):
                    seen_fingerprints.add(codex_chrome_response_fingerprint(response))
            signal, response_state, normalized = codex_chrome_setup_signal(response)
            if signal == "ready":
                return {
                    "action": "continue",
                    "reason": "codex_chrome_preflight_ready",
                    "preflight_state": "ready",
                }, seen_fingerprints
            if signal == "terminal" and normalized is not None:
                write_codex_chrome_setup_latch(
                    root,
                    response_state,
                    str(normalized.get("reason") or response_state),
                )
                return normalized, seen_fingerprints
            if signal == "setup":
                response_stage = codex_chrome_setup_stage(response_state)
                if response_stage != stage:
                    next_state = response_state
                    break
                current_state = response_state

        if next_state:
            current_state = next_state
            continue

        timeout_state = codex_chrome_setup_timeout_state(stage)
        reason = f"codex_chrome_setup_timeout:{current_state}"
        write_codex_chrome_setup_latch(root, timeout_state, reason)
        return {
            "action": "skip",
            "reason": reason,
            "preflight_state": timeout_state,
        }, seen_fingerprints

    return {
        "action": "unhandled",
        "reason": f"codex_chrome_setup_invalid_state:{current_state or 'unknown'}",
        "preflight_state": current_state or "preflight_unavailable",
    }, seen_fingerprints


def external_handoff_marker_path(root: Path, event_name: str) -> Path:
    return root / "control_state" / f"{event_name}.external_handoff.json"


def write_external_handoff_marker(
    root: Path,
    event_name: str,
    *,
    status: str,
    deadline_epoch_seconds: int,
    reason: str,
) -> None:
    write_json(
        external_handoff_marker_path(root, event_name),
        {
            "schema": "laps_external_handoff_state_v1",
            "event_id": event_name,
            "status": status,
            "deadline_epoch_seconds": deadline_epoch_seconds,
            "reason": reason,
            "updated_at": utc_now(),
        },
    )


def computer_use_response_paths(
    root: Path,
    event_name: str,
    extension_response_candidates: list[Path],
) -> tuple[Path, list[Path]]:
    response_path = (
        root / "computer_use_responses" / f"{event_name}.json"
    )
    candidates = [response_path, *extension_response_candidates]
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return response_path, unique


def computer_use_fallback_eligible(
    request: dict[str, Any],
    response: dict[str, Any] | None,
) -> bool:
    if str(request.get("challenge_type") or "").casefold() not in (
        VERIFICATION_CHALLENGE_TYPES
    ):
        return False
    reason = str((response or {}).get("reason") or "").casefold()
    return not any(
        marker in reason
        for marker in (
            "access_denied",
            "subscription_required",
            "rate_limit",
            "local_chrome_not_found",
            "codex_chrome_control_declined",
        )
    )


def codex_computer_use_handoff(
    payload: dict[str, Any],
    root: Path,
    event_name: str,
    extension_request: dict[str, Any],
    attempt: dict[str, Any],
    response_candidates: list[Path],
    *,
    deadline_monotonic: float,
    ignored_fingerprints: set[str] | None = None,
) -> dict[str, Any] | None:
    if not codex_windows_control_preauthorized(payload):
        return None
    remaining = max(0, int(deadline_monotonic - time.monotonic()))
    if remaining < 1:
        return None
    response_path, candidates = computer_use_response_paths(
        root,
        event_name,
        response_candidates,
    )
    request = build_codex_computer_use_request(
        extension_request,
        attempt,
        response_path=str(response_path),
        timeout_seconds=remaining,
    )
    expected_response_event_id = protocol_event_id_for_request(
        request,
        event_name,
    )
    request_path = root / "computer_use_requests" / f"{event_name}.json"
    write_json(request_path, request)
    write_json(
        root / "browser_attempts" / f"{event_name}_computer_use_requested.json",
        {
            "event_id": event_name,
            "status": "computer_use_requested",
            "request_path": str(request_path),
            "response_path": str(response_path),
            "timeout_seconds": remaining,
            "created_at": utc_now(),
        },
    )
    ignored = set(ignored_fingerprints or set())
    while time.monotonic() < deadline_monotonic:
        response = read_response_candidates(
            candidates,
            expected_event_id=expected_response_event_id,
        )
        if response is None:
            time.sleep(1)
            continue
        fingerprint = codex_chrome_response_fingerprint(response)
        if fingerprint in ignored:
            time.sleep(1)
            continue
        ignored.add(fingerprint)
        if response.get("schema") == CODEX_COMPUTER_USE_RESPONSE_SCHEMA:
            valid, reason = validate_codex_computer_use_response(
                response,
                request,
            )
            if not valid:
                return {
                    "action": "unhandled",
                    "reason": reason,
                    "computer_use_status": "computer_use_stopped",
                }
            status = str(response.get("status") or "")
            if status in {"computer_use_requested", "computer_use_ready"}:
                time.sleep(1)
                continue
            if status != "computer_use_external_session_ready":
                normalized = dict(response)
                normalized.setdefault("reason", status)
                normalized["computer_use_status"] = status
                return normalized
        valid, reason = validate_codex_extension_response(
            response,
            challenge_type=str(extension_request.get("challenge_type") or ""),
            event=str(extension_request.get("event") or ""),
            request=extension_request,
            root=root,
        )
        if not valid:
            return {
                "action": "unhandled",
                "reason": f"computer_use_external_response_invalid:{reason}",
                "computer_use_status": "computer_use_stopped",
            }
        normalized = dict(response)
        normalized.setdefault(
            "computer_use_status",
            "computer_use_external_session_ready",
        )
        normalized.setdefault("reason", "computer_use_external_session_ready")
        return normalized
    return None


def _codex_extension_handoff(
    payload: dict[str, Any],
    root: Path,
    event_name: str,
    attempt: dict[str, Any],
    approval_response: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not codex_extension_control_enabled(payload):
        return None
    latched = read_codex_chrome_setup_latch(root)
    if latched is not None:
        return latched
    preflight_state = codex_chrome_preflight_state()
    if preflight_state == "codex_chrome_control_declined":
        write_codex_chrome_setup_latch(
            root,
            preflight_state,
            "codex_chrome_control_declined",
        )
        write_json(
            root / "browser_attempts" / f"{event_name}_codex_extension_declined.json",
            {
                "reason": "codex_chrome_control_declined",
                "preflight_state": preflight_state,
                "created_at": utc_now(),
            },
        )
        return {
            "action": "skip",
            "reason": "codex_chrome_control_declined",
            "preflight_state": preflight_state,
        }
    if find_local_chrome() is None:
        write_json(
            root / "browser_attempts" / f"{event_name}_codex_extension_unavailable.json",
            {
                "reason": "codex_extension_handoff_unavailable:local_chrome_not_found",
                "preflight_state": "local_chrome_not_found",
                "created_at": utc_now(),
            },
        )
        return {
            "action": "skip",
            "reason": "local_chrome_not_found",
            "preflight_state": "local_chrome_not_found",
        }
    timeout_seconds = codex_extension_control_timeout_seconds()
    requested_handoff_seconds = external_handoff_timeout_seconds(payload)
    response_candidates = response_candidate_paths(root, event_name, payload)
    response_path = response_candidates[0]
    storage_path = storage_state_path(root, event_name, payload, "codex_extension")
    request_payload = dict(payload)
    request_payload.update({key: value for key, value in attempt.items() if value})
    request_payload.setdefault("event_id", str(payload.get("event_id") or event_name))
    request_payload["preflight_state"] = preflight_state
    request = build_codex_extension_handoff_request(
        request_payload,
        response_path=str(response_path),
        storage_state_path=str(storage_path),
        timeout_seconds=requested_handoff_seconds,
    )
    credential_broker: RuntimeCredentialBroker | None = None
    if preflight_state == "ready":
        credential_broker = start_runtime_credential_broker(
            request_payload,
            root,
            event_name,
            requested_handoff_seconds,
        )
        if credential_broker is not None:
            request["runtime_credential_fill"] = (
                credential_broker.public_contract()
            )
    expected_response_event_id = protocol_event_id_for_request(
        request,
        event_name,
    )
    request_path = root / "extension_requests" / f"{event_name}.json"
    write_json(request_path, request)
    write_json(
        root / "browser_attempts" / f"{event_name}_codex_extension_requested.json",
        {
            "request_path": str(request_path),
            "response_path": str(response_path),
            "storage_state_path": str(storage_path),
            "timeout_seconds": requested_handoff_seconds,
            "controller_timeout_seconds": timeout_seconds,
            "reason": "codex_extension_handoff_requested",
            "created_at": utc_now(),
        },
    )
    consumed_setup_fingerprints: set[str] = set()
    if preflight_state in CODEX_CHROME_SETUP_REQUIRED_STATES:
        write_json(
            root / "browser_attempts" / f"{event_name}_codex_extension_setup_required.json",
            {
                "reason": preflight_state,
                "preflight_state": preflight_state,
                "request_path": str(request_path),
                "created_at": utc_now(),
            },
        )
        setup_result, consumed_setup_fingerprints = wait_for_codex_chrome_setup(
            preflight_state,
            request,
            request_path,
            response_candidates,
            root,
            event_name,
            initial_approval_response=approval_response,
        )
        if setup_result.get("action") != "continue":
            return setup_result
        preflight_state = "ready"
        request_preflight = dict(request.get("preflight") or {})
        request_preflight.update(
            {"state": "ready", "stage": "ready", "phase": "handoff"}
        )
        request["preflight"] = request_preflight
        if credential_broker is None:
            credential_broker = start_runtime_credential_broker(
                request_payload,
                root,
                event_name,
                requested_handoff_seconds,
            )
            if credential_broker is not None:
                request["runtime_credential_fill"] = (
                    credential_broker.public_contract()
                )
        write_json(request_path, request)
    if preflight_state in CODEX_CHROME_SKIP_STATES:
        reason = preflight_state
        write_codex_chrome_setup_latch(root, preflight_state, reason)
        return {
            "action": "skip",
            "reason": reason,
            "preflight_state": preflight_state,
        }
    if preflight_state == "preflight_unavailable":
        write_json(
            root / "browser_attempts" / f"{event_name}_codex_extension_preflight_required.json",
            {
                "reason": "codex_chrome_capability_check_required",
                "preflight_state": preflight_state,
                "request_path": str(request_path),
                "created_at": utc_now(),
            },
        )
        return {
            "action": "manual_pending",
            "reason": "codex_chrome_capability_check_required",
            "preflight_state": preflight_state,
        }

    handoff_seconds = external_handoff_timeout_seconds(payload)
    deadline_monotonic = time.monotonic() + handoff_seconds
    deadline_epoch_seconds = int(time.time()) + handoff_seconds
    request["timeout_seconds"] = handoff_seconds
    request["active_handoff"] = {
        "status": "external_handoff_pending",
        "event_id": expected_response_event_id,
        "timeout_seconds": handoff_seconds,
        "deadline_epoch_seconds": deadline_epoch_seconds,
        "response_must_match_full_event_id": True,
    }
    write_json(request_path, request)
    write_external_handoff_marker(
        root,
        event_name,
        status="active",
        deadline_epoch_seconds=deadline_epoch_seconds,
        reason="external_handoff_pending",
    )

    def finish_handoff(result: dict[str, Any], marker_status: str = "complete") -> dict[str, Any]:
        normalized = dict(result)
        normalized.setdefault(
            "reason",
            "codex_extension_handoff_succeeded"
            if normalized.get("action") == "retry"
            else "codex_extension_handoff_response",
        )
        if normalized.get("external_browser_session") is True:
            normalized["same_browser_handoff"] = False
            normalized["browser_transport"] = (
                ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT
            )
            normalized.setdefault("browser_name", "chrome")
        write_external_handoff_marker(
            root,
            event_name,
            status=marker_status,
            deadline_epoch_seconds=deadline_epoch_seconds,
            reason=str(normalized.get("reason") or marker_status),
        )
        write_json(
            root
            / "browser_attempts"
            / f"{event_name}_codex_extension_response.json",
            {
                "reason": normalized.get("reason"),
                "action": normalized.get("action"),
                "computer_use_status": normalized.get("computer_use_status"),
                "created_at": utc_now(),
            },
        )
        return normalized

    def validate_response(
        candidate: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str]:
        ok, validation_reason = validate_codex_extension_response(
            candidate,
            challenge_type=str(request.get("challenge_type") or ""),
            event=str(request.get("event") or ""),
            request=request,
            root=root,
        )
        if not ok:
            return None, validation_reason
        return candidate, validation_reason

    remaining = max(1, int(deadline_monotonic - time.monotonic()))
    controller_timeout = min(timeout_seconds, remaining)
    response = run_codex_extension_control_hook(request, controller_timeout)
    ignored_fingerprints = set(consumed_setup_fingerprints)
    if isinstance(response, dict):
        ignored_fingerprints.add(codex_chrome_response_fingerprint(response))
    if response is None:
        response = wait_for_response_paths(
            response_candidates,
            min(controller_timeout, max(1, int(deadline_monotonic - time.monotonic()))),
            consumed_setup_fingerprints,
            expected_event_id=expected_response_event_id,
        )
        if isinstance(response, dict):
            ignored_fingerprints.add(codex_chrome_response_fingerprint(response))

    if isinstance(response, dict):
        validated, validation_reason = validate_response(response)
        if validated is None:
            write_json(
                root
                / "browser_attempts"
                / f"{event_name}_codex_extension_invalid_response.json",
                {
                    "reason": validation_reason,
                    "response": response,
                    "created_at": utc_now(),
                },
            )
            return finish_handoff(
                {
                    "action": "unhandled",
                    "reason": (
                        "codex_extension_handoff_unhandled:"
                        f"{validation_reason}"
                    ),
                }
            )
        if str(validated.get("action") or "").casefold() == "retry":
            return finish_handoff(validated)

    if computer_use_fallback_eligible(request, response):
        computer_use_response = codex_computer_use_handoff(
            payload,
            root,
            event_name,
            request,
            response or attempt,
            response_candidates,
            deadline_monotonic=deadline_monotonic,
            ignored_fingerprints=ignored_fingerprints,
        )
        if computer_use_response is not None:
            return finish_handoff(computer_use_response)

    if isinstance(response, dict) and str(
        response.get("action") or ""
    ).casefold() in {"skip", "cooldown"}:
        return finish_handoff(response)

    remaining = max(0, int(deadline_monotonic - time.monotonic()))
    if remaining > 0:
        late_response = wait_for_response_paths(
            response_candidates,
            remaining,
            ignored_fingerprints,
            expected_event_id=expected_response_event_id,
        )
        if late_response is not None:
            validated, validation_reason = validate_response(late_response)
            if validated is not None:
                return finish_handoff(validated)
            return finish_handoff(
                {
                    "action": "unhandled",
                    "reason": (
                        "codex_extension_handoff_unhandled:"
                        f"{validation_reason}"
                    ),
                }
            )

    expired = {
        "action": "unhandled",
        "reason": "external_handoff_deadline_expired",
    }
    write_json(
        root / "browser_attempts" / f"{event_name}_codex_extension_timeout.json",
        {
            "reason": expired["reason"],
            "request_path": str(request_path),
            "deadline_epoch_seconds": deadline_epoch_seconds,
            "created_at": utc_now(),
        },
    )
    return finish_handoff(expired, marker_status="expired")


def codex_extension_handoff(
    payload: dict[str, Any],
    root: Path,
    event_name: str,
    attempt: dict[str, Any],
    approval_response: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    try:
        return _codex_extension_handoff(
            payload,
            root,
            event_name,
            attempt,
            approval_response,
        )
    finally:
        stop_runtime_credential_broker(event_name)


def selected_url(payload: dict[str, Any]) -> str:
    return (
        str(payload.get("raw_candidate_url") or "")
        or str(payload.get("raw_url") or "")
        or str(payload.get("candidate_url") or "")
        or str(payload.get("raw_current_url") or "")
        or str(payload.get("current_url") or "")
        or str(payload.get("raw_entry_url") or "")
        or str(payload.get("entry_url") or "")
    ).strip()


def browser_order(payload: dict[str, Any]) -> list[str]:
    del payload
    order = ["chromium", "chrome"]
    if not chrome_fallback_enabled():
        order = [name for name in order if name != "chrome"]
    return order


def payload_timeout_seconds(payload: dict[str, Any], default: int = 60) -> int:
    try:
        return max(10, int(str(payload.get("timeout_seconds") or default)))
    except Exception:
        return default


def payload_manual_wait_seconds(payload: dict[str, Any]) -> int:
    raw = str(
        payload.get("manual_wait_seconds")
        or os.getenv("CODEX_HOOK_MANUAL_WAIT_SECONDS", "")
        or os.getenv("LAPS_VERIFICATION_MANUAL_TIMEOUT_SECONDS", "")
        or "0"
    )
    try:
        return max(0, int(raw))
    except Exception:
        return 0


def consume_shared_manual_wait(
    remaining_seconds: int,
    base_deadline: float,
    *,
    now: float | None = None,
) -> tuple[int, int]:
    current = time.monotonic() if now is None else now
    used = max(
        0,
        min(
            max(0, int(remaining_seconds)),
            int(max(0.0, current - base_deadline) + 0.999),
        ),
    )
    return used, max(0, int(remaining_seconds) - used)


def keep_browser_open(payload: dict[str, Any]) -> bool:
    raw = payload.get("keep_browser_open")
    if raw is None:
        return True
    return truthy(str(raw))


def auth_state_challenge_recovery_only(payload: dict[str, Any]) -> bool:
    return (
        str(payload.get("control_mode") or "").strip().casefold()
        == "auth_state_challenge_recovery"
    )


def browser_timeout_seconds(payload: dict[str, Any], browser_name: str) -> int:
    if browser_name == "chrome":
        return env_int(
            ("CODEX_HOOK_BROWSER_TIMEOUT_SECONDS", "LAPS_CHROME_CONTROL_TIMEOUT_SECONDS", "CODEX_HOOK_CHROME_TIMEOUT_SECONDS"),
            180,
            10,
        )
    return env_int(
        ("CODEX_HOOK_CHROMIUM_TIMEOUT_SECONDS", "LAPS_CHROMIUM_CONTROL_TIMEOUT_SECONDS", "LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS"),
        min(payload_timeout_seconds(payload, 60), 60),
        10,
    )


def ensure_pdf_download_preferences(profile: Path) -> None:
    try:
        preferences_path = profile / "Default" / "Preferences"
        preferences_path.parent.mkdir(parents=True, exist_ok=True)
        preferences: dict[str, Any] = {}
        if preferences_path.exists():
            try:
                loaded = json.loads(preferences_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    preferences = loaded
            except Exception:
                preferences = {}
        plugins = preferences.setdefault("plugins", {})
        if isinstance(plugins, dict):
            plugins["always_open_pdf_externally"] = True
        download = preferences.setdefault("download", {})
        if isinstance(download, dict):
            download["prompt_for_download"] = False
        preferences_path.write_text(json.dumps(preferences, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def launch_persistent_context(
    playwright: Any,
    root: Path,
    browser_name: str,
    timeout_seconds: int,
    headless: bool,
) -> tuple[Any | None, str]:
    profile = root / "browser_profiles" / browser_name
    ensure_pdf_download_preferences(profile)
    args = ["--disable-blink-features=AutomationControlled"]
    launch_kwargs: dict[str, Any] = {
        "user_data_dir": str(profile),
        "headless": headless,
        "timeout": timeout_seconds * 1000,
        "accept_downloads": True,
        "args": args,
    }
    if browser_name == "chrome":
        chrome_path = find_local_chrome()
        if chrome_path is None:
            return None, "local_chrome_not_found"
        launch_kwargs["executable_path"] = str(chrome_path)
    try:
        return playwright.chromium.launch_persistent_context(**launch_kwargs), ""
    except Exception as exc:
        detail = str(exc).splitlines()[0][:500]
        return None, f"{browser_name}_launch_failed:{exc.__class__.__name__}:{detail}"


def resolve_loopback_cdp_websocket(endpoint: str) -> str:
    candidate = str(endpoint or "").strip()
    parsed = urlsplit(candidate)
    if (
        parsed.scheme == "ws"
        and parsed.hostname == "127.0.0.1"
        and parsed.port is not None
    ):
        return candidate
    if not (
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.port is not None
    ):
        return ""
    try:
        version_url = candidate.rstrip("/") + "/json/version"
        with urllib_request.urlopen(version_url, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        websocket_url = str(payload.get("webSocketDebuggerUrl") or "").strip()
        websocket_parts = urlsplit(websocket_url)
        if (
            websocket_parts.scheme == "ws"
            and websocket_parts.hostname == "127.0.0.1"
            and websocket_parts.port == parsed.port
        ):
            return websocket_url
    except (OSError, ValueError, json.JSONDecodeError, urllib_error.URLError):
        return ""
    return ""


def page_cdp_target_id(context: Any, page: Any) -> str:
    session = None
    try:
        session = context.new_cdp_session(page)
        payload = session.send("Target.getTargetInfo")
        target_info = payload.get("targetInfo") if isinstance(payload, dict) else None
        return str(
            target_info.get("targetId") if isinstance(target_info, dict) else ""
        ).strip()
    except Exception:
        return ""
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def connect_parent_browser_context(
    playwright: Any,
    payload: dict[str, Any],
) -> tuple[Any | None, Any | None, Any | None, str]:
    if not parent_browser_attachment_requested(payload):
        return None, None, None, "parent_browser_attachment_not_requested"
    endpoint = resolve_loopback_cdp_websocket(
        str(payload.get("parent_browser_cdp_endpoint") or "")
    )
    if not endpoint:
        return None, None, None, "parent_browser_cdp_endpoint_unavailable"
    target_id = str(payload.get("parent_browser_target_id") or "").strip()
    try:
        browser = playwright.chromium.connect_over_cdp(endpoint, timeout=10_000)
    except Exception as exc:
        return (
            None,
            None,
            None,
            f"parent_browser_cdp_attach_failed:{exc.__class__.__name__}",
        )
    matches: list[tuple[Any, Any]] = []
    for context in browser.contexts:
        for page in context.pages:
            if page_cdp_target_id(context, page) == target_id:
                matches.append((context, page))
    if len(matches) != 1:
        return browser, None, None, "parent_browser_target_not_unique"
    context, page = matches[0]
    return browser, context, page, ""


def page_text(page: Any) -> str:
    try:
        return str(page.locator("body").inner_text(timeout=3000))
    except Exception:
        try:
            return str(page.evaluate("() => document.body ? document.body.innerText : ''"))
        except Exception:
            return ""


def stable_page_snapshot(page: Any) -> tuple[str, str, bool]:
    url_before = str(getattr(page, "url", "") or "")
    text = page_text(page)
    url_after = str(getattr(page, "url", "") or "")
    return url_after, text, url_before == url_after


def page_document_epoch(page: Any) -> str:
    try:
        return str(
            page.evaluate(
                "() => String(Math.trunc(globalThis.performance?.timeOrigin || 0))"
            )
            or ""
        )
    except Exception:
        return ""


AUTH_PRELOGIN_MARKERS = (
    "find your organization",
    "find your institution",
    "search for your organization",
    "search for your institution",
    "select your organization",
    "select your institution",
    "choose your organization",
    "choose your institution",
    "institutional sign in",
    "institution search",
    "organization search",
    "查找您的组织",
    "查找您的机构",
    "选择您的组织",
    "选择您的机构",
    "搜索机构",
    "机构搜索",
)

AMBIGUOUS_AUTH_SUCCESS_MARKERS = (
    "xiamen university",
    "厦门大学",
    "sign in to access",
    "institutional access",
)

CAPTCHA_CHALLENGE_MARKERS = (
    "recaptcha",
    "hcaptcha",
    "captcha",
    "altcha",
    "验证码",
)

MFA_CHALLENGE_MARKERS = (
    "mfa",
    "multi-factor",
    "two-factor",
    "verification code",
    "otp",
    "短信",
    "短信验证码",
    "邮箱验证",
    "邮箱验证码",
    "二次验证",
    "扫码确认",
)

ROBOT_CHALLENGE_MARKERS = (
    "verify you are human",
    "verify that you are human",
    "verify human",
    "are you a robot",
    "robot verification",
    "robot check",
    "unusual traffic",
    "automated queries",
    "异常流量",
    "稍后重新发送请求",
    "google.com/sorry",
    "/sorry/",
    "malicious bots",
    "我不是机器人",
    "机器人验证",
    "人机验证",
)

SLIDER_CHALLENGE_MARKERS = (
    "slider",
    "drag the slider",
    "slide to verify",
    "滑块",
    "拖动滑块",
    "滑动验证",
)

WAF_CHALLENGE_MARKERS = (
    "cloudflare",
    "performing security verification",
    "security check",
    "checking your browser",
    "you have been blocked",
    "安全验证",
)


def classify_challenge(text: str, reason: str = "", url: str = "", event: str = "") -> str:
    lowered = " ".join((text or "", reason or "", url or "")).casefold()
    if any(token in lowered for token in CAPTCHA_CHALLENGE_MARKERS + SLIDER_CHALLENGE_MARKERS):
        return "captcha_required"
    if any(token in lowered for token in MFA_CHALLENGE_MARKERS):
        return "mfa_required"
    if any(token in lowered for token in ROBOT_CHALLENGE_MARKERS):
        return "robot_check"
    if publisher_reference_error_page(text):
        return "cloudflare_or_waf"
    if any(token in lowered for token in WAF_CHALLENGE_MARKERS) or re.search(r"(?<![a-z0-9])waf(?![a-z0-9])", lowered):
        return "cloudflare_or_waf"
    if any(token in lowered for token in ("subscription required", "purchase this article", "sign in to access", "not subscribed", "subscribe to access")):
        return "subscription_required"
    if any(token in lowered for token in ("access denied", "forbidden", "not authorized", "unauthorized", "permission denied")):
        return "access_denied"
    reason_value = (reason or "").strip().casefold()
    lowered_url = (url or "").casefold()
    if reason_value == "institution_login" or (
        event == "auth_challenge"
        and (
            any(token in lowered_url for token in ("/login", "/signin", "/wayf", "/saml", "authserver"))
            or any(token in lowered for token in AUTH_PRELOGIN_MARKERS)
        )
    ):
        return "institution_login"
    return "unknown_verification"


def classify_live_page_challenge(text: str, url: str = "", event: str = "") -> str:
    # The request reason describes the landing page. Reusing it after navigation
    # would keep a resolved verification challenge active indefinitely.
    return classify_challenge(text, "", url, event)


def cnki_active_verification_surface(page: Any) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    parsed = urlsplit(current_url)
    if (parsed.hostname or "").casefold().endswith("cnki.net") and "/verify/" in (parsed.path or "").casefold():
        return True
    for selector in (
        "#tcaptcha_transform_dy",
        "#tCaptchaDyMainWrap",
        "iframe[src*='captcha' i]",
        "iframe[title*='验证']",
        "[class*='captcha' i][class*='show' i]",
    ):
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 12)):
                locator = locators.nth(index)
                if not locator.is_visible(timeout=300):
                    continue
                box = locator.bounding_box(timeout=500)
                if not box or box["width"] < 20 or box["height"] < 20:
                    continue
                if box["x"] + box["width"] <= 0 or box["y"] + box["height"] <= 0:
                    continue
                opacity = locator.evaluate(
                    "element => Number.parseFloat(getComputedStyle(element).opacity || '1')"
                )
                if float(opacity or 0) > 0.05:
                    return True
        except Exception:
            continue
    return False


def wanfang_login_surface_visible(page: Any) -> bool:
    for selector in (
        "iframe#anxs-8qwe-login[src*='my.wanfangdata.com.cn']",
        "iframe[src*='fsso.wanfangdata.com.cn']",
    ):
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 8)):
                locator = locators.nth(index)
                if not locator.is_visible(timeout=300):
                    continue
                box = locator.bounding_box(timeout=500)
                if box and box["width"] >= 100 and box["height"] >= 100:
                    return True
        except Exception:
            continue
    parsed = urlsplit(str(getattr(page, "url", "") or ""))
    host = (parsed.hostname or "").casefold()
    path = (parsed.path or "").casefold()
    return bool(
        host in {"my.wanfangdata.com.cn", "fsso.wanfangdata.com.cn"}
        and any(marker in path for marker in ("/auth/", "/login", "/wayf"))
    )


def wanfang_embedded_login_frame_allowed(url: str) -> bool:
    parsed = urlsplit(url or "")
    return bool(
        parsed.scheme.casefold() == "https"
        and (parsed.hostname or "").casefold() == "my.wanfangdata.com.cn"
        and (parsed.path or "/").casefold().startswith("/auth/")
    )


def wanfang_external_access_url_allowed(url: str) -> bool:
    parsed = urlsplit(url or "")
    return bool(
        parsed.scheme.casefold() == "https"
        and (parsed.hostname or "").casefold() == "fsso.wanfangdata.com.cn"
        and (parsed.path or "/") == "/"
        and not parsed.username
        and not parsed.password
    )


def handle_wanfang_embedded_external_access(page: Any, payload: dict[str, Any]) -> bool:
    if str(payload.get("auth_state_scope") or "").strip().casefold() != "wanfang_data":
        return False
    if payload.get("_codex_wanfang_external_access_opened"):
        return False
    for frame in getattr(page, "frames", []):
        if frame == getattr(page, "main_frame", None):
            continue
        frame_url = str(getattr(frame, "url", "") or "")
        if not wanfang_embedded_login_frame_allowed(frame_url):
            continue
        try:
            links = frame.locator("a[href]")
            for index in range(min(links.count(), 20)):
                locator = links.nth(index)
                href = str(locator.get_attribute("href", timeout=500) or "").strip()
                if not wanfang_external_access_url_allowed(href):
                    continue
                # The visible CARSI icon opens a new tab and has no accessible
                # name. Navigate the current controlled page to its observed,
                # allowlisted URL so the auth loop keeps a single page owner.
                payload["_codex_wanfang_external_access_opened"] = True
                mark_page_automation_click(
                    page,
                    "wanfang_external_access_navigation",
                    "a[href='https://fsso.wanfangdata.com.cn/']",
                )
                try:
                    page.goto(href, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    pass
                wait_briefly(page, 1000)
                return True
        except Exception:
            continue
    return False


def wanfang_active_verification_surface(page: Any) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    parsed = urlsplit(current_url)
    host = (parsed.hostname or "").casefold()
    path = (parsed.path or "").casefold()
    if host.endswith("wanfangdata.com.cn") and any(
        marker in path for marker in ("/verify", "/captcha", "/challenge")
    ):
        return True
    for selector in (
        "iframe[src*='captcha' i]",
        "iframe[src*='challenge' i]",
        "iframe[title*='验证']",
        "[class*='captcha' i]",
        "[id*='captcha' i]",
        "[class*='verify' i]",
        "[id*='verify' i]",
        "[class*='slider' i]",
    ):
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 12)):
                locator = locators.nth(index)
                if not locator.is_visible(timeout=300):
                    continue
                box = locator.bounding_box(timeout=500)
                if not box or box["width"] < 20 or box["height"] < 20:
                    continue
                if box["x"] + box["width"] <= 0 or box["y"] + box["height"] <= 0:
                    continue
                opacity = locator.evaluate(
                    "element => Number.parseFloat(getComputedStyle(element).opacity || '1')"
                )
                if float(opacity or 0) > 0.05:
                    return True
        except Exception:
            continue
    return False


def classify_visible_page_challenge(
    page: Any,
    text: str,
    url: str,
    event: str,
    payload: dict[str, Any] | None = None,
) -> str:
    auth_scope = str((payload or {}).get("auth_state_scope") or "").strip().casefold()
    if auth_scope == "cnki" and not cnki_active_verification_surface(page):
        return "unknown_verification"
    if auth_scope == "wanfang_data" and not wanfang_active_verification_surface(page):
        return "unknown_verification"
    return classify_live_page_challenge(text, url, event)


def has_access_blocker(text: str) -> bool:
    return classify_challenge(text) in {
        "captcha_required",
        "mfa_required",
        "robot_check",
        "cloudflare_or_waf",
        "subscription_required",
        "access_denied",
    }


def has_hard_access_blocker(text: str) -> bool:
    return classify_challenge(text) in {
        "mfa_required",
        "subscription_required",
        "access_denied",
    }


def has_stale_challenge_marker(text: str) -> bool:
    return classify_challenge(text) in {
        "captcha_required",
        "robot_check",
        "cloudflare_or_waf",
    }


def has_active_access_blocker(text: str) -> bool:
    if has_hard_access_blocker(text):
        return True
    return has_stale_challenge_marker(text)


def google_unusual_traffic_page(text: str, url: str) -> bool:
    lowered = " ".join((text or "", url or "")).casefold()
    return ("google.com/sorry" in lowered or "/sorry/" in lowered) and any(
        marker in lowered
        for marker in ("unusual traffic", "automated queries", "异常流量", "稍后重新发送请求")
    )


def publisher_reference_error_page(text: str) -> bool:
    lowered = " ".join(str(text or "").split()).casefold()
    return (
        "there was a problem providing the content you requested" in lowered
        and "reference number" in lowered
    )


def search_challenge_resolution_allowed(challenge_type: str, text: str, url: str) -> bool:
    if challenge_type in {
        "captcha_required",
        "mfa_required",
        "robot_check",
        "cloudflare_or_waf",
        "subscription_required",
        "access_denied",
        "institution_login",
    }:
        return False
    lowered_url = (url or "").casefold()
    if any(marker in lowered_url for marker in ("accounts.google.com/", "/signin/", "/login/", "/sorry/")):
        return False
    return not has_access_blocker(text)


def page_has_visible_verification_control(page: Any) -> bool:
    selectors = (
        "input[type='checkbox']:visible",
        "[role='checkbox']:visible",
        "[role='slider']:visible",
        "input[name*='captcha' i]:visible",
        "button[aria-label*='verify' i]:visible",
        "button:has-text('Verify'):visible",
        "button:has-text('验证'):visible",
        "iframe[src*='captcha' i]:visible",
        "iframe[src*='turnstile' i]:visible",
        "iframe[src*='challenges.cloudflare.com' i]:visible",
        "iframe[title*='challenge' i]:visible",
        "iframe[title*='cloudflare' i]:visible",
    )
    for selector in selectors:
        try:
            if page.locator(selector).count() > 0:
                return True
        except Exception:
            continue
    return False


def page_has_visible_verification_surface(page: Any) -> bool:
    if page_has_visible_verification_control(page):
        return True
    try:
        return bool(
            page.locator("body *").evaluate_all(
                """elements => elements.some((node) => {
                  const text = (node.innerText || '').replace(/\\s+/g, ' ').trim();
                  if (!text || text.length > 600) return false;
                  if (!/(verify (you are )?human|are you a robot|robot (verification|check)|unusual (activity|traffic)|automated queries|captcha|security check|验证码|机器人验证|我不是机器人|异常流量|安全验证|滑块|拖动滑块)/i.test(text)) {
                    return false;
                  }
                  const style = window.getComputedStyle(node);
                  if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity || '1') === 0) {
                    return false;
                  }
                  const rect = node.getBoundingClientRect();
                  return rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0;
                })"""
            )
        )
    except Exception:
        return False


def page_has_actionable_search_resume_control(page: Any, payload: dict[str, Any]) -> bool:
    selectors = [
        str(value).strip()
        for value in payload.get("resume_action_selectors") or []
        if str(value).strip()
    ]
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() == 0 or not locator.is_visible(timeout=500):
                continue
            locator.click(trial=True, timeout=1000)
            return True
        except Exception:
            continue
    return False


def page_has_visible_search_surface(page: Any, payload: dict[str, Any]) -> bool:
    selectors = [
        str(value).strip()
        for value in payload.get("search_surface_selectors") or []
        if str(value).strip()
    ]
    for selector in selectors:
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 20)):
                if locators.nth(index).is_visible(timeout=500):
                    return True
        except Exception:
            continue
    return False


def click_actionable_search_resume_control(page: Any, payload: dict[str, Any]) -> bool:
    selectors = [
        str(value).strip()
        for value in payload.get("resume_action_selectors") or []
        if str(value).strip()
    ]
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() == 0 or not locator.is_visible(timeout=500):
                continue
            locator.click(trial=True, timeout=1000)
            click_traced_locator(locator, 3000, "search_challenge_resume", selector)
            return True
        except Exception:
            continue
    return False


def has_explicit_auth_failure(text: str) -> bool:
    lowered = (text or "").casefold()
    return any(
        marker in lowered
        for marker in (
            "subscription required",
            "purchase this article",
            "not subscribed",
            "subscribe to access",
            "access denied",
            "forbidden",
            "not authorized",
            "unauthorized",
            "permission denied",
            "invalid password",
            "incorrect password",
            "invalid username",
            "incorrect username",
            "authentication failed",
            "login failed",
            "未订阅",
            "无权访问",
            "拒绝访问",
            "账号或密码错误",
            "用户名或密码错误",
            "登录失败",
        )
    )


def has_blocking_auth_gate(text: str) -> bool:
    return has_explicit_auth_failure(text) or classify_challenge(text) == "mfa_required"


def has_auth_success(text: str, final_url: str, markers: list[str]) -> bool:
    lowered_text = text.casefold()
    lowered_url = final_url.casefold()
    if institutional_agreement_non_auth_redirect(text, final_url):
        return False
    if any(token in lowered_text for token in AUTH_PRELOGIN_MARKERS):
        return False
    if has_blocking_auth_gate(text):
        return False
    success_seen = False
    for marker in markers:
        marker = str(marker or "").strip().casefold()
        if marker and any(token in marker for token in AMBIGUOUS_AUTH_SUCCESS_MARKERS):
            continue
        if marker and (marker in lowered_text or marker in lowered_url):
            success_seen = True
            break
    if any(token in lowered_text for token in ("logout", "log out", "sign out", "access provided by", "signed in as", "authenticated via")):
        success_seen = True
    if not success_seen:
        return False
    # Generic "Sign in to access" marketing copy can remain on an authenticated publisher page.
    # Explicit denial and unsubscription markers remain authoritative.
    return not has_blocking_auth_gate(text)


COOKIE_DISMISSAL_ATTEMPTS_DATASET = "codexCookieDismissalAttempts"


def click_cookie_control_once(
    page: Any,
    locator: Any,
    action_kind: str,
    selector_hint: str,
) -> bool:
    try:
        if locator.count() == 0:
            return False
        if not locator.is_visible(timeout=500):
            return False
        if not locator.is_enabled(timeout=500):
            return False
    except Exception:
        return False
    fingerprint = locator_control_fingerprint(
        locator,
        action_kind,
        selector_hint,
    )
    if page_control_fingerprint_attempted(
        page,
        COOKIE_DISMISSAL_ATTEMPTS_DATASET,
        fingerprint,
    ):
        return False
    mark_page_control_fingerprint(
        page,
        COOKIE_DISMISSAL_ATTEMPTS_DATASET,
        fingerprint,
    )
    try:
        click_traced_locator(locator, 1500, action_kind, selector_hint)
    except Exception:
        return False
    wait_briefly(page, 300)
    return True


def dismiss_cookie_banners(page: Any) -> bool:
    selectors = (
        "button[data-cc-action='reject']",
        "button[data-cc-action='accept']",
        "button#onetrust-reject-all-handler",
        "button#onetrust-accept-btn-handler",
        "button[aria-label*='reject' i][aria-label*='cookie' i]",
        "button[aria-label*='accept' i][aria-label*='cookie' i]",
        "[id*='cookie' i] button[aria-label*='close' i]",
        "[class*='cookie' i] button[aria-label*='close' i]",
        "[id*='cookie' i] button[aria-label*='关闭' i]",
        "[class*='cookie' i] button[aria-label*='关闭' i]",
        "[id*='pendo' i] button[aria-label*='close' i]",
        "[class*='pendo' i] button[aria-label*='close' i]",
    )
    for selector in selectors:
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 20)):
                if click_cookie_control_once(
                    page,
                    locators.nth(index),
                    "cookie_selector",
                    selector,
                ):
                    return True
        except Exception:
            continue
    unambiguous_labels = (
        "Reject optional cookies",
        "Allow all cookies",
        "Allow selected cookies",
        "Use necessary cookies only",
        "Accept all",
        "Accept Cookies",
        "I Understand",
        "接受Cookies",
    )
    for label in unambiguous_labels:
        try:
            locator = page.get_by_role("button", name=label, exact=True).first
            if click_cookie_control_once(
                page,
                locator,
                "cookie_label",
                label,
            ):
                return True
        except Exception:
            continue
    cookie_scope_selectors = (
        "#onetrust-banner-sdk",
        "#onetrust-pc-sdk",
        "[id*='cookie' i]",
        "[class*='cookie' i]",
        "[aria-label*='cookie' i]",
        "[aria-label*='cookies' i]",
    )
    scoped_labels = (
        "Accept",
        "I agree",
        "Agree",
        "Got it",
        "No thanks",
        "Close",
        "Dismiss",
        "同意",
        "接受",
        "确定",
        "关闭",
    )
    for scope_selector in cookie_scope_selectors:
        try:
            scopes = page.locator(scope_selector)
            for scope_index in range(min(scopes.count(), 20)):
                scope = scopes.nth(scope_index)
                if not scope.is_visible(timeout=500):
                    continue
                for label in scoped_labels:
                    locator = scope.get_by_role(
                        "button",
                        name=label,
                        exact=True,
                    ).first
                    if click_cookie_control_once(
                        page,
                        locator,
                        "cookie_scoped_label",
                        f"{scope_selector}:{label}",
                    ):
                        return True
        except Exception:
            continue
    return False


def wait_briefly(page: Any, timeout_ms: int = 500) -> None:
    try:
        page.wait_for_timeout(timeout_ms)
    except Exception:
        pass


def newest_context_page(context: Any, known_page_ids: set[int]) -> Any | None:
    try:
        pages = list(context.pages)
    except Exception:
        return None
    for candidate in reversed(pages):
        if id(candidate) in known_page_ids:
            continue
        try:
            if candidate.is_closed():
                continue
        except Exception:
            pass
        return candidate
    return None


def click_first_visible_selector(scope: Any, selectors: tuple[str, ...], timeout_ms: int = 1000) -> bool:
    for selector in selectors:
        try:
            locator = scope.locator(selector).first
            if locator.count() == 0:
                continue
            try:
                if not locator.is_visible(timeout=500):
                    continue
            except Exception:
                pass
            click_traced_locator(locator, timeout_ms, "selector", selector)
            return True
        except Exception:
            continue
    return False


def click_first_visible_text_in_scope(scope: Any, labels: tuple[str, ...], timeout_ms: int = 1000) -> bool:
    for label in labels:
        for role in ("button", "link"):
            try:
                locator = scope.get_by_role(role, name=label, exact=False).first
                if locator.count() > 0:
                    try:
                        if not locator.is_visible(timeout=500):
                            continue
                    except Exception:
                        pass
                    click_traced_locator(locator, timeout_ms, "role_text", f"{role}:{label}")
                    return True
            except Exception:
                continue
        try:
            locator = scope.get_by_text(label, exact=False).first
            if locator.count() > 0:
                try:
                    if not locator.is_visible(timeout=500):
                        continue
                except Exception:
                    pass
                click_traced_locator(locator, timeout_ms, "visible_text", label)
                return True
        except Exception:
            continue
    return False


def click_first_visible_text(page: Any, labels: tuple[str, ...], timeout_ms: int = 1000) -> bool:
    if click_first_visible_text_in_scope(page, labels, timeout_ms=timeout_ms):
        return True
    for frame in getattr(page, "frames", []):
        if frame == getattr(page, "main_frame", None):
            continue
        if click_first_visible_text_in_scope(frame, labels, timeout_ms=timeout_ms):
            return True
    return False


def click_first_visible_role_text(
    page: Any,
    labels: tuple[str, ...],
    *,
    exact: bool,
    timeout_ms: int = 1000,
) -> bool:
    scopes = [page]
    scopes.extend(frame for frame in getattr(page, "frames", []) if frame != getattr(page, "main_frame", None))
    for scope in scopes:
        for label in labels:
            for role in ("button", "link"):
                try:
                    locator = scope.get_by_role(role, name=label, exact=exact).first
                    if locator.count() == 0:
                        continue
                    try:
                        if not locator.is_visible(timeout=500):
                            continue
                    except Exception:
                        pass
                    click_traced_locator(locator, timeout_ms, "role_text", f"{role}:{label}")
                    return True
                except Exception:
                    continue
    return False


def click_first_exact_command(page: Any, labels: tuple[str, ...], timeout_ms: int = 1000) -> bool:
    return click_first_visible_role_text(page, labels, exact=True, timeout_ms=timeout_ms)


def click_visible_checkbox_or_button_in_frames(page: Any) -> bool:
    selectors = (
        "label:has(input[type='checkbox'][name*='captcha' i])",
        "input[type='checkbox'][name*='captcha' i]",
        "input[type='checkbox'][id*='captcha' i]",
        "[role='checkbox'][aria-label*='robot' i]",
        "[role='checkbox'][aria-label*='verify' i]",
        "button[id*='captcha' i]",
        "button[data-testid*='captcha' i]",
    )
    labels = (
        "I am not a robot",
        "I'm not a robot",
        "我不是机器人",
        "Verify",
        "验证",
    )
    scopes = [page]
    scopes.extend(frame for frame in getattr(page, "frames", []) if frame != getattr(page, "main_frame", None))
    for scope in scopes:
        for label in labels:
            for role in ("checkbox", "button"):
                try:
                    locator = scope.get_by_role(role, name=label, exact=False).first
                    if locator.count() > 0:
                        click_traced_locator(locator, 1000, "verification_role", f"{role}:{label}")
                        return True
                except Exception:
                    continue
            try:
                locator = scope.get_by_label(label, exact=False).first
                if locator.count() > 0:
                    click_traced_locator(locator, 1000, "verification_label", label)
                    return True
            except Exception:
                pass
            try:
                locator = scope.locator("label").filter(has_text=label).first
                if locator.count() > 0:
                    click_traced_locator(locator, 1000, "verification_text", label)
                    return True
            except Exception:
                pass
        for selector in selectors:
            try:
                locator = scope.locator(selector).first
                if locator.count() == 0:
                    continue
                try:
                    if not locator.is_visible(timeout=500):
                        continue
                except Exception:
                    pass
                click_traced_locator(locator, 1000, "verification_selector", selector)
                return True
            except Exception:
                continue
    try:
        challenge_iframes = page.locator(
            "iframe[src*='captcha' i], iframe[src*='recaptcha' i], iframe[src*='hcaptcha' i], "
            "iframe[src*='turnstile' i], iframe[src*='challenges.cloudflare.com' i], "
            "iframe[title*='challenge' i], iframe[title*='captcha' i], iframe[title*='cloudflare' i]"
        )
        iframe_count = challenge_iframes.count()
    except Exception:
        iframe_count = 0
    for index in range(iframe_count):
        try:
            iframe = challenge_iframes.nth(index)
            if not iframe.is_visible(timeout=500):
                continue
            box = iframe.bounding_box(timeout=1000)
            if not box:
                continue
            mark_page_automation_click(page, "verification_iframe_coordinate", f"iframe:{index}")
            checkbox_x = box["x"] + min(30, max(18, box["width"] * 0.08))
            checkbox_y = box["y"] + box["height"] / 2
            page.mouse.click(checkbox_x, checkbox_y)
            try:
                page.wait_for_timeout(500)
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


def fill_first_selector(page: Any, selectors: tuple[str, ...], value: str) -> bool:
    if not value:
        return False
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() > 0:
                try:
                    current = str(locator.input_value(timeout=500) or "")
                    if current.strip() == value.strip():
                        return False
                except Exception:
                    pass
                locator.fill(value, timeout=1000)
                return True
        except Exception:
            continue
    return False


def type_first_selector_sequentially(
    page: Any,
    selectors: tuple[str, ...],
    value: str,
    *,
    delay_ms: int = 40,
) -> bool:
    if not value:
        return False
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() == 0 or not locator.is_visible(timeout=500):
                continue
            mark_automation_click(locator, "sequential_input", selector)
            locator.click(timeout=1000)
            locator.press("Control+A", timeout=1000)
            locator.press("Backspace", timeout=1000)
            try:
                locator.press_sequentially(
                    value,
                    delay=delay_ms,
                    timeout=max(3000, len(value) * delay_ms + 2000),
                )
            except AttributeError:
                locator.type(
                    value,
                    delay=delay_ms,
                    timeout=max(3000, len(value) * delay_ms + 2000),
                )
            return True
        except Exception:
            continue
    return False


def page_has_filled_input(page: Any) -> bool:
    try:
        return bool(
            page.locator("input:not([type='hidden']), textarea").evaluate_all(
                "(els) => els.some((e) => (e.value || '').trim().length > 0)"
            )
        )
    except Exception:
        return False


def auth_form_has_filled_credentials(page: Any) -> bool:
    try:
        password_filled = bool(
            page.locator("input[type='password']").evaluate_all(
                "(els) => els.some((e) => (e.value || '').trim().length > 0)"
            )
        )
        account_filled = bool(
            page.locator(
                "input[type='email'], input[name*='user' i], input[name*='account' i], "
                "input[name*='login' i], input[id*='user' i], input[id*='account' i], "
                "input[id*='login' i], input[type='text']"
            ).evaluate_all("(els) => els.some((e) => (e.value || '').trim().length > 0)")
        )
        return password_filled and account_filled
    except Exception:
        return False


def submit_filled_auth_form(page: Any, payload: dict[str, Any]) -> bool:
    if not auth_form_has_filled_credentials(page) or page_control_flag(page, "codexAuthFormSubmitted"):
        return False
    clicked = click_first_visible_selector(
        page,
        (
            "button[type='submit']",
            "input[type='submit']",
            "#login_submit",
            "#login-submit",
            "button[id*='login' i]",
            "button[class*='login' i]",
            "button:has-text('登 录')",
            "button:has-text('登录')",
        ),
        timeout_ms=2000,
    )
    if not clicked:
        return False
    mark_page_control_flag(page, "codexAuthFormSubmitted")
    payload["_codex_auth_form_submitted"] = True
    try:
        page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass
    wait_briefly(page, 1000)
    return True


def institution_sso_round_trip_succeeded(
    text: str,
    final_url: str,
    initial_host: str,
    visited_external_auth_host: bool,
    submitted_credentials: bool,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    if not visited_external_auth_host or not submitted_credentials or not school.strip():
        return False
    current_host = (urlsplit(final_url).hostname or "").casefold()
    if not current_host or current_host != initial_host.casefold():
        return False
    lowered = text.casefold()
    if not institution_text_contains_exact_school(
        text,
        school,
        school_aliases,
    ) or has_blocking_auth_gate(text):
        return False
    return not any(
        marker in lowered
        for marker in (
            "invalid password",
            "incorrect password",
            "invalid username",
            "incorrect username",
            "authentication failed",
            "login failed",
            "账号或密码错误",
            "用户名或密码错误",
            "登录失败",
        )
    )


def attempt_visible_slider_drag(page: Any) -> bool:
    selectors = (
        "[role='slider']",
        "input[type='range']",
        "[aria-label*='slider' i]",
        "[class*='slider']",
        "[id*='slider']",
        "[class*='slide']",
        "[id*='slide']",
    )
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() == 0:
                continue
            try:
                if not locator.is_visible(timeout=500):
                    continue
            except Exception:
                pass
            box = locator.bounding_box(timeout=1000)
            if not box:
                continue
            start_x = box["x"] + max(2, min(box["width"] / 2, 20))
            start_y = box["y"] + box["height"] / 2
            distance = max(160, min(320, box["width"] * 1.5))
            page.mouse.move(start_x, start_y)
            page.mouse.down()
            page.mouse.move(start_x + distance * 0.35, start_y, steps=8)
            page.mouse.move(start_x + distance * 0.75, start_y, steps=8)
            page.mouse.move(start_x + distance, start_y, steps=8)
            page.mouse.up()
            try:
                page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


def unique_visible_auth_locator(page: Any, selectors: tuple[str, ...]) -> Any | None:
    if not selectors:
        return None
    try:
        locator = page.locator(", ".join(selectors))
        visible: list[Any] = []
        for index in range(min(int(locator.count()), 8)):
            candidate = locator.nth(index)
            if not hasattr(candidate, "is_visible") or candidate.is_visible(timeout=500):
                visible.append(candidate)
        return visible[0] if len(visible) == 1 else None
    except Exception:
        return None


def auth_form_binding(locator: Any, current_url: str) -> dict[str, Any] | None:
    try:
        raw = locator.evaluate(
            """(element) => {
                const form = element.closest('form');
                if (!form) return {has_form: false, form_index: -1, action: '', target: ''};
                return {
                    has_form: true,
                    form_index: Array.from(document.forms).indexOf(form),
                    action: form.getAttribute('action') || form.action || '',
                    target: form.getAttribute('target') || ''
                };
            }"""
        )
    except Exception:
        return None
    if not isinstance(raw, dict) or not bool(raw.get("has_form")):
        return None
    try:
        form_index = int(raw.get("form_index", -1))
    except (TypeError, ValueError):
        return None
    action = str(raw.get("action") or "")
    return {
        "form_index": form_index,
        "action": urljoin(current_url, action) if action else current_url,
        "target": str(raw.get("target") or ""),
    }


def guarded_known_auth_locators(
    page: Any,
    payload: dict[str, Any],
) -> tuple[Any, Any] | None:
    username = unique_visible_auth_locator(
        page,
        (
            "input[type='email']",
            "input[name*='user' i]",
            "input[name*='account' i]",
            "input[name*='login' i]",
            "input[name*='email' i]",
            "input[id*='user' i]",
            "input[id*='account' i]",
            "input[id*='login' i]",
            "input[id*='email' i]",
        ),
    )
    password = unique_visible_auth_locator(
        page,
        (
            "input[type='password']",
            "input[name*='password' i]",
            "input[id*='password' i]",
        ),
    )
    if username is None or password is None:
        return None
    current_url = str(getattr(page, "url", "") or "")
    bindings = [
        auth_form_binding(locator, current_url) for locator in (username, password)
    ]
    if any(binding is None for binding in bindings):
        return None
    typed = [binding for binding in bindings if binding is not None]
    if len({binding["form_index"] for binding in typed}) != 1:
        return None
    if any(
        binding["form_index"] < 0
        or str(binding.get("target") or "").casefold() not in {"", "_self"}
        or not payload_credentials_allowed_on_url(payload, binding["action"])
        for binding in typed
    ):
        return None
    return username, password


def fill_known_auth_fields(page: Any, payload: dict[str, Any]) -> bool:
    changed = False
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    account = str(payload.get("raw_account") or "").strip()
    password = str(payload.get("raw_password") or "").strip()
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    lowered_surface = " ".join((text, final_url)).casefold()
    is_carsi_directory = carsi_directory_page(page, text, final_url)
    school_surface = is_carsi_directory or institution_entry_reached(text, final_url) or any(
        marker in lowered_surface
        for marker in (
            "wayf",
            "shibboleth",
            "openathens",
            "authserver",
            "search institution",
            "search organization",
            "select your institution",
            "choose your institution",
        )
    )
    if school_surface:
        school_selectors = (
            (("#show",) if is_carsi_directory else ())
            + (
                "#searchFormTextInput",
                "input[name='search']",
                "input[placeholder*='School' i]",
                "input[placeholder*='Institution' i]",
                "input[placeholder*='University' i]",
                "input[placeholder*='Organization' i]",
                "input[placeholder*='Organisation' i]",
                "input[aria-label*='School' i]",
                "input[aria-label*='Institution' i]",
                "input[aria-label*='University' i]",
                "input[aria-label*='Organization' i]",
                "input[aria-label*='Organisation' i]",
                "input[name*='school' i]",
                "input[name*='institution' i]",
                "input[name*='organization' i]",
                "input[name*='organisation' i]",
                "input[id*='institution' i]",
                "input[id*='organization' i]",
                "input[id*='organisation' i]",
            )
        )
        search_query = (
            preferred_carsi_institution_query(school, school_aliases)
            if is_carsi_directory
            else institution_search_query(
                school,
                text,
                final_url,
                str(payload.get("auth_state_scope") or ""),
                prefer_carsi=payload_prefers_carsi(payload),
            )
        )
        if search_query != school and carsi_federation_label_matches(search_query):
            mark_page_control_flag(page, "codexCarsiFederationQueryPending")
        school_changed = fill_first_selector(
            page,
            school_selectors,
            search_query,
        )
        if school_changed:
            mark_page_control_flag(page, "codexInstitutionSearchEntered")
            changed = True
    if account and password and payload_credentials_allowed_on_url(payload, final_url):
        auth_locators = guarded_known_auth_locators(page, payload)
        if auth_locators is not None:
            username_locator, password_locator = auth_locators
            try:
                username_locator.fill(account, timeout=3000)
                password_locator.fill(password, timeout=3000)
                changed = True
            except Exception:
                pass
    return changed


def springernature_wayf_page(text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    return "wayf.springernature.com" in lowered or "find your institution" in lowered


def handle_springernature_wayf(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not springernature_wayf_page(text, final_url):
        return False
    if dismiss_cookie_banners(page):
        return True
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    if not school:
        return False
    changed = False
    if not page_control_flag(page, "codexSpringerNatureWayfSearchEntered"):
        changed = type_first_selector_sequentially(
            page,
            ("#searchFormTextInput", "input[name='search']"),
            school,
        )
        if changed:
            mark_page_control_flag(page, "codexSpringerNatureWayfSearchEntered")
            wait_briefly(page, 1500)
            return True
    if (
        not page_control_flag(page, "codexSpringerNatureWayfSelected")
        and click_school_result(page, school, school_aliases)
    ):
        mark_page_control_flag(page, "codexSpringerNatureWayfSelected")
        wait_briefly(page, 1000)
        return True
    return changed


def acs_institution_wayf_page(text: str, final_url: str) -> bool:
    lowered = " ".join((text or "", final_url or "")).casefold()
    return bool(
        "pubs.acs.org/action/ssostart" in lowered
        and ("choose your institution" in lowered or "search for your institution" in lowered)
    )


def acs_auth_flow_owned(
    payload: dict[str, Any],
    final_url: str,
    text: str = "",
) -> bool:
    surface = " ".join((str(text or ""), str(final_url or ""))).casefold()
    return bool(
        str(payload.get("auth_state_scope") or "").strip().casefold()
        == "acs_publications"
        and "pubs.acs.org/action/ssostart" in surface
        and (
            payload.get("_codex_acs_search_attempted")
            or payload.get("_codex_acs_federation_attempts")
        )
    )


def acs_pending_elapsed_seconds(payload: dict[str, Any], key: str) -> float | None:
    try:
        started = float(payload.get(key))
    except (TypeError, ValueError):
        return None
    return max(0.0, time.monotonic() - started)


def acs_pending_within_result_window(payload: dict[str, Any], key: str) -> bool:
    elapsed = acs_pending_elapsed_seconds(payload, key)
    return elapsed is not None and elapsed < institution_result_wait_seconds()


def acs_auth_flow_waiting(payload: dict[str, Any]) -> bool:
    return acs_pending_within_result_window(
        payload,
        "_codex_acs_search_pending_since",
    ) or acs_pending_within_result_window(
        payload,
        "_codex_acs_federation_pending_since",
    )


def acs_federation_priority(
    label: str,
    school: str = "",
    school_aliases: tuple[str, ...] = (),
) -> int:
    return 0 if institution_prefers_carsi(school, school_aliases) and carsi_federation_label_matches(label) else 1


def carsi_federation_label_matches(label: Any) -> bool:
    normalized = normalize_institution_name(label)
    if not normalized or any(token in normalized for token in ("about carsi", "关于carsi")):
        return False
    return "carsi" in normalized or normalized in {
        "china cernet federation",
        "china cernet federation(carsi)",
        "cernet authentication and resource sharing infrastructure",
        "中国教育和科研计算机网联邦认证与资源共享基础设施",
    }


def institution_prefers_carsi(
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    return configured_institution_is_xiamen(school, school_aliases)


def payload_prefers_carsi(payload: dict[str, Any]) -> bool:
    if str(payload.get("auth_entry_mode") or "").strip().casefold() == "carsi_federation":
        return True
    scope = str(payload.get("auth_state_scope") or "").strip().casefold()
    return scope in {"web_of_science", "acs_publications"} and institution_prefers_carsi(
        str(payload.get("school") or ""),
        payload_school_aliases(payload),
    )


def institution_search_query(
    school: str,
    text: str,
    final_url: str,
    auth_state_scope: str = "",
    *,
    prefer_carsi: bool = False,
) -> str:
    parsed = urlsplit(final_url or "")
    host = (parsed.hostname or "").casefold()
    lowered = " ".join((text or "", final_url or "")).casefold()
    elsevier_host = host in {"auth.elsevier.com", "id.elsevier.com"} or any(
        host.endswith(suffix) for suffix in (".auth.elsevier.com", ".id.elsevier.com")
    )
    local_elsevier_fixture = (
        auth_state_scope.strip().casefold() == "elsevier"
        and (parsed.scheme.casefold() == "file" or host in {"localhost", "127.0.0.1", "::1"})
    )
    if (
        prefer_carsi
        and (elsevier_host or local_elsevier_fixture)
        and any(marker in lowered for marker in ("institution", "organization", "organisation", "shibauth"))
    ):
        return "CHINA CERNET Federation"
    return school


def configured_credentials_allowed_on_url(
    school: str,
    final_url: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    if not configured_institution_is_xiamen(school, school_aliases):
        return True
    parsed = urlsplit(final_url or "")
    host = (parsed.hostname or "").casefold()
    if parsed.scheme.casefold() == "file" or host in {"localhost", "127.0.0.1", "::1"}:
        return True
    return host == "xmu.edu.cn" or host.endswith(".xmu.edu.cn")


def credential_scope_allows_url(
    credential_scope: str,
    source: str,
    final_url: str,
    allowed_hosts: tuple[str, ...] = (),
    school: str = "",
    school_aliases: tuple[str, ...] = (),
) -> bool:
    if credential_scope.strip().casefold() != "site_personal":
        parsed = urlsplit(final_url or "")
        host = (parsed.hostname or "").casefold().strip(".")
        permitted = {
            str(candidate).strip().casefold().strip(".")
            for candidate in allowed_hosts
            if str(candidate).strip()
        }
        return bool(
            parsed.scheme.casefold() == "https"
            and host
            and host in permitted
        )
    if source != "度衍":
        return False
    parsed = urlsplit(final_url or "")
    host = (parsed.hostname or "").casefold().strip(".")
    if parsed.scheme.casefold() == "file" or host in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        return True
    if parsed.scheme.casefold() != "https":
        return False
    permitted = {
        candidate
        for candidate in allowed_hosts
        if candidate in {"uyanip.com", "api.duyandb.com"}
    }
    return any(
        host == candidate
        or (candidate == "uyanip.com" and host.endswith(".uyanip.com"))
        for candidate in permitted
    )


def payload_credentials_allowed_on_url(
    payload: dict[str, Any],
    final_url: str,
) -> bool:
    raw_hosts = payload.get("credential_allowed_hosts")
    allowed_hosts = tuple(
        str(value).strip().casefold().strip(".")
        for value in raw_hosts
        if str(value).strip()
    ) if isinstance(raw_hosts, list) else ()
    return credential_scope_allows_url(
        str(payload.get("credential_scope") or ""),
        str(payload.get("source") or payload.get("channel") or ""),
        final_url,
        allowed_hosts,
        str(payload.get("school") or ""),
        payload_school_aliases(payload),
    )


def configured_institution_idp_mismatch(page: Any, payload: dict[str, Any]) -> bool:
    if str(payload.get("credential_scope") or "").strip().casefold() == "site_personal":
        return False
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    if not configured_institution_is_xiamen(school, school_aliases):
        return False
    try:
        if page.locator("input[type='password']:visible").count() == 0:
            return False
    except Exception:
        return False
    final_url = str(getattr(page, "url", "") or "")
    host = (urlsplit(final_url).hostname or "").casefold()
    external_idp = host.endswith(".edu.cn") or "/idp/" in urlsplit(final_url).path.casefold()
    return bool(
        external_idp
        and not configured_credentials_allowed_on_url(
            school,
            final_url,
            school_aliases,
        )
    )


def click_carsi_federation(page: Any, enabled: bool = False) -> bool:
    if not enabled:
        return False
    if page_control_flag(page, "codexCarsiSelected"):
        return False
    current_text = page_text(page)
    current_url = str(getattr(page, "url", "") or "")
    if carsi_host(current_url) or carsi_directory_page(page, current_text, current_url):
        return False
    clicked = False
    selectors = (
        "a[href*='carsi' i]:not([href*='about' i])",
        "button[data-id*='carsi' i]",
        "button[value*='carsi' i]",
        "[role='option'][data-value*='carsi' i]",
        "a",
        "button",
        "[role='option']",
    )
    for selector in selectors:
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 100)):
                locator = locators.nth(index)
                try:
                    if not locator.is_visible(timeout=200):
                        continue
                    label = re.sub(r"\s+", " ", str(locator.inner_text(timeout=500) or "")).strip()
                except Exception:
                    continue
                if not carsi_federation_label_matches(label):
                    continue
                click_traced_locator(locator, 1500, "carsi_federation", selector)
                clicked = True
                break
        except Exception:
            continue
        if clicked:
            break
    if not clicked:
        return False
    mark_page_control_flag(page, "codexCarsiSelected")
    try:
        page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass
    wait_briefly(page, 750)
    return True


def click_acs_school_via_federations(
    page: Any,
    school: str,
    payload: dict[str, Any],
) -> bool:
    if page_control_flag(page, "codexAcsFederationsScanned"):
        return False
    school_aliases = payload_school_aliases(payload)
    try:
        links = page.locator("a[href='#']")
        candidates: list[tuple[int, str]] = []
        seen_labels: set[str] = set()
        for index in range(links.count()):
            locator = links.nth(index)
            try:
                if not locator.is_visible(timeout=300):
                    continue
                text = str(locator.inner_text(timeout=500) or "").strip()
            except Exception:
                continue
            lowered = text.casefold()
            if not any(
                token in lowered
                for token in (
                    "federation",
                    "carsi",
                    "identity",
                    "access management",
                    "research and education network",
                    "science and technology network",
                    "others",
                )
            ):
                continue
            normalized = " ".join(text.split())
            if not normalized or normalized.casefold() in seen_labels:
                continue
            seen_labels.add(normalized.casefold())
            candidates.append(
                (
                    acs_federation_priority(
                        normalized,
                        school,
                        school_aliases,
                    ),
                    normalized,
                )
            )
        attempted = {
            str(value).casefold()
            for value in payload.get("_codex_acs_federation_attempts", [])
            if str(value).strip()
        }
        for priority, label in sorted(candidates, key=lambda item: item[0]):
            normalized_label = label.casefold()
            if normalized_label in attempted:
                continue
            if (
                institution_prefers_carsi(school, school_aliases)
                and priority > 0
                and any(carsi_federation_label_matches(value) for value in attempted)
            ):
                continue
            label_key = hashlib.sha256(label.casefold().encode("utf-8")).hexdigest()[:16]
            flag = f"codexAcsFederationAttempted_{label_key}"
            if page_control_flag(page, flag):
                continue
            mark_page_control_flag(page, flag)
            if not click_first_visible_text(page, (label,), timeout_ms=1500):
                continue
            attempted.add(normalized_label)
            payload["_codex_acs_federation_attempts"] = sorted(attempted)
            payload["_codex_acs_federation_pending_since"] = time.monotonic()
            wait_briefly(page, 1500 if priority == 0 else 600)
            return True
    except Exception:
        pass
    mark_page_control_flag(page, "codexAcsFederationsScanned")
    return False


def handle_acs_institution_wayf(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not acs_institution_wayf_page(text, final_url):
        return False
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    if not school:
        return False
    search_selectors = (
        "input[aria-label*='Search By University' i]",
        "input[aria-label*='University or Organization' i]",
        "input[placeholder*='Institution' i]",
        "input[placeholder*='University' i]",
        "input[placeholder*='Organization' i]",
    )
    changed = False
    if not payload.get("_codex_acs_search_attempted"):
        changed = type_first_selector_sequentially(page, search_selectors, school)
        if changed:
            payload["_codex_acs_search_attempted"] = True
            payload["_codex_acs_search_pending_since"] = time.monotonic()
            mark_page_control_flag(page, "codexAcsInstitutionSearchEntered")
            mark_page_control_flag(page, "codexInstitutionSearchEntered")
            wait_briefly(page, 1500)
            return True
    if (
        not page_control_flag(page, "codexAcsSchoolSelected")
        and click_school_result(page, school, school_aliases)
    ):
        mark_page_control_flag(page, "codexAcsSchoolSelected")
        wait_briefly(page, 1000)
        return True
    if acs_pending_within_result_window(payload, "_codex_acs_search_pending_since"):
        return False
    if click_acs_school_via_federations(page, school, payload):
        wait_briefly(page, 1000)
        return True
    if acs_pending_within_result_window(
        payload,
        "_codex_acs_federation_pending_since",
    ):
        return False
    return changed


def acs_federation_selection_no_progress(
    page: Any,
    payload: dict[str, Any],
) -> bool:
    attempts = [
        str(value).strip()
        for value in payload.get("_codex_acs_federation_attempts", [])
        if str(value).strip()
    ]
    if not attempts:
        return False
    if acs_pending_within_result_window(
        payload,
        "_codex_acs_federation_pending_since",
    ):
        return False
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not acs_institution_wayf_page(text, final_url) and not acs_auth_flow_owned(
        payload,
        final_url,
        text,
    ):
        return False
    school = str(payload.get("school") or "").strip()
    return not institution_text_contains_exact_school(
        text,
        school,
        payload_school_aliases(payload),
    )


def detects_personal_login_only(text: str) -> bool:
    lowered = text.casefold()
    has_personal_login = any(
        token in lowered
        for token in (
            "acs id",
            "personal account",
            "publishing center",
            "chronoshub",
            "personal sign in",
            "personal sign-in",
        )
    )
    has_institution_hint = any(
        token in lowered
        for token in (
            "institutional login",
            "sign in via your organization",
            "sign in through your institution",
            "access through your institution",
            "institutions",
            "机构登录",
            "通过机构",
        )
    )
    return has_personal_login and not has_institution_hint


def institution_entry_reached(text: str, final_url: str) -> bool:
    lowered = " ".join((text or "", final_url or "")).casefold()
    return any(
        token in lowered
        for token in (
            "institution-entry",
            "organization-entry",
            "organization-entry-filled",
            "find your institution",
            "find your organization",
            "institution selected",
        )
    )


def page_control_flag(page: Any, flag: str) -> bool:
    try:
        return bool(
            page.evaluate(
                """(flag) => document.documentElement.dataset[flag] === "1" """,
                flag,
            )
        )
    except Exception:
        return False


def mark_page_control_flag(page: Any, flag: str) -> None:
    try:
        page.evaluate(
            """(flag) => {
                document.documentElement.dataset[flag] = "1";
                const timestampKey = `${flag}At`;
                if (!document.documentElement.dataset[timestampKey]) {
                    document.documentElement.dataset[timestampKey] = String(Date.now());
                }
            }""",
            flag,
        )
    except Exception:
        pass


def page_control_flag_age_seconds(page: Any, flag: str) -> float | None:
    try:
        value = page.evaluate(
            '(flag) => document.documentElement.dataset[`${flag}At`] || ""',
            flag,
        )
        timestamp_ms = float(value)
        if timestamp_ms <= 0:
            return None
        return max(0.0, time.time() - timestamp_ms / 1000.0)
    except Exception:
        return None


INSTITUTION_ENTRY_ATTEMPTS_DATASET = "codexInstitutionEntryAttempts"
COMMAND_ATTEMPTS_DATASET = "codexCommandAttempts"


def locator_control_fingerprint(locator: Any, action_kind: str, selector_hint: str) -> str:
    try:
        element = locator.evaluate(
            r"""(node) => {
                const parts = [];
                let current = node;
                while (current && current.nodeType === 1 && parts.length < 6) {
                    const tag = String(current.tagName || "").toLowerCase();
                    if (current.id) {
                        parts.unshift(`${tag}#${current.id}`);
                        break;
                    }
                    const siblings = current.parentElement
                        ? Array.from(current.parentElement.children).filter(
                            (item) => item.tagName === current.tagName
                        )
                        : [];
                    const index = siblings.indexOf(current);
                    parts.unshift(`${tag}:nth-of-type(${Math.max(1, index + 1)})`);
                    current = current.parentElement;
                }
                return {
                    tag: String(node.tagName || "").toLowerCase(),
                    role: String(node.getAttribute("role") || ""),
                    id: String(node.id || ""),
                    name: String(node.getAttribute("name") || ""),
                    aria: String(node.getAttribute("aria-label") || ""),
                    href: String(node.getAttribute("href") || ""),
                    text: String(node.innerText || node.textContent || "").trim().replace(/\s+/g, " ").slice(0, 160),
                    path: parts.join(" > ")
                };
            }"""
        )
    except Exception:
        element = {}
    normalized_element = element if isinstance(element, dict) else {}
    material = json.dumps(
        {"element": normalized_element}
        if any(str(value or "") for value in normalized_element.values())
        else {
            "fallback_action_kind": action_kind,
            "fallback_selector_hint": selector_hint,
        },
        ensure_ascii=True,
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:20]


def page_control_fingerprint_attempted(page: Any, dataset: str, fingerprint: str) -> bool:
    try:
        return bool(
            page.evaluate(
                """([dataset, fingerprint]) => {
                    try {
                        const values = JSON.parse(document.documentElement.dataset[dataset] || "[]");
                        return Array.isArray(values) && values.includes(fingerprint);
                    } catch (_) {
                        return false;
                    }
                }""",
                [dataset, fingerprint],
            )
        )
    except Exception:
        return False


def mark_page_control_fingerprint(page: Any, dataset: str, fingerprint: str) -> None:
    try:
        page.evaluate(
            """([dataset, fingerprint]) => {
                let values = [];
                try {
                    const parsed = JSON.parse(document.documentElement.dataset[dataset] || "[]");
                    if (Array.isArray(parsed)) values = parsed;
                } catch (_) {}
                if (!values.includes(fingerprint)) values.push(fingerprint);
                document.documentElement.dataset[dataset] = JSON.stringify(values.slice(-40));
            }""",
            [dataset, fingerprint],
        )
    except Exception:
        pass


def click_institution_entry_once(
    page: Any,
    selectors: tuple[str, ...],
    labels: tuple[str, ...],
    *,
    timeout_ms: int = 1500,
) -> bool:
    scopes = [page]
    scopes.extend(
        frame
        for frame in getattr(page, "frames", [])
        if frame != getattr(page, "main_frame", None)
    )
    for scope in scopes:
        for selector in selectors:
            try:
                locators = scope.locator(selector)
                for index in range(min(locators.count(), 20)):
                    locator = locators.nth(index)
                    if not locator.is_visible(timeout=500):
                        continue
                    fingerprint = locator_control_fingerprint(
                        locator,
                        "selector",
                        selector,
                    )
                    if page_control_fingerprint_attempted(
                        page,
                        INSTITUTION_ENTRY_ATTEMPTS_DATASET,
                        fingerprint,
                    ):
                        continue
                    mark_page_control_fingerprint(
                        page,
                        INSTITUTION_ENTRY_ATTEMPTS_DATASET,
                        fingerprint,
                    )
                    try:
                        click_traced_locator(locator, timeout_ms, "selector", selector)
                    except Exception:
                        pass
                    return True
            except Exception:
                continue
        for label in labels:
            for role in ("button", "link"):
                try:
                    locators = scope.get_by_role(role, name=label, exact=False)
                    for index in range(min(locators.count(), 20)):
                        locator = locators.nth(index)
                        if not locator.is_visible(timeout=500):
                            continue
                        selector_hint = f"{role}:{label}"
                        fingerprint = locator_control_fingerprint(
                            locator,
                            "role_text",
                            selector_hint,
                        )
                        if page_control_fingerprint_attempted(
                            page,
                            INSTITUTION_ENTRY_ATTEMPTS_DATASET,
                            fingerprint,
                        ):
                            continue
                        mark_page_control_fingerprint(
                            page,
                            INSTITUTION_ENTRY_ATTEMPTS_DATASET,
                            fingerprint,
                        )
                        try:
                            click_traced_locator(
                                locator,
                                timeout_ms,
                                "role_text",
                                selector_hint,
                            )
                        except Exception:
                            pass
                        return True
                except Exception:
                    continue
    return False


def click_first_exact_command_once(
    page: Any,
    labels: tuple[str, ...],
    timeout_ms: int = 1000,
) -> bool:
    scopes = [page]
    scopes.extend(
        frame
        for frame in getattr(page, "frames", [])
        if frame != getattr(page, "main_frame", None)
    )
    for scope in scopes:
        for label in labels:
            for role in ("button", "link"):
                try:
                    locators = scope.get_by_role(role, name=label, exact=True)
                    for index in range(min(locators.count(), 20)):
                        locator = locators.nth(index)
                        if not locator.is_visible(timeout=500):
                            continue
                        selector_hint = f"{role}:{label}"
                        fingerprint = locator_control_fingerprint(
                            locator,
                            "exact_command",
                            selector_hint,
                        )
                        if page_control_fingerprint_attempted(
                            page,
                            COMMAND_ATTEMPTS_DATASET,
                            fingerprint,
                        ):
                            continue
                        mark_page_control_fingerprint(
                            page,
                            COMMAND_ATTEMPTS_DATASET,
                            fingerprint,
                        )
                        try:
                            click_traced_locator(
                                locator,
                                timeout_ms,
                                "exact_command",
                                selector_hint,
                            )
                        except Exception:
                            pass
                        return True
                except Exception:
                    continue
    return False


def normalize_institution_name(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).replace("\u00a0", " ")
    text = re.sub(r"\s+", " ", text).strip(" \t\r\n,;:")
    return re.sub(r"\s*([()])\s*", r"\1", text).casefold()


def normalize_school_aliases(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, (list, tuple, set, frozenset)) else (value,) if isinstance(value, str) else ()
    output: list[str] = []
    seen: set[str] = set()
    for item in values:
        label = re.sub(r"\s+", " ", str(item or "")).strip()
        normalized = normalize_institution_name(label)
        if normalized and normalized not in seen:
            seen.add(normalized)
            output.append(label)
    return tuple(output)


def payload_school_aliases(payload: dict[str, Any]) -> tuple[str, ...]:
    return normalize_school_aliases(payload.get("school_aliases"))


def exact_school_labels(
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> tuple[str, ...]:
    configured = re.sub(r"\s+", " ", str(school or "")).strip()
    if not configured:
        return ()
    labels = [configured, *normalize_school_aliases(school_aliases)]
    output: list[str] = []
    seen: set[str] = set()
    for label in labels:
        normalized = normalize_institution_name(label)
        if normalized and normalized not in seen:
            seen.add(normalized)
            output.append(label)
    return tuple(output)


def institution_name_matches(
    candidate: Any,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    normalized_candidate = normalize_institution_name(candidate)
    return bool(
        normalized_candidate
        and normalized_candidate
        in {
            normalize_institution_name(label)
            for label in exact_school_labels(school, school_aliases)
        }
    )


def institution_bilingual_name_matches(
    candidate: Any,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    normalized = unicodedata.normalize("NFKC", str(candidate or ""))
    normalized = re.sub(r"\s+", " ", normalized).strip(" \t\r\n,;:")
    if institution_name_matches(normalized, school, school_aliases):
        return True
    base = re.split(r"\s*\(", normalized, maxsplit=1)[0].strip()
    translated = [part.strip() for part in re.findall(r"\(([^()]*)\)", normalized)]
    parts = [base, *translated]
    return bool(
        base
        and all(
            part and institution_name_matches(part, school, school_aliases)
            for part in parts
        )
    )


def institution_authorization_name_matches(
    candidate: Any,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    if institution_name_matches(candidate, school, school_aliases):
        return True
    candidate_tokens = re.findall(
        r"[a-z0-9]+",
        normalize_institution_name(candidate),
    )
    if not candidate_tokens:
        return False
    for label in exact_school_labels(school, school_aliases):
        configured_tokens = re.findall(
            r"[a-z0-9]+",
            normalize_institution_name(label),
        )
        if len(candidate_tokens) != len(configured_tokens):
            continue
        if all(
            candidate_token == configured_token
            or (
                len(candidate_token) >= 4
                and configured_token.startswith(candidate_token)
            )
            for candidate_token, configured_token in zip(
                candidate_tokens,
                configured_tokens,
            )
        ):
            return True
    return False


def institution_text_contains_exact_school(
    text: str,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    normalized_text = unicodedata.normalize("NFKC", str(text or ""))
    segments = [segment.strip() for segment in re.split(r"[\r\n|•]+", normalized_text) if segment.strip()]
    return any(
        institution_name_matches(segment, school, school_aliases)
        for segment in segments
    )


def access_provided_by_text_contains_exact_school(
    text: str,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    if not school.strip():
        return False
    normalized = unicodedata.normalize("NFKC", str(text or ""))
    for match in re.finditer(
        r"access\s+provided\s+by\s*:?\s*([^\r\n|•]+)",
        normalized,
        flags=re.IGNORECASE,
    ):
        candidate = re.split(
            r"\s+(?:sign\s+out|log\s*out|logout|sign\s+in|log\s+in)\b",
            match.group(1),
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0].strip(" \t,;:")
        if institution_authorization_name_matches(
            candidate,
            school,
            school_aliases,
        ):
            return True
    return False


def institution_access_pattern_contains_exact_school(
    text: str,
    school: str,
    school_aliases: tuple[str, ...],
    patterns: tuple[str, ...],
) -> bool:
    if not school.strip():
        return False
    normalized = unicodedata.normalize("NFKC", str(text or ""))
    for pattern in patterns:
        for match in re.finditer(pattern, normalized, flags=re.IGNORECASE):
            candidate = str(match.groupdict().get("school") or "").strip(" \t,;:.")
            if candidate and institution_name_matches(candidate, school, school_aliases):
                return True
    return False


def configured_institution_is_xiamen(
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    configured = {
        normalize_institution_name(label)
        for label in exact_school_labels(school, school_aliases)
    }
    return bool(
        configured
        & {
            normalize_institution_name("Xiamen University"),
            normalize_institution_name("厦门大学"),
        }
    )


def carsi_host(final_url: str) -> bool:
    host = (urlsplit(str(final_url or "")).hostname or "").casefold()
    return host == "carsi.edu.cn" or host.endswith(".carsi.edu.cn")


def carsi_directory_page(page: Any, text: str = "", final_url: str = "") -> bool:
    body = text or page_text(page)
    url = final_url or str(getattr(page, "url", "") or "")
    lowered = " ".join((body, url)).casefold()
    try:
        has_directory_input = page.locator("#show").count() > 0
    except Exception:
        has_directory_input = False
    federation_institution_count = 0
    if any(
        marker in lowered
        for marker in (
            "china cernet federation",
            "cernet authentication and resource sharing infrastructure",
            "中国教育和科研计算机网联邦认证与资源共享基础设施",
        )
    ):
        try:
            links = page.locator("a")
            for index in range(min(links.count(), 200)):
                try:
                    locator = links.nth(index)
                    if not locator.is_visible(timeout=200):
                        continue
                    label = normalize_institution_name(
                        locator.inner_text(timeout=500)
                    )
                except Exception:
                    continue
                if any(
                    token in label
                    for token in (
                        "university",
                        "college",
                        "institute",
                        "academy",
                        "大学",
                        "学院",
                        "研究院",
                    )
                ):
                    federation_institution_count += 1
                    if federation_institution_count >= 5:
                        break
        except Exception:
            federation_institution_count = 0
    return bool(
        (
            has_directory_input
            and (
                (carsi_host(url) and "login" in url.casefold())
                or any(marker in lowered for marker in ("请输入高校/机构名称", "用户登录", "select your institution"))
            )
        )
        or federation_institution_count >= 5
    )


def preferred_carsi_institution_query(
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> str:
    labels = exact_school_labels(school, school_aliases)
    return next(
        (
            label
            for label in labels
            if any("\u4e00" <= character <= "\u9fff" for character in label)
        ),
        labels[0] if labels else "",
    )


def click_school_result_locator(page: Any, locator: Any, selector_hint: str) -> bool:
    try:
        locator.scroll_into_view_if_needed(timeout=1000)
    except Exception:
        pass
    try:
        if not locator.is_visible(timeout=500):
            return False
    except Exception:
        pass
    click_traced_locator(
        locator,
        3000,
        "institution_result",
        selector_hint,
        no_wait_after=True,
    )
    mark_page_control_flag(page, "codexInstitutionExactSchoolSelected")
    return True


def batched_school_candidate_rows(locators: Any, limit: int = 2000) -> list[dict[str, Any]]:
    try:
        rows = locators.evaluate_all(
            """
            (elements, limit) => elements.slice(0, limit).map((element, index) => {
              const style = window.getComputedStyle(element);
              const rect = element.getBoundingClientRect();
              return {
                index,
                text: element.innerText || element.textContent || '',
                visible: style.display !== 'none'
                  && style.visibility !== 'hidden'
                  && rect.width > 0
                  && rect.height > 0,
              };
            })
            """,
            max(1, limit),
        )
    except Exception:
        return []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def click_school_result(
    page: Any,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    labels = exact_school_labels(school, school_aliases)
    if not labels:
        return False
    try:
        select_count = page.locator("select").count()
    except Exception:
        select_count = 0
    for index in range(select_count):
        try:
            select = page.locator("select").nth(index)
            options = select.locator("option").evaluate_all(
                "(els) => els.map((e) => ({value: e.value || '', text: e.textContent || ''}))"
            )
            if not isinstance(options, list):
                continue
            for option in options:
                text = str((option or {}).get("text") or "")
                value = str((option or {}).get("value") or "")
                if institution_bilingual_name_matches(
                    text,
                    school,
                    school_aliases,
                ):
                    if value:
                        select.select_option(value=value, timeout=1000)
                    else:
                        select.select_option(label=text, timeout=1000)
                    mark_page_control_flag(page, "codexInstitutionExactSchoolSelected")
                    return True
        except Exception:
            continue
    for role in ("option", "link", "button", "listitem"):
        for label in labels:
            try:
                locator = page.get_by_role(role, name=label, exact=True).first
                if locator.count() == 0:
                    continue
                try:
                    if not locator.is_visible(timeout=500):
                        continue
                except Exception:
                    pass
                if click_school_result_locator(
                    page,
                    locator,
                    f"{role}:configured_school",
                ):
                    return True
            except Exception:
                continue
    for label in labels:
        try:
            locator = page.get_by_text(label, exact=True).first
            if locator.count() == 0:
                continue
            if click_school_result_locator(
                page,
                locator,
                "configured_school",
            ):
                return True
        except Exception:
            continue
    for selector in (
        "a,[role='option'],button",
        "[role='listitem'],li",
    ):
        try:
            locators = page.locator(selector)
            for row in batched_school_candidate_rows(locators):
                if not row.get("visible") or not institution_bilingual_name_matches(
                    row.get("text"),
                    school,
                    school_aliases,
                ):
                    continue
                index = row.get("index")
                if not isinstance(index, int):
                    continue
                if click_school_result_locator(
                    page,
                    locators.nth(index),
                    f"{selector}:configured_school_batch",
                ):
                    return True
        except Exception:
            continue
    return False


def click_visible_carsi_federation_option(page: Any) -> bool:
    selectors = ("[role='option']", "mat-option", ".mat-mdc-option", ".mdc-list-item")
    for selector in selectors:
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 100)):
                locator = locators.nth(index)
                try:
                    if not locator.is_visible(timeout=200):
                        continue
                    label = re.sub(r"\s+", " ", str(locator.inner_text(timeout=500) or "")).strip()
                except Exception:
                    continue
                if not carsi_federation_label_matches(label):
                    continue
                click_traced_locator(locator, 1500, "carsi_federation", f"{selector}:exact_carsi")
                return True
        except Exception:
            continue
    return False


def handle_web_of_science_carsi_entry(page: Any, payload: dict[str, Any]) -> bool:
    if str(payload.get("auth_state_scope") or "").strip().casefold() != "web_of_science":
        return False
    if not payload_prefers_carsi(payload):
        return False
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    lowered = " ".join((text, final_url)).casefold()
    if carsi_host(final_url) or carsi_directory_page(page, text, final_url):
        return False
    if "access.clarivate.com/login" not in lowered and not (
        "select institution" in lowered and "federation" in lowered
    ):
        return False

    if not page_control_flag(page, "codexWosCarsiFederationSelected"):
        selected = click_visible_carsi_federation_option(page)
        if not selected:
            opened = click_first_visible_selector(
                page,
                (
                    "[role='combobox'][aria-label*='federation' i]",
                    ".mat-mdc-select-trigger",
                    "mat-select",
                    "[role='combobox']",
                ),
                timeout_ms=1500,
            )
            if opened:
                wait_briefly(page, 500)
                return True
        if selected:
            mark_page_control_flag(page, "codexWosCarsiFederationSelected")
            wait_briefly(page, 500)
            return True
    if page_control_flag(page, "codexWosCarsiFederationSelected") and not page_control_flag(
        page, "codexWosCarsiFederationSubmitted"
    ):
        submitted = click_first_exact_command(
            page,
            ("Next", "转到机构", "Go to institution", "Continue"),
            timeout_ms=2000,
        )
        if submitted:
            mark_page_control_flag(page, "codexWosCarsiFederationSubmitted")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass
            wait_briefly(page, 750)
            return True
    return False


def handle_carsi_directory(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not carsi_directory_page(page, text, final_url):
        return False
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    if not school:
        return False
    changed = fill_first_selector(
        page,
        ("#show",),
        preferred_carsi_institution_query(school, school_aliases),
    )
    if changed:
        mark_page_control_flag(page, "codexInstitutionSearchEntered")
        wait_briefly(page, 1000)
        return True
    if not page_control_flag(
        page,
        "codexInstitutionExactSchoolSelected",
    ) and click_school_result(page, school, school_aliases):
        wait_briefly(page, 500)
        return True
    if page_control_flag(page, "codexInstitutionExactSchoolSelected") and not page_control_flag(
        page, "codexCarsiLoginSubmitted"
    ):
        submitted = click_first_visible_selector(
            page,
            ("#idpSkipButton", "#login", "button[type='submit']"),
            timeout_ms=2000,
        ) or click_first_exact_command(page, ("登录", "Login"), timeout_ms=2000)
        if submitted:
            mark_page_control_flag(page, "codexCarsiLoginSubmitted")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass
            wait_briefly(page, 750)
            return True
    return False


def xmu_authserver_login_page(
    text: str,
    final_url: str,
    school: str = "",
    school_aliases: tuple[str, ...] = (),
) -> bool:
    host = (urlsplit(str(final_url or "")).hostname or "").casefold()
    lowered = " ".join((text or "", final_url or "")).casefold()
    recognized_surface = host == "ids.xmu.edu.cn" and "authserver/login" in lowered
    configured_fixture_surface = configured_institution_is_xiamen(
        school,
        school_aliases,
    ) and all(
        marker in lowered for marker in ("厦门大学", "统一身份认证", "扫码登录", "账号登录")
    )
    return (recognized_surface or configured_fixture_surface) and any(
        marker in lowered for marker in ("账号登录", "扫码登录", "统一身份认证")
    )


def handle_xmu_authserver_login_mode(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not xmu_authserver_login_page(
        text,
        final_url,
        str(payload.get("school") or ""),
        payload_school_aliases(payload),
    ):
        return False
    try:
        if page.locator("input[type='password']:visible").count() > 0:
            return False
    except Exception:
        pass
    if page_control_flag(page, "codexXmuAccountLoginSelected"):
        return False
    clicked = click_first_visible_selector(
        page,
        ("#userNameLogin_a", "a.loginFont_a"),
        timeout_ms=1500,
    ) or click_first_visible_role_text(page, ("账号登录",), exact=True, timeout_ms=1500)
    if not clicked:
        return False
    mark_page_control_flag(page, "codexXmuAccountLoginSelected")
    wait_briefly(page, 750)
    return True


def saml_consent_surface(text: str, final_url: str) -> bool:
    lowered_text = (text or "").casefold()
    lowered_url = (final_url or "").casefold()
    if has_blocking_auth_gate(text):
        return False
    saml_route = "saml" in lowered_url and any(
        marker in lowered_url for marker in ("/idp/", "/profile/", "/sso")
    )
    consent_copy = any(
        marker in lowered_text
        for marker in (
            "information will be sent",
            "release information",
            "attribute release",
            "consent",
            "将向服务机构提供",
            "信息共享",
            "您是否同意",
            "自我释放期限",
        )
    )
    return saml_route and consent_copy


def handle_saml_consent(page: Any) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not saml_consent_surface(text, final_url) or page_control_flag(page, "codexSamlConsentSubmitted"):
        return False
    clicked = click_first_visible_selector(
        page,
        (
            "input[name='_eventId_proceed']",
            "button[name='_eventId_proceed']",
        ),
        timeout_ms=2000,
    )
    if not clicked:
        return False
    mark_page_control_flag(page, "codexSamlConsentSubmitted")
    try:
        page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass
    wait_briefly(page, 750)
    return True


def institution_result_candidate_labels(page: Any) -> list[str]:
    selectors = (
        "select option",
        "[role='listbox'] [role='option']",
        "[role='option']",
        "[data-testid*='institution-result' i]",
        "[data-testid*='organization-result' i]",
    )
    output: list[str] = []
    seen: set[str] = set()
    for selector in selectors:
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 50)):
                locator = locators.nth(index)
                try:
                    if not locator.is_visible(timeout=200):
                        continue
                    label = re.sub(r"\s+", " ", str(locator.inner_text(timeout=500) or "")).strip()
                except Exception:
                    continue
                normalized = normalize_institution_name(label)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    output.append(label)
        except Exception:
            continue
    return output


def configured_institution_result_missing(page: Any, payload: dict[str, Any]) -> bool:
    school = str(payload.get("school") or "").strip()
    if not school or page_control_flag(page, "codexInstitutionExactSchoolSelected"):
        return False
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    lowered_surface = " ".join((text, final_url)).casefold()
    explicit_submit_flag = ""
    if "annualreviews.org" in lowered_surface or "sign-in with shibboleth" in lowered_surface:
        explicit_submit_flag = "codexAnnualFindClicked"
    elif rsc_wayf_page(text, final_url):
        explicit_submit_flag = "codexRscWayfSearchClicked"
    elif acm_surface_detected(text, final_url) and (
        "search institutions by name" in lowered_surface
        or "/institutions" in lowered_surface
    ):
        explicit_submit_flag = "codexAcmInstitutionSearchSubmitted"
    if explicit_submit_flag and not page_control_flag(page, explicit_submit_flag):
        return False
    search_flags = (
        "codexInstitutionSearchEntered",
        "codexSpringerNatureWayfSearchEntered",
        "codexAcsInstitutionSearchEntered",
        "codexAcmInstitutionSearchSubmitted",
        "codexRscWayfSearchClicked",
        "codexAnnualFindClicked",
    )
    if not any(page_control_flag(page, flag) for flag in search_flags):
        return False
    lowered = text.casefold()
    missing_markers = [
        "no institution found",
        "no organization found",
        "no matching institution",
        "no matching organization",
        "no results found",
        "未找到机构",
        "没有找到机构",
        "无匹配机构",
    ]
    # ACM keeps generic VPN/help copy containing "Institution not listed?"
    # beside valid search results. It is not evidence that the configured
    # institution is absent.
    if not acm_surface_detected(text, final_url):
        missing_markers.append("institution not listed")
    if any(marker in lowered for marker in missing_markers):
        return True
    school_tokens = (
        "university",
        "college",
        "institute",
        "school",
        "universität",
        "universidade",
        "大学",
        "学院",
        "研究院",
    )
    candidates = [
        label
        for label in institution_result_candidate_labels(page)
        if any(token in normalize_institution_name(label) for token in school_tokens)
    ]
    school_aliases = payload_school_aliases(payload)
    return bool(candidates) and not any(
        institution_name_matches(label, school, school_aliases)
        for label in candidates
    )


INSTITUTION_SEARCH_FLAGS = (
    "codexInstitutionSearchEntered",
    "codexSpringerNatureWayfSearchEntered",
    "codexAcsInstitutionSearchEntered",
    "codexAcmInstitutionSearchSubmitted",
    "codexRscWayfSearchClicked",
    "codexAnnualFindClicked",
)


def institution_search_pending(page: Any, payload: dict[str, Any]) -> bool:
    if page_control_flag(page, "codexInstitutionExactSchoolSelected"):
        return False
    active_flags = [
        flag for flag in INSTITUTION_SEARCH_FLAGS if page_control_flag(page, flag)
    ]
    if not active_flags or configured_institution_result_missing(page, payload):
        return False
    if institution_result_candidate_labels(page):
        return False
    ages = [
        age
        for flag in active_flags
        if (age := page_control_flag_age_seconds(page, flag)) is not None
    ]
    return not ages or min(ages) < institution_result_wait_seconds()


def institution_search_results_unavailable(page: Any, payload: dict[str, Any]) -> bool:
    if page_control_flag(page, "codexInstitutionExactSchoolSelected"):
        return False
    active_flags = [
        flag for flag in INSTITUTION_SEARCH_FLAGS if page_control_flag(page, flag)
    ]
    if not active_flags or configured_institution_result_missing(page, payload):
        return False
    if institution_result_candidate_labels(page):
        return False
    ages = [
        age
        for flag in active_flags
        if (age := page_control_flag_age_seconds(page, flag)) is not None
    ]
    return bool(ages) and min(ages) >= institution_result_wait_seconds()


def configured_institution_unavailable_reason(payload: dict[str, Any]) -> str:
    del payload
    return "configured_institution_not_listed"


def press_first_visible_input(page: Any, selectors: tuple[str, ...], key: str = "Enter") -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() == 0:
                continue
            try:
                if not locator.is_visible(timeout=500):
                    continue
            except Exception:
                pass
            locator.press(key, timeout=1000)
            return True
        except Exception:
            continue
    return False


def acm_institution_search_surface(page: Any, text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    if "search institutions by name" in lowered or "/institutions" in lowered or "#institutions" in lowered:
        return True
    try:
        search_input = page.locator("input.search-input:visible").first
        return search_input.count() > 0
    except Exception:
        return False


def click_acm_sso_school_result(
    page: Any,
    school: str,
    school_aliases: tuple[str, ...] = (),
) -> bool:
    if not exact_school_labels(school, school_aliases):
        return False
    try:
        locators = page.locator("a[href*='/action/ssostart' i]")
        rows = batched_school_candidate_rows(locators)
    except Exception:
        return False
    for row in rows:
        if not row.get("visible") or not institution_name_matches(
            row.get("text"),
            school,
            school_aliases,
        ):
            continue
        index = row.get("index")
        if not isinstance(index, int):
            continue
        if click_school_result_locator(
            page,
            locators.nth(index),
            "acm_sso:configured_school",
        ):
            return True
    return False


def handle_acm_institution_search(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not acm_institution_search_surface(page, text, final_url):
        return False
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    if not school:
        return False
    if not page_control_flag(page, "codexAcmInstitutionSearchSubmitted"):
        try:
            search_input = page.locator("input.search-input:visible").first
            if search_input.count() > 0:
                current = str(search_input.input_value(timeout=500) or "").strip()
                if current != school:
                    search_input.fill(school, timeout=1500)
                    mark_page_control_flag(page, "codexInstitutionSearchEntered")
                    mark_page_control_flag(page, "codexAcmInstitutionSearchSubmitted")
                    wait_briefly(page, 1500)
                    return True
                if current:
                    mark_page_control_flag(page, "codexInstitutionSearchEntered")
                    mark_page_control_flag(page, "codexAcmInstitutionSearchSubmitted")
        except Exception:
            pass
    changed = fill_known_auth_fields(page, payload)
    if changed:
        return True
    if (
        not page_control_flag(page, "codexAcmSchoolSelected")
        and click_acm_sso_school_result(page, school, school_aliases)
    ):
        mark_page_control_flag(page, "codexAcmSchoolSelected")
        try:
            page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        wait_briefly(page)
        return True
    if not page_control_flag(page, "codexAcmInstitutionSearchSubmitted"):
        submitted = (
            click_first_visible_selector(
                page,
                (
                    "button[aria-label*='Search' i]",
                    "button:has-text('Search')",
                    "input[type='submit'][value*='Search' i]",
                    "input[type='button'][value*='Search' i]",
                    "[class*='search' i] button",
                ),
            )
            or press_first_visible_input(
                page,
                (
                    "input[placeholder*='Institution' i]",
                    "input[aria-label*='Institution' i]",
                    "input[name*='institution' i]",
                    "input.search-input",
                ),
            )
        )
        if submitted:
            changed = True
            mark_page_control_flag(page, "codexAcmInstitutionSearchSubmitted")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
            wait_briefly(page, 1000)
            return True
    return changed


def acm_surface_detected(text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    return "dl.acm.org" in lowered or "acm digital library" in lowered or "association for computing machinery" in lowered


def acm_gateway_reached(text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    return "acm librarians and institutions gateway" in lowered or "institutional trial" in lowered


def acm_institution_not_listed(
    page: Any,
    text: str,
    final_url: str,
    payload: dict[str, Any],
) -> bool:
    return (
        acm_surface_detected(text, final_url)
        and page_control_flag(page, "codexAcmInstitutionSearchSubmitted")
        and configured_institution_result_missing(page, payload)
    )


def acm_show_login_surface(final_url: str) -> bool:
    lowered = (final_url or "").casefold()
    return "/action/showlogin" in lowered or "#showlogin" in lowered or "#signin" in lowered


def acm_saml_post_callback(final_url: str) -> bool:
    lowered = (final_url or "").casefold()
    return "/action/saml2post" in lowered or "#saml2post" in lowered


def acm_institution_content_page(final_url: str) -> bool:
    parsed = urlsplit(final_url or "")
    return re.fullmatch(r"/institution/\d+", parsed.path.casefold().rstrip("/")) is not None


def acm_terms_consent_surface(text: str, final_url: str) -> bool:
    if not acm_saml_post_callback(final_url):
        return False
    lowered = re.sub(r"\s+", " ", text or "").casefold()
    return all(
        marker in lowered
        for marker in (
            "i have read and agree to",
            "terms and conditions",
            "privacy policy",
        )
    )


def handle_acm_terms_consent(page: Any) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not acm_terms_consent_surface(text, final_url) or page_control_flag(
        page,
        "codexAcmTermsConsentAccepted",
    ):
        return False
    clicked = click_first_visible_selector(
        page,
        (
            "button[value='Yes' i]",
            "input[type='submit'][value='Yes' i]",
            "input[type='button'][value='Yes' i]",
        ),
        timeout_ms=2000,
    ) or click_first_visible_role_text(page, ("Yes",), exact=True, timeout_ms=2000)
    if not clicked:
        return False
    mark_page_control_flag(page, "codexAcmTermsConsentAccepted")
    try:
        page.wait_for_load_state("domcontentloaded", timeout=10000)
    except Exception:
        pass
    wait_briefly(page, 1500)
    return True


def acm_saml_callback_timed_out(page: Any, final_url: str) -> bool:
    if not acm_saml_post_callback(final_url):
        return False
    age = page_control_flag_age_seconds(page, "codexAcmSamlCallbackObserved")
    return age is not None and age >= env_int(
        ("LAPS_ACM_SAML_CALLBACK_WAIT_SECONDS",),
        90,
        5,
    )


def springernature_institution_sso_unavailable(text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    return "springernature.com/gp/open-science/oa-agreements" in lowered or (
        "open access agreements" in lowered and "paying for oa apcs through your institution" in lowered
    )


def rsc_institution_button_page(text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    return "pubs.rsc.org/institutional-login" in lowered and "access through your institution" in lowered


def rsc_wayf_page(text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    return "sso.rsc.org/wayf" in lowered and "search for your institution name" in lowered


def handle_rsc_wayf_checkpoint(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if not rsc_wayf_page(text, final_url) or not page_control_flag(
        page,
        "codexInstitutionExactSchoolSelected",
    ):
        return False

    try:
        remember = page.locator("#checkbox-1").first
        remember_present = remember.count() > 0 and remember.is_visible(timeout=500)
    except Exception:
        remember = None
        remember_present = False
    if not remember_present or remember is None:
        return False

    try:
        remember_checked = bool(remember.is_checked(timeout=500))
    except Exception:
        remember_checked = False
    if not remember_checked:
        if page_control_flag(page, "codexRscRememberInstitutionChecked"):
            return False
        try:
            click_traced_locator(
                remember,
                2000,
                "rsc_wayf_remember_institution",
                "#checkbox-1",
            )
        except Exception:
            return False
        mark_page_control_flag(page, "codexRscRememberInstitutionChecked")
        wait_briefly(page, 500)
        return True
    if not page_control_flag(page, "codexRscRememberInstitutionChecked"):
        mark_page_control_flag(page, "codexRscRememberInstitutionChecked")

    if page_control_flag(page, "codexRscWayfNextSubmitted"):
        return False
    try:
        next_button = page.get_by_role("button", name="Next", exact=True).first
        if next_button.count() == 0:
            return False
        if not next_button.is_visible(timeout=500) or not next_button.is_enabled(timeout=500):
            return False
        click_traced_locator(
            next_button,
            2000,
            "rsc_wayf_next",
            "button:Next",
        )
    except Exception:
        return False
    mark_page_control_flag(page, "codexRscWayfNextSubmitted")
    try:
        page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass
    wait_briefly(page, 750)
    return True


def handle_rsc_institution_entry(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if rsc_wayf_page(text, final_url):
        changed = fill_known_auth_fields(page, payload)
        if changed:
            return True
        if not page_control_flag(page, "codexRscWayfSearchClicked"):
            search_clicked = click_first_visible_selector(
                page,
                (
                    "button[aria-label*='search' i]",
                    "button[title*='search' i]",
                    "input[type='search'] + button",
                    "input[type='text'] + button",
                ),
                timeout_ms=2000,
            )
            if search_clicked:
                mark_page_control_flag(page, "codexRscWayfSearchClicked")
                wait_briefly(page, 1000)
                return True
        school = str(payload.get("school") or "").strip()
        school_aliases = payload_school_aliases(payload)
        if (
            school
            and not page_control_flag(page, "codexInstitutionExactSchoolSelected")
            and click_school_result(page, school, school_aliases)
        ):
            wait_briefly(page, 500)
            return True
        if handle_rsc_wayf_checkpoint(page, payload):
            return True
        # The WAYF button labelled Close clears the selected institution. It
        # is optional UI and must never be treated as an authentication step.
        return False
    if not rsc_institution_button_page(text, final_url):
        return False
    if page_control_flag(page, "codexRscInstitutionAccessClicked"):
        return False
    clicked = click_first_visible_text(page, ("Access through your institution",), timeout_ms=2000)
    if not clicked:
        return False
    mark_page_control_flag(page, "codexRscInstitutionAccessClicked")
    try:
        page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        pass
    wait_briefly(page, 750)
    return True


def acs_institution_sso_unavailable(text: str, final_url: str) -> bool:
    lowered = " ".join((text, final_url)).casefold()
    return "acsopenscience.org/institutions/institutional-open-access-agreements" in lowered or (
        "acs institutional open access agreements" in lowered and "lookup current agreements" in lowered
    )


def institutional_agreement_non_auth_redirect(text: str, final_url: str) -> bool:
    return springernature_institution_sso_unavailable(text, final_url) or acs_institution_sso_unavailable(text, final_url)


def handle_acm_overlay_and_signin(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    if acm_saml_post_callback(final_url):
        if handle_acm_terms_consent(page):
            return True
        if not page_control_flag(page, "codexAcmSamlCallbackObserved"):
            mark_page_control_flag(page, "codexAcmSamlCallbackObserved")
        return False
    if acm_institution_content_page(final_url):
        return False
    changed = handle_acm_institution_search(page, payload)
    if changed:
        return True
    lowered = " ".join((text, final_url)).casefold()
    if "dl.acm.org" not in lowered and "acm is now open access" not in lowered and "acm digital library" not in lowered:
        return False
    if dismiss_cookie_banners(page):
        return True
    if not page_control_flag(page, "codexAcmOpenAccessDismissAttempted"):
        selectors = (
            "#modalOverlay[role='dialog'] button[aria-label*='close' i]",
            "#modalOverlay[role='dialog'] button:has-text('×')",
            "#modalOverlay[role='dialog'] span:has-text('×')",
            "[role='dialog'][aria-label*='Open Access' i] button[aria-label*='close' i]",
            "section[aria-label*='Open Access' i] button[aria-label*='close' i]",
            "#oa-modal button#dismiss",
            "#dismiss",
        )
        if click_first_visible_selector(page, selectors):
            mark_page_control_flag(page, "codexAcmOpenAccessDismissAttempted")
            wait_briefly(page)
            return True
    if dismiss_cookie_banners(page):
        return True
    if click_institution_entry_once(
        page,
        (
            "a[role='tab']:has-text('Institutional Login')",
            "button[role='tab']:has-text('Institutional Login')",
            "button#institution",
        ),
        (),
        timeout_ms=1500,
    ):
        try:
            page.wait_for_load_state("domcontentloaded", timeout=3000)
        except Exception:
            pass
        wait_briefly(page)
        return True
    if click_first_exact_command_once(
        page,
        ("Select your institution:", "Select your institution"),
        timeout_ms=1500,
    ):
        wait_briefly(page, 1000)
        return True
    if click_institution_entry_once(
        page,
        (),
        (
            "Institutional Login",
            "Institutional login",
            "Access through your institution",
            "Sign in via your organization",
        ),
        timeout_ms=1000,
    ):
        try:
            page.wait_for_load_state("domcontentloaded", timeout=3000)
        except Exception:
            pass
        wait_briefly(page)
        return True
    if not acm_show_login_surface(final_url) and click_institution_entry_once(
        page,
        (
            "a[href*='/action/showLogin' i]",
            "a[href='/action/showLogin' i]",
            "a[href$='/action/showLogin' i]",
        ),
        (),
        timeout_ms=1500,
    ):
        try:
            page.wait_for_load_state("domcontentloaded", timeout=3000)
        except Exception:
            pass
        wait_briefly(page)
        return True
    return False


def handle_annual_reviews_institution_entry(page: Any, payload: dict[str, Any]) -> bool:
    text = page_text(page)
    final_url = str(getattr(page, "url", "") or "")
    lowered = " ".join((text, final_url)).casefold()
    if "annualreviews.org" not in lowered and "annual reviews" not in lowered and "sign-in with shibboleth" not in lowered:
        return False
    if dismiss_cookie_banners(page):
        return True
    if "sign-in with shibboleth" not in page_text(page).casefold():
        if click_first_visible_text(page, ("Institutional Login", "Institutional login"), timeout_ms=1000):
            try:
                page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
            wait_briefly(page)
            return True
    if fill_known_auth_fields(page, payload):
        wait_briefly(page)
        return True
    text = page_text(page)
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    if school and not page_control_flag(page, "codexAnnualFindClicked"):
        if (
            click_first_visible_selector(
                page,
                (
                    "#find",
                    "button:has-text('Find Your Organization')",
                    "button:has-text('Find your organization')",
                    "input[type='submit'][value*='Find' i]",
                    "input[type='button'][value*='Find' i]",
                ),
                timeout_ms=1000,
            )
            or click_first_visible_text(page, ("Find Your Organization", "Find your organization"), timeout_ms=1000)
        ):
            mark_page_control_flag(page, "codexAnnualFindClicked")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
            wait_briefly(page)
            return True
    if (
        school
        and not page_control_flag(page, "codexAnnualSchoolSelected")
        and click_school_result(page, school, school_aliases)
    ):
        mark_page_control_flag(page, "codexAnnualSchoolSelected")
        wait_briefly(page)
        return True
    if page_control_flag(page, "codexAnnualSchoolSelected"):
        if (
            click_first_visible_selector(
                page,
                (
                    "#go",
                    "button:has-text('Go To Sign-in')",
                    "button:has-text('Go to Sign-in')",
                    "button:has-text('Go To Sign In')",
                    "button:has-text('Go to Sign In')",
                    "input[type='submit'][value*='Go To Sign' i]",
                    "input[type='button'][value*='Go To Sign' i]",
                ),
                timeout_ms=1000,
            )
            or click_first_visible_text(page, ("Go To Sign-in", "Go to Sign-in", "Go To Sign In", "Go to Sign In"), timeout_ms=1000)
        ):
            mark_page_control_flag(page, "codexAnnualGoClicked")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass
            wait_briefly(page)
            return True
    return False


def annual_reviews_institution_result_missing(page: Any, text: str, final_url: str, payload: dict[str, Any]) -> bool:
    lowered = " ".join((text or "", final_url or "")).casefold()
    if "annualreviews.org" not in lowered and "sign-in with shibboleth" not in lowered:
        return False
    if not page_control_flag(page, "codexAnnualFindClicked"):
        return False
    school = str(payload.get("school") or "").strip()
    has_school = bool(school and page_control_flag(page, "codexAnnualSchoolSelected"))
    has_next_step = any(token in lowered for token in ("go to sign-in", "go to sign in", "saml", "shibboleth.sso"))
    return not (has_school or has_next_step or page_control_flag(page, "codexAnnualSchoolSelected"))


def bounded_non_success_response(
    event: str,
    reason: str,
    final_url: str,
    challenge_type: str,
    screenshot: str,
    storage_path: str,
) -> dict[str, Any] | None:
    if event != "auth_challenge":
        return None
    return {
        "action": "unhandled",
        "reason": reason,
        "final_url": final_url,
        "challenge_type": challenge_type,
        "screenshot_path": screenshot,
        "storage_state_path": storage_path,
    }


COMMON_INSTITUTION_SEARCH_SELECTORS = (
    "#searchFormTextInput",
    "input[name='search']",
    "input[placeholder*='institution' i]",
    "input[placeholder*='organization' i]",
    "input[aria-label*='institution' i]",
    "input[aria-label*='organization' i]",
    "input[name*='institution' i]",
    "input[name*='organization' i]",
)

ELSEVIER_INSTITUTION_SEARCH_SELECTORS = (
    "input[aria-label*='Organization name or email' i]",
    "input[placeholder*='Organization name or email' i]",
    "input[aria-label*='组织名称' i]",
    "input[placeholder*='组织名称' i]",
    "input[aria-label*='电子邮箱' i]",
    "input[placeholder*='电子邮箱' i]",
    "input[role='combobox'][aria-label*='组织' i]",
    *COMMON_INSTITUTION_SEARCH_SELECTORS,
)

ELSEVIER_INSTITUTION_ENTRY_SELECTORS = (
    "#gh-inst-icon-btn",
    "button[aria-label*='Institutional Access' i]",
    "button:has-text('Sign in via your organization')",
    "a:has-text('Sign in via your organization')",
    "button:has-text('通过您的组织登录')",
    "a:has-text('通过您的组织登录')",
)


INSTITUTION_AUTH_PROFILES: dict[str, dict[str, tuple[str, ...]]] = {
    "web_of_science": {
        "entry_selectors": (
            "a[href*='institution' i]",
            "button[aria-label*='institution' i]",
        ),
        "entry_labels": (
            "Institutional Sign In",
            "Sign in via your organization",
            "Sign in through your institution",
        ),
        "school_selectors": COMMON_INSTITUTION_SEARCH_SELECTORS,
        "authenticated_institution_selectors": (
            "span.institutional-name",
            ".institutional-name",
            "[data-testid*='institutional-name' i]",
        ),
        "success_markers": ("access provided by", "signed in", "sign out"),
    },
    "ieee_xplore": {
        "entry_selectors": (
            "a.inst-sign-in",
            "button.inst-sign-in",
            "[role='dialog'] a:has-text('Access Through Your Institution')",
            "[role='dialog'] button:has-text('Access Through Your Institution')",
            "[aria-modal='true'] a:has-text('Access Through Your Institution')",
            "[aria-modal='true'] button:has-text('Access Through Your Institution')",
            ".modal-dialog a:has-text('Access Through Your Institution')",
            ".modal-dialog button:has-text('Access Through Your Institution')",
        ),
        "entry_labels": (),
        "school_selectors": (
            "[role='dialog'] input[placeholder*='institution' i]",
            "[role='dialog'] input[aria-label*='institution' i]",
            "[role='dialog'] input[type='search']",
            "[role='dialog'] input[type='text']",
            ".modal input[placeholder*='institution' i]",
            ".modal input[type='search']",
            ".modal input[type='text']",
            *COMMON_INSTITUTION_SEARCH_SELECTORS,
        ),
        "success_markers": ("sign out", "access provided by"),
    },
    "elsevier": {
        "entry_selectors": ELSEVIER_INSTITUTION_ENTRY_SELECTORS,
        "entry_labels": (
            "Sign in via your organization",
            "Access through your institution",
            "通过您的组织登录",
        ),
        "school_selectors": ELSEVIER_INSTITUTION_SEARCH_SELECTORS,
        "success_markers": ("signed in", "sign out", "institutional access"),
    },
    "springerlink": {
        "entry_selectors": ("a[href*='wayf.springernature.com' i]",),
        "entry_labels": ("Log in via an institution", "Access through your institution"),
        "school_selectors": COMMON_INSTITUTION_SEARCH_SELECTORS,
        "success_markers": ("access provided by", "log out", "sign out"),
    },
    "nature": {
        "entry_selectors": ("a[href*='wayf.springernature.com' i]",),
        "entry_labels": ("Log in via an institution", "Access through your institution"),
        "school_selectors": COMMON_INSTITUTION_SEARCH_SELECTORS,
        "authenticated_institution_patterns": (
            r"(?:you\s+have\s+)?full\s+access\s+to\s+this\s+article\s+via\s+(?P<school>[^\r\n|•]+)",
        ),
        "success_markers": ("access provided by", "log out", "sign out"),
    },
    "acs_publications": {
        "entry_selectors": ("a[href*='/action/ssostart' i]",),
        "entry_labels": ("Log in via an institution", "Access through your institution"),
        "school_selectors": COMMON_INSTITUTION_SEARCH_SELECTORS,
        "success_markers": ("access provided by", "log out", "sign out"),
    },
    "rsc_publishing": {
        "entry_selectors": ("a[href*='institution' i]", "button[id*='institution' i]"),
        "entry_labels": ("Access through your institution", "Log in via an institution"),
        "school_selectors": COMMON_INSTITUTION_SEARCH_SELECTORS,
        "success_markers": ("access provided by", "log out", "sign out"),
    },
    "acm_metadata": {
        "entry_selectors": (
            "a[role='tab']:has-text('Institutional Login')",
            "button[role='tab']:has-text('Institutional Login')",
            "button:has-text('Institutional Login')",
            "a:has-text('Institutional Login')",
        ),
        "entry_labels": ("Institutional Login", "Sign in via your institution"),
        "school_selectors": COMMON_INSTITUTION_SEARCH_SELECTORS,
        "success_markers": ("signed in", "sign out", "institutional access"),
    },
    "cnki": {
        "entry_selectors": (
            ".ecp_header_unit_loginIcon",
            ".ecp_header_unit_loginbg",
            "button:has-text('机构登录')",
            "a:has-text('机构登录')",
        ),
        "entry_labels": ("机构登录", "机构登录认证", "Institution Login"),
        "school_selectors": COMMON_INSTITUTION_SEARCH_SELECTORS,
        "authenticated_institution_selectors": (
            ".ecp_header_login_status1 .ecp_header_unitName",
            ".ecp_header_unitName",
        ),
        "success_markers": ("退出登录", "机构用户", "机构账号", "institutional access"),
    },
    "wanfang_data": {
        "entry_selectors": (
            ".anxs-8qwe-jgName",
            ".anxs-8qwe-login-jg",
            "iframe#anxs-8qwe-login a[href*='fsso.wanfangdata.com.cn']",
            "a[href*='fsso.wanfangdata.com.cn']",
        ),
        "entry_labels": (
            "登录机构账号",
            "机构登录",
            "机构用户登录",
            "校外访问",
            "Institution Login",
        ),
        "school_selectors": (
            "input[placeholder*='机构']",
            "input[placeholder*='学校']",
            "input[aria-label*='机构']",
            "input[aria-label*='学校']",
            "input[type='search']",
            *COMMON_INSTITUTION_SEARCH_SELECTORS,
        ),
        "authenticated_institution_selectors": (
            ".anxs-8qwe-jgName b[title]",
            ".anxs-8qwe-list-jg .anxs-8qwe-jgName",
        ),
        "success_markers": ("机构账号", "退出登录", "institutional access"),
    },
}


STRICT_INSTITUTION_ENTRY_SELECTOR_SCOPES = {"ieee_xplore"}


def institution_auth_profile(payload: dict[str, Any]) -> dict[str, tuple[str, ...]] | None:
    scope = str(payload.get("auth_state_scope") or "").strip().casefold()
    return INSTITUTION_AUTH_PROFILES.get(scope)


def page_has_authenticated_institution_marker(
    page: Any,
    payload: dict[str, Any],
    observed_text: str | None = None,
    observed_url: str | None = None,
) -> bool:
    profile = institution_auth_profile(payload)
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    auth_scope = str(payload.get("auth_state_scope") or "").strip().casefold()
    selectors = profile.get("authenticated_institution_selectors", ()) if profile else ()
    institution_patterns = (
        profile.get("authenticated_institution_patterns", ())
        if profile
        else ()
    )
    if not school:
        return False
    text = page_text(page) if observed_text is None else observed_text
    final_url = (
        str(getattr(page, "url", "") or "")
        if observed_url is None
        else observed_url
    )
    if str(getattr(page, "url", "") or "") != final_url:
        return False
    lowered = " ".join((text, final_url)).casefold()
    active_cnki_gate = auth_scope == "cnki" and cnki_active_verification_surface(page)
    active_wanfang_gate = auth_scope == "wanfang_data" and (
        wanfang_active_verification_surface(page)
        or wanfang_login_surface_visible(page)
    )
    if active_wanfang_gate:
        return False
    if (
        (
            has_blocking_auth_gate(text)
            and (
                (auth_scope != "cnki" or active_cnki_gate)
                and (auth_scope != "wanfang_data" or active_wanfang_gate)
            )
        )
        or (
            any(token in lowered for token in AUTH_PRELOGIN_MARKERS)
            and (auth_scope != "wanfang_data" or active_wanfang_gate)
        )
    ):
        return False
    if any(
        token in (urlsplit(final_url).path or "").casefold()
        for token in ("/login", "/signin", "/wayf", "/saml")
    ):
        return False
    if institution_access_pattern_contains_exact_school(
        text,
        school,
        school_aliases,
        institution_patterns,
    ):
        return True
    if auth_scope == "ieee_xplore":
        try:
            locators = page.get_by_text(re.compile(r"access\s+provided\s+by", re.IGNORECASE))
            for index in range(min(locators.count(), 20)):
                locator = locators.nth(index)
                if not locator.is_visible(timeout=300):
                    continue
                candidates = [locator]
                current = locator
                for _ in range(2):
                    current = current.locator("xpath=..")
                    candidates.append(current)
                for candidate_locator in candidates:
                    candidate = str(candidate_locator.inner_text(timeout=500) or "")
                    if len(candidate) <= 500 and access_provided_by_text_contains_exact_school(
                        candidate,
                        school,
                        school_aliases,
                    ):
                        return True
        except Exception:
            pass
    if not selectors:
        return False
    for selector in selectors:
        try:
            locators = page.locator(selector)
            for index in range(min(locators.count(), 20)):
                locator = locators.nth(index)
                try:
                    if not locator.is_visible(timeout=300):
                        continue
                    candidate = str(locator.inner_text(timeout=500) or "")
                except Exception:
                    continue
                if (
                    institution_name_matches(candidate, school, school_aliases)
                    or (
                        auth_scope == "cnki"
                        and configured_institution_is_xiamen(school, school_aliases)
                        and normalize_institution_name(candidate)
                        in {
                            normalize_institution_name("Xiamen University"),
                            normalize_institution_name("厦门大学"),
                        }
                    )
                ):
                    return True
        except Exception:
            continue
    return False


def auth_page_success_reason(
    page: Any,
    payload: dict[str, Any],
    text: str,
    final_url: str,
    success_markers: list[str],
    initial_host: str,
    visited_external_auth_host: bool,
    submitted_credentials: bool,
) -> str:
    if str(getattr(page, "url", "") or "") != final_url:
        return ""
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    auth_scope = str(payload.get("auth_state_scope") or "").strip().casefold()
    if page_has_authenticated_institution_marker(
        page,
        payload,
        text,
        final_url,
    ) or (
        school
        and access_provided_by_text_contains_exact_school(
            text,
            school,
            school_aliases,
        )
    ):
        return "institution_marker"
    if school and "access provided by" in text.casefold():
        return ""
    if institution_sso_round_trip_succeeded(
        text,
        final_url,
        initial_host,
        visited_external_auth_host,
        submitted_credentials,
        str(payload.get("school") or ""),
        school_aliases,
    ):
        return "sso_round_trip"
    if auth_scope == "wanfang_data" and school:
        return ""
    if has_auth_success(text, final_url, success_markers):
        return "auth_state"
    return ""


def preferred_elsevier_institution_query(
    school: str,
    school_aliases: tuple[str, ...],
    page_text_value: str,
) -> str:
    if not any(
        marker in (page_text_value or "")
        for marker in ("查找您的组织", "组织名称", "电子邮箱")
    ):
        return school
    return next(
        (
            label
            for label in exact_school_labels(school, school_aliases)
            if any("\u4e00" <= character <= "\u9fff" for character in label)
        ),
        school,
    )


def remembered_institution_name_matches(
    candidate: str,
    school: str,
    school_aliases: tuple[str, ...],
) -> bool:
    return institution_bilingual_name_matches(
        candidate,
        school,
        school_aliases,
    )


def elsevier_remembered_institution_candidate(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(text or ""))
    lines = [
        re.sub(r"\s+", " ", line).strip(" \t\r\n,;:")
        for line in normalized.splitlines()
        if line.strip()
    ]
    candidates: list[str] = []
    for line in lines:
        chinese_match = re.search(r"通过\s*(.+?)\s*访问", line)
        if chinese_match:
            candidates.append(chinese_match.group(1))
            continue
        english_match = re.search(
            r"access\s+through\s+(?:your\s+institution\s*)[:\-]?\s*(.*)$",
            line,
            flags=re.IGNORECASE,
        )
        if english_match:
            tail = english_match.group(1).strip()
            if tail:
                candidates.append(tail)
            continue
        if "access through your institution" not in line.casefold():
            candidates.append(line)
    return next((candidate for candidate in candidates if candidate), "")


def handle_elsevier_remembered_institution(
    page: Any,
    payload: dict[str, Any],
) -> bool | None:
    auth_scope = str(payload.get("auth_state_scope") or "").strip().casefold()
    if auth_scope != "elsevier":
        return None
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    if not school:
        return None
    remembered_surface = False
    try:
        locators = page.locator("button, a, [role='button']")
        for index in range(min(locators.count(), 40)):
            locator = locators.nth(index)
            try:
                if not locator.is_visible(timeout=300):
                    continue
                label = str(locator.inner_text(timeout=500) or "").strip()
            except Exception:
                continue
            lowered = label.casefold()
            if not (
                "access through your institution" in lowered
                or re.search(r"通过\s*.+?\s*访问", label)
            ):
                continue
            remembered_surface = True
            candidate = elsevier_remembered_institution_candidate(label)
            if not remembered_institution_name_matches(
                candidate,
                school,
                school_aliases,
            ):
                continue
            if page_control_flag(page, "codexElsevierRememberedInstitutionSelected"):
                return False
            click_traced_locator(
                locator,
                3000,
                "remembered_institution",
                "elsevier:configured_school",
                no_wait_after=True,
            )
            mark_page_control_flag(
                page,
                "codexElsevierRememberedInstitutionSelected",
            )
            wait_briefly(page, 750)
            return True
    except Exception:
        return None
    if not remembered_surface:
        return None
    if not page_control_flag(page, "codexElsevierRememberedInstitutionMismatch"):
        mark_page_control_flag(page, "codexElsevierRememberedInstitutionMismatch")
    switched = click_first_exact_command_once(
        page,
        (
            "Use another organization",
            "Use a different organization",
            "Sign in with a different institution",
            "使用其他组织",
            "使用其他机构",
            "选择其他机构",
            "更改机构",
        ),
        timeout_ms=2000,
    )
    if switched:
        mark_page_control_flag(page, "codexElsevierUseAnotherInstitutionSelected")
        wait_briefly(page, 750)
        return True
    return False


def apply_institution_auth_profile(page: Any, payload: dict[str, Any]) -> bool:
    profile = institution_auth_profile(payload)
    if profile is None:
        return False
    auth_scope = str(payload.get("auth_state_scope") or "").strip().casefold()
    remembered_result = handle_elsevier_remembered_institution(page, payload)
    if remembered_result is not None:
        return remembered_result
    current_text = page_text(page)
    current_url = str(getattr(page, "url", "") or "")
    lowered_surface = " ".join((current_text, current_url)).casefold()
    institution_surface = institution_entry_reached(current_text, current_url) or any(
        marker in lowered_surface
        for marker in (
            *AUTH_PRELOGIN_MARKERS,
            "wayf",
            "shibboleth",
            "openathens",
            "authserver",
            "search institution",
            "search organization",
            "select your institution",
            "choose your institution",
        )
    )
    if institution_surface:
        school = str(payload.get("school") or "").strip()
        school_aliases = payload_school_aliases(payload)
        search_query = institution_search_query(
            school,
            current_text,
            current_url,
            auth_scope,
            prefer_carsi=payload_prefers_carsi(payload),
        )
        if auth_scope == "elsevier" and search_query == school:
            search_query = preferred_elsevier_institution_query(
                school,
                school_aliases,
                current_text,
            )
        if auth_scope == "ieee_xplore" and (
            "search for your institution" in lowered_surface
            or page_control_flag(page, "codexInstitutionSearchEntered")
        ):
            if (
                school
                and not page_control_flag(page, "codexInstitutionSearchEntered")
                and type_first_selector_sequentially(
                    page,
                    profile["school_selectors"],
                    search_query,
                )
            ):
                mark_page_control_flag(page, "codexInstitutionSearchEntered")
                wait_briefly(page, 1500)
                return True
            if (
                school
                and not page_control_flag(page, "codexInstitutionExactSchoolSelected")
                and click_school_result(page, school, school_aliases)
            ):
                wait_briefly(page, 500)
                return True
            return False
        if search_query != school and carsi_federation_label_matches(search_query):
            mark_page_control_flag(page, "codexCarsiFederationQueryPending")
        if school and fill_first_selector(page, profile["school_selectors"], search_query):
            mark_page_control_flag(page, "codexInstitutionSearchEntered")
            wait_briefly(page, 750)
            return True
        if search_query != school and carsi_federation_label_matches(search_query):
            if click_carsi_federation(
                page,
                enabled=payload_prefers_carsi(payload),
            ):
                wait_briefly(page, 500)
                return True
        elif (
            school
            and not page_control_flag(page, "codexInstitutionExactSchoolSelected")
            and click_school_result(page, school, school_aliases)
        ):
            wait_briefly(page, 500)
            return True
    pending_age = page_control_flag_age_seconds(
        page,
        "codexInstitutionEntryTransitionPending",
    )
    if (
        pending_age is not None
        and pending_age < institution_entry_transition_wait_seconds()
    ):
        return False
    changed = click_institution_entry_once(
        page,
        profile["entry_selectors"],
        profile["entry_labels"],
        timeout_ms=1500,
    )
    if changed:
        mark_page_control_flag(page, "codexInstitutionEntryTransitionPending")
        try:
            page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        wait_briefly(page, 500)
        return True
    return False


def perform_low_risk_page_control(
    page: Any,
    event: str,
    challenge_type: str,
    payload: dict[str, Any],
    *,
    interaction_trace: dict[str, Any] | None = None,
) -> bool:
    # Verification is a hard gate. Normal site controls resume only after the
    # outer loop has observed a stable clear page on a later iteration.
    live_text = page_text(page)
    live_url = str(getattr(page, "url", "") or "")
    live_challenge = classify_visible_page_challenge(
        page,
        live_text,
        live_url,
        event,
        payload,
    )
    if (
        challenge_type in VERIFICATION_CHALLENGE_TYPES
        or live_challenge in VERIFICATION_CHALLENGE_TYPES
        or external_intervention_pause_remaining(interaction_trace) > 0
    ):
        return False
    if dismiss_cookie_banners(page):
        return True
    if event == "auth_challenge":
        if handle_web_of_science_carsi_entry(page, payload):
            return True
        if handle_carsi_directory(page, payload):
            return True
        if handle_wanfang_embedded_external_access(page, payload):
            return True
        if handle_xmu_authserver_login_mode(page, payload):
            return True
        if handle_saml_consent(page):
            return True
        if handle_acm_overlay_and_signin(page, payload):
            return True
        if handle_annual_reviews_institution_entry(page, payload):
            return True
        current_text = page_text(page)
        current_url = str(getattr(page, "url", "") or "")
        if springernature_wayf_page(current_text, current_url):
            return handle_springernature_wayf(page, payload)
        if acs_institution_wayf_page(current_text, current_url) or acs_auth_flow_owned(
            payload,
            current_url,
            current_text,
        ):
            return handle_acs_institution_wayf(page, payload)
        if handle_rsc_institution_entry(page, payload):
            return True
        if click_carsi_federation(
            page,
            enabled=payload_prefers_carsi(payload),
        ):
            return True
        if apply_institution_auth_profile(page, payload):
            return True
        pending_age = page_control_flag_age_seconds(
            page,
            "codexInstitutionEntryTransitionPending",
        )
        if (
            pending_age is not None
            and pending_age < institution_entry_transition_wait_seconds()
        ):
            return False
    if external_intervention_pause_remaining(interaction_trace) > 0:
        return False
    if fill_known_auth_fields(page, payload):
        return True
    school = str(payload.get("school") or "").strip()
    school_aliases = payload_school_aliases(payload)
    current_text = page_text(page)
    current_url = str(getattr(page, "url", "") or "")
    institution_selection_surface = carsi_directory_page(page, current_text, current_url) or institution_entry_reached(
        current_text, current_url
    ) or any(marker in " ".join((current_text, current_url)).casefold() for marker in AUTH_PRELOGIN_MARKERS)
    if (
        event == "auth_challenge"
        and school
        and institution_selection_surface
        and not acm_surface_detected(current_text, current_url)
        and not page_control_flag(page, "codexInstitutionExactSchoolSelected")
        and not page_control_flag(page, "codexCarsiFederationQueryPending")
        and click_school_result(page, school, school_aliases)
    ):
        wait_briefly(page, 500)
        return True
    if event == "auth_challenge" and submit_filled_auth_form(page, payload):
        return True
    is_acm_auth_surface = event == "auth_challenge" and acm_surface_detected(page_text(page), str(getattr(page, "url", "") or ""))
    institution_labels = (
        "Sign in via your organization",
        "Sign in via your institution",
        "Sign in through your institution",
        "Access through your institution",
        "Institutional login",
        "Institutional Login",
        "Log in via an institution",
        "Log in through your institution",
        "机构登录",
        "机构登录认证",
        "通过机构访问",
        "通过机构登录",
    )
    fallback_labels = (
        "Continue",
        "Proceed",
        "Continue to site",
        "Next",
        "Submit",
        "Sign in",
        "Log in",
        "I accept",
        "Agree",
        "同意",
        "继续",
        "下一步",
        "提交",
        "登录",
    )
    if event != "auth_challenge":
        institution_labels = ()
        fallback_labels = tuple(label for label in fallback_labels if label.casefold() not in {"sign in", "log in", "登录"})
    elif institution_auth_profile(payload) is not None:
        fallback_labels = tuple(
            label
            for label in fallback_labels
            if label.casefold() not in {"sign in", "log in", "登录"}
        )
    if str(payload.get("auth_state_scope") or "").strip().casefold() in STRICT_INSTITUTION_ENTRY_SELECTOR_SCOPES:
        institution_labels = ()
    if is_acm_auth_surface:
        institution_labels = ()
        # The ACM home page exposes carousel arrows with accessible names such
        # as Continue/Next. The ACM-specific controller owns every auth action.
        fallback_labels = ()
    if event == "security_challenge":
        text_labels = ("Download PDF", "PDF", "View PDF", "Full text PDF", "Open PDF")
    elif challenge_type in {"captcha_required", "mfa_required", "robot_check", "cloudflare_or_waf"}:
        text_labels = ()
    elif challenge_type == "institution_login":
        text_labels = () if is_acm_auth_surface else institution_labels
    else:
        text_labels = institution_labels
    if external_intervention_pause_remaining(interaction_trace) > 0:
        return False
    if event == "security_challenge":
        clicked = click_first_visible_text(page, text_labels)
    else:
        clicked = False
        remaining_text_labels = text_labels
        if event == "auth_challenge" and institution_labels:
            clicked = click_institution_entry_once(
                page,
                (),
                institution_labels,
                timeout_ms=1000,
            )
            institution_label_keys = {label.casefold() for label in institution_labels}
            remaining_text_labels = tuple(
                label
                for label in text_labels
                if label.casefold() not in institution_label_keys
            )
        if not clicked and remaining_text_labels:
            clicked = click_first_visible_role_text(
                page,
                remaining_text_labels,
                exact=False,
            )
    if not clicked and external_intervention_pause_remaining(interaction_trace) <= 0:
        clicked = click_first_exact_command_once(page, fallback_labels)
    if clicked:
        try:
            page.wait_for_load_state("domcontentloaded", timeout=3000)
        except Exception:
            pass
        return True
    return False


def attempt_visible_verification_control(page: Any) -> bool:
    if attempt_visible_slider_drag(page):
        return True
    if click_visible_checkbox_or_button_in_frames(page):
        return True
    return click_first_visible_role_text(
        page,
        (
            "I am not a robot",
            "I'm not a robot",
            "Verify",
            "请验证您是真人",
            "我不是机器人",
            "验证",
        ),
        exact=False,
    )


def screenshot_path(root: Path, event_name: str, payload: dict[str, Any], browser_name: str) -> Path:
    configured = str(payload.get("hook_screenshot_path") or payload.get("screenshot_path") or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.suffix:
            return path
        return path / f"{event_name}_{browser_name}.png"
    return root / "screenshots" / f"{event_name}_{browser_name}.png"


def storage_state_path(root: Path, event_name: str, payload: dict[str, Any], browser_name: str) -> Path:
    configured = str(payload.get("storage_state_path") or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.suffix:
            return path
        return path / f"{event_name}_{browser_name}.storage_state.json"
    return root / "auth_states" / f"{event_name}_{browser_name}.storage_state.json"


def save_screenshot(page: Any, path: Path) -> str:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path), full_page=True)
        return str(path)
    except Exception:
        return ""


def page_viewport_size(page: Any) -> tuple[int, int]:
    try:
        value = page.evaluate("() => ({ width: window.innerWidth, height: window.innerHeight })")
        if isinstance(value, dict):
            width = max(1, int(value.get("width") or 0))
            height = max(1, int(value.get("height") or 0))
            return width, height
    except Exception:
        pass
    return 1280, 720


def png_pixel_size(value: Any) -> tuple[int, int]:
    if not isinstance(value, (bytes, bytearray)):
        return 0, 0
    data = bytes(value)
    if (
        len(data) < 24
        or data[:8] != b"\x89PNG\r\n\x1a\n"
        or data[12:16] != b"IHDR"
    ):
        return 0, 0
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    if width < 1 or height < 1:
        return 0, 0
    return width, height


def page_control_public_diagnostics(page: Any, payload: dict[str, Any]) -> dict[str, Any]:
    selector_counts: dict[str, int] = {}
    for selector in payload.get("result_card_selectors") or []:
        selector_text = str(selector).strip()
        if not selector_text:
            continue
        try:
            selector_counts[selector_text] = min(1000, int(page.locator(selector_text).count()))
        except Exception:
            selector_counts[selector_text] = -1
    data_ta_values: list[str] = []
    try:
        raw_values = page.locator("[data-ta]").evaluate_all(
            "elements => [...new Set(elements.map((node) => node.getAttribute('data-ta') || '')"
            ".filter((value) => /(record|result|summary|title)/i.test(value)))].slice(0, 80)"
        )
        data_ta_values = [str(value)[:160] for value in raw_values if str(value).strip()]
    except Exception:
        pass
    link_samples: list[dict[str, str]] = []
    try:
        raw_links = page.locator("a[href]").evaluate_all(
            "elements => elements.map((node) => ({ href: node.href || '', text: (node.innerText || node.textContent || '').trim() }))"
            ".filter((item) => /(record|summary|full-record|document|doi)/i.test(item.href + ' ' + item.text))"
            ".slice(0, 40)"
        )
        for item in raw_links:
            if not isinstance(item, dict):
                continue
            link_samples.append(
                {
                    "href": sanitize_url_for_event(str(item.get("href") or "")),
                    "text": " ".join(str(item.get("text") or "").split())[:200],
                }
            )
    except Exception:
        pass
    return {
        "result_selector_counts": selector_counts,
        "candidate_data_ta_values": data_ta_values,
        "candidate_result_links": link_samples,
    }


def write_codex_page_control_request(
    page: Any,
    root: Path,
    event_name: str,
    payload: dict[str, Any],
    browser_name: str,
    challenge_type: str,
    sequence: int,
) -> tuple[Path, Path] | None:
    if not codex_page_control_enabled():
        return None
    request_path = root / "control_requests" / f"{event_name}.{browser_name}.{sequence}.json"
    response_path = root / "control_responses" / f"{event_name}.{browser_name}.{sequence}.json"
    screenshot = root / "control_screenshots" / f"{event_name}.{browser_name}.{sequence}.png"
    try:
        screenshot.parent.mkdir(parents=True, exist_ok=True)
        screenshot_bytes = page.screenshot(path=str(screenshot), full_page=False)
        width, height = page_viewport_size(page)
        pixel_width, pixel_height = png_pixel_size(screenshot_bytes)
        if pixel_width < 1 or pixel_height < 1:
            try:
                pixel_width, pixel_height = png_pixel_size(screenshot.read_bytes())
            except Exception:
                pixel_width, pixel_height = 0, 0
        css_per_screenshot_pixel = {
            "x": width / pixel_width if pixel_width else 1.0,
            "y": height / pixel_height if pixel_height else 1.0,
        }
        screenshot_pixels_per_css_pixel = {
            "x": pixel_width / width if width and pixel_width else 1.0,
            "y": pixel_height / height if height and pixel_height else 1.0,
        }
        action_authorization = challenge_action_authorization_contract(
            {
                **payload,
                "event_id": event_name,
                "challenge_type": challenge_type,
                "current_url": str(page.url or ""),
            }
        )
        write_json(
            request_path,
            {
                "schema": CODEX_PAGE_CONTROL_REQUEST_SCHEMA,
                "event_id": event_name,
                "event": str(payload.get("event") or ""),
                "source": str(payload.get("source") or payload.get("channel") or ""),
                "browser": browser_name,
                "challenge_type": challenge_type,
                "sequence": sequence,
                "current_url": sanitize_url_for_event(str(page.url or "")),
                "screenshot_path": str(screenshot),
                "response_path": str(response_path),
                "coordinate_space": "css_viewport",
                "viewport": {"width": width, "height": height},
                "screenshot_pixels": {
                    "width": pixel_width,
                    "height": pixel_height,
                },
                "screenshot_to_viewport_scale": css_per_screenshot_pixel,
                "screenshot_pixels_per_css_pixel": screenshot_pixels_per_css_pixel,
                "allowed_actions": ["click", "drag"],
                "max_actions": CODEX_PAGE_CONTROL_MAX_ACTIONS,
                "challenge_action_authorization": action_authorization,
                "public_diagnostics": page_control_public_diagnostics(page, payload),
                "forbidden_actions": list(CODEX_EXTENSION_FORBIDDEN_ACTIONS),
                "created_at": utc_now(),
            },
        )
        return request_path, response_path
    except Exception:
        return None


def read_codex_page_control_response(
    response_path: Path,
    event_name: str,
    sequence: int,
    request_path: Path | None = None,
) -> tuple[list[dict[str, Any]], str]:
    if not response_path.is_file():
        return [], "pending"
    try:
        loaded = json.loads(response_path.read_text(encoding="utf-8-sig"))
    except Exception:
        return [], "invalid_json"
    finally:
        try:
            response_path.unlink(missing_ok=True)
        except Exception:
            pass
    if not isinstance(loaded, dict):
        return [], "invalid_response"
    if loaded.get("schema") != CODEX_PAGE_CONTROL_RESPONSE_SCHEMA:
        return [], "invalid_schema"
    if str(loaded.get("event_id") or "") != event_name:
        return [], "event_mismatch"
    try:
        response_sequence = int(loaded.get("sequence"))
    except (TypeError, ValueError):
        return [], "invalid_sequence"
    if response_sequence != sequence:
        return [], "sequence_mismatch"
    if request_path is not None:
        try:
            request = json.loads(request_path.read_text(encoding="utf-8-sig"))
        except Exception:
            return [], "request_invalid"
        authorization_contract = (
            request.get("challenge_action_authorization")
            if isinstance(request, dict)
            else None
        )
        if (
            isinstance(authorization_contract, dict)
            and authorization_contract.get("required") is True
        ):
            if (
                authorization_contract.get("schema")
                != CODEX_CHALLENGE_ACTION_AUTHORIZATION_SCHEMA
                or authorization_contract.get("authorized") is not True
                or authorization_contract.get(
                    "session_preauthorization_is_sufficient"
                )
                is not True
                or int(authorization_contract.get("single_action_budget") or 0)
                != 1
                or str(authorization_contract.get("event_id") or "")
                != event_name
                or not str(
                    authorization_contract.get("challenge_fingerprint") or ""
                )
            ):
                return [], "challenge_action_authorization_invalid"
        legacy_contract = (
            request.get("challenge_action_confirmation")
            if isinstance(request, dict)
            else None
        )
        if (
            not isinstance(authorization_contract, dict)
            and isinstance(legacy_contract, dict)
            and legacy_contract.get("required") is True
            and not legacy_challenge_action_confirmation_matches_contract(
                loaded.get("challenge_action_confirmation"),
                legacy_contract,
            )
        ):
            return [], "challenge_action_confirmation_invalid"
    actions = loaded.get("actions")
    if (
        not isinstance(actions, list)
        or not actions
        or len(actions) > CODEX_PAGE_CONTROL_MAX_ACTIONS
    ):
        return [], "invalid_actions"
    normalized = [action for action in actions if isinstance(action, dict)]
    if len(normalized) != len(actions):
        return [], "invalid_actions"
    return normalized, "ready"


def bounded_control_coordinate(value: Any, maximum: int) -> float | None:
    try:
        coordinate = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(coordinate) or coordinate < 0 or coordinate > maximum:
        return None
    return coordinate


def execute_codex_page_control_actions(page: Any, actions: list[dict[str, Any]]) -> int:
    width, height = page_viewport_size(page)
    executed = 0
    for action in actions[:1]:
        action_type = str(action.get("type") or "").strip().casefold()
        if action_type == "click":
            x = bounded_control_coordinate(action.get("x"), width)
            y = bounded_control_coordinate(action.get("y"), height)
            if x is None or y is None:
                continue
            mark_page_automation_click(page, "codex_page_control", f"coordinate:{x:.1f},{y:.1f}")
            page.mouse.click(x, y)
            executed += 1
        elif action_type == "drag":
            from_x = bounded_control_coordinate(action.get("from_x"), width)
            from_y = bounded_control_coordinate(action.get("from_y"), height)
            to_x = bounded_control_coordinate(action.get("to_x"), width)
            to_y = bounded_control_coordinate(action.get("to_y"), height)
            if None in {from_x, from_y, to_x, to_y}:
                continue
            mark_page_automation_click(
                page,
                "codex_page_control_drag",
                f"coordinate:{from_x:.1f},{from_y:.1f}->{to_x:.1f},{to_y:.1f}",
            )
            page.mouse.move(from_x, from_y)
            page.mouse.down()
            page.mouse.move(to_x, to_y, steps=12)
            page.mouse.up()
            executed += 1
        if executed:
            try:
                page.wait_for_timeout(250)
            except Exception:
                pass
            break
    if executed:
        try:
            page.wait_for_timeout(1000)
        except Exception:
            pass
    return executed


def save_storage_state(context: Any, path: Path) -> str:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        context.storage_state(path=str(path))
        if os.name != "nt":
            path.chmod(0o600)
        return str(path)
    except Exception:
        return ""


def import_seed_storage_state(context: Any, payload: dict[str, Any]) -> bool:
    configured = str(payload.get("seed_storage_state_path") or "").strip()
    if not configured:
        return False
    try:
        path = Path(configured).expanduser().resolve()
        if not path.is_file() or path.stat().st_size > 25 * 1024 * 1024:
            return False
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            return False
        cookies = loaded.get("cookies")
        origins = loaded.get("origins")
        imported = False
        if isinstance(cookies, list) and cookies:
            context.add_cookies([cookie for cookie in cookies if isinstance(cookie, dict)])
            imported = True
        origin_storage: dict[str, dict[str, str]] = {}
        if isinstance(origins, list):
            for origin_record in origins:
                if not isinstance(origin_record, dict):
                    continue
                origin = str(origin_record.get("origin") or "").strip()
                if not origin.startswith(("https://", "http://")):
                    continue
                values = {
                    str(item.get("name")): str(item.get("value"))
                    for item in origin_record.get("localStorage") or []
                    if isinstance(item, dict) and item.get("name") is not None and item.get("value") is not None
                }
                if values:
                    origin_storage[origin] = values
        if origin_storage:
            serialized = json.dumps(origin_storage, ensure_ascii=False).replace("</", "<\\/")
            context.add_init_script(
                "(() => { const states = "
                + serialized
                + "; const values = states[location.origin]; if (!values) return; "
                + "for (const [name, value] of Object.entries(values)) localStorage.setItem(name, value); })();"
            )
            imported = True
        return imported
    except Exception:
        return False


def search_next_page_state(page: Any, payload: dict[str, Any]) -> tuple[bool, str]:
    selectors = [str(value).strip() for value in payload.get("next_page_selectors") or [] if str(value).strip()]
    for selector in selectors:
        try:
            locators = page.locator(selector)
            for index in range(locators.count()):
                locator = locators.nth(index)
                if not locator.is_visible(timeout=500):
                    continue
                text = " ".join(str(locator.inner_text(timeout=500) or "").split())
                aria_label = str(locator.get_attribute("aria-label") or "").strip()
                title = str(locator.get_attribute("title") or "").strip()
                labels = {value.casefold() for value in (text, aria_label, title) if value}
                if not labels.intersection({"下一页", "next", "next page"}):
                    continue
                href = str(locator.get_attribute("href") or "").strip()
                if href and not href.casefold().startswith(("javascript:", "#")):
                    return True, urljoin(str(page.url or ""), href)
                # Snapshot creation is read-only. A JavaScript-backed pager is
                # represented as a pending control and clicked only by the
                # source adapter after verification has cleared.
                return True, ""
        except Exception:
            continue
    return False, ""


def save_sanitized_search_snapshot(page: Any, root: Path, event_name: str, payload: dict[str, Any]) -> str:
    selectors = [str(value).strip() for value in payload.get("result_card_selectors") or [] if str(value).strip()]
    if not selectors:
        return ""
    try:
        fragments = page.evaluate(
            """
            (selectors) => {
              const seen = new Set();
              const nodes = [];
              for (const selector of selectors) {
                for (const node of document.querySelectorAll(selector)) {
                  if (!seen.has(node)) { seen.add(node); nodes.push(node); }
                }
              }
              const allowed = new Set(['href', 'class', 'datetime', 'content', 'name', 'rel', 'title']);
              return nodes.map((node) => {
                const clone = node.cloneNode(true);
                clone.querySelectorAll('script, style, form, input, textarea, select, button, iframe, object, embed').forEach((item) => item.remove());
                for (const element of [clone, ...clone.querySelectorAll('*')]) {
                  for (const attribute of [...element.attributes]) {
                    const name = attribute.name.toLowerCase();
                    if (!allowed.has(name)) {
                      element.removeAttribute(attribute.name);
                    } else if (name === 'href') {
                      try {
                        const url = new URL(attribute.value, document.baseURI);
                        for (const key of [...url.searchParams.keys()]) {
                          if (/(token|session|cookie|password|credential|authorization|code|key|secret)/i.test(key)) url.searchParams.delete(key);
                        }
                        element.setAttribute('href', url.toString());
                      } catch (_) {
                        element.removeAttribute('href');
                      }
                    }
                  }
                }
                return clone.outerHTML;
              });
            }
            """,
            selectors,
        )
        explicit_no_results = False
        if not isinstance(fragments, list) or not fragments:
            lowered = page_text(page).casefold()
            markers = [str(value).strip().casefold() for value in payload.get("no_result_markers") or [] if str(value).strip()]
            explicit_no_results = any(marker in lowered for marker in markers)
            if not explicit_no_results:
                return ""
            fragments = ["<p class='laps-explicit-no-results'>No results found</p>"]
        html_text = "<html><body>" + "\n".join(str(fragment) for fragment in fragments if fragment) + "</body></html>"
        if len(html_text.encode("utf-8")) > 25 * 1024 * 1024:
            return ""
        final_url = str(page.url or "")
        has_next_control, next_url = (False, "") if explicit_no_results else search_next_page_state(page, payload)
        path = root / "search_snapshots" / f"{event_name}.sanitized.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema": "laps_sanitized_search_snapshot_v1",
                    "event_id": str(payload.get("event_id") or event_name),
                    "source": str(payload.get("source") or payload.get("channel") or ""),
                    "keyword": str(payload.get("keyword") or payload.get("title") or ""),
                    "auth_state_scope": str(payload.get("auth_state_scope") or ""),
                    "search_record_type": str(
                        payload.get("search_record_type") or "literature"
                    ),
                    "page_number": max(1, int(payload.get("page_number") or 1)),
                    "final_url": sanitize_search_result_url(final_url),
                    "next_url": sanitize_search_result_url(next_url),
                    "has_next_control": has_next_control,
                    "explicit_no_results": explicit_no_results,
                    "html": html_text,
                    "created_at": utc_now(),
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return str(path)
    except Exception:
        return ""


def pdf_anchors(page: Any) -> list[str]:
    try:
        anchors = page.eval_on_selector_all(
            "a[href]",
            "(els) => els.map((a) => a.href).filter((href) => href && href.toLowerCase().includes('.pdf')).slice(0, 10)",
        )
        return [str(value) for value in anchors if value]
    except Exception:
        return []


def browser_control_success_response(
    event: str,
    reason: str,
    final_url: str,
    content_type: str,
    anchors: list[str],
    storage_path: str,
    sanitized_search_snapshot_path: str = "",
    browser_name: str = "",
) -> dict[str, Any] | None:
    normalized_browser = browser_name.strip().casefold()
    browser_payload = (
        {"browser_name": normalized_browser}
        if normalized_browser in {"chromium", "chrome"}
        else {}
    )
    if event == "auth_challenge" and storage_path:
        return {
            "action": "retry",
            "storage_state_path": storage_path,
            "final_url": final_url,
            "reason": reason,
            **browser_payload,
        }
    if event == "security_challenge":
        if "pdf" in content_type.casefold() or final_url.casefold().endswith(".pdf"):
            return {"action": "retry", "candidate_urls": [final_url], "storage_state_path": storage_path, "final_url": final_url, "reason": reason, **browser_payload}
        if anchors:
            return {"action": "retry", "candidate_urls": anchors, "storage_state_path": storage_path, "final_url": final_url, "reason": reason, **browser_payload}
    if event == "search_challenge" and (storage_path or sanitized_search_snapshot_path):
        return {
            "action": "retry",
            "storage_state_path": storage_path,
            "final_url": final_url,
            "sanitized_search_snapshot_path": sanitized_search_snapshot_path,
            "reason": reason,
            **browser_payload,
        }
    return None


def search_challenge_success_response(
    page: Any,
    root: Path,
    event_name: str,
    payload: dict[str, Any],
    current_challenge: str,
    text: str,
    final_url: str,
    content_type: str,
    anchors: list[str],
    storage_path: str,
    reason: str,
    initial_challenge: str = "",
    require_snapshot: bool = False,
    browser_name: str = "",
) -> tuple[dict[str, Any] | None, str]:
    security_challenges = {"captcha_required", "robot_check", "cloudflare_or_waf"}
    resume_selectors = bool(payload.get("resume_action_selectors"))
    resume_actionable = page_has_actionable_search_resume_control(page, payload)
    search_surface_visible = page_has_visible_search_surface(page, payload)
    visible_verification_surface = page_has_visible_verification_surface(page)
    result_snapshot_path = ""
    if (
        payload.get("result_card_selectors")
        and not visible_verification_surface
        and (not require_snapshot or not resume_actionable)
        and current_challenge
        in {
            "unknown_verification",
            "captcha_required",
            "robot_check",
            "cloudflare_or_waf",
            "subscription_required",
        }
    ):
        result_snapshot_path = save_sanitized_search_snapshot(
            page,
            root,
            event_name,
            payload,
        )
        if result_snapshot_path:
            return (
                browser_control_success_response(
                    "search_challenge",
                    reason,
                    final_url,
                    content_type,
                    anchors,
                    storage_path,
                    result_snapshot_path,
                    browser_name,
                ),
                result_snapshot_path,
            )
    if (
        initial_challenge in security_challenges
        and current_challenge not in security_challenges
        and resume_selectors
        and not resume_actionable
    ):
        return None, ""
    hidden_challenge_cleared = (
        current_challenge in security_challenges
        and not visible_verification_surface
        and resume_actionable
    )
    if not hidden_challenge_cleared and not search_challenge_resolution_allowed(
        current_challenge, text, final_url
    ):
        return None, ""
    snapshot_path = save_sanitized_search_snapshot(page, root, event_name, payload)
    meaningful_text = len(" ".join(str(text or "").split())) >= 20
    if (
        payload.get("result_card_selectors")
        and not snapshot_path
        and not resume_actionable
        and not search_surface_visible
        and not meaningful_text
    ):
        return None, ""
    if require_snapshot and not snapshot_path:
        return None, ""
    if payload.get("result_card_selectors") and not snapshot_path and not storage_path:
        return None, ""
    return (
        browser_control_success_response(
            "search_challenge",
            reason,
            final_url,
            content_type,
            anchors,
            storage_path,
            snapshot_path,
            browser_name,
        ),
        snapshot_path,
    )


def finalize_playwright_browser_resolution(
    payload: dict[str, Any],
    root: Path,
    event_name: str,
    last_timeout: dict[str, Any] | None,
    last_missing_chrome: bool,
    url: str,
) -> dict[str, Any] | None:
    extension_attempt = last_timeout or {
        "reason": "browser_resolution_unavailable",
        "final_url": url,
        "current_url": url,
        "challenge_type": str(payload.get("challenge_type") or ""),
    }
    if not codex_extension_control_enabled(payload):
        if last_missing_chrome:
            return {"action": "skip", "reason": "local_chrome_not_found"}
        return last_timeout
    if find_local_chrome() is None:
        if last_timeout is not None:
            fallback = dict(last_timeout)
            fallback["action"] = "cooldown"
            fallback["ordinary_chrome_handoff_reason"] = "local_chrome_not_found"
            return fallback
        return {"action": "skip", "reason": "local_chrome_not_found"}

    approval_response = {
        "event_id": protocol_event_id_for_request(payload, event_name),
        "allow_open_ordinary_chrome": True,
        "preauthorized": True,
        "authorization_source": "project_default",
    }

    extension_response = codex_extension_handoff(
        payload,
        root,
        event_name,
        extension_attempt,
        approval_response=approval_response,
    )
    if extension_response is not None:
        extension_action = str(extension_response.get("action") or "").casefold()
        if last_timeout is not None and extension_action not in {"retry", "cooldown"}:
            fallback = dict(last_timeout)
            fallback["action"] = "cooldown"
            fallback["playwright_reason"] = str(
                fallback.get("reason") or "playwright_chrome_unresolved"
            )
            handoff_reason = str(
                extension_response.get("reason")
                or "ordinary_chrome_handoff_unresolved"
            )
            fallback["reason"] = handoff_reason
            fallback["ordinary_chrome_handoff_reason"] = handoff_reason
            preflight_state = str(extension_response.get("preflight_state") or "")
            if preflight_state:
                fallback["ordinary_chrome_preflight_state"] = preflight_state
            return fallback
        return extension_response
    if last_timeout is not None:
        return last_timeout
    return None


def try_browser_resolution(payload: dict[str, Any], root: Path, event_name: str) -> dict[str, Any] | None:
    url = selected_url(payload)
    if not url or "://" not in url:
        return None
    if str(payload.get("channel") or "").casefold().startswith("sci-hub") and url.rstrip("/").casefold().endswith("sci-hub.ru"):
        write_json(root / "browser_attempts" / f"{event_name}_skipped.json", {"input_url": url, "reason": "sci_hub_base_page_has_no_candidate_pdf", "created_at": utc_now()})
        return None

    configure_playwright_browsers_path()
    add_local_package_paths()
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        write_json(root / "errors" / f"{event_name}_playwright_import.json", {"error": repr(exc), "created_at": utc_now()})
        return None

    event = str(payload.get("event") or "")
    headless = truthy(os.getenv("CODEX_HOOK_BROWSER_HEADLESS"))
    response_candidates = response_candidate_paths(root, event_name, payload)
    success_markers = [str(value) for value in payload.get("success_markers") or [] if str(value or "").strip()]
    profile = institution_auth_profile(payload)
    if profile is not None:
        success_markers.extend(
            marker for marker in profile["success_markers"] if marker not in success_markers
        )
    initial_challenge = str(payload.get("challenge_type") or "")
    initial_host = (urlsplit(url).hostname or "").casefold()
    last_missing_chrome = False
    last_timeout: dict[str, Any] | None = None
    shared_manual_wait_remaining = (
        payload_manual_wait_seconds(payload) if keep_browser_open(payload) else 0
    )

    with sync_playwright() as playwright:
        attached_parent_browser = parent_browser_attachment_requested(payload)
        browser_names = (
            [str(payload.get("parent_browser_name") or "chromium").casefold()]
            if attached_parent_browser
            else browser_order(payload)
        )
        for browser_index, browser_name in enumerate(browser_names):
            previous_browser = (
                browser_names[browser_index - 1] if browser_index > 0 else ""
            )
            if (
                browser_index > 0
                and last_timeout is not None
                and (
                    initial_challenge in VERIFICATION_CHALLENGE_TYPES
                    or str(last_timeout.get("challenge_type") or "")
                    in VERIFICATION_CHALLENGE_TYPES
                )
            ):
                cooldown_seconds = verification_browser_transition_cooldown_seconds(
                    last_timeout
                )
                write_browser_layer_event(
                    root,
                    event_name,
                    previous_browser,
                    "browser_layer_advanced",
                    action=str(last_timeout.get("action") or ""),
                    challenge_type=str(
                        last_timeout.get("challenge_type") or initial_challenge
                    ),
                    cooldown_seconds=cooldown_seconds,
                    next_browser=browser_name,
                    reason=str(last_timeout.get("reason") or "browser_layer_unresolved"),
                )
                write_json(
                    root / "browser_attempts" / f"{event_name}_{browser_name}_fallback_cooldown.json",
                    {
                        "reason": "verification_browser_fallback_cooldown",
                        "cooldown_seconds": cooldown_seconds,
                        "created_at": utc_now(),
                    },
                )
                external_response = wait_for_response_paths(response_candidates, cooldown_seconds)
                if external_response is not None:
                    return external_response
            write_browser_layer_event(
                root,
                event_name,
                browser_name,
                "browser_layer_started",
                challenge_type=str(
                    (last_timeout or {}).get("challenge_type") or initial_challenge
                ),
                reason=str(
                    (last_timeout or {}).get("reason") or "browser_layer_initial"
                ),
            )
            timeout_seconds = browser_timeout_seconds(payload, browser_name)
            attached_browser = None
            page = None
            if attached_parent_browser:
                attached_browser, context, page, launch_error = (
                    connect_parent_browser_context(playwright, payload)
                )
            else:
                context, launch_error = launch_persistent_context(
                    playwright,
                    root,
                    browser_name,
                    timeout_seconds,
                    headless,
                )
            if context is None:
                last_missing_chrome = launch_error == "local_chrome_not_found"
                write_json(root / "browser_attempts" / f"{event_name}_{browser_name}_launch.json", {"reason": launch_error, "created_at": utc_now()})
                write_browser_layer_event(
                    root,
                    event_name,
                    browser_name,
                    "browser_layer_finished",
                    action="unhandled",
                    challenge_type=initial_challenge,
                    reason=launch_error,
                )
                last_timeout = {
                    "action": "unhandled",
                    "reason": launch_error,
                    "challenge_type": initial_challenge,
                }
                continue
            if not attached_parent_browser:
                import_seed_storage_state(context, payload)
            content_type = ""
            final_url = url
            anchors: list[str] = []
            current_challenge = str(payload.get("challenge_type") or "")
            shot_path = ""
            storage_path = ""
            visited_external_auth_host = False
            submitted_credentials = False
            interaction_trace = install_interaction_trace(
                context,
                root,
                event_name,
                payload,
                browser_name,
            )
            payload.pop("_codex_auth_form_submitted", None)
            control_sequence = 1
            pending_page_control: tuple[Path, Path] | None = None
            search_resume_submitted = False
            awaiting_search_outcome = False
            automatic_verification_actions = 0
            verification_cycle_action_count = 0
            initial_verification_cycle = initial_challenge in VERIFICATION_CHALLENGE_TYPES
            verification_cycle_number = 1 if initial_verification_cycle else 0
            verification_cycle_active = initial_verification_cycle
            verification_cycle_node = (
                verification_node_key(url, initial_challenge)
                if initial_verification_cycle
                else ""
            )
            verification_cycle_location = (
                verification_node_location_key(url)
                if initial_verification_cycle
                else ""
            )
            verification_clear_since: float | None = None
            verification_settle_until = 0.0
            verification_page_visible_since: float | None = None
            verification_control_visible_since: float | None = None
            verification_interaction_observed = False
            verification_surface_observed = False
            verification_action_actor = ""
            verification_action_node = ""
            verification_action_stage = ""
            verification_action_location = ""
            verification_action_observation_deadline = 0.0
            verification_action_same_node_since: float | None = None
            verification_loop_detected = False
            verification_loop_stage_progress = False
            verification_loop_navigation_progress = False
            verification_clear_recorded = False
            auth_state_challenge_cleared = False
            verification_document_epoch = ""
            verification_document_node = ""
            verification_document_reload_node = ""
            verification_document_reload_settle_until = 0.0
            last_external_sequence = 0
            browser_navigation_error = ""
            browser_layer_result = "browser_layer_context_closed"
            browser_layer_action = ""
            try:
                if page is None:
                    page = context.new_page()
                    response = page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=timeout_seconds * 1000,
                    )
                    if response is not None:
                        content_type = str(response.headers.get("content-type") or "")
                else:
                    final_url = str(getattr(page, "url", "") or url)
                base_deadline = time.monotonic() + timeout_seconds
                deadline = base_deadline + shared_manual_wait_remaining
                while time.monotonic() < deadline:
                    external_response = read_response_candidates(
                        response_candidates,
                        expected_event_id=event_name,
                    )
                    if external_response is not None:
                        browser_layer_result = str(
                            external_response.get("reason") or "external_response"
                        )
                        browser_layer_action = str(
                            external_response.get("action") or ""
                        )
                        return external_response
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=2000)
                    except Exception:
                        pass
                    final_url, text, snapshot_stable = stable_page_snapshot(page)
                    if not snapshot_stable:
                        page.wait_for_timeout(250)
                        continue
                    if browser_internal_navigation_error(final_url):
                        browser_navigation_error = "browser_internal_navigation_error"
                        break
                    current_host = (urlsplit(final_url).hostname or "").casefold()
                    if current_host and initial_host and current_host != initial_host:
                        visited_external_auth_host = True
                    submitted_credentials = submitted_credentials or bool(
                        interaction_trace
                        and interaction_trace.get("external_auth_form_submitted")
                    )
                    current_challenge = classify_visible_page_challenge(
                        page,
                        text,
                        final_url,
                        event,
                        payload,
                    )
                    now = time.monotonic()
                    current_verification_node = (
                        verification_node_key(final_url, current_challenge)
                        if current_challenge in VERIFICATION_CHALLENGE_TYPES
                        else ""
                    )
                    current_document_epoch = page_document_epoch(page)
                    if same_verification_document_reloaded(
                        previous_epoch=verification_document_epoch,
                        current_epoch=current_document_epoch,
                        previous_node=verification_document_node,
                        current_node=current_verification_node,
                        current_challenge=current_challenge,
                    ):
                        if (
                            verification_document_reload_node
                            != current_verification_node
                        ):
                            verification_document_reload_settle_until = (
                                now + verification_document_reload_settle_seconds()
                            )
                        verification_document_reload_node = current_verification_node
                    elif (
                        verification_document_reload_node
                        and current_verification_node
                        != verification_document_reload_node
                    ):
                        verification_document_reload_node = ""
                        verification_document_reload_settle_until = 0.0
                    if current_document_epoch:
                        verification_document_epoch = current_document_epoch
                    verification_document_node = current_verification_node
                    visible_verification_surface = (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and page_has_visible_verification_surface(page)
                    )
                    verification_clear_pending = False
                    if current_challenge in VERIFICATION_CHALLENGE_TYPES:
                        auth_state_challenge_cleared = False
                        current_verification_location = verification_node_location_key(
                            final_url
                        )
                        if (
                            not verification_cycle_active
                            or (
                                verification_cycle_location
                                and current_verification_location
                                != verification_cycle_location
                            )
                            or (
                                verification_clear_since is not None
                                and verification_cycle_node
                                and current_verification_node
                                != verification_cycle_node
                            )
                        ):
                            verification_cycle_active = True
                            verification_cycle_number += 1
                            verification_cycle_node = current_verification_node
                            verification_cycle_location = (
                                current_verification_location
                            )
                            verification_cycle_action_count = 0
                            verification_interaction_observed = False
                            verification_page_visible_since = None
                            verification_control_visible_since = None
                            verification_settle_until = 0.0
                            verification_surface_observed = False
                            verification_action_actor = ""
                            verification_action_node = ""
                            verification_action_stage = ""
                            verification_action_location = ""
                            verification_action_observation_deadline = 0.0
                            verification_action_same_node_since = None
                            verification_clear_recorded = False
                            last_external_sequence = latest_external_interaction_sequence(
                                interaction_trace
                            )
                        if visible_verification_surface:
                            verification_surface_observed = True
                        verification_clear_since = None
                    elif verification_cycle_active:
                        verification_action_same_node_since = None
                        if verification_clear_since is None:
                            verification_clear_since = now
                        if (
                            now - verification_clear_since
                            < verification_resolution_stable_seconds()
                        ):
                            verification_clear_pending = True
                        else:
                            if (
                                verification_surface_observed
                                and not verification_action_actor
                                and not verification_clear_recorded
                            ):
                                record_untraced_verification_completion(
                                    interaction_trace,
                                    verification_cycle_node.split("|", 1)[0]
                                    if verification_cycle_node
                                    else initial_challenge,
                                    final_url,
                                )
                                verification_clear_recorded = True
                            auth_state_challenge_cleared = True
                            verification_cycle_active = False
                            verification_cycle_node = ""
                            verification_cycle_location = ""
                            verification_clear_since = None
                            verification_cycle_action_count = 0
                            verification_interaction_observed = False
                            verification_page_visible_since = None
                            verification_control_visible_since = None
                            verification_settle_until = 0.0
                            verification_surface_observed = False
                            verification_action_actor = ""
                            verification_action_node = ""
                            verification_action_stage = ""
                            verification_action_location = ""
                            verification_action_observation_deadline = 0.0
                            verification_action_same_node_since = None
                            verification_clear_recorded = False
                            last_external_sequence = latest_external_interaction_sequence(
                                interaction_trace
                            )
                    if (
                        verification_document_reload_node
                        and current_verification_node
                        == verification_document_reload_node
                        and visible_verification_surface
                        and not verification_interaction_observed
                        and now >= verification_document_reload_settle_until
                    ):
                        verification_action_actor = "document_auto_reload"
                        verification_action_node = current_verification_node
                        verification_loop_detected = True
                        break
                    auth_success_reason = (
                        auth_page_success_reason(
                            page,
                            payload,
                            text,
                            final_url,
                            success_markers,
                            initial_host,
                            visited_external_auth_host,
                            submitted_credentials,
                        )
                        if event == "auth_challenge"
                        and current_challenge not in VERIFICATION_CHALLENGE_TYPES
                        and not verification_clear_pending
                        else ""
                    )
                    record_interaction_stage(
                        interaction_trace,
                        "authenticated"
                        if auth_success_reason
                        else "verification_settling"
                        if verification_clear_pending
                        else classify_interaction_stage(text, final_url, current_challenge, event),
                        final_url,
                        current_challenge,
                    )
                    if current_challenge not in VERIFICATION_CHALLENGE_TYPES:
                        external_pause_remaining = external_intervention_pause_remaining(
                            interaction_trace
                        )
                        if external_pause_remaining > 0:
                            deadline = max(
                                deadline,
                                time.monotonic() + external_pause_remaining,
                            )
                            if pause_for_external_intervention(
                                page,
                                interaction_trace,
                            ):
                                continue
                    if (
                        event == "auth_challenge"
                        and auth_state_challenge_recovery_only(payload)
                        and auth_state_challenge_cleared
                    ):
                        anchors = pdf_anchors(page)
                        shot_path = save_screenshot(
                            page,
                            screenshot_path(root, event_name, payload, browser_name),
                        )
                        storage_path = save_storage_state(
                            context,
                            storage_state_path(root, event_name, payload, browser_name),
                        )
                        reason = f"codex_hook_{browser_name}_auth_state_challenge_cleared"
                        write_json(
                            root / "browser_attempts" / f"{event_name}_{browser_name}.json",
                            {
                                "input_url": url,
                                "final_url": final_url,
                                "challenge_type": current_challenge,
                                "screenshot_path": shot_path,
                                "storage_state_path": storage_path,
                                "reason": reason,
                                "created_at": utc_now(),
                            },
                        )
                        success = browser_control_success_response(
                            event,
                            reason,
                            final_url,
                            content_type,
                            anchors,
                            storage_path,
                            browser_name=browser_name,
                        )
                        if success is not None:
                            browser_layer_result = str(
                                success.get("reason") or "auth_state_challenge_cleared"
                            )
                            browser_layer_action = str(success.get("action") or "retry")
                            return success
                        browser_layer_result = (
                            "auth_state_challenge_storage_state_export_failed"
                        )
                        browser_layer_action = "unhandled"
                        return {
                            "action": "unhandled",
                            "reason": "auth_state_challenge_storage_state_export_failed",
                            "final_url": final_url,
                        }
                    if auth_success_reason:
                        anchors = pdf_anchors(page)
                        shot_path = save_screenshot(page, screenshot_path(root, event_name, payload, browser_name))
                        storage_path = save_storage_state(
                            context, storage_state_path(root, event_name, payload, browser_name)
                        )
                        write_json(
                            root / "browser_attempts" / f"{event_name}_{browser_name}.json",
                            {
                                "input_url": url,
                                "final_url": final_url,
                                "challenge_type": current_challenge,
                                "screenshot_path": shot_path,
                                "storage_state_path": storage_path,
                                "created_at": utc_now(),
                            },
                        )
                        browser_layer_result = auth_success_reason
                        browser_layer_action = "retry"
                        return browser_control_success_response(
                            event,
                            f"codex_hook_{browser_name}_{auth_success_reason}",
                            final_url,
                            content_type,
                            anchors,
                            storage_path,
                            browser_name=browser_name,
                        )
                    if verification_clear_pending:
                        page.wait_for_timeout(1000)
                        continue
                    visible_verification_control = False
                    if current_challenge in VERIFICATION_CHALLENGE_TYPES:
                        if verification_page_visible_since is None:
                            verification_page_visible_since = now
                        visible_verification_control = visible_verification_surface
                        if visible_verification_control:
                            if verification_control_visible_since is None:
                                verification_control_visible_since = now
                        else:
                            verification_control_visible_since = None
                        external_sequence = latest_external_interaction_sequence(interaction_trace)
                        if external_sequence > last_external_sequence:
                            last_external_sequence = external_sequence
                            verification_interaction_observed = True
                            verification_action_actor = "external_input"
                            verification_action_node = verification_node_key(
                                final_url,
                                current_challenge,
                            )
                            verification_action_stage = classify_interaction_stage(
                                text,
                                final_url,
                                current_challenge,
                                event,
                            )
                            verification_action_location = verification_node_location_key(
                                final_url
                            )
                            verification_action_observation_deadline = (
                                now + verification_post_action_wait_seconds()
                            )
                            verification_action_same_node_since = now
                            deadline = max(
                                deadline,
                                verification_action_observation_deadline,
                            )
                    else:
                        verification_page_visible_since = None
                        verification_control_visible_since = None
                    if (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and verification_interaction_observed
                        and not (
                            not visible_verification_control
                            and publisher_reference_error_page(text)
                        )
                    ):
                        current_action_node = verification_node_key(
                            final_url,
                            current_challenge,
                        )
                        if current_action_node == verification_action_node:
                            if verification_action_same_node_since is None:
                                verification_action_same_node_since = now
                            if verification_action_same_node_is_stable(
                                verification_action_same_node_since,
                                now=now,
                            ):
                                current_stage = classify_interaction_stage(
                                    text,
                                    final_url,
                                    current_challenge,
                                    event,
                                )
                                verification_loop_stage_progress = bool(
                                    current_stage in AUTHENTICATION_PROGRESS_STAGES
                                    and current_stage != verification_action_stage
                                )
                                verification_loop_navigation_progress = bool(
                                    verification_action_location
                                    and verification_node_location_key(final_url)
                                    != verification_action_location
                                )
                                verification_loop_detected = verification_loop_unresolved(
                                    interaction_observed=True,
                                    action_node=verification_action_node,
                                    current_node=current_action_node,
                                    stage_progress_observed=verification_loop_stage_progress,
                                    navigation_progress_observed=verification_loop_navigation_progress,
                                    current_challenge=current_challenge,
                                )
                                if verification_loop_detected:
                                    break
                        else:
                            verification_action_same_node_since = None
                    if pause_for_external_intervention(page, interaction_trace):
                        continue
                    if (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and (
                            visible_verification_control
                            and not verification_control_is_stable(
                                verification_control_visible_since,
                                now,
                            )
                            or not visible_verification_control
                            and not verification_control_is_stable(
                                verification_page_visible_since,
                                now,
                            )
                        )
                    ):
                        page.wait_for_timeout(1000)
                        continue
                    if (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and not visible_verification_control
                        and publisher_reference_error_page(text)
                    ):
                        shot_path = save_screenshot(
                            page,
                            screenshot_path(root, event_name, payload, browser_name),
                        )
                        reason = "publisher_reference_error_cooldown"
                        write_json(
                            root
                            / "browser_attempts"
                            / f"{event_name}_{browser_name}_cooldown.json",
                            {
                                "final_url": final_url,
                                "challenge_type": current_challenge,
                                "screenshot_path": shot_path,
                                "reason": reason,
                                "created_at": utc_now(),
                            },
                        )
                        browser_layer_result = reason
                        browser_layer_action = "cooldown"
                        return {
                            "action": "cooldown",
                            "reason": reason,
                            "challenge_type": current_challenge,
                            "screenshot_path": shot_path,
                            "final_url": final_url,
                        }
                    if (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and verification_interaction_observed
                    ):
                        if (
                            verification_action_observation_deadline > 0
                            and now >= verification_action_observation_deadline
                        ):
                            current_stage = classify_interaction_stage(
                                text,
                                final_url,
                                current_challenge,
                                event,
                            )
                            verification_loop_stage_progress = bool(
                                current_stage in AUTHENTICATION_PROGRESS_STAGES
                                and current_stage != verification_action_stage
                            )
                            verification_loop_navigation_progress = bool(
                                verification_action_location
                                and verification_node_location_key(final_url)
                                != verification_action_location
                            )
                            verification_loop_detected = verification_loop_unresolved(
                                interaction_observed=True,
                                action_node=verification_action_node,
                                current_node=verification_node_key(
                                    final_url,
                                    current_challenge,
                                ),
                                stage_progress_observed=verification_loop_stage_progress,
                                navigation_progress_observed=verification_loop_navigation_progress,
                                current_challenge=current_challenge,
                            )
                            if verification_loop_detected:
                                break
                        page.wait_for_timeout(1000)
                        continue
                    if (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and time.monotonic() < verification_settle_until
                    ):
                        remaining_settle = verification_settle_until - time.monotonic()
                        page.wait_for_timeout(min(2000, max(250, int(remaining_settle * 1000))))
                        continue
                    known_page_ids = {id(candidate) for candidate in context.pages}
                    pre_control_challenge = current_challenge
                    control_changed = perform_low_risk_page_control(
                        page,
                        event,
                        current_challenge,
                        payload,
                        interaction_trace=interaction_trace,
                    )
                    verification_action_performed = False
                    if (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and verification_cycle_action_count
                        < automatic_verification_action_limit()
                    ):
                        verification_action_performed = attempt_visible_verification_control(page)
                        if verification_action_performed:
                            automatic_verification_actions += 1
                            verification_cycle_action_count += 1
                            verification_interaction_observed = True
                            verification_action_actor = "hook_automation"
                            verification_action_node = verification_node_key(
                                final_url,
                                current_challenge,
                            )
                            verification_action_stage = classify_interaction_stage(
                                text,
                                final_url,
                                current_challenge,
                                event,
                            )
                            verification_action_location = verification_node_location_key(
                                final_url
                            )
                            write_json(
                                root
                                / "browser_attempts"
                                / f"{event_name}_{browser_name}_automatic_verification_action_{automatic_verification_actions}.json",
                                {
                                    "reason": "automatic_visible_verification_action_executed",
                                    "action_number": automatic_verification_actions,
                                    "verification_cycle_number": verification_cycle_number,
                                    "cycle_action_number": verification_cycle_action_count,
                                    "stable_seconds": verification_control_stable_seconds(),
                                    "post_action_wait_seconds": verification_post_action_wait_seconds(),
                                    "created_at": utc_now(),
                                },
                            )
                            action_now = time.monotonic()
                            verification_action_observation_deadline = (
                                action_now + verification_post_action_wait_seconds()
                            )
                            verification_action_same_node_since = action_now
                            deadline = max(deadline, verification_action_observation_deadline)
                            verification_settle_until = (
                                action_now + verification_action_settle_seconds()
                            )
                            control_changed = True
                    opened_page = newest_context_page(context, known_page_ids)
                    if opened_page is not None:
                        page = opened_page
                        try:
                            page.wait_for_load_state("domcontentloaded", timeout=5000)
                        except Exception:
                            pass
                        wait_briefly(page, 500)
                        control_changed = True
                    submitted_credentials = (
                        submitted_credentials
                        or bool(payload.get("_codex_auth_form_submitted"))
                        or bool(
                            interaction_trace
                            and interaction_trace.get("external_auth_form_submitted")
                        )
                    )
                    final_url, text, snapshot_stable = stable_page_snapshot(page)
                    if not snapshot_stable:
                        page.wait_for_timeout(250)
                        continue
                    current_host = (urlsplit(final_url).hostname or "").casefold()
                    if current_host and initial_host and current_host != initial_host:
                        visited_external_auth_host = True
                    current_challenge = classify_visible_page_challenge(
                        page,
                        text,
                        final_url,
                        event,
                        payload,
                    )
                    post_control_verification_started = (
                        current_challenge in VERIFICATION_CHALLENGE_TYPES
                        and pre_control_challenge not in VERIFICATION_CHALLENGE_TYPES
                    )
                    post_control_verification_clear_pending = (
                        verification_cycle_active
                        and current_challenge not in VERIFICATION_CHALLENGE_TYPES
                    )
                    if (
                        post_control_verification_clear_pending
                        and verification_clear_since is None
                    ):
                        verification_clear_since = time.monotonic()
                    auth_success_reason = (
                        auth_page_success_reason(
                            page,
                            payload,
                            text,
                            final_url,
                            success_markers,
                            initial_host,
                            visited_external_auth_host,
                            submitted_credentials,
                        )
                        if event == "auth_challenge"
                        and current_challenge not in VERIFICATION_CHALLENGE_TYPES
                        and not post_control_verification_clear_pending
                        else ""
                    )
                    record_interaction_stage(
                        interaction_trace,
                        "authenticated"
                        if auth_success_reason
                        else "verification_settling"
                        if post_control_verification_clear_pending
                        else classify_interaction_stage(text, final_url, current_challenge, event),
                        final_url,
                        current_challenge,
                    )
                    if (
                        post_control_verification_started
                        or post_control_verification_clear_pending
                    ):
                        page.wait_for_timeout(1000)
                        continue
                    if auth_success_reason:
                        anchors = pdf_anchors(page)
                        shot_path = save_screenshot(
                            page,
                            screenshot_path(root, event_name, payload, browser_name),
                        )
                        storage_path = save_storage_state(
                            context,
                            storage_state_path(root, event_name, payload, browser_name),
                        )
                        write_json(
                            root / "browser_attempts" / f"{event_name}_{browser_name}.json",
                            {
                                "input_url": url,
                                "final_url": final_url,
                                "challenge_type": current_challenge,
                                "screenshot_path": shot_path,
                                "storage_state_path": storage_path,
                                "created_at": utc_now(),
                            },
                        )
                        browser_layer_result = auth_success_reason
                        browser_layer_action = "retry"
                        return browser_control_success_response(
                            event,
                            f"codex_hook_{browser_name}_{auth_success_reason}",
                            final_url,
                            content_type,
                            anchors,
                            storage_path,
                            browser_name=browser_name,
                        )
                    if control_changed:
                        # Every ordinary action, popup switch, or navigation is
                        # a node boundary. Re-enter the loop so verification is
                        # classified before another site action or failure rule.
                        page.wait_for_timeout(500)
                        continue
                    if (
                        event == "search_challenge"
                        and initial_challenge
                        in {"captcha_required", "robot_check", "cloudflare_or_waf"}
                        and not search_resume_submitted
                        and click_actionable_search_resume_control(page, payload)
                    ):
                        search_resume_submitted = True
                        awaiting_search_outcome = True
                        try:
                            page.wait_for_timeout(1000)
                        except Exception:
                            pass
                        continue
                    if (
                        pending_page_control is not None
                        and awaiting_search_outcome
                        and page_has_actionable_search_resume_control(page, payload)
                    ):
                        awaiting_search_outcome = False
                    anchors = pdf_anchors(page)
                    shot_path = save_screenshot(page, screenshot_path(root, event_name, payload, browser_name))
                    storage_path = save_storage_state(context, storage_state_path(root, event_name, payload, browser_name))

                    if verification_action_performed:
                        continue

                    control_challenge = current_challenge
                    if control_challenge not in {
                        "captcha_required",
                        "robot_check",
                        "cloudflare_or_waf",
                    } and initial_challenge in {
                        "captcha_required",
                        "robot_check",
                        "cloudflare_or_waf",
                    }:
                        control_challenge = initial_challenge
                    if control_challenge in {
                        "captcha_required",
                        "robot_check",
                        "cloudflare_or_waf",
                    }:
                        if (
                            pending_page_control is None
                            and not verification_interaction_observed
                            and control_sequence <= codex_page_control_sequence_limit()
                        ):
                            pending_page_control = write_codex_page_control_request(
                                page,
                                root,
                                event_name,
                                payload,
                                browser_name,
                                control_challenge,
                                control_sequence,
                            )
                        if pending_page_control is not None:
                            request_path, control_response_path = pending_page_control
                            actions, control_status = read_codex_page_control_response(
                                control_response_path,
                                event_name,
                                control_sequence,
                                request_path,
                            )
                            if control_status == "ready":
                                executed_actions = execute_codex_page_control_actions(page, actions)
                                write_json(
                                    root
                                    / "browser_attempts"
                                    / f"{event_name}_{browser_name}_codex_page_control_{control_sequence}.json",
                                    {
                                        "request_path": str(request_path),
                                        "action_count": executed_actions,
                                        "settle_seconds": verification_action_settle_seconds(),
                                        "reason": "codex_page_control_executed"
                                        if executed_actions
                                        else "codex_page_control_no_valid_actions",
                                        "created_at": utc_now(),
                                    },
                                )
                                pending_page_control = None
                                control_sequence += 1
                                if executed_actions:
                                    awaiting_search_outcome = False
                                    verification_interaction_observed = True
                                    verification_action_actor = "codex_page_control"
                                    verification_action_node = verification_node_key(
                                        final_url,
                                        current_challenge,
                                    )
                                    verification_action_stage = classify_interaction_stage(
                                        text,
                                        final_url,
                                        current_challenge,
                                        event,
                                    )
                                    verification_action_location = verification_node_location_key(
                                        final_url
                                    )
                                    action_now = time.monotonic()
                                    verification_action_observation_deadline = (
                                        action_now
                                        + verification_post_action_wait_seconds()
                                    )
                                    verification_action_same_node_since = action_now
                                    deadline = max(
                                        deadline,
                                        verification_action_observation_deadline,
                                    )
                                    verification_settle_until = (
                                        action_now + verification_action_settle_seconds()
                                    )
                                    continue
                            elif control_status != "pending":
                                write_json(
                                    root
                                    / "browser_attempts"
                                    / f"{event_name}_{browser_name}_codex_page_control_{control_sequence}_invalid.json",
                                    {
                                        "request_path": str(request_path),
                                        "reason": f"codex_page_control_{control_status}",
                                        "created_at": utc_now(),
                                    },
                                )
                                pending_page_control = None
                                control_sequence += 1

                    if (
                        event == "search_challenge"
                        and current_challenge == "robot_check"
                        and google_unusual_traffic_page(text, final_url)
                        and not page_has_visible_verification_control(page)
                    ):
                        write_json(
                            root / "browser_attempts" / f"{event_name}_{browser_name}_cooldown.json",
                            {
                                "input_url": url,
                                "final_url": final_url,
                                "challenge_type": current_challenge,
                                "screenshot_path": shot_path,
                                "storage_state_path": storage_path,
                                "reason": "google_unusual_traffic_ip_cooldown",
                                "created_at": utc_now(),
                            },
                        )
                        browser_layer_result = "google_unusual_traffic_ip_cooldown"
                        browser_layer_action = "cooldown"
                        return {
                            "action": "cooldown",
                            "reason": "google_unusual_traffic_ip_cooldown",
                            "storage_state_path": storage_path,
                            "final_url": final_url,
                        }

                    bounded_reason = ""
                    if (
                        event == "auth_challenge"
                        and initial_challenge == "institution_login"
                        and institution_entry_reached(text, final_url)
                        and not control_changed
                    ):
                        if fill_known_auth_fields(page, payload):
                            try:
                                page.wait_for_timeout(500)
                            except Exception:
                                pass
                            final_url = page.url
                            text = page_text(page)
                            current_challenge = classify_visible_page_challenge(
                                page,
                                text,
                                final_url,
                                event,
                                payload,
                            )
                    if event == "auth_challenge" and acm_gateway_reached(text, final_url):
                        bounded_reason = "acm_institution_gateway_not_auth_entry"
                    elif event == "auth_challenge" and acm_institution_content_page(final_url):
                        bounded_reason = "acm_non_sso_institution_result"
                    elif event == "auth_challenge" and configured_institution_idp_mismatch(page, payload):
                        bounded_reason = "institution_idp_mismatch:configured_institution"
                    elif event == "auth_challenge" and acm_saml_callback_timed_out(page, final_url):
                        bounded_reason = "acm_saml_callback_timeout"
                    elif event == "auth_challenge" and acm_institution_not_listed(
                        page,
                        text,
                        final_url,
                        payload,
                    ):
                        bounded_reason = configured_institution_unavailable_reason(payload)
                    elif event == "auth_challenge" and acs_federation_selection_no_progress(
                        page,
                        payload,
                    ):
                        bounded_reason = "acs_federation_selection_no_progress"
                    elif (
                        event == "auth_challenge"
                        and acs_auth_flow_owned(payload, final_url, text)
                        and acs_auth_flow_waiting(payload)
                    ):
                        bounded_reason = ""
                    elif event == "auth_challenge" and configured_institution_result_missing(page, payload):
                        bounded_reason = configured_institution_unavailable_reason(payload)
                    elif event == "auth_challenge" and institution_search_pending(
                        page,
                        payload,
                    ):
                        bounded_reason = ""
                    elif event == "auth_challenge" and institution_search_results_unavailable(
                        page,
                        payload,
                    ):
                        bounded_reason = "institution_search_results_unavailable"
                    elif event == "auth_challenge" and acs_institution_sso_unavailable(text, final_url):
                        bounded_reason = "acs_institution_sso_unavailable"
                    elif (
                        event == "auth_challenge"
                        and acs_institution_wayf_page(text, final_url)
                        and page_control_flag(page, "codexAcsFederationsScanned")
                        and not page_control_flag(page, "codexAcsSchoolSelected")
                    ):
                        bounded_reason = configured_institution_unavailable_reason(payload)
                    elif event == "auth_challenge" and springernature_institution_sso_unavailable(text, final_url):
                        bounded_reason = "springernature_institution_sso_unavailable"
                    elif event == "auth_challenge" and detects_personal_login_only(text):
                        bounded_reason = "personal_login_only"
                    elif event == "auth_challenge" and annual_reviews_institution_result_missing(page, text, final_url, payload):
                        bounded_reason = configured_institution_unavailable_reason(payload)
                    elif (
                        event == "auth_challenge"
                        and initial_challenge == "institution_login"
                        and institution_entry_reached(text, final_url)
                        and not control_changed
                    ):
                        bounded_reason = "institution_entry_not_found"
                    if bounded_reason:
                        write_json(
                            root / "browser_attempts" / f"{event_name}_{browser_name}.json",
                            {
                                "input_url": url,
                                "final_url": final_url,
                                "challenge_type": current_challenge,
                                "screenshot_path": shot_path,
                                "storage_state_path": storage_path,
                                "reason": bounded_reason,
                                "created_at": utc_now(),
                            },
                        )
                        bounded = bounded_non_success_response(
                            event,
                            bounded_reason,
                            final_url,
                            current_challenge,
                            shot_path,
                            storage_path,
                        )
                        if bounded is not None:
                            browser_layer_result = str(
                                bounded.get("reason") or "bounded_manual_response"
                            )
                            browser_layer_action = str(
                                bounded.get("action") or "unhandled"
                            )
                            return bounded

                    if event == "security_challenge":
                        success = browser_control_success_response(event, f"codex_hook_{browser_name}_resolved", final_url, content_type, anchors, storage_path, browser_name=browser_name)
                        if success and (anchors or "pdf" in content_type.casefold() or final_url.casefold().endswith(".pdf") or not has_access_blocker(text)):
                            write_json(
                                root / "browser_attempts" / f"{event_name}_{browser_name}.json",
                                {
                                    "input_url": url,
                                    "final_url": final_url,
                                    "content_type": content_type,
                                    "anchors": anchors,
                                    "challenge_type": current_challenge,
                                    "screenshot_path": shot_path,
                                    "storage_state_path": storage_path,
                                    "created_at": utc_now(),
                                },
                            )
                            browser_layer_result = str(
                                success.get("reason") or "security_challenge_resolved"
                            )
                            browser_layer_action = str(success.get("action") or "retry")
                            return success

                    if event == "search_challenge":
                        success, snapshot_path = search_challenge_success_response(
                            page,
                            root,
                            event_name,
                            payload,
                            current_challenge,
                            text,
                            final_url,
                            content_type,
                            anchors,
                            storage_path,
                            f"codex_hook_{browser_name}_search_challenge_resolved",
                            initial_challenge,
                            awaiting_search_outcome,
                            browser_name,
                        )
                        if success:
                            write_json(
                                root / "browser_attempts" / f"{event_name}_{browser_name}.json",
                                {
                                    "input_url": url,
                                    "final_url": final_url,
                                    "content_type": content_type,
                                    "challenge_type": current_challenge,
                                    "screenshot_path": shot_path,
                                    "storage_state_path": storage_path,
                                    "sanitized_search_snapshot_path": snapshot_path,
                                    "created_at": utc_now(),
                                },
                            )
                            browser_layer_result = str(
                                success.get("reason") or "search_challenge_resolved"
                            )
                            browser_layer_action = str(success.get("action") or "retry")
                            return success

                    page.wait_for_timeout(2000)

                if verification_loop_detected:
                    shot_path = save_screenshot(
                        page,
                        screenshot_path(root, event_name, payload, browser_name),
                    )
                    storage_path = save_storage_state(
                        context,
                        storage_state_path(root, event_name, payload, browser_name),
                    )
                    has_later_browser = browser_index + 1 < len(browser_names)
                    if verification_action_actor == "document_auto_reload":
                        loop_action = "cooldown"
                        loop_reason = (
                            "verification_document_reload_loop_after_chrome"
                            if browser_name == "chrome"
                            else "verification_document_reload_loop"
                        )
                    else:
                        loop_action, loop_reason = verification_loop_response(
                            browser_name,
                            has_later_browser=has_later_browser,
                        )
                    loop_evidence = {
                        "input_url": url,
                        "final_url": final_url,
                        "browser": browser_name,
                        "challenge_type": current_challenge,
                        "verification_node_fingerprint": verification_node_fingerprint(
                            verification_action_node
                        ),
                        "verification_cycle_number": verification_cycle_number,
                        "verification_cycle_action_count": verification_cycle_action_count,
                        "verification_action_actor": verification_action_actor,
                        "stage_progress_observed": verification_loop_stage_progress,
                        "navigation_progress_observed": verification_loop_navigation_progress,
                        "screenshot_path": shot_path,
                        "storage_state_path": storage_path,
                        "reason": loop_reason,
                        "created_at": utc_now(),
                    }
                    write_json(
                        root
                        / "browser_attempts"
                        / f"{event_name}_{browser_name}_verification_loop.json",
                        loop_evidence,
                    )
                    last_timeout = {
                        "action": loop_action,
                        "reason": loop_reason,
                        "storage_state_path": storage_path,
                        "final_url": final_url,
                        "challenge_type": current_challenge,
                        "screenshot_path": shot_path,
                        "verification_interaction_observed": (
                            verification_interaction_observed
                        ),
                        "verification_node_fingerprint": loop_evidence[
                            "verification_node_fingerprint"
                        ],
                    }
                    browser_layer_result = loop_reason
                    browser_layer_action = loop_action
                    if browser_name == "chromium" and has_later_browser:
                        continue
                    break
                if browser_navigation_error:
                    shot_path = save_screenshot(
                        page,
                        screenshot_path(root, event_name, payload, browser_name),
                    )
                    storage_path = save_storage_state(
                        context,
                        storage_state_path(root, event_name, payload, browser_name),
                    )
                    record_interaction_stage(
                        interaction_trace,
                        "navigation_error",
                        final_url,
                        current_challenge,
                    )
                    write_json(
                        root
                        / "browser_attempts"
                        / f"{event_name}_{browser_name}_navigation_error.json",
                        {
                            "input_url": url,
                            "final_url": final_url,
                            "challenge_type": current_challenge,
                            "screenshot_path": shot_path,
                            "storage_state_path": storage_path,
                            "reason": browser_navigation_error,
                            "created_at": utc_now(),
                        },
                    )
                    last_timeout = {
                        "action": "unhandled",
                        "reason": browser_navigation_error,
                        "storage_state_path": storage_path,
                        "final_url": final_url,
                        "challenge_type": current_challenge,
                        "screenshot_path": shot_path,
                        "verification_interaction_observed": verification_interaction_observed,
                    }
                    browser_layer_result = browser_navigation_error
                    browser_layer_action = "unhandled"
                    if verification_interaction_requires_same_browser_cooldown(
                        verification_interaction_observed,
                        initial_challenge,
                        current_challenge,
                    ):
                        last_timeout = {
                            **last_timeout,
                            "action": "cooldown",
                            "reason": "verification_interaction_pending_same_browser_cooldown",
                        }
                    continue
                manual_wait_used, shared_manual_wait_remaining = consume_shared_manual_wait(
                    shared_manual_wait_remaining,
                    base_deadline,
                )
                record_interaction_stage(
                    interaction_trace,
                    "timeout",
                    final_url,
                    current_challenge,
                )
                write_json(
                    root / "browser_attempts" / f"{event_name}_{browser_name}_timeout.json",
                    {
                        "input_url": url,
                        "final_url": final_url,
                        "content_type": content_type,
                        "anchors": anchors,
                        "challenge_type": current_challenge,
                        "screenshot_path": shot_path,
                        "storage_state_path": storage_path,
                        "reason": "browser_verification_timeout",
                        "shared_manual_wait_used_seconds": manual_wait_used,
                        "shared_manual_wait_remaining_seconds": shared_manual_wait_remaining,
                        "verification_interaction_observed": verification_interaction_observed,
                        "created_at": utc_now(),
                    },
                )
                last_timeout = {
                    "action": "unhandled",
                    "reason": "browser_verification_timeout",
                    "storage_state_path": storage_path,
                    "final_url": final_url,
                    "challenge_type": current_challenge,
                    "screenshot_path": shot_path,
                    "verification_interaction_observed": verification_interaction_observed,
                }
                browser_layer_result = str(last_timeout.get("reason") or "browser_verification_timeout")
                browser_layer_action = str(last_timeout.get("action") or "unhandled")
                if verification_interaction_requires_same_browser_cooldown(
                    verification_interaction_observed,
                    initial_challenge,
                    current_challenge,
                ):
                    last_timeout = {
                        **last_timeout,
                        "action": "cooldown",
                        "reason": "verification_interaction_pending_same_browser_cooldown",
                    }
            except Exception as exc:
                browser_layer_result = f"exception:{exc.__class__.__name__}"
                browser_layer_action = "unhandled"
                write_json(
                    root / "errors" / f"{event_name}_{browser_name}.json",
                    {
                        "error_type": exc.__class__.__name__,
                        "error": repr(exc),
                        "frames": safe_exception_frames(exc),
                        "created_at": utc_now(),
                        "url": url,
                    },
                )
                verification_transport_unstable = bool(
                    browser_transport_unstable_exception(exc)
                    and verification_interaction_requires_same_browser_cooldown(
                        verification_interaction_observed,
                        initial_challenge,
                        current_challenge,
                    )
                )
                if verification_transport_unstable:
                    last_timeout = {
                        "action": "unhandled",
                        "reason": "client_transport_unstable_after_captcha_action",
                        "storage_state_path": storage_path,
                        "final_url": final_url,
                        "challenge_type": current_challenge,
                        "screenshot_path": shot_path,
                        "verification_interaction_observed": True,
                    }
                elif verification_interaction_requires_same_browser_cooldown(
                    verification_interaction_observed,
                    initial_challenge,
                    current_challenge,
                ):
                    last_timeout = {
                        "action": "cooldown",
                        "reason": "verification_interaction_pending_same_browser_cooldown",
                        "storage_state_path": storage_path,
                        "final_url": final_url,
                        "challenge_type": current_challenge,
                        "screenshot_path": shot_path,
                        "verification_interaction_observed": True,
                    }
            finally:
                if not attached_parent_browser:
                    try:
                        context.close()
                    except Exception:
                        pass
                write_browser_layer_event(
                    root,
                    event_name,
                    browser_name,
                    "browser_layer_finished",
                    action=browser_layer_action,
                    challenge_type=current_challenge,
                    reason=browser_layer_result,
                )
    if (
        attached_parent_browser
        and str(payload.get("parent_browser_name") or "chromium").casefold()
        == "chromium"
    ):
        if last_missing_chrome:
            return {"action": "skip", "reason": "local_chrome_not_found"}
        return last_timeout
    return finalize_playwright_browser_resolution(
        payload,
        root,
        event_name,
        last_timeout,
        last_missing_chrome,
        url,
    )


def default_response(payload: dict[str, Any]) -> dict[str, Any]:
    event = str(payload.get("event") or "")
    if event == "security_challenge":
        return {"action": "unhandled", "reason": "codex_hook_logged_unresolved_security_challenge"}
    if event == "auth_challenge":
        return {"action": "unhandled", "reason": "codex_hook_logged_unresolved_auth_challenge"}
    if event == "search_challenge":
        return {"action": "unhandled", "reason": "codex_hook_logged_unresolved_search_challenge"}
    return {"action": "unhandled", "reason": "codex_hook_unknown_event"}


def guarded_browser_resolution(payload: dict[str, Any], root: Path, event_name: str) -> dict[str, Any] | None:
    try:
        response = try_browser_resolution(payload, root, event_name)
        if response is None or not parent_browser_attachment_requested(payload):
            return response
        browser_name = str(payload.get("parent_browser_name") or "").casefold()
        normalized = dict(response)
        normalized["browser_name"] = browser_name
        if str(normalized.get("action") or "").casefold() == "retry":
            if (
                normalized.get("external_browser_session") is True
                or str(normalized.get("browser_transport") or "")
                == ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT
            ):
                normalized["browser_name"] = "chrome"
                normalized["same_browser_handoff"] = False
                normalized["browser_transport"] = (
                    ORDINARY_CHROME_EXTERNAL_SESSION_TRANSPORT
                )
                return normalized
            normalized["same_browser_handoff"] = True
            return normalized
        reason = str(normalized.get("reason") or "").casefold()
        challenge_type = str(
            normalized.get("challenge_type")
            or payload.get("challenge_type")
            or ""
        ).casefold()
        switchable_failure = (
            reason.startswith("verification_interaction_pending_same_browser_cooldown")
            or reason.startswith("browser_verification_timeout")
            or reason.startswith("verification_loop")
            or reason.startswith("verification_document_reload_loop")
            or reason.startswith("client_transport_unstable_after_captcha_action")
            or reason.startswith("browser_internal_navigation_error")
        )
        transport_failure = reason.startswith("browser_internal_navigation_error")
        if (
            browser_name == "chromium"
            and (
                challenge_type in VERIFICATION_CHALLENGE_TYPES
                or transport_failure
            )
            and switchable_failure
            and chrome_fallback_enabled()
            and find_local_chrome() is not None
        ):
            normalized.update(
                {
                    "action": "retry",
                    "reason": f"parent_browser_switch_requested:{reason}",
                    "same_browser_handoff": False,
                    "switch_browser_to": "chrome",
                }
            )
        return normalized
    except Exception as exc:
        error_type = exc.__class__.__name__
        write_json(
            root / "errors" / f"{event_name}_internal.json",
            {
                "error_type": error_type,
                "error": redact_persisted_string(repr(exc)),
                "frames": safe_exception_frames(exc),
                "created_at": utc_now(),
            },
        )
        return {
            "action": "unhandled",
            "reason": f"codex_hook_internal_error:{error_type}",
        }


def safe_exception_frames(exc: BaseException) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    current = exc.__traceback__
    while current is not None:
        code = current.tb_frame.f_code
        frames.append(
            {
                "file": Path(code.co_filename).name,
                "function": code.co_name,
                "line": current.tb_lineno,
            }
        )
        current = current.tb_next
    return frames[-12:]


def main() -> int:
    root = hook_root()
    incoming_payload = read_payload()
    name = event_id(incoming_payload)
    redact_preexisting_unbound_responses(root, name)
    try:
        payload = ensure_verification_request_v2(incoming_payload, name)
    except Exception:
        response_root = root / "responses"
        redact_rejected_response_artifact(
            response_root / f"{name}.json",
            name,
            "challenge_request_invalid",
        )
        redact_rejected_response_artifact(
            response_root / "latest.json",
            name,
            "challenge_request_invalid",
            require_embedded_event_id=True,
        )
        raise
    record = {"id": name, "created_at": utc_now(), "payload": payload}
    write_json(root / "pending" / f"{name}.json", record)
    append_jsonl(root / "events.jsonl", record)

    bound_response = read_bound_verification_response(
        root / "responses",
        payload,
    )
    if bound_response.payload is not None:
        response, response_validation_reason = validate_bound_hook_response(
            root,
            payload,
            bound_response.payload,
        )
        if response is None:
            redact_rejected_response_artifact(
                bound_response.path,
                name,
                response_validation_reason,
                require_embedded_event_id=(
                    bound_response.path is not None
                    and bound_response.path.name == "latest.json"
                ),
            )
            write_json(
                root / "errors" / f"{name}_response_rejected.json",
                {
                    "event_id": name,
                    "reason_code": response_validation_reason,
                    "created_at": utc_now(),
                },
            )
    else:
        response = None
        if bound_response.reason_code != "challenge_response_missing":
            redact_rejected_response_artifact(
                bound_response.path,
                name,
                bound_response.reason_code,
                require_embedded_event_id=(
                    bound_response.path is not None
                    and bound_response.path.name == "latest.json"
                ),
            )
    if str(payload.get("event") or "") in {"security_challenge", "auth_challenge", "search_challenge"}:
        if response is None:
            response = guarded_browser_resolution(payload, root, name)
    if response is None:
        if str(payload.get("event") or "") == "auth_challenge":
            wait_seconds = int(os.getenv("CODEX_HOOK_WAIT_AUTH_SECONDS", "0"))
        else:
            wait_seconds = int(os.getenv("CODEX_HOOK_WAIT_SECONDS", "0"))
        response = wait_for_bound_verification_response(root, payload, wait_seconds)
    if response is None:
        response = default_response(payload)
    response.setdefault("reason", "codex_hook_response")
    response = bind_hook_response_v2(payload, response)
    validated_response, validation_reason = validate_bound_hook_response(
        root,
        payload,
        response,
    )
    if validated_response is None:
        response = bind_hook_response_v2(
            payload,
            {
                "action": "unhandled",
                "reason": validation_reason,
                "reason_code": validation_reason,
                "category": "contract",
                "retryable": False,
            },
        )
    else:
        response = validated_response
    if str(response.get("action") or "").casefold() != "manual_pending":
        write_verification_response_atomic(root / "responses", payload, response)
    write_json(
        root / "completed" / f"{name}.json",
        {"id": name, "created_at": utc_now(), "response": response},
    )
    sys.stdout.write(json.dumps(response, ensure_ascii=False))
    return 0


def guarded_main() -> int:
    try:
        return main()
    except Exception as exc:
        error_type = exc.__class__.__name__
        root = hook_root()
        fallback_id = f"hook_internal_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        write_json(
            root / "errors" / f"{fallback_id}.json",
            {
                "error_type": error_type,
                "error": redact_persisted_string(repr(exc)),
                "frames": safe_exception_frames(exc),
                "created_at": utc_now(),
            },
        )
        sys.stdout.write(
            json.dumps(
                {
                    "action": "unhandled",
                    "reason": f"codex_hook_process_error:{error_type}",
                },
                ensure_ascii=False,
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(guarded_main())
