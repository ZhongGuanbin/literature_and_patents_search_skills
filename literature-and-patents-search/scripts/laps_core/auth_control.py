from __future__ import annotations

"""Cross-process authentication coordination and v2 state attestations."""

from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import random
import secrets
import shutil
import sqlite3
import threading
import time
import unicodedata
from typing import Any, Iterator, Mapping

from .challenge_protocol import (
    atomic_write_json,
    canonical_json_bytes,
    sha256_file,
    utc_now,
    validate_verification_request,
)


AUTH_CONTROL_SCHEMA_VERSION = 1
AUTH_STATE_ATTESTATION_SCHEMA = "laps_auth_state_attestation_v2"
AUTH_STATE_ATTESTATION_MIN_TTL_SECONDS = 60 * 60
AUTH_STATE_ATTESTATION_MAX_TTL_SECONDS = 7 * 24 * 60 * 60
AUTH_SCOPE_LEASE_HEARTBEAT_SECONDS = 15
AUTH_SCOPE_LEASE_TTL_SECONDS = 60
AUTH_SCOPE_LEASE_POLL_MIN_SECONDS = 0.25
AUTH_SCOPE_LEASE_POLL_MAX_SECONDS = 0.75
AUTH_CONFIRMATION_KINDS = frozenset(
    {
        "exact_institution_marker",
        "sso_round_trip",
        "challenge_recovered",
        "site_personal_session",
    }
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS control_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_scope_leases (
    scope_key TEXT PRIMARY KEY,
    owner_token TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_state_generations (
    scope_key TEXT PRIMARY KEY,
    generation_id TEXT NOT NULL,
    auth_state_scope TEXT NOT NULL,
    auth_mode TEXT NOT NULL,
    principal_digest TEXT NOT NULL,
    confirmation_kind TEXT NOT NULL,
    service_host TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state_path TEXT NOT NULL,
    state_sha256 TEXT NOT NULL,
    attestation_sha256 TEXT NOT NULL,
    browser_name TEXT NOT NULL,
    headful_required INTEGER NOT NULL CHECK (headful_required IN (0, 1)),
    producer_component TEXT NOT NULL,
    producer_operation_id TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_events (
    event_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    producer TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'responded', 'consumed', 'expired', 'rejected')
    ),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    responded_at TEXT NOT NULL DEFAULT '',
    consumed_at TEXT NOT NULL DEFAULT '',
    response_sha256 TEXT NOT NULL DEFAULT '',
    final_reason_code TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_events_status
ON verification_events(status, expires_at);
"""


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


def _as_utc(value: datetime | None = None) -> datetime:
    selected = value or datetime.now(timezone.utc)
    if selected.tzinfo is None:
        raise ValueError("timezone-aware datetime required")
    return selected.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _normalize_identity(value: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or ""))
    return " ".join(normalized.casefold().split()) or "<anonymous>"


def auth_scope_key(
    *,
    auth_mode: str,
    principal_digest: str,
    auth_state_scope: str,
    channel: str = "",
    state_path_digest: str = "",
    shared_scope: bool = True,
) -> str:
    payload = {
        "auth_mode": str(auth_mode or "").strip().casefold(),
        "principal_digest": str(principal_digest or "").strip().casefold(),
        "auth_state_scope": str(auth_state_scope or "").strip(),
        "channel": "" if shared_scope else str(channel or "").strip(),
        "state_path_digest": ""
        if shared_scope
        else str(state_path_digest or "").strip().casefold(),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class LeaseResult:
    acquired: bool
    reason_code: str
    scope_key: str
    owner_token: str
    operation_id: str
    heartbeat_at: str = ""
    lease_expires_at: str = ""


@dataclass(frozen=True)
class AttestationValidation:
    valid: bool
    reason_code: str
    payload: dict[str, Any] | None = None


class _AuthStatePublicationRejected(RuntimeError):
    """Internal structured abort used while the SQLite write fence is held."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class AuthControlStore:
    """Small SQLite authority for auth leases, generations and replay state."""

    def __init__(self, path: str | Path, *, timeout: float = 30.0) -> None:
        self.path = Path(path).expanduser().resolve()
        self.timeout = float(timeout)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.timeout)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(_SCHEMA)
            now = utc_now()
            row = connection.execute(
                "SELECT value FROM control_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO control_meta(key, value, updated_at) VALUES (?, ?, ?)",
                    ("schema_version", str(AUTH_CONTROL_SCHEMA_VERSION), now),
                )
            elif int(row["value"]) != AUTH_CONTROL_SCHEMA_VERSION:
                raise RuntimeError("auth_control_schema_version_unsupported")
            connection.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _private_hmac_key(self) -> bytes:
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT value FROM control_meta WHERE key='principal_hmac_key'"
            ).fetchone()
            if row is not None:
                try:
                    key = base64.urlsafe_b64decode(str(row["value"]).encode("ascii"))
                except (ValueError, UnicodeError) as exc:
                    raise RuntimeError("auth_control_hmac_key_invalid") from exc
                if len(key) < 32:
                    raise RuntimeError("auth_control_hmac_key_invalid")
                return key
            key = secrets.token_bytes(32)
            connection.execute(
                "INSERT INTO control_meta(key, value, updated_at) VALUES (?, ?, ?)",
                (
                    "principal_hmac_key",
                    base64.urlsafe_b64encode(key).decode("ascii"),
                    utc_now(),
                ),
            )
            return key

    def principal_digest(self, principal: object) -> str:
        return hmac.new(
            self._private_hmac_key(),
            _normalize_identity(principal).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def acquire_scope_lease(
        self,
        scope_key: str,
        *,
        owner_token: str,
        operation_id: str,
        ttl_seconds: int = AUTH_SCOPE_LEASE_TTL_SECONDS,
        now: datetime | None = None,
    ) -> LeaseResult:
        if not scope_key or not owner_token or not operation_id:
            raise ValueError("auth_scope_lease_identity_missing")
        if ttl_seconds <= 0:
            raise ValueError("auth_scope_lease_ttl_invalid")
        selected_now = _as_utc(now)
        heartbeat = _utc_text(selected_now)
        expires = _utc_text(selected_now + timedelta(seconds=ttl_seconds))
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM auth_scope_leases WHERE scope_key=?", (scope_key,)
            ).fetchone()
            if row is not None:
                current_expiry = _parse_utc(row["lease_expires_at"])
                active_other_owner = (
                    current_expiry is not None
                    and current_expiry > selected_now
                    and str(row["owner_token"]) != owner_token
                )
                if active_other_owner:
                    return LeaseResult(
                        False,
                        "auth_scope_busy",
                        scope_key,
                        str(row["owner_token"]),
                        str(row["operation_id"]),
                        str(row["heartbeat_at"]),
                        str(row["lease_expires_at"]),
                    )
            connection.execute(
                """
                INSERT INTO auth_scope_leases(
                    scope_key, owner_token, operation_id, heartbeat_at,
                    lease_expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope_key) DO UPDATE SET
                    owner_token=excluded.owner_token,
                    operation_id=excluded.operation_id,
                    heartbeat_at=excluded.heartbeat_at,
                    lease_expires_at=excluded.lease_expires_at,
                    updated_at=excluded.updated_at
                """,
                (scope_key, owner_token, operation_id, heartbeat, expires, heartbeat),
            )
        return LeaseResult(
            True,
            "auth_scope_lease_acquired",
            scope_key,
            owner_token,
            operation_id,
            heartbeat,
            expires,
        )

    def renew_scope_lease(
        self,
        scope_key: str,
        *,
        owner_token: str,
        ttl_seconds: int = AUTH_SCOPE_LEASE_TTL_SECONDS,
        now: datetime | None = None,
    ) -> LeaseResult:
        selected_now = _as_utc(now)
        heartbeat = _utc_text(selected_now)
        expires = _utc_text(selected_now + timedelta(seconds=ttl_seconds))
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM auth_scope_leases WHERE scope_key=?", (scope_key,)
            ).fetchone()
            if row is None or not hmac.compare_digest(
                str(row["owner_token"]), owner_token
            ):
                return LeaseResult(
                    False,
                    "auth_scope_lease_lost",
                    scope_key,
                    owner_token,
                    "",
                )
            current_expiry = _parse_utc(row["lease_expires_at"])
            if current_expiry is None or current_expiry <= selected_now:
                return LeaseResult(
                    False,
                    "auth_scope_lease_expired",
                    scope_key,
                    owner_token,
                    str(row["operation_id"]),
                    str(row["heartbeat_at"]),
                    str(row["lease_expires_at"]),
                )
            connection.execute(
                """
                UPDATE auth_scope_leases
                SET heartbeat_at=?, lease_expires_at=?, updated_at=?
                WHERE scope_key=? AND owner_token=?
                """,
                (heartbeat, expires, heartbeat, scope_key, owner_token),
            )
            operation_id = str(row["operation_id"])
        return LeaseResult(
            True,
            "auth_scope_lease_renewed",
            scope_key,
            owner_token,
            operation_id,
            heartbeat,
            expires,
        )

    def release_scope_lease(self, scope_key: str, *, owner_token: str) -> bool:
        with self._immediate() as connection:
            cursor = connection.execute(
                "DELETE FROM auth_scope_leases WHERE scope_key=? AND owner_token=?",
                (scope_key, owner_token),
            )
            return cursor.rowcount == 1

    def current_scope_lease(self, scope_key: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM auth_scope_leases WHERE scope_key=?", (scope_key,)
            ).fetchone()
        return dict(row) if row is not None else None

    def owns_active_scope_lease(
        self,
        scope_key: str,
        *,
        owner_token: str,
        operation_id: str = "",
        now: datetime | None = None,
    ) -> bool:
        row = self.current_scope_lease(scope_key)
        expires = _parse_utc(row.get("lease_expires_at")) if row is not None else None
        return bool(
            row is not None
            and hmac.compare_digest(str(row.get("owner_token") or ""), owner_token)
            and (
                not operation_id
                or hmac.compare_digest(
                    str(row.get("operation_id") or ""), operation_id
                )
            )
            and expires is not None
            and expires > _as_utc(now)
        )

    @staticmethod
    def _active_scope_lease_in_connection(
        connection: sqlite3.Connection,
        scope_key: str,
        *,
        owner_token: str,
        operation_id: str = "",
        now: datetime | None = None,
    ) -> tuple[sqlite3.Row | None, str]:
        row = connection.execute(
            "SELECT * FROM auth_scope_leases WHERE scope_key=?", (scope_key,)
        ).fetchone()
        if row is None or not hmac.compare_digest(
            str(row["owner_token"]), owner_token
        ):
            return None, "auth_scope_lease_lost"
        if operation_id and not hmac.compare_digest(
            str(row["operation_id"]), operation_id
        ):
            return None, "auth_scope_lease_lost"
        expiry = _parse_utc(row["lease_expires_at"])
        if expiry is None or expiry <= _as_utc(now):
            return None, "auth_scope_lease_expired"
        return row, "auth_scope_lease_active"

    def wait_for_scope_lease(
        self,
        scope_key: str,
        *,
        owner_token: str,
        operation_id: str,
        deadline: float,
        ttl_seconds: int = AUTH_SCOPE_LEASE_TTL_SECONDS,
    ) -> LeaseResult:
        latest = LeaseResult(
            False,
            "auth_scope_busy",
            scope_key,
            owner_token,
            operation_id,
        )
        while time.monotonic() < deadline:
            latest = self.acquire_scope_lease(
                scope_key,
                owner_token=owner_token,
                operation_id=operation_id,
                ttl_seconds=ttl_seconds,
            )
            if latest.acquired:
                return latest
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(
                min(
                    remaining,
                    random.uniform(
                        AUTH_SCOPE_LEASE_POLL_MIN_SECONDS,
                        AUTH_SCOPE_LEASE_POLL_MAX_SECONDS,
                    ),
                )
            )
        return LeaseResult(
            False,
            "auth_scope_lease_timeout",
            scope_key,
            latest.owner_token,
            latest.operation_id,
            latest.heartbeat_at,
            latest.lease_expires_at,
        )

    def register_verification_request(
        self, request: Mapping[str, Any]
    ) -> tuple[bool, str]:
        validation = validate_verification_request(request, allow_expired=True)
        if not validation.valid:
            return False, validation.reason_code
        binding = request.get("binding")
        assert isinstance(binding, Mapping)
        event_id = str(request["event_id"])
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM verification_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is not None:
                if not hmac.compare_digest(
                    str(row["request_digest"]), str(request["request_digest"])
                ) or not hmac.compare_digest(
                    str(row["binding_digest"]), str(request["binding_digest"])
                ):
                    return False, "challenge_event_id_collision"
                return True, "challenge_request_already_registered"
            now = utc_now()
            connection.execute(
                """
                INSERT INTO verification_events(
                    event_id, request_digest, binding_digest, producer, status,
                    created_at, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (
                    event_id,
                    str(request["request_digest"]),
                    str(request["binding_digest"]),
                    str(binding.get("producer") or ""),
                    str(request["created_at"]),
                    str(request["expires_at"]),
                    now,
                ),
            )
        return True, "challenge_request_registered"

    @staticmethod
    def _verification_terminal_reason(status: str) -> str:
        if status == "consumed":
            return "challenge_response_replayed"
        if status == "expired":
            return "challenge_response_expired"
        if status == "rejected":
            return "challenge_response_rejected"
        return "challenge_response_state_invalid"

    @staticmethod
    def _verification_identity_matches(
        row: sqlite3.Row,
        request: Mapping[str, Any],
    ) -> bool:
        return hmac.compare_digest(
            str(row["request_digest"]), str(request.get("request_digest") or "")
        ) and hmac.compare_digest(
            str(row["binding_digest"]), str(request.get("binding_digest") or "")
        )

    def mark_verification_responded(
        self,
        request: Mapping[str, Any],
        *,
        response_sha256: str,
        responded_at: str,
        reason_code: str = "challenge_response_valid",
    ) -> tuple[bool, str]:
        """Persist the accepted response before it can be consumed.

        ``responded`` is deliberately recoverable: if the process stops between
        this transition and consumption, the exact same response may finish the
        transition later.  A different response, or any terminal state, can
        never replace it.
        """

        registered, reason = self.register_verification_request(request)
        if not registered:
            return False, reason
        event_id = str(request.get("event_id") or "")
        selected_now = datetime.now(timezone.utc)
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM verification_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None or not self._verification_identity_matches(row, request):
                return False, "challenge_response_unbound"
            status = str(row["status"])
            if status in {"consumed", "expired", "rejected"}:
                return False, self._verification_terminal_reason(status)
            expires = _parse_utc(row["expires_at"])
            if expires is None or expires <= selected_now:
                updated_at = utc_now()
                connection.execute(
                    """
                    UPDATE verification_events
                    SET status='expired', final_reason_code=?, updated_at=?
                    WHERE event_id=? AND status IN ('pending', 'responded')
                    """,
                    ("challenge_response_expired", updated_at, event_id),
                )
                return False, "challenge_response_expired"
            if status == "responded":
                if hmac.compare_digest(
                    str(row["response_sha256"]), str(response_sha256)
                ):
                    return True, "challenge_response_already_responded"
                return False, "challenge_response_replayed"
            updated_at = utc_now()
            connection.execute(
                """
                UPDATE verification_events
                SET status='responded', responded_at=?, response_sha256=?,
                    final_reason_code=?, updated_at=?
                WHERE event_id=? AND status='pending'
                """,
                (
                    responded_at,
                    response_sha256,
                    reason_code or "challenge_response_valid",
                    updated_at,
                    event_id,
                ),
            )
        return True, "challenge_response_responded"

    def consume_verification_response(
        self,
        request: Mapping[str, Any],
        *,
        response_sha256: str,
        responded_at: str,
        final_reason_code: str,
    ) -> tuple[bool, str]:
        registered, reason = self.register_verification_request(request)
        if not registered:
            return False, reason
        event_id = str(request.get("event_id") or "")
        selected_now = datetime.now(timezone.utc)
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM verification_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None:  # pragma: no cover - protected by registration
                return False, "challenge_response_unbound"
            if not self._verification_identity_matches(row, request):
                return False, "challenge_response_unbound"
            status = str(row["status"])
            if status in {"consumed", "expired", "rejected"}:
                return False, self._verification_terminal_reason(status)
            if status not in {"pending", "responded"}:
                return False, "challenge_response_state_invalid"
            expires = _parse_utc(row["expires_at"])
            if expires is None or expires <= selected_now:
                connection.execute(
                    """
                    UPDATE verification_events
                    SET status='expired', final_reason_code=?, updated_at=?
                    WHERE event_id=?
                    """,
                    ("challenge_response_expired", utc_now(), event_id),
                )
                return False, "challenge_response_expired"
            if status == "responded" and not hmac.compare_digest(
                str(row["response_sha256"]), str(response_sha256)
            ):
                return False, "challenge_response_replayed"
            consumed_at = utc_now()
            effective_responded_at = (
                str(row["responded_at"]) if status == "responded" else responded_at
            )
            connection.execute(
                """
                UPDATE verification_events
                SET status='consumed', responded_at=?, consumed_at=?,
                    response_sha256=?, final_reason_code=?, updated_at=?
                WHERE event_id=?
                """,
                (
                    effective_responded_at,
                    consumed_at,
                    response_sha256,
                    final_reason_code or "challenge_response_valid",
                    consumed_at,
                    event_id,
                ),
            )
        return True, "challenge_response_consumed"

    def mark_verification_rejected(
        self,
        request: Mapping[str, Any],
        reason_code: str,
        *,
        response_sha256: str = "",
        responded_at: str = "",
    ) -> tuple[bool, str]:
        registered, registration_reason = self.register_verification_request(request)
        if not registered:
            return False, registration_reason
        event_id = str(request.get("event_id") or "")
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM verification_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None or not self._verification_identity_matches(row, request):
                return False, "challenge_response_unbound"
            status = str(row["status"])
            if status in {"consumed", "expired", "rejected"}:
                return False, self._verification_terminal_reason(status)
            if status == "responded":
                # Validation is complete before ``responded`` is written. A
                # later malformed response cannot destroy that accepted
                # response while it is waiting for its consume step.
                return False, "challenge_response_replayed"
            updated_at = utc_now()
            connection.execute(
                """
                UPDATE verification_events
                SET status='rejected',
                    responded_at=CASE WHEN ?!='' THEN ? ELSE responded_at END,
                    response_sha256=CASE WHEN ?!='' THEN ? ELSE response_sha256 END,
                    final_reason_code=?, updated_at=?
                WHERE event_id=? AND status IN ('pending', 'responded')
                """,
                (
                    responded_at,
                    responded_at,
                    response_sha256,
                    response_sha256,
                    reason_code or "challenge_response_rejected",
                    updated_at,
                    event_id,
                ),
            )
        return True, "challenge_response_rejected"

    def mark_verification_expired(
        self,
        request: Mapping[str, Any],
        reason_code: str = "challenge_response_expired",
    ) -> tuple[bool, str]:
        registered, registration_reason = self.register_verification_request(request)
        if not registered:
            return False, registration_reason
        event_id = str(request.get("event_id") or "")
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM verification_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None or not self._verification_identity_matches(row, request):
                return False, "challenge_response_unbound"
            status = str(row["status"])
            if status in {"consumed", "expired", "rejected"}:
                return False, self._verification_terminal_reason(status)
            updated_at = utc_now()
            connection.execute(
                """
                UPDATE verification_events
                SET status='expired', final_reason_code=?, updated_at=?
                WHERE event_id=? AND status IN ('pending', 'responded')
                """,
                (
                    reason_code or "challenge_response_expired",
                    updated_at,
                    event_id,
                ),
            )
        return True, "challenge_response_expired"

    def verification_event(self, event_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM verification_events WHERE event_id=?", (event_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def record_auth_generation(
        self,
        scope_key: str,
        attestation: Mapping[str, Any],
        *,
        state_path: str | Path,
        owner_token: str,
        operation_id: str = "",
        attestation_sha256: str = "",
        now: datetime | None = None,
    ) -> tuple[bool, str]:
        if attestation.get("schema") != AUTH_STATE_ATTESTATION_SCHEMA:
            return False, "auth_state_attestation_schema_invalid"
        logical_attestation_sha = hashlib.sha256(
            canonical_json_bytes(dict(attestation))
        ).hexdigest()
        if attestation_sha256 and not hmac.compare_digest(
            logical_attestation_sha, attestation_sha256.casefold()
        ):
            return False, "auth_state_attestation_digest_mismatch"
        try:
            raw_path = Path(state_path).expanduser()
            if raw_path.is_symlink():
                return False, "auth_state_unreadable"
            path = raw_path.resolve(strict=True)
            actual_sha = sha256_file(path)
        except (OSError, RuntimeError):
            return False, "auth_state_unreadable"
        if not hmac.compare_digest(
            actual_sha, str(attestation.get("state_sha256") or "")
        ):
            return False, "auth_state_digest_mismatch"
        with self._immediate() as connection:
            selected_now = _as_utc(now)
            _lease, lease_reason = self._active_scope_lease_in_connection(
                connection,
                scope_key,
                owner_token=owner_token,
                operation_id=operation_id,
                now=selected_now,
            )
            if lease_reason != "auth_scope_lease_active":
                return False, lease_reason
            previous = connection.execute(
                "SELECT generation_id FROM auth_state_generations WHERE scope_key=?",
                (scope_key,),
            ).fetchone()
            previous_generation_id = (
                str(previous["generation_id"]) if previous is not None else None
            )
            if not self._write_auth_generation_cas(
                connection,
                scope_key,
                attestation,
                state_path=path,
                state_sha256=actual_sha,
                attestation_sha256=logical_attestation_sha,
                expected_generation_id=previous_generation_id,
                now=selected_now,
            ):
                return False, "auth_state_generation_cas_failed"
        return True, "auth_state_generation_recorded"

    def _write_auth_generation_cas(
        self,
        connection: sqlite3.Connection,
        scope_key: str,
        attestation: Mapping[str, Any],
        *,
        state_path: str | Path,
        state_sha256: str,
        attestation_sha256: str,
        expected_generation_id: str | None,
        now: datetime | None = None,
    ) -> bool:
        """Advance one generation only if the observed authority is unchanged."""

        values = (
            str(attestation.get("generation_id") or ""),
            str(attestation.get("auth_state_scope") or ""),
            str(attestation.get("auth_mode") or ""),
            str(attestation.get("principal_digest") or ""),
            str(attestation.get("confirmation_kind") or ""),
            str(attestation.get("service_host") or ""),
            str(attestation.get("confirmed_at") or ""),
            str(attestation.get("expires_at") or ""),
            str(Path(state_path).resolve()),
            state_sha256,
            attestation_sha256,
            str(attestation.get("browser_name") or ""),
            1 if attestation.get("headful_required") is True else 0,
            str(attestation.get("producer_component") or ""),
            str(attestation.get("producer_operation_id") or ""),
            _utc_text(_as_utc(now)),
        )
        if expected_generation_id is None:
            try:
                connection.execute(
                    """
                    INSERT INTO auth_state_generations(
                        scope_key, generation_id, auth_state_scope, auth_mode,
                        principal_digest, confirmation_kind, service_host,
                        confirmed_at, expires_at, state_path, state_sha256,
                        attestation_sha256, browser_name, headful_required,
                        producer_component, producer_operation_id, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scope_key, *values),
                )
            except sqlite3.IntegrityError:
                return False
            return True
        cursor = connection.execute(
            """
            UPDATE auth_state_generations
            SET generation_id=?, auth_state_scope=?, auth_mode=?,
                principal_digest=?, confirmation_kind=?, service_host=?,
                confirmed_at=?, expires_at=?, state_path=?, state_sha256=?,
                attestation_sha256=?, browser_name=?, headful_required=?,
                producer_component=?, producer_operation_id=?, updated_at=?
            WHERE scope_key=? AND generation_id=?
            """,
            (*values, scope_key, expected_generation_id),
        )
        return cursor.rowcount == 1

    @staticmethod
    def _restore_auth_generation_snapshot(
        connection: sqlite3.Connection,
        scope_key: str,
        snapshot: Mapping[str, Any] | None,
    ) -> None:
        connection.execute(
            "DELETE FROM auth_state_generations WHERE scope_key=?", (scope_key,)
        )
        if snapshot is None:
            return
        columns = (
            "scope_key",
            "generation_id",
            "auth_state_scope",
            "auth_mode",
            "principal_digest",
            "confirmation_kind",
            "service_host",
            "confirmed_at",
            "expires_at",
            "state_path",
            "state_sha256",
            "attestation_sha256",
            "browser_name",
            "headful_required",
            "producer_component",
            "producer_operation_id",
            "updated_at",
        )
        connection.execute(
            f"INSERT INTO auth_state_generations({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            tuple(snapshot.get(column) for column in columns),
        )

    def publish_auth_generation(
        self,
        scope_key: str,
        attestation: Mapping[str, Any],
        *,
        staged_state_path: str | Path,
        target_state_path: str | Path,
        staged_attestation_path: str | Path,
        target_attestation_path: str | Path,
        owner_token: str,
        operation_id: str,
        now: datetime | None = None,
    ) -> tuple[bool, str]:
        """Publish a state/sidecar pair under a lease-fenced SQLite commit.

        The previous pair remains backed up until the generation CAS commits.
        Any replace, CAS, or commit failure restores the prior files before the
        database write fence is released.
        """

        if not scope_key or not owner_token or not operation_id:
            return False, "auth_scope_lease_missing"
        if attestation.get("schema") != AUTH_STATE_ATTESTATION_SCHEMA:
            return False, "auth_state_attestation_schema_invalid"
        staged_state = Path(staged_state_path).expanduser()
        target_state = Path(target_state_path).expanduser()
        staged_attestation = Path(staged_attestation_path).expanduser()
        target_attestation = Path(target_attestation_path).expanduser()
        try:
            if (
                staged_state.is_symlink()
                or staged_attestation.is_symlink()
                or target_state.is_symlink()
                or target_attestation.is_symlink()
            ):
                return False, "auth_state_publication_path_invalid"
            resolved_staged_state = staged_state.resolve(strict=True)
            resolved_staged_attestation = staged_attestation.resolve(strict=True)
            if not resolved_staged_state.is_file() or not resolved_staged_attestation.is_file():
                return False, "auth_state_publication_staging_missing"
            if resolved_staged_state == target_state.resolve(strict=False):
                return False, "auth_state_publication_staging_invalid"
            if resolved_staged_attestation == target_attestation.resolve(strict=False):
                return False, "auth_state_publication_staging_invalid"
            staged_state_sha = sha256_file(resolved_staged_state)
            loaded_attestation = json.loads(
                resolved_staged_attestation.read_text(encoding="utf-8-sig")
            )
        except (OSError, RuntimeError, ValueError, UnicodeError):
            return False, "auth_state_publication_staging_invalid"
        if not isinstance(loaded_attestation, dict) or not hmac.compare_digest(
            canonical_json_bytes(loaded_attestation),
            canonical_json_bytes(dict(attestation)),
        ):
            return False, "auth_state_attestation_digest_mismatch"
        if not hmac.compare_digest(
            staged_state_sha,
            str(attestation.get("state_sha256") or "").strip().casefold(),
        ):
            return False, "auth_state_digest_mismatch"

        target_state.parent.mkdir(parents=True, exist_ok=True)
        target_attestation.parent.mkdir(parents=True, exist_ok=True)
        backup_token = secrets.token_hex(12)
        state_backup = target_state.with_name(
            f".{target_state.name}.{backup_token}.bak"
        )
        attestation_backup = target_attestation.with_name(
            f".{target_attestation.name}.{backup_token}.bak"
        )
        had_state = False
        had_attestation = False
        formal_touched = False
        previous_generation: dict[str, Any] | None = None
        connection = self._connect()

        def restore_previous_pair() -> None:
            if had_state:
                if not state_backup.is_file():
                    raise RuntimeError("auth_state_backup_missing")
                os.replace(state_backup, target_state)
            else:
                target_state.unlink(missing_ok=True)
            if had_attestation:
                if not attestation_backup.is_file():
                    raise RuntimeError("auth_attestation_backup_missing")
                os.replace(attestation_backup, target_attestation)
            else:
                target_attestation.unlink(missing_ok=True)

        try:
            connection.execute("BEGIN IMMEDIATE")
            selected_now = _as_utc(now)
            _lease, lease_reason = self._active_scope_lease_in_connection(
                connection,
                scope_key,
                owner_token=owner_token,
                operation_id=operation_id,
                now=selected_now,
            )
            if lease_reason != "auth_scope_lease_active":
                raise _AuthStatePublicationRejected(lease_reason)
            previous = connection.execute(
                "SELECT * FROM auth_state_generations WHERE scope_key=?",
                (scope_key,),
            ).fetchone()
            previous_generation = dict(previous) if previous is not None else None
            previous_generation_id = (
                str(previous["generation_id"]) if previous is not None else None
            )
            had_state = target_state.is_file()
            had_attestation = target_attestation.is_file()
            if had_state:
                shutil.copy2(target_state, state_backup)
            if had_attestation:
                shutil.copy2(target_attestation, attestation_backup)
            os.replace(staged_state, target_state)
            formal_touched = True
            os.replace(staged_attestation, target_attestation)
            try:
                os.chmod(target_state, 0o600)
                os.chmod(target_attestation, 0o600)
            except OSError:
                pass
            published_state_sha = sha256_file(target_state)
            if not hmac.compare_digest(published_state_sha, staged_state_sha):
                raise _AuthStatePublicationRejected(
                    "auth_state_publication_replace_mismatch"
                )
            published_attestation = json.loads(
                target_attestation.read_text(encoding="utf-8-sig")
            )
            if not isinstance(published_attestation, dict) or not hmac.compare_digest(
                canonical_json_bytes(published_attestation),
                canonical_json_bytes(dict(attestation)),
            ):
                raise _AuthStatePublicationRejected(
                    "auth_state_publication_replace_mismatch"
                )
            logical_attestation_sha = hashlib.sha256(
                canonical_json_bytes(dict(attestation))
            ).hexdigest()
            if not self._write_auth_generation_cas(
                connection,
                scope_key,
                attestation,
                state_path=target_state,
                state_sha256=published_state_sha,
                attestation_sha256=logical_attestation_sha,
                expected_generation_id=previous_generation_id,
                now=selected_now,
            ):
                raise _AuthStatePublicationRejected(
                    "auth_state_generation_cas_failed"
                )
            connection.commit()
        except _AuthStatePublicationRejected as exc:
            rollback_error = ""
            if formal_touched:
                try:
                    restore_previous_pair()
                except Exception as rollback_exc:  # pragma: no cover - catastrophic I/O
                    rollback_error = rollback_exc.__class__.__name__
            if formal_touched and not rollback_error:
                try:
                    if not connection.in_transaction:
                        connection.execute("BEGIN IMMEDIATE")
                        _lease, lease_reason = self._active_scope_lease_in_connection(
                            connection,
                            scope_key,
                            owner_token=owner_token,
                            operation_id=operation_id,
                        )
                        if lease_reason != "auth_scope_lease_active":
                            raise RuntimeError(lease_reason)
                    self._restore_auth_generation_snapshot(
                        connection, scope_key, previous_generation
                    )
                    connection.commit()
                except Exception as rollback_exc:  # pragma: no cover - catastrophic SQLite/I/O
                    rollback_error = rollback_exc.__class__.__name__
                    try:
                        connection.rollback()
                    except sqlite3.Error:
                        pass
            else:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            if rollback_error:
                return False, f"auth_state_publication_rollback_failed:{rollback_error}"
            return False, exc.reason_code
        except Exception as exc:
            rollback_error = ""
            if formal_touched:
                try:
                    restore_previous_pair()
                except Exception as rollback_exc:  # pragma: no cover - catastrophic I/O
                    rollback_error = rollback_exc.__class__.__name__
            if formal_touched and not rollback_error:
                try:
                    if not connection.in_transaction:
                        connection.execute("BEGIN IMMEDIATE")
                        _lease, lease_reason = self._active_scope_lease_in_connection(
                            connection,
                            scope_key,
                            owner_token=owner_token,
                            operation_id=operation_id,
                        )
                        if lease_reason != "auth_scope_lease_active":
                            raise RuntimeError(lease_reason)
                    self._restore_auth_generation_snapshot(
                        connection, scope_key, previous_generation
                    )
                    connection.commit()
                except Exception as rollback_exc:  # pragma: no cover - catastrophic SQLite/I/O
                    rollback_error = rollback_exc.__class__.__name__
                    try:
                        connection.rollback()
                    except sqlite3.Error:
                        pass
            else:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            if rollback_error:
                return False, f"auth_state_publication_rollback_failed:{rollback_error}"
            return False, f"auth_state_generation_commit_failed:{exc.__class__.__name__}"
        finally:
            connection.close()
            for path in (state_backup, attestation_backup):
                path.unlink(missing_ok=True)
        return True, "auth_state_generation_published"

    def auth_generation(self, scope_key: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM auth_state_generations WHERE scope_key=?", (scope_key,)
            ).fetchone()
        return dict(row) if row is not None else None


class _LeaseHeartbeat:
    def __init__(
        self,
        store: AuthControlStore,
        lease: LeaseResult,
        *,
        ttl_seconds: int,
        interval_seconds: int,
    ) -> None:
        self.store = store
        self.lease = lease
        self.ttl_seconds = ttl_seconds
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self.lost = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"laps-auth-lease-{lease.scope_key[:10]}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            result = self.store.renew_scope_lease(
                self.lease.scope_key,
                owner_token=self.lease.owner_token,
                ttl_seconds=self.ttl_seconds,
            )
            if not result.acquired:
                self.lost.set()
                return

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1, self.interval_seconds + 1))


@contextmanager
def held_auth_scope_lease(
    store: AuthControlStore,
    scope_key: str,
    *,
    owner_token: str,
    operation_id: str,
    deadline: float,
    ttl_seconds: int = AUTH_SCOPE_LEASE_TTL_SECONDS,
    heartbeat_seconds: int = AUTH_SCOPE_LEASE_HEARTBEAT_SECONDS,
) -> Iterator[tuple[LeaseResult, threading.Event]]:
    if heartbeat_seconds <= 0 or heartbeat_seconds >= ttl_seconds:
        raise ValueError("auth_scope_heartbeat_interval_invalid")
    lease = store.wait_for_scope_lease(
        scope_key,
        owner_token=owner_token,
        operation_id=operation_id,
        deadline=deadline,
        ttl_seconds=ttl_seconds,
    )
    if not lease.acquired:
        yield lease, threading.Event()
        return
    heartbeat = _LeaseHeartbeat(
        store,
        lease,
        ttl_seconds=ttl_seconds,
        interval_seconds=heartbeat_seconds,
    )
    heartbeat.start()
    try:
        yield lease, heartbeat.lost
    finally:
        heartbeat.stop()
        store.release_scope_lease(scope_key, owner_token=owner_token)


def build_auth_state_attestation_v2(
    *,
    state_path: str | Path,
    generation_id: str,
    auth_state_scope: str,
    auth_mode: str,
    principal_digest: str,
    confirmation_kind: str,
    service_host: str,
    browser_name: str,
    headful_required: bool,
    producer_component: str,
    producer_operation_id: str,
    ttl_seconds: int,
    confirmed_at: str | None = None,
) -> dict[str, Any]:
    if ttl_seconds < AUTH_STATE_ATTESTATION_MIN_TTL_SECONDS or ttl_seconds > AUTH_STATE_ATTESTATION_MAX_TTL_SECONDS:
        raise ValueError("auth_state_attestation_ttl_invalid")
    if confirmation_kind not in AUTH_CONFIRMATION_KINDS:
        raise ValueError("auth_state_attestation_confirmation_kind_invalid")
    raw_path = Path(state_path).expanduser()
    if raw_path.is_symlink():
        raise ValueError("auth_state_attestation_state_invalid")
    selected_path = raw_path.resolve(strict=True)
    if not selected_path.is_file():
        raise ValueError("auth_state_attestation_state_invalid")
    confirmed = _parse_utc(confirmed_at or utc_now())
    if confirmed is None:
        raise ValueError("auth_state_attestation_timestamp_invalid")
    host = str(service_host or "").strip().casefold().rstrip(".")
    required_strings = {
        "generation_id": generation_id,
        "auth_state_scope": auth_state_scope,
        "auth_mode": auth_mode,
        "principal_digest": principal_digest,
        "service_host": host,
        "browser_name": browser_name,
        "producer_component": producer_component,
        "producer_operation_id": producer_operation_id,
    }
    if any(not str(value or "").strip() for value in required_strings.values()):
        raise ValueError("auth_state_attestation_field_missing")
    if len(str(principal_digest)) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in str(principal_digest)
    ):
        raise ValueError("auth_state_attestation_principal_digest_invalid")
    if not host or any(character in host for character in "/:@") or " " in host:
        raise ValueError("auth_state_attestation_service_host_invalid")
    return {
        "schema": AUTH_STATE_ATTESTATION_SCHEMA,
        "generation_id": str(generation_id),
        "auth_state_scope": str(auth_state_scope),
        "auth_mode": str(auth_mode).strip().casefold(),
        "principal_digest": str(principal_digest).strip().casefold(),
        "confirmation_kind": confirmation_kind,
        "service_host": host,
        "confirmed_at": _utc_text(confirmed),
        "expires_at": _utc_text(confirmed + timedelta(seconds=ttl_seconds)),
        "state_sha256": sha256_file(selected_path),
        "browser_name": str(browser_name).strip().casefold(),
        "headful_required": bool(headful_required),
        "producer_component": str(producer_component).strip(),
        "producer_operation_id": str(producer_operation_id).strip(),
    }


def validate_auth_state_attestation_v2(
    attestation: Mapping[str, Any],
    state_path: str | Path,
    *,
    expected_scope: str,
    expected_auth_mode: str,
    expected_principal_digest: str,
    expected_service_host: str,
    scope_key: str = "",
    store: AuthControlStore | None = None,
    now: datetime | None = None,
) -> AttestationValidation:
    if attestation.get("schema") != AUTH_STATE_ATTESTATION_SCHEMA:
        return AttestationValidation(False, "auth_state_attestation_schema_invalid")
    selected_now = _as_utc(now)
    confirmed = _parse_utc(attestation.get("confirmed_at"))
    expires = _parse_utc(attestation.get("expires_at"))
    if confirmed is None or expires is None or expires <= confirmed:
        return AttestationValidation(False, "auth_state_attestation_timestamp_invalid")
    ttl = (expires - confirmed).total_seconds()
    if ttl < AUTH_STATE_ATTESTATION_MIN_TTL_SECONDS or ttl > AUTH_STATE_ATTESTATION_MAX_TTL_SECONDS:
        return AttestationValidation(False, "auth_state_attestation_ttl_invalid")
    if confirmed > selected_now + timedelta(minutes=5):
        return AttestationValidation(False, "auth_state_attestation_timestamp_in_future")
    if expires < selected_now:
        return AttestationValidation(False, "auth_state_attestation_expired")
    expected_values = {
        "auth_state_scope": expected_scope,
        "auth_mode": str(expected_auth_mode or "").strip().casefold(),
        "principal_digest": str(expected_principal_digest or "").strip().casefold(),
        "service_host": str(expected_service_host or "").strip().casefold().rstrip("."),
    }
    for field, expected in expected_values.items():
        actual = str(attestation.get(field) or "").strip()
        if field in {"auth_mode", "principal_digest", "service_host"}:
            actual = actual.casefold().rstrip(".") if field == "service_host" else actual.casefold()
        if not hmac.compare_digest(actual, expected):
            return AttestationValidation(False, f"auth_state_attestation_{field}_mismatch")
    if str(attestation.get("confirmation_kind") or "") not in AUTH_CONFIRMATION_KINDS:
        return AttestationValidation(False, "auth_state_attestation_confirmation_kind_invalid")
    generation_id = str(attestation.get("generation_id") or "")
    if not generation_id:
        return AttestationValidation(False, "auth_state_attestation_generation_missing")
    path = Path(state_path).expanduser()
    try:
        if path.is_symlink():
            return AttestationValidation(False, "auth_state_attestation_state_invalid")
        resolved = path.resolve(strict=True)
        actual_sha = sha256_file(resolved)
    except (OSError, RuntimeError):
        return AttestationValidation(False, "auth_state_attestation_state_invalid")
    expected_sha = str(attestation.get("state_sha256") or "").casefold()
    if len(expected_sha) != 64 or not hmac.compare_digest(actual_sha, expected_sha):
        return AttestationValidation(False, "auth_state_attestation_state_mismatch")
    if store is not None:
        if not scope_key:
            return AttestationValidation(False, "auth_state_attestation_scope_key_missing")
        generation = store.auth_generation(scope_key)
        if generation is None:
            return AttestationValidation(False, "auth_state_generation_missing")
        checks = {
            "generation_id": generation_id,
            "auth_state_scope": expected_scope,
            "auth_mode": expected_values["auth_mode"],
            "principal_digest": expected_values["principal_digest"],
            "service_host": expected_values["service_host"],
            "state_sha256": expected_sha,
            "attestation_sha256": hashlib.sha256(
                canonical_json_bytes(dict(attestation))
            ).hexdigest(),
            "confirmation_kind": str(attestation.get("confirmation_kind") or ""),
            "browser_name": str(attestation.get("browser_name") or ""),
            "producer_component": str(
                attestation.get("producer_component") or ""
            ),
            "producer_operation_id": str(
                attestation.get("producer_operation_id") or ""
            ),
        }
        for field, expected in checks.items():
            actual = str(generation.get(field) or "").strip().casefold()
            if not hmac.compare_digest(actual, str(expected).strip().casefold()):
                return AttestationValidation(False, "auth_state_generation_mismatch")
        try:
            generation_path = Path(str(generation.get("state_path") or "")).resolve(strict=True)
        except (OSError, RuntimeError):
            return AttestationValidation(False, "auth_state_generation_mismatch")
        if generation_path != resolved:
            return AttestationValidation(False, "auth_state_generation_mismatch")
    return AttestationValidation(True, "auth_state_attestation_valid", dict(attestation))


def write_auth_state_attestation_v2_atomic(
    path: str | Path, attestation: Mapping[str, Any]
) -> Path:
    if attestation.get("schema") != AUTH_STATE_ATTESTATION_SCHEMA:
        raise ValueError("auth_state_attestation_schema_invalid")
    return atomic_write_json(path, attestation)


def commit_auth_state_generation(
    store: AuthControlStore,
    *,
    scope_key: str,
    owner_token: str,
    operation_id: str = "",
    state_path: str | Path,
    attestation_path: str | Path,
    attestation: Mapping[str, Any],
) -> tuple[bool, str]:
    """Republish an existing state as a fenced state/sidecar generation pair."""

    lease = store.current_scope_lease(scope_key)
    bound_operation_id = operation_id or (
        str(lease.get("operation_id") or "")
        if lease is not None
        and hmac.compare_digest(
            str(lease.get("owner_token") or ""), owner_token
        )
        else ""
    )
    if not bound_operation_id or not store.owns_active_scope_lease(
        scope_key,
        owner_token=owner_token,
        operation_id=bound_operation_id,
    ):
        return False, "auth_scope_lease_lost"
    target_state = Path(state_path).expanduser()
    target_attestation = Path(attestation_path).expanduser()
    token = secrets.token_hex(12)
    staged_state = target_state.with_name(f".{target_state.name}.{token}.tmp")
    staged_attestation = target_attestation.with_name(
        f".{target_attestation.name}.{token}.tmp"
    )
    try:
        if target_state.is_symlink() or not target_state.is_file():
            return False, "auth_state_unreadable"
        shutil.copy2(target_state, staged_state)
        atomic_write_json(staged_attestation, attestation)
        return store.publish_auth_generation(
            scope_key,
            attestation,
            staged_state_path=staged_state,
            target_state_path=target_state,
            staged_attestation_path=staged_attestation,
            target_attestation_path=target_attestation,
            owner_token=owner_token,
            operation_id=bound_operation_id,
        )
    except (OSError, RuntimeError) as exc:
        return False, f"auth_state_generation_commit_failed:{exc.__class__.__name__}"
    finally:
        staged_state.unlink(missing_ok=True)
        staged_attestation.unlink(missing_ok=True)


__all__ = [name for name in globals() if not name.startswith("_")]
