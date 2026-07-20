from __future__ import annotations

"""Generation-bound canonical-v2 handoff publication and validation.

The manifest is the publication commit point. SQLite and the two JSONL files
may be replaced one at a time, but a consumer accepts them only when every
piece describes the same generation and the same canonical record content.
"""

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import sqlite3
import tempfile
import time
from typing import Any, Iterable, Iterator, Literal, Mapping, Sequence, cast
import uuid

from .contracts import (
    CANONICAL_SCHEMA_VERSION,
    HANDOFF_MANIFEST_V2_FILENAME,
    LITERATURE_RECORDS_V2_FILENAME,
    PATENT_RECORDS_V2_FILENAME,
    CanonicalRecord,
    RecordType,
    canonical_json_dumps,
    iter_records_jsonl,
    write_records_jsonl,
)
from .sqlite_store import (
    SQLITE_SCHEMA_VERSION,
    connect_canonical_database,
    current_schema_version,
    iter_records,
    migrate_schema,
    upsert_record,
)


HANDOFF_MANIFEST_SCHEMA = "laps_handoff_manifest_v2"
HANDOFF_MANIFEST_VERSION = 2
CANONICAL_DATABASE_V2_FILENAME = "canonical_records.v2.sqlite3"
HANDOFF_LOCK_FILENAME = ".handoff.v2.lock"
_SHA256_HEX = frozenset("0123456789abcdef")
_RECORD_TYPES: tuple[RecordType, RecordType] = ("literature", "patent")

BindingStatus = Literal["bound", "legacy_unbound", "standalone_unbound"]


class HandoffError(ValueError):
    """A fail-closed handoff error carrying a stable machine reason code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)


@dataclass(frozen=True, slots=True)
class ValidatedHandoffBundle:
    binding_status: BindingStatus
    manifest_path: Path | None
    database_path: Path | None
    literature_records: tuple[CanonicalRecord, ...]
    patent_records: tuple[CanonicalRecord, ...]
    aliases_by_type: dict[RecordType, dict[str, str]]
    evidence: dict[str, Any]

    def records_for(self, record_type: RecordType) -> tuple[CanonicalRecord, ...]:
        return (
            self.literature_records
            if record_type == "literature"
            else self.patent_records
        )

    def aliases_for_target(self, record_type: RecordType) -> dict[str, tuple[str, ...]]:
        by_target: dict[str, list[str]] = {}
        for alias, target in self.aliases_by_type.get(record_type, {}).items():
            by_target.setdefault(target, []).append(alias)
        return {
            target: tuple(sorted(values))
            for target, values in sorted(by_target.items())
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_mapping_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_sha256(value: Any) -> bool:
    text = str(value or "").strip().casefold()
    return len(text) == 64 and all(character in _SHA256_HEX for character in text)


def _validated_uuid4(value: Any) -> str:
    text = str(value or "").strip()
    try:
        parsed = uuid.UUID(text)
    except (ValueError, TypeError, AttributeError) as exc:
        raise HandoffError("handoff_manifest_invalid", "invalid generation ID") from exc
    if parsed.version != 4 or str(parsed) != text.casefold():
        raise HandoffError(
            "handoff_manifest_invalid",
            "generation ID must be canonical UUIDv4",
        )
    return text.casefold()


def _record_type_from_id(record_id: str) -> RecordType | None:
    if record_id.startswith("lit_"):
        return "literature"
    if record_id.startswith("pat_"):
        return "patent"
    return None


def normalize_typed_aliases(
    records: Sequence[CanonicalRecord],
    aliases_by_type: Mapping[str, Mapping[str, str]] | None,
) -> dict[RecordType, dict[str, str]]:
    record_types = {record.record_id: record.record_type for record in records}
    if len(record_types) != len(records):
        raise HandoffError(
            "handoff_jsonl_duplicate_record_id",
            "canonical record IDs must be globally unique",
        )
    normalized: dict[RecordType, dict[str, str]] = {
        "literature": {},
        "patent": {},
    }
    seen_aliases: set[str] = set()
    raw = aliases_by_type or {}
    if not isinstance(raw, Mapping):
        raise HandoffError(
            "handoff_manifest_invalid",
            "typed aliases must be an object",
        )
    extra_types = set(str(key) for key in raw) - set(_RECORD_TYPES)
    if extra_types:
        raise HandoffError(
            "handoff_alias_type_mismatch",
            "unknown alias record type",
        )
    for record_type in _RECORD_TYPES:
        values = raw.get(record_type, {})
        if not isinstance(values, Mapping):
            raise HandoffError(
                "handoff_manifest_invalid",
                f"aliases for {record_type} must be an object",
            )
        for raw_alias, raw_target in sorted(
            values.items(),
            key=lambda item: str(item[0]),
        ):
            alias = str(raw_alias or "").strip()
            target = str(raw_target or "").strip()
            inferred_type = _record_type_from_id(alias)
            if (
                not alias
                or not target
                or alias == target
                or alias in record_types
                or target not in record_types
                or record_types[target] != record_type
                or (inferred_type is not None and inferred_type != record_type)
                or alias in seen_aliases
            ):
                raise HandoffError(
                    "handoff_alias_type_mismatch",
                    f"invalid {record_type} alias {alias!r}",
                )
            normalized[record_type][alias] = target
            seen_aliases.add(alias)
    return normalized


def aliases_sha256(aliases_by_type: Mapping[str, Mapping[str, str]]) -> str:
    normalized = {
        record_type: dict(sorted(aliases_by_type.get(record_type, {}).items()))
        for record_type in _RECORD_TYPES
    }
    return sha256_bytes(canonical_mapping_json(normalized).encode("utf-8"))


def _record_summaries(
    literature_records: Sequence[CanonicalRecord],
    patent_records: Sequence[CanonicalRecord],
) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    records_by_type = {
        "literature": literature_records,
        "patent": patent_records,
    }
    readiness = {
        record_type: dict(
            sorted(
                Counter(
                    record.retrieval_readiness
                    for record in records
                ).items()
            )
        )
        for record_type, records in records_by_type.items()
    }
    unresolved = {
        "literature_metadata_only": sum(
            record.retrieval_readiness == "metadata_only"
            for record in literature_records
        ),
        "patent_metadata_only": sum(
            record.retrieval_readiness == "metadata_only"
            for record in patent_records
        ),
    }
    unresolved["total"] = (
        unresolved["literature_metadata_only"]
        + unresolved["patent_metadata_only"]
    )
    return readiness, unresolved


def build_handoff_content_payload(
    *,
    literature_records: Sequence[CanonicalRecord],
    patent_records: Sequence[CanonicalRecord],
    literature_sha256: str,
    patent_sha256: str,
    aliases_by_type: Mapping[str, Mapping[str, str]],
    search_status: str,
    legacy_literature_count: int,
    legacy_patent_count: int,
    registry_schema_version: int,
    registry_version: str,
) -> dict[str, Any]:
    readiness, unresolved = _record_summaries(
        literature_records,
        patent_records,
    )
    typed_aliases = {
        record_type: dict(sorted(aliases_by_type.get(record_type, {}).items()))
        for record_type in _RECORD_TYPES
    }
    return {
        "schema": HANDOFF_MANIFEST_SCHEMA,
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "manifest_version": HANDOFF_MANIFEST_VERSION,
        "sqlite_schema_version": SQLITE_SCHEMA_VERSION,
        "registry_schema_version": int(registry_schema_version),
        "registry_version": str(registry_version),
        "search_status": search_status,
        "files": {
            "literature_records": {
                "path": LITERATURE_RECORDS_V2_FILENAME,
                "count": len(literature_records),
                "sha256": literature_sha256,
            },
            "patent_records": {
                "path": PATENT_RECORDS_V2_FILENAME,
                "count": len(patent_records),
                "sha256": patent_sha256,
            },
            "canonical_database": {
                "path": CANONICAL_DATABASE_V2_FILENAME,
                "sqlite_schema_version": SQLITE_SCHEMA_VERSION,
            },
        },
        "record_counts": {
            "literature": len(literature_records),
            "patent": len(patent_records),
            "total": len(literature_records) + len(patent_records),
        },
        "legacy_projection_counts": {
            "literature": int(legacy_literature_count),
            "patent": int(legacy_patent_count),
        },
        "retrieval_readiness_counts": readiness,
        "unresolved_counts": unresolved,
        "record_aliases_by_type": typed_aliases,
        "record_aliases_sha256": aliases_sha256(typed_aliases),
    }


def _lock_once(handle: Any) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle: Any) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def handoff_file_lock(
    root: Path,
    *,
    timeout: float = 30.0,
) -> Iterator[Path]:
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / HANDOFF_LOCK_FILENAME
    deadline = time.monotonic() + max(0.0, timeout)
    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
            os.fsync(handle.fileno())
        while True:
            try:
                _lock_once(handle)
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise HandoffError("handoff_busy", str(lock_path))
                time.sleep(random.uniform(0.05, 0.15))
        try:
            yield lock_path
        finally:
            _unlock(handle)


def _stage_jsonl(path: Path, records: Sequence[CanonicalRecord]) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    os.close(descriptor)
    staged = Path(name)
    write_records_jsonl(staged, records, atomic=False)
    return staged


def _stage_json(path: Path, payload: Mapping[str, Any]) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    staged = Path(name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(
                dict(payload),
                handle,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return staged
    except Exception:
        staged.unlink(missing_ok=True)
        raise


def _sync_directory(path: Path) -> str:
    if os.name == "nt":
        return "file_fsync_only"
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return "file_and_directory_fsync"


def write_handoff_bundle(
    *,
    records: Iterable[CanonicalRecord],
    aliases_by_type: Mapping[str, Mapping[str, str]],
    literature_path: Path,
    patent_path: Path,
    manifest_path: Path,
    database_path: Path,
    search_status: str,
    legacy_literature_count: int,
    legacy_patent_count: int,
    registry_schema_version: int,
    registry_version: str,
    lock_timeout: float = 30.0,
) -> dict[str, Any]:
    """Publish a complete generation-bound handoff, committing manifest last."""

    status = str(search_status or "").strip().casefold()
    if status not in {"complete", "partial", "failed"}:
        raise HandoffError(
            "handoff_manifest_invalid",
            "invalid search status",
        )
    root = manifest_path.parent.resolve()
    expected_paths = {
        literature_path.resolve(): LITERATURE_RECORDS_V2_FILENAME,
        patent_path.resolve(): PATENT_RECORDS_V2_FILENAME,
        manifest_path.resolve(): HANDOFF_MANIFEST_V2_FILENAME,
        database_path.resolve(): CANONICAL_DATABASE_V2_FILENAME,
    }
    if any(
        path.parent != root or path.name != name
        for path, name in expected_paths.items()
    ):
        raise HandoffError(
            "handoff_manifest_invalid",
            "formal handoff files must use fixed sibling filenames",
        )
    root.mkdir(parents=True, exist_ok=True)
    ordered = tuple(
        sorted(records, key=lambda item: (item.record_type, item.record_id))
    )
    record_ids = [record.record_id for record in ordered]
    if len(record_ids) != len(set(record_ids)):
        raise HandoffError(
            "handoff_jsonl_duplicate_record_id",
            "canonical record IDs must be globally unique",
        )
    literature_records = tuple(
        record for record in ordered
        if record.record_type == "literature"
    )
    patent_records = tuple(
        record for record in ordered
        if record.record_type == "patent"
    )
    typed_aliases = normalize_typed_aliases(ordered, aliases_by_type)
    generation_id = str(uuid.uuid4())
    staged_literature: Path | None = None
    staged_patent: Path | None = None
    staged_manifest: Path | None = None
    try:
        staged_literature = _stage_jsonl(
            literature_path,
            literature_records,
        )
        staged_patent = _stage_jsonl(patent_path, patent_records)
        literature_sha = sha256_file(staged_literature)
        patent_sha = sha256_file(staged_patent)
        content_payload = build_handoff_content_payload(
            literature_records=literature_records,
            patent_records=patent_records,
            literature_sha256=literature_sha,
            patent_sha256=patent_sha,
            aliases_by_type=typed_aliases,
            search_status=status,
            legacy_literature_count=legacy_literature_count,
            legacy_patent_count=legacy_patent_count,
            registry_schema_version=registry_schema_version,
            registry_version=registry_version,
        )
        content_json = canonical_mapping_json(content_payload)
        content_sha = sha256_bytes(content_json.encode("utf-8"))
        materialized_at = utc_now()
        durability_level = (
            "file_fsync_only"
            if os.name == "nt"
            else "file_and_directory_fsync"
        )
        manifest_payload: dict[str, Any] = {
            **content_payload,
            "handoff_generation_id": generation_id,
            "handoff_content_sha256": content_sha,
            "created_at": materialized_at,
            "ok": status == "complete",
            "durability_level": durability_level,
            # A flat union cannot safely represent mixed record-type aliases.
            "record_aliases": {},
        }
        staged_manifest = _stage_json(manifest_path, manifest_payload)

        with handoff_file_lock(root, timeout=lock_timeout):
            connection = connect_canonical_database(database_path)
            try:
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("BEGIN IMMEDIATE")
                migrate_schema(connection)
                connection.execute("DELETE FROM handoff_state")
                connection.execute("DELETE FROM record_aliases")
                connection.execute("DELETE FROM canonical_records")
                for record in ordered:
                    upsert_record(connection, record, commit=False)
                for record_type in _RECORD_TYPES:
                    for alias, target in typed_aliases[record_type].items():
                        connection.execute(
                            """
                            INSERT INTO record_aliases(
                                alias_record_id, canonical_record_id,
                                reason, created_at
                            ) VALUES (?, ?, 'identity_upgrade', ?)
                            """,
                            (alias, target, materialized_at),
                        )
                connection.execute(
                    """
                    INSERT INTO handoff_state(
                        singleton_id, handoff_generation_id,
                        handoff_content_sha256, manifest_version,
                        literature_jsonl_sha256,
                        literature_record_count,
                        patent_jsonl_sha256, patent_record_count,
                        record_aliases_sha256,
                        registry_schema_version, registry_version,
                        search_status, content_payload_json,
                        materialized_at
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        generation_id,
                        content_sha,
                        HANDOFF_MANIFEST_VERSION,
                        literature_sha,
                        len(literature_records),
                        patent_sha,
                        len(patent_records),
                        content_payload["record_aliases_sha256"],
                        int(registry_schema_version),
                        str(registry_version),
                        status,
                        content_json,
                        materialized_at,
                    ),
                )
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

            os.replace(staged_literature, literature_path)
            staged_literature = None
            os.replace(staged_patent, patent_path)
            staged_patent = None
            if sha256_file(literature_path) != literature_sha:
                raise HandoffError(
                    "handoff_content_mismatch",
                    "literature replace verification",
                )
            if sha256_file(patent_path) != patent_sha:
                raise HandoffError(
                    "handoff_content_mismatch",
                    "patent replace verification",
                )
            _sync_directory(root)
            os.replace(staged_manifest, manifest_path)
            staged_manifest = None
            _sync_directory(root)
        return {
            **manifest_payload,
            "manifest_path": str(manifest_path.resolve()),
        }
    finally:
        for staged in (
            staged_literature,
            staged_patent,
            staged_manifest,
        ):
            if staged is not None:
                staged.unlink(missing_ok=True)


def _read_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        decoded = raw.decode("utf-8-sig")
        value = json.loads(decoded)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HandoffError("handoff_manifest_invalid", str(exc)) from exc
    if not isinstance(value, dict):
        raise HandoffError(
            "handoff_manifest_invalid",
            "manifest must be an object",
        )
    return value, raw


def _safe_sibling(
    root: Path,
    entry: Mapping[str, Any],
    expected_name: str,
    *,
    strict: bool,
) -> Path:
    declared = str(entry.get("path") or "").strip()
    if not declared:
        raise HandoffError(
            "handoff_manifest_invalid",
            f"missing path for {expected_name}",
        )
    if strict and (
        Path(declared).name != declared
        or declared != expected_name
    ):
        raise HandoffError(
            "handoff_manifest_invalid",
            f"unsafe path for {expected_name}",
        )
    if not strict and Path(declared).name != expected_name:
        raise HandoffError(
            "handoff_manifest_invalid",
            f"path mismatch for {expected_name}",
        )
    candidate = root / expected_name
    if candidate.is_symlink() or candidate.resolve().parent != root.resolve():
        raise HandoffError(
            "handoff_manifest_invalid",
            f"path escape for {expected_name}",
        )
    return candidate


def _load_jsonl_snapshot(
    path: Path,
    record_type: RecordType,
) -> tuple[tuple[CanonicalRecord, ...], str]:
    try:
        records = tuple(iter_records_jsonl(path))
    except (OSError, ValueError) as exc:
        raise HandoffError("handoff_manifest_invalid", str(exc)) from exc
    seen: set[str] = set()
    for record in records:
        if record.record_type != record_type:
            raise HandoffError(
                "handoff_manifest_invalid",
                f"record {record.record_id!r} has wrong type",
            )
        if record.record_id in seen:
            raise HandoffError(
                "handoff_jsonl_duplicate_record_id",
                record.record_id,
            )
        seen.add(record.record_id)
    return records, sha256_file(path)


def _records_map(records: Sequence[CanonicalRecord]) -> dict[str, str]:
    return {
        record.record_id: canonical_json_dumps(record)
        for record in records
    }


def _sqlite_snapshot(
    database_path: Path,
) -> tuple[
    int,
    tuple[CanonicalRecord, ...],
    dict[RecordType, dict[str, str]],
    dict[str, Any] | None,
]:
    try:
        connection = connect_canonical_database(
            database_path,
            read_only=True,
            timeout=10,
        )
    except sqlite3.Error as exc:
        raise HandoffError(
            "handoff_manifest_invalid",
            f"canonical SQLite: {exc}",
        ) from exc
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        version = current_schema_version(connection)
        foreign_key_violations = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        if foreign_key_violations:
            raise HandoffError(
                "handoff_content_mismatch",
                "canonical SQLite foreign-key integrity",
            )
        records = tuple(iter_records(connection, initialize=False))
        aliases: dict[RecordType, dict[str, str]] = {
            "literature": {},
            "patent": {},
        }
        for row in connection.execute(
            """
            SELECT a.alias_record_id, a.canonical_record_id,
                   r.record_type
            FROM record_aliases AS a
            JOIN canonical_records AS r
              ON r.record_id = a.canonical_record_id
            ORDER BY a.alias_record_id
            """
        ):
            record_type = cast(
                RecordType,
                str(row["record_type"]),
            )
            aliases[record_type][str(row["alias_record_id"])] = str(
                row["canonical_record_id"]
            )
        alias_count_row = connection.execute(
            "SELECT COUNT(*) FROM record_aliases"
        ).fetchone()
        alias_count = int(alias_count_row[0]) if alias_count_row else 0
        if alias_count != sum(len(values) for values in aliases.values()):
            raise HandoffError(
                "handoff_content_mismatch",
                "canonical SQLite orphan alias",
            )
        state: dict[str, Any] | None = None
        if version >= 2:
            row = connection.execute(
                "SELECT * FROM handoff_state WHERE singleton_id=1"
            ).fetchone()
            state = dict(row) if row is not None else None
        connection.commit()
        return version, records, aliases, state
    except HandoffError:
        if connection.in_transaction:
            connection.rollback()
        raise
    except (sqlite3.Error, ValueError) as exc:
        if connection.in_transaction:
            connection.rollback()
        raise HandoffError(
            "handoff_manifest_invalid",
            f"canonical SQLite: {exc}",
        ) from exc
    finally:
        connection.close()


def _assert_no_uncommitted_schema2_handoff(root: Path) -> None:
    """Reject a schema-2 SQLite generation whose manifest commit is absent.

    A canonical-v2 JSONL is allowed to stand alone only when its directory does
    not also contain evidence of a generation-bound schema-2 publication.  The
    manifest is the sole publication commit point, so accepting the SQLite file
    (with zero, one, or both fixed JSONL files present) would expose a crashed
    writer's unpublished generation.

    The caller must hold the handoff file lock while this check runs.
    """

    manifest_path = root / HANDOFF_MANIFEST_V2_FILENAME
    if manifest_path.is_file():
        return
    database_path = root / CANONICAL_DATABASE_V2_FILENAME
    if not database_path.is_file():
        return
    try:
        connection = connect_canonical_database(
            database_path,
            read_only=True,
            timeout=10,
        )
    except sqlite3.Error as exc:
        raise HandoffError(
            "handoff_manifest_invalid",
            f"canonical SQLite residue cannot be inspected: {exc}",
        ) from exc
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        version = current_schema_version(connection)
        has_handoff_state = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type='table' AND name='handoff_state'
            LIMIT 1
            """
        ).fetchone() is not None
        connection.commit()
    except sqlite3.Error as exc:
        if connection.in_transaction:
            connection.rollback()
        raise HandoffError(
            "handoff_manifest_invalid",
            f"canonical SQLite residue cannot be inspected: {exc}",
        ) from exc
    finally:
        connection.close()
    if version >= 2 or has_handoff_state:
        raise HandoffError(
            "handoff_manifest_invalid",
            "schema-2 canonical SQLite exists without the handoff manifest "
            "publication commit point",
        )


def assert_no_uncommitted_schema2_handoff(
    root: str | os.PathLike[str],
    *,
    lock_timeout: float = 30.0,
) -> None:
    """Fail closed when ``root`` contains an unpublished schema-2 handoff."""

    resolved_root = Path(root).expanduser().resolve()
    with handoff_file_lock(resolved_root, timeout=lock_timeout):
        _assert_no_uncommitted_schema2_handoff(resolved_root)


def _assert_file_entry(
    entry: Mapping[str, Any],
    *,
    actual_sha: str,
    actual_count: int,
    label: str,
) -> None:
    if str(entry.get("sha256") or "").casefold() != actual_sha:
        raise HandoffError(
            "handoff_content_mismatch",
            f"{label} SHA-256",
        )
    try:
        expected_count = int(entry.get("count"))
    except (TypeError, ValueError) as exc:
        raise HandoffError(
            "handoff_manifest_invalid",
            f"{label} count",
        ) from exc
    if expected_count != actual_count:
        raise HandoffError(
            "handoff_content_mismatch",
            f"{label} count",
        )


def _status_from_manifest(payload: Mapping[str, Any]) -> str:
    status = str(
        payload.get("search_status") or ""
    ).strip().casefold()
    if status not in {"complete", "partial", "failed"}:
        raise HandoffError(
            "handoff_manifest_invalid",
            "invalid search_status",
        )
    ok = payload.get("ok")
    if not isinstance(ok, bool) or ok != (status == "complete"):
        raise HandoffError(
            "handoff_manifest_invalid",
            "inconsistent ok/search_status",
        )
    return status


def _legacy_aliases(
    payload: Mapping[str, Any],
    records: Sequence[CanonicalRecord],
) -> dict[str, str]:
    raw = payload.get("record_aliases", {})
    if raw in (None, {}):
        return {}
    if not isinstance(raw, Mapping):
        raise HandoffError(
            "handoff_manifest_invalid",
            "legacy aliases must be an object",
        )
    record_ids = {record.record_id for record in records}
    aliases: dict[str, str] = {}
    for raw_alias, raw_target in raw.items():
        alias = str(raw_alias or "").strip()
        target = str(raw_target or "").strip()
        if (
            not alias
            or not target
            or alias == target
            or alias in record_ids
            or target not in record_ids
        ):
            raise HandoffError(
                "handoff_alias_type_mismatch",
                f"invalid legacy alias {alias!r}",
            )
        aliases[alias] = target
    return aliases


def _validate_formal_bundle(
    root: Path,
    manifest_path: Path,
    payload: dict[str, Any],
    manifest_raw: bytes,
) -> ValidatedHandoffBundle:
    if payload.get("schema") != HANDOFF_MANIFEST_SCHEMA:
        raise HandoffError(
            "handoff_manifest_invalid",
            "unknown manifest schema",
        )
    if (
        int(payload.get("schema_version") or 0)
        != CANONICAL_SCHEMA_VERSION
    ):
        raise HandoffError(
            "handoff_manifest_invalid",
            "unsupported canonical schema",
        )
    status = _status_from_manifest(payload)
    try:
        raw_manifest_version = payload.get("manifest_version")
        manifest_version = (
            1
            if raw_manifest_version is None
            else int(raw_manifest_version)
        )
    except (TypeError, ValueError) as exc:
        raise HandoffError(
            "handoff_manifest_invalid",
            "invalid manifest version",
        ) from exc
    if manifest_version not in {1, HANDOFF_MANIFEST_VERSION}:
        raise HandoffError(
            "handoff_manifest_invalid",
            "unsupported manifest version",
        )
    files = payload.get("files")
    if not isinstance(files, Mapping):
        raise HandoffError(
            "handoff_manifest_invalid",
            "files must be an object",
        )
    literature_entry = files.get("literature_records")
    patent_entry = files.get("patent_records")
    database_entry = files.get("canonical_database")
    if not all(
        isinstance(item, Mapping)
        for item in (
            literature_entry,
            patent_entry,
            database_entry,
        )
    ):
        raise HandoffError(
            "handoff_manifest_invalid",
            "formal bundle must declare all files",
        )
    strict = manifest_version == HANDOFF_MANIFEST_VERSION
    literature_path = _safe_sibling(
        root,
        cast(Mapping[str, Any], literature_entry),
        LITERATURE_RECORDS_V2_FILENAME,
        strict=strict,
    )
    patent_path = _safe_sibling(
        root,
        cast(Mapping[str, Any], patent_entry),
        PATENT_RECORDS_V2_FILENAME,
        strict=strict,
    )
    database_path = _safe_sibling(
        root,
        cast(Mapping[str, Any], database_entry),
        CANONICAL_DATABASE_V2_FILENAME,
        strict=strict,
    )
    literature_records, literature_sha = _load_jsonl_snapshot(
        literature_path,
        "literature",
    )
    patent_records, patent_sha = _load_jsonl_snapshot(
        patent_path,
        "patent",
    )
    _assert_file_entry(
        cast(Mapping[str, Any], literature_entry),
        actual_sha=literature_sha,
        actual_count=len(literature_records),
        label="literature JSONL",
    )
    _assert_file_entry(
        cast(Mapping[str, Any], patent_entry),
        actual_sha=patent_sha,
        actual_count=len(patent_records),
        label="patent JSONL",
    )
    (
        sqlite_version,
        database_records,
        database_aliases,
        handoff_state,
    ) = _sqlite_snapshot(database_path)
    try:
        declared_sqlite_version = int(
            cast(
                Mapping[str, Any],
                database_entry,
            ).get("sqlite_schema_version")
        )
    except (TypeError, ValueError) as exc:
        raise HandoffError(
            "handoff_manifest_invalid",
            "invalid SQLite schema version",
        ) from exc
    if sqlite_version != declared_sqlite_version:
        raise HandoffError(
            "handoff_generation_mismatch",
            "SQLite schema declaration",
        )
    all_jsonl = (*literature_records, *patent_records)
    if len(all_jsonl) != len({record.record_id for record in all_jsonl}):
        raise HandoffError(
            "handoff_jsonl_duplicate_record_id",
            "record ID occurs across record-type JSONL files",
        )
    if _records_map(all_jsonl) != _records_map(database_records):
        raise HandoffError(
            "handoff_content_mismatch",
            "SQLite/JSONL canonical records",
        )

    if manifest_version == 1:
        if sqlite_version != 1:
            raise HandoffError(
                "handoff_generation_mismatch",
                "legacy manifest cannot bind schema-2 SQLite",
            )
        manifest_aliases = _legacy_aliases(payload, all_jsonl)
        database_flat_aliases = {
            alias: target
            for record_type in _RECORD_TYPES
            for alias, target in database_aliases[record_type].items()
        }
        if manifest_aliases != database_flat_aliases:
            raise HandoffError(
                "handoff_content_mismatch",
                "legacy SQLite/manifest aliases",
            )
        evidence = {
            "present": True,
            "validated": True,
            "binding_status": "legacy_unbound",
            "generation_bound": False,
            "reason_code": "legacy_unbound_manifest",
            "path": str(manifest_path),
            "manifest_sha256": sha256_bytes(manifest_raw),
            "search_status": status,
            "sqlite_schema_version": sqlite_version,
            "record_counts": {
                "literature": len(literature_records),
                "patent": len(patent_records),
            },
            "legacy_alias_count": len(manifest_aliases),
            "alias_reuse_allowed": False,
        }
        return ValidatedHandoffBundle(
            binding_status="legacy_unbound",
            manifest_path=manifest_path,
            database_path=database_path,
            literature_records=literature_records,
            patent_records=patent_records,
            aliases_by_type={"literature": {}, "patent": {}},
            evidence=evidence,
        )

    if (
        sqlite_version != SQLITE_SCHEMA_VERSION
        or handoff_state is None
    ):
        raise HandoffError(
            "handoff_generation_mismatch",
            "schema-2 handoff state missing",
        )
    generation_id = _validated_uuid4(
        payload.get("handoff_generation_id")
    )
    content_sha = str(
        payload.get("handoff_content_sha256") or ""
    ).casefold()
    if not _is_sha256(content_sha):
        raise HandoffError(
            "handoff_manifest_invalid",
            "invalid handoff content digest",
        )
    raw_typed_aliases = payload.get("record_aliases_by_type")
    if not isinstance(raw_typed_aliases, Mapping):
        raise HandoffError(
            "handoff_manifest_invalid",
            "typed aliases missing",
        )
    typed_aliases = normalize_typed_aliases(
        all_jsonl,
        cast(
            Mapping[str, Mapping[str, str]],
            raw_typed_aliases,
        ),
    )
    if payload.get("record_aliases") != {}:
        raise HandoffError(
            "handoff_manifest_invalid",
            "flat aliases must be empty",
        )
    if typed_aliases != database_aliases:
        raise HandoffError(
            "handoff_content_mismatch",
            "SQLite/manifest typed aliases",
        )
    try:
        legacy_counts = cast(
            Mapping[str, Any],
            payload["legacy_projection_counts"],
        )
        legacy_literature_count = int(
            legacy_counts["literature"]
        )
        legacy_patent_count = int(legacy_counts["patent"])
        registry_schema_version = int(
            payload["registry_schema_version"]
        )
        registry_version = str(payload["registry_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HandoffError(
            "handoff_manifest_invalid",
            "invalid content summary",
        ) from exc
    expected_content = build_handoff_content_payload(
        literature_records=literature_records,
        patent_records=patent_records,
        literature_sha256=literature_sha,
        patent_sha256=patent_sha,
        aliases_by_type=typed_aliases,
        search_status=status,
        legacy_literature_count=legacy_literature_count,
        legacy_patent_count=legacy_patent_count,
        registry_schema_version=registry_schema_version,
        registry_version=registry_version,
    )
    for key, expected in expected_content.items():
        if payload.get(key) != expected:
            raise HandoffError(
                "handoff_content_mismatch",
                f"manifest field {key}",
            )
    expected_content_json = canonical_mapping_json(
        expected_content
    )
    expected_content_sha = sha256_bytes(
        expected_content_json.encode("utf-8")
    )
    if content_sha != expected_content_sha:
        raise HandoffError(
            "handoff_content_mismatch",
            "content digest",
        )
    expected_state = {
        "handoff_generation_id": generation_id,
        "handoff_content_sha256": content_sha,
        "manifest_version": HANDOFF_MANIFEST_VERSION,
        "literature_jsonl_sha256": literature_sha,
        "literature_record_count": len(literature_records),
        "patent_jsonl_sha256": patent_sha,
        "patent_record_count": len(patent_records),
        "record_aliases_sha256": expected_content[
            "record_aliases_sha256"
        ],
        "registry_schema_version": registry_schema_version,
        "registry_version": registry_version,
        "search_status": status,
        "content_payload_json": expected_content_json,
    }
    for key, expected in expected_state.items():
        if handoff_state.get(key) != expected:
            raise HandoffError(
                "handoff_generation_mismatch",
                f"SQLite state {key}",
            )
    evidence = {
        "present": True,
        "validated": True,
        "binding_status": "bound",
        "generation_bound": True,
        "reason_code": "",
        "path": str(manifest_path),
        "manifest_version": HANDOFF_MANIFEST_VERSION,
        "manifest_sha256": sha256_bytes(manifest_raw),
        "handoff_generation_id": generation_id,
        "handoff_content_sha256": content_sha,
        "search_status": status,
        "sqlite_schema_version": sqlite_version,
        "record_counts": {
            "literature": len(literature_records),
            "patent": len(patent_records),
        },
        "alias_count": sum(
            len(values)
            for values in typed_aliases.values()
        ),
        "record_aliases_sha256": expected_content[
            "record_aliases_sha256"
        ],
        "alias_reuse_allowed": True,
    }
    return ValidatedHandoffBundle(
        binding_status="bound",
        manifest_path=manifest_path,
        database_path=database_path,
        literature_records=literature_records,
        patent_records=patent_records,
        aliases_by_type=typed_aliases,
        evidence=evidence,
    )


def validate_handoff_bundle(
    selected_path: str | os.PathLike[str],
    record_type: RecordType,
    *,
    lock_timeout: float = 30.0,
) -> ValidatedHandoffBundle:
    """Return a lock-validated immutable snapshot for one v2 input root."""

    selected = Path(selected_path).expanduser().resolve()
    root = selected.parent
    manifest_path = root / HANDOFF_MANIFEST_V2_FILENAME
    with handoff_file_lock(root, timeout=lock_timeout):
        if not manifest_path.is_file():
            _assert_no_uncommitted_schema2_handoff(root)
            records, actual_sha = _load_jsonl_snapshot(
                selected,
                record_type,
            )
            evidence = {
                "present": False,
                "validated": True,
                "binding_status": "standalone_unbound",
                "generation_bound": False,
                "reason_code": "standalone_unbound_jsonl",
                "jsonl_sha256": actual_sha,
                "record_count": len(records),
                "alias_reuse_allowed": False,
            }
            return ValidatedHandoffBundle(
                binding_status="standalone_unbound",
                manifest_path=None,
                database_path=None,
                literature_records=(
                    records
                    if record_type == "literature"
                    else ()
                ),
                patent_records=(
                    records
                    if record_type == "patent"
                    else ()
                ),
                aliases_by_type={
                    "literature": {},
                    "patent": {},
                },
                evidence=evidence,
            )
        payload, manifest_raw = _read_manifest(manifest_path)
        bundle = _validate_formal_bundle(
            root,
            manifest_path,
            payload,
            manifest_raw,
        )
        try:
            current_raw = manifest_path.read_bytes()
        except OSError as exc:
            raise HandoffError(
                "handoff_changed_during_validation",
                str(exc),
            ) from exc
        if current_raw != manifest_raw:
            raise HandoffError(
                "handoff_changed_during_validation",
                str(manifest_path),
            )
        expected_selected = (
            root / LITERATURE_RECORDS_V2_FILENAME
            if record_type == "literature"
            else root / PATENT_RECORDS_V2_FILENAME
        )
        if selected != expected_selected.resolve():
            raise HandoffError(
                "handoff_manifest_invalid",
                "selected JSONL is not the formal sibling "
                "declared by the manifest",
            )
        return bundle


__all__ = [
    "BindingStatus",
    "CANONICAL_DATABASE_V2_FILENAME",
    "HANDOFF_LOCK_FILENAME",
    "HANDOFF_MANIFEST_SCHEMA",
    "HANDOFF_MANIFEST_VERSION",
    "HandoffError",
    "ValidatedHandoffBundle",
    "aliases_sha256",
    "assert_no_uncommitted_schema2_handoff",
    "build_handoff_content_payload",
    "canonical_mapping_json",
    "handoff_file_lock",
    "normalize_typed_aliases",
    "sha256_file",
    "validate_handoff_bundle",
    "write_handoff_bundle",
]
