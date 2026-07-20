from __future__ import annotations

"""SQLite persistence primitives for the canonical v2 record contract."""

from contextlib import nullcontext
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Iterable, Iterator

from .contracts import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalRecord,
    Identifier,
    Locator,
    Provenance,
    canonical_identity_key,
)


SQLITE_SCHEMA_VERSION = 2

_MIGRATION_1 = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS canonical_records (
    record_id TEXT PRIMARY KEY,
    contract_schema_version INTEGER NOT NULL,
    record_type TEXT NOT NULL CHECK (record_type IN ('literature', 'patent')),
    identity_key TEXT NOT NULL,
    retrieval_readiness TEXT NOT NULL CHECK (
        retrieval_readiness IN (
            'direct_pdf', 'identifier_resolvable',
            'landing_discoverable', 'metadata_only'
        )
    ),
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_canonical_records_type
ON canonical_records(record_type, record_id);

CREATE INDEX IF NOT EXISTS idx_canonical_records_identity
ON canonical_records(identity_key);

CREATE TABLE IF NOT EXISTS record_identifiers (
    record_id TEXT NOT NULL REFERENCES canonical_records(record_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    identifier_type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    PRIMARY KEY (record_id, ordinal)
);

CREATE INDEX IF NOT EXISTS idx_record_identifiers_lookup
ON record_identifiers(identifier_type, normalized_value);

CREATE TABLE IF NOT EXISTS record_locators (
    record_id TEXT NOT NULL REFERENCES canonical_records(record_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL,
    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    source TEXT NOT NULL,
    auth_scope TEXT NOT NULL,
    stability TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (record_id, ordinal)
);

CREATE INDEX IF NOT EXISTS idx_record_locators_url
ON record_locators(normalized_url);

CREATE TABLE IF NOT EXISTS record_provenance (
    record_id TEXT NOT NULL REFERENCES canonical_records(record_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    source TEXT NOT NULL,
    keyword TEXT NOT NULL,
    query_variant TEXT NOT NULL,
    rank_value INTEGER,
    path TEXT NOT NULL,
    raw_id TEXT NOT NULL,
    PRIMARY KEY (record_id, ordinal)
);

CREATE INDEX IF NOT EXISTS idx_record_provenance_source
ON record_provenance(source, raw_id);

CREATE TABLE IF NOT EXISTS record_aliases (
    alias_record_id TEXT PRIMARY KEY,
    canonical_record_id TEXT NOT NULL REFERENCES canonical_records(record_id) ON DELETE CASCADE,
    reason TEXT NOT NULL DEFAULT 'identity_upgrade',
    created_at TEXT NOT NULL
);
"""


_MIGRATION_2 = """
CREATE TABLE IF NOT EXISTS handoff_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    handoff_generation_id TEXT NOT NULL,
    handoff_content_sha256 TEXT NOT NULL,
    manifest_version INTEGER NOT NULL,
    literature_jsonl_sha256 TEXT NOT NULL,
    literature_record_count INTEGER NOT NULL,
    patent_jsonl_sha256 TEXT NOT NULL,
    patent_record_count INTEGER NOT NULL,
    record_aliases_sha256 TEXT NOT NULL,
    registry_schema_version INTEGER NOT NULL,
    registry_version TEXT NOT NULL,
    search_status TEXT NOT NULL CHECK (search_status IN ('complete', 'partial', 'failed')),
    content_payload_json TEXT NOT NULL,
    materialized_at TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def connect_canonical_database(
    path: str | Path,
    *,
    read_only: bool = False,
    timeout: float = 30.0,
) -> sqlite3.Connection:
    if str(path) == ":memory:":
        if read_only:
            raise ValueError(":memory: cannot be opened read-only")
        connection = sqlite3.connect(":memory:", timeout=timeout)
    else:
        database_path = Path(path).expanduser().resolve()
        if read_only:
            connection = sqlite3.connect(
                f"file:{database_path.as_posix()}?mode=ro",
                uri=True,
                timeout=timeout,
            )
        else:
            database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(database_path, timeout=timeout)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def current_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row else 0


def migrate_schema(
    connection: sqlite3.Connection,
    *,
    target_version: int = SQLITE_SCHEMA_VERSION,
) -> int:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    current = current_schema_version(connection)
    if current > SQLITE_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema {current} is newer than supported {SQLITE_SCHEMA_VERSION}"
        )
    if target_version < current or target_version > SQLITE_SCHEMA_VERSION:
        raise ValueError(
            f"Invalid target schema version {target_version}; current={current}, "
            f"supported={SQLITE_SCHEMA_VERSION}"
        )
    migrations = {
        1: (_MIGRATION_1, "canonical v2 records and provenance"),
        2: (_MIGRATION_2, "generation-bound canonical v2 handoff state"),
    }
    owns_transaction = not connection.in_transaction
    try:
        if owns_transaction:
            connection.execute("BEGIN IMMEDIATE")
        for version in range(current + 1, target_version + 1):
            script, description = migrations[version]
            statement_buffer = ""
            for line in script.splitlines(keepends=True):
                statement_buffer += line
                if sqlite3.complete_statement(statement_buffer):
                    statement = statement_buffer.strip()
                    if statement:
                        connection.execute(statement)
                    statement_buffer = ""
            if statement_buffer.strip():
                raise RuntimeError(f"Incomplete SQLite migration {version}")
            connection.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, description) VALUES (?, ?)",
                (version, description),
            )
            connection.execute(f"PRAGMA user_version = {version}")
        if owns_transaction:
            connection.commit()
    except Exception:
        if owns_transaction and connection.in_transaction:
            connection.rollback()
        raise
    return current_schema_version(connection)


def initialize_schema(connection: sqlite3.Connection) -> int:
    return migrate_schema(connection)


def open_canonical_store(
    path: str | Path,
    *,
    read_only: bool = False,
    timeout: float = 30.0,
) -> sqlite3.Connection:
    connection = connect_canonical_database(path, read_only=read_only, timeout=timeout)
    if read_only:
        version = current_schema_version(connection)
        if version != SQLITE_SCHEMA_VERSION:
            connection.close()
            raise RuntimeError(
                f"Database schema {version} does not match supported {SQLITE_SCHEMA_VERSION}"
            )
    else:
        initialize_schema(connection)
    return connection


def _upsert_record(connection: sqlite3.Connection, record: CanonicalRecord, now: str) -> None:
    if record.schema_version != CANONICAL_SCHEMA_VERSION:
        raise ValueError(f"Unsupported record contract version: {record.schema_version}")
    identity_key = canonical_identity_key(
        record.record_type,
        record.metadata,
        record.identifiers,
        record.locators,
        record.provenance,
    )
    metadata_json = json.dumps(
        record.metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    connection.execute(
        """
        INSERT INTO canonical_records(
            record_id, contract_schema_version, record_type, identity_key,
            retrieval_readiness, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(record_id) DO UPDATE SET
            contract_schema_version = excluded.contract_schema_version,
            record_type = excluded.record_type,
            identity_key = excluded.identity_key,
            retrieval_readiness = excluded.retrieval_readiness,
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        """,
        (
            record.record_id,
            record.schema_version,
            record.record_type,
            identity_key,
            record.retrieval_readiness,
            metadata_json,
            now,
            now,
        ),
    )
    connection.execute("DELETE FROM record_identifiers WHERE record_id = ?", (record.record_id,))
    connection.execute("DELETE FROM record_locators WHERE record_id = ?", (record.record_id,))
    connection.execute("DELETE FROM record_provenance WHERE record_id = ?", (record.record_id,))
    connection.executemany(
        """
        INSERT INTO record_identifiers(
            record_id, ordinal, identifier_type, value, normalized_value,
            source, is_primary
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                record.record_id,
                ordinal,
                item.identifier_type,
                item.value,
                item.normalized_value,
                item.source or "unknown",
                int(item.primary),
            )
            for ordinal, item in enumerate(record.identifiers)
        ],
    )
    connection.executemany(
        """
        INSERT INTO record_locators(
            record_id, ordinal, kind, url, normalized_url, source,
            auth_scope, stability, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                record.record_id,
                ordinal,
                item.kind,
                item.url,
                item.normalized_url,
                item.source or "unknown",
                item.auth_scope or "unknown",
                item.stability or "unknown",
                item.observed_at,
            )
            for ordinal, item in enumerate(record.locators)
        ],
    )
    connection.executemany(
        """
        INSERT INTO record_provenance(
            record_id, ordinal, source, keyword, query_variant,
            rank_value, path, raw_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                record.record_id,
                ordinal,
                item.source or "unknown",
                item.keyword,
                item.query_variant or "unknown",
                item.rank,
                item.path or "unknown",
                item.raw_id,
            )
            for ordinal, item in enumerate(record.provenance)
        ],
    )


def upsert_record(
    connection: sqlite3.Connection,
    record: CanonicalRecord,
    *,
    commit: bool = True,
) -> None:
    initialize_schema(connection)
    manager = connection if commit else nullcontext(connection)
    with manager:
        _upsert_record(connection, record, utc_now())


def upsert_records(
    connection: sqlite3.Connection,
    records: Iterable[CanonicalRecord],
) -> int:
    initialize_schema(connection)
    count = 0
    now = utc_now()
    with connection:
        for record in records:
            _upsert_record(connection, record, now)
            count += 1
    return count


def add_record_alias(
    connection: sqlite3.Connection,
    alias_record_id: str,
    canonical_record_id: str,
    *,
    reason: str = "identity_upgrade",
) -> None:
    if not alias_record_id or not canonical_record_id:
        raise ValueError("alias and canonical record IDs must not be empty")
    initialize_schema(connection)
    with connection:
        connection.execute(
            """
            INSERT INTO record_aliases(alias_record_id, canonical_record_id, reason, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(alias_record_id) DO UPDATE SET
                canonical_record_id = excluded.canonical_record_id,
                reason = excluded.reason
            """,
            (alias_record_id, canonical_record_id, reason or "identity_upgrade", utc_now()),
        )


def resolve_record_id(connection: sqlite3.Connection, record_id: str) -> str:
    row = connection.execute(
        "SELECT canonical_record_id FROM record_aliases WHERE alias_record_id = ?",
        (record_id,),
    ).fetchone()
    return str(row[0]) if row else record_id


def load_record(
    connection: sqlite3.Connection,
    record_id: str,
    *,
    initialize: bool = True,
) -> CanonicalRecord | None:
    if initialize:
        initialize_schema(connection)
    resolved = resolve_record_id(connection, record_id)
    row = connection.execute(
        "SELECT * FROM canonical_records WHERE record_id = ?",
        (resolved,),
    ).fetchone()
    if row is None:
        return None
    identifier_rows = connection.execute(
        "SELECT * FROM record_identifiers WHERE record_id = ? ORDER BY ordinal",
        (resolved,),
    ).fetchall()
    locator_rows = connection.execute(
        "SELECT * FROM record_locators WHERE record_id = ? ORDER BY ordinal",
        (resolved,),
    ).fetchall()
    provenance_rows = connection.execute(
        "SELECT * FROM record_provenance WHERE record_id = ? ORDER BY ordinal",
        (resolved,),
    ).fetchall()
    return CanonicalRecord(
        schema_version=int(row["contract_schema_version"]),
        record_id=str(row["record_id"]),
        record_type=str(row["record_type"]),  # type: ignore[arg-type]
        metadata=json.loads(str(row["metadata_json"])),
        identifiers=tuple(
            Identifier(
                identifier_type=str(item["identifier_type"]),
                value=str(item["value"]),
                source=str(item["source"]),
                primary=bool(item["is_primary"]),
            )
            for item in identifier_rows
        ),
        locators=tuple(
            Locator(
                kind=str(item["kind"]),
                url=str(item["url"]),
                source=str(item["source"]),
                auth_scope=str(item["auth_scope"]),
                stability=str(item["stability"]),
                observed_at=str(item["observed_at"]),
            )
            for item in locator_rows
        ),
        provenance=tuple(
            Provenance(
                source=str(item["source"]),
                keyword=str(item["keyword"]),
                query_variant=str(item["query_variant"]),
                rank=int(item["rank_value"]) if item["rank_value"] is not None else None,
                path=str(item["path"]),
                raw_id=str(item["raw_id"]),
            )
            for item in provenance_rows
        ),
        retrieval_readiness=str(row["retrieval_readiness"]),  # type: ignore[arg-type]
    )


def iter_records(
    connection: sqlite3.Connection,
    *,
    record_type: str | None = None,
    initialize: bool = True,
) -> Iterator[CanonicalRecord]:
    if initialize:
        initialize_schema(connection)
    if record_type is None:
        rows = connection.execute(
            "SELECT record_id FROM canonical_records ORDER BY record_type, record_id"
        ).fetchall()
    elif record_type in {"literature", "patent"}:
        rows = connection.execute(
            "SELECT record_id FROM canonical_records WHERE record_type = ? ORDER BY record_id",
            (record_type,),
        ).fetchall()
    else:
        raise ValueError(f"Unsupported record_type: {record_type!r}")
    for row in rows:
        record = load_record(
            connection,
            str(row["record_id"]),
            initialize=False,
        )
        if record is not None:
            yield record


def record_count(connection: sqlite3.Connection, *, record_type: str | None = None) -> int:
    initialize_schema(connection)
    if record_type is None:
        row = connection.execute("SELECT COUNT(*) FROM canonical_records").fetchone()
    elif record_type in {"literature", "patent"}:
        row = connection.execute(
            "SELECT COUNT(*) FROM canonical_records WHERE record_type = ?",
            (record_type,),
        ).fetchone()
    else:
        raise ValueError(f"Unsupported record_type: {record_type!r}")
    return int(row[0]) if row else 0


# Adoption aliases for callers that prefer shorter names.
connect_database = connect_canonical_database
initialize_database = initialize_schema


__all__ = [
    "SQLITE_SCHEMA_VERSION",
    "connect_canonical_database",
    "connect_database",
    "current_schema_version",
    "migrate_schema",
    "initialize_schema",
    "initialize_database",
    "open_canonical_store",
    "upsert_record",
    "upsert_records",
    "add_record_alias",
    "resolve_record_id",
    "load_record",
    "iter_records",
    "record_count",
]
