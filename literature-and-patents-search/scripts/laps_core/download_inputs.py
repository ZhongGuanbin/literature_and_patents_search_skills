from __future__ import annotations

"""Read-only adapters from canonical-v2 or legacy CSV download inputs.

The adapter deliberately does not create or replace a canonical JSONL file when a
legacy CSV is selected.  It projects each legacy row in memory and records that
fact in a migration report; callers may persist that report as audit evidence.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import codecs
import csv
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Iterator, Literal, Mapping, Sequence, cast

from .contracts import (
    CANONICAL_SCHEMA_VERSION,
    HANDOFF_MANIFEST_V2_FILENAME,
    CanonicalRecord,
    Identifier,
    Locator,
    Provenance,
    RecordType,
    canonical_json_dumps,
    canonical_record_from_legacy_row,
    iter_records_jsonl,
    make_canonical_record,
    normalize_doi,
    normalize_http_url,
    normalize_publication_number,
)
from .handoff import (
    CANONICAL_DATABASE_V2_FILENAME,
    ValidatedHandoffBundle,
    assert_no_uncommitted_schema2_handoff,
    validate_handoff_bundle,
)


InputContract = Literal["auto", "v2", "legacy"]
ResolvedContract = Literal["v2", "legacy", "legacy_sqlite"]
INPUT_CONTRACT_VALUES = frozenset({"auto", "v2", "legacy"})
MIGRATION_REPORT_SCHEMA_VERSION = 2
_CSV_ENCODINGS = ("utf-8-sig", "utf-8", "gb18030")
_DIRECT_PDF_KINDS = frozenset({"direct_pdf", "pdf"})


def _handoff_contract_for_v2(
    path: Path,
    record_type: RecordType,
) -> tuple[
    dict[str, tuple[str, ...]],
    dict[str, Any],
    tuple[CanonicalRecord, ...],
    ValidatedHandoffBundle,
]:
    """Validate the whole sibling bundle and return an immutable type view."""

    bundle = validate_handoff_bundle(path, record_type)
    aliases = (
        bundle.aliases_for_target(record_type)
        if bundle.binding_status == "bound"
        else {}
    )
    return (
        aliases,
        dict(bundle.evidence),
        bundle.records_for(record_type),
        bundle,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_evidence(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": _sha256_file(path),
    }


def _validate_record_type(record_type: str) -> RecordType:
    normalized = str(record_type).strip().casefold()
    if normalized not in {"literature", "patent"}:
        raise ValueError("record_type must be 'literature' or 'patent'")
    return cast(RecordType, normalized)


def _validate_contract(input_contract: str) -> InputContract:
    normalized = str(input_contract).strip().casefold()
    if normalized not in INPUT_CONTRACT_VALUES:
        raise ValueError("input_contract must be one of: auto, v2, legacy")
    return cast(InputContract, normalized)


def _source_auth_scope(record_type: RecordType, source: str) -> str:
    """Use only an exact shared-registry source match; never infer a scope."""
    from .registry import get_search_adapters

    normalized = str(source or "").strip().casefold()
    matches = [
        spec.auth_scope
        for spec in get_search_adapters(record_type)
        if spec.display_name.casefold() == normalized
    ]
    return matches[0] if len(matches) == 1 else "unknown"


def _ordered_sources(record: CanonicalRecord) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    def append(value: Any) -> None:
        if isinstance(value, (list, tuple)):
            for item in value:
                append(item)
            return
        text = str(value or "").strip() or "unknown"
        marker = text.casefold()
        if marker not in seen:
            seen.add(marker)
            result.append(text)

    if "metadata_sources" in record.metadata:
        append(record.metadata.get("metadata_sources"))
    for provenance in record.provenance:
        append(provenance.source)
    for identifier in record.identifiers:
        append(identifier.source)
    for locator in record.locators:
        append(locator.source)
    return result or ["unknown"]


def _preferred_identifier(identifiers: Sequence[Identifier], kind: str) -> str:
    matches: list[tuple[bool, int, str]] = []
    for index, identifier in enumerate(identifiers):
        if identifier.identifier_type.casefold() != kind.casefold():
            continue
        if kind.casefold() == "doi":
            normalized = normalize_doi(identifier.value)
        elif kind.casefold() == "publication_number":
            normalized = normalize_publication_number(identifier.value)
        else:
            normalized = str(identifier.value).strip()
        if normalized:
            matches.append((not identifier.primary, index, normalized))
    return min(matches)[2] if matches else ""


def _preferred_locator(
    locators: Sequence[Locator],
    *,
    direct_pdf_only: bool,
) -> str:
    matches: list[tuple[int, int, int, str]] = []
    for index, locator in enumerate(locators):
        # Use normalization only as an HTTP(S) validity check.  Return the
        # observed URL byte-for-byte (apart from surrounding whitespace):
        # reordering or requoting a signed query can invalidate the locator.
        observed_url = str(locator.url).strip()
        if not normalize_http_url(observed_url):
            continue
        kind = locator.kind.casefold()
        direct_pdf = kind in _DIRECT_PDF_KINDS
        if direct_pdf_only and not direct_pdf:
            continue
        # A declared direct PDF is more useful to the planner than a landing
        # page.  Within that group, preserve stable locators before unknown or
        # volatile locators and otherwise preserve canonical input order.
        matches.append(
            (
                0 if direct_pdf else 1,
                0 if locator.stability.casefold() == "stable" else 1,
                index,
                observed_url,
            )
        )
    return min(matches)[3] if matches else ""


def _identifier_value(record: CanonicalRecord, *kinds: str) -> str:
    for kind in kinds:
        value = _preferred_identifier(record.identifiers, kind)
        if value:
            return value
    return ""


def canonical_record_to_planner_row(record: CanonicalRecord) -> dict[str, Any]:
    """Conservatively flatten a v2 record without discarding rich fields.

    ``_canonical_record`` is an ordinary JSON-safe mapping so the row can cross
    process boundaries.  The typed arrays are also exposed individually for a
    planner that wants to retain locator/auth provenance while legacy scalar
    aliases keep the existing download implementation usable.
    """

    canonical = record.to_dict()
    legacy_fields = record.metadata.get("legacy_fields")
    row: dict[str, Any] = dict(legacy_fields) if isinstance(legacy_fields, Mapping) else {}

    for key, value in record.metadata.items():
        if key == "legacy_fields" or key in row:
            continue
        if value is None or isinstance(value, (str, int, float, bool)):
            row[key] = value

    identifiers = [item.to_dict() for item in record.identifiers]
    locators = [item.to_dict() for item in record.locators]
    provenance = [item.to_dict() for item in record.provenance]
    metadata_sources = _ordered_sources(record)

    row.update(
        {
            "schema_version": record.schema_version,
            "record_id": record.record_id,
            "record_type": record.record_type,
            "retrieval_readiness": record.retrieval_readiness,
            "metadata": dict(record.metadata),
            "identifiers": identifiers,
            "locators": locators,
            "provenance": provenance,
            "metadata_sources": metadata_sources,
            "metadata_sources_json": json.dumps(metadata_sources, ensure_ascii=False),
            "locator_urls": [item["url"] for item in locators],
            "_canonical_record": canonical,
            "_canonical_record_json": canonical_json_dumps(record),
        }
    )

    title = str(
        record.metadata.get("title")
        or record.metadata.get("patent_name")
        or row.get("title")
        or row.get("patent_name")
        or ""
    ).strip()
    if title:
        row["title"] = title

    # Several formal download adapters consume a provider-scoped raw ID
    # (OpenReview, IACR, DBLP, CORE and OpenAIRE).  Keep the typed value
    # available through the legacy scalar alias used by those parsers; the
    # complete typed identifier remains preserved in ``identifiers`` above.
    raw_id = _identifier_value(record, "raw_id")
    if raw_id:
        row["raw_id"] = raw_id
        row["source_id"] = raw_id

    if record.record_type == "literature":
        doi = _preferred_identifier(record.identifiers, "doi")
        direct_pdf_url = _preferred_locator(record.locators, direct_pdf_only=True)
        if doi:
            row["doi"] = doi
            row["DOI"] = doi
        # Do not blank a legacy URL which could not be proven to be a direct
        # PDF during conservative migration.  Its original value remains in
        # legacy_fields, while canonical locators retain the uncertainty.
        if direct_pdf_url:
            row["url"] = direct_pdf_url
            row["URL"] = direct_pdf_url
            row["pdf_url"] = direct_pdf_url
        for identifier_type, aliases in (
            ("pmcid", ("pmcid", "PMCID")),
            ("pmid", ("pmid", "PMID")),
            ("arxiv_id", ("arxiv_id", "arXiv")),
        ):
            value = _identifier_value(record, identifier_type)
            if value:
                for alias in aliases:
                    row[alias] = value
    else:
        publication_number = _preferred_identifier(record.identifiers, "publication_number")
        best_url = _preferred_locator(record.locators, direct_pdf_only=False)
        if title:
            row["patent_name"] = title
        if publication_number:
            row["publication_number"] = publication_number
        if best_url:
            row["url"] = best_url
            row["URL"] = best_url

    return row


def _select_csv_encoding(path: Path) -> str:
    last_error: UnicodeDecodeError | None = None
    for encoding in _CSV_ENCODINGS:
        decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
        try:
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    decoder.decode(block, final=False)
                decoder.decode(b"", final=True)
            return encoding
        except UnicodeDecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return "utf-8-sig"


@dataclass(slots=True)
class ResolvedInputContract:
    requested_contract: InputContract
    resolved_contract: ResolvedContract
    record_type: RecordType
    source_path: Path
    v2_path: Path
    legacy_csv_path: Path
    legacy_sqlite_path: Path | None = None
    record_aliases: dict[str, tuple[str, ...]] = field(default_factory=dict)
    migration_report: dict[str, Any] = field(default_factory=dict)
    records_snapshot: tuple[CanonicalRecord, ...] | None = None

    @property
    def input_contract(self) -> ResolvedContract:
        """Alias convenient for CLI/report integration."""

        return self.resolved_contract

    def iter_records(self) -> Iterator[CanonicalRecord]:
        records_read = 0
        converted = 0
        if self.resolved_contract == "v2":
            try:
                source_records = (
                    self.records_snapshot
                    if self.records_snapshot is not None
                    else iter_records_jsonl(self.source_path)
                )
                for record in source_records:
                    records_read += 1
                    if record.record_type != self.record_type:
                        raise ValueError(
                            f"Canonical record {record.record_id!r} has record_type "
                            f"{record.record_type!r}; expected {self.record_type!r}"
                        )
                    converted += 1
                    yield record
            finally:
                self.migration_report["records_read"] = records_read
                self.migration_report["records_converted"] = 0
            return

        if self.resolved_contract == "legacy_sqlite":
            try:
                yield from self._iter_legacy_sqlite_records()
            finally:
                self.migration_report["records_read"] = int(
                    self.migration_report.get("records_read") or 0
                )
                self.migration_report["records_converted"] = int(
                    self.migration_report.get("records_converted") or 0
                )
            return

        encoding = _select_csv_encoding(self.source_path)
        self.migration_report["source_encoding"] = encoding
        try:
            with self.source_path.open("r", encoding=encoding, newline="") as handle:
                reader = csv.DictReader(handle)
                if reader.fieldnames is None:
                    raise ValueError(f"Legacy CSV has no header: {self.source_path}")
                for row in reader:
                    records_read += 1
                    legacy_row = {
                        str(key): "" if value is None else str(value)
                        for key, value in row.items()
                        if key is not None
                    }
                    source_value = str(
                        legacy_row.get("source")
                        or legacy_row.get("来源")
                        or "unknown"
                    ).strip() or "unknown"
                    try:
                        record = canonical_record_from_legacy_row(
                            legacy_row,
                            self.record_type,
                            source=source_value,
                            auth_scope=_source_auth_scope(
                                self.record_type,
                                source_value,
                            ),
                        )
                    except Exception as exc:
                        raise ValueError(
                            f"Invalid legacy CSV row at {self.source_path}:{reader.line_num}: {exc}"
                        ) from exc
                    converted += 1
                    yield record
        finally:
            self.migration_report["records_read"] = records_read
            self.migration_report["records_converted"] = converted

    def _iter_legacy_sqlite_records(self) -> Iterator[CanonicalRecord]:
        """Read old search occurrence state without opening it for writes."""
        connection = sqlite3.connect(
            f"file:{self.source_path.as_posix()}?mode=ro",
            uri=True,
            timeout=10,
        )
        connection.row_factory = sqlite3.Row
        # Keep schema inspection and the full occurrence scan on one immutable
        # read snapshot.  This is also the logical input used by the download
        # run fingerprint; concurrent search writes cannot produce a mixed view.
        connection.execute("BEGIN")
        records_read = 0
        converted = 0
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "occurrences" not in tables:
                raise ValueError(
                    f"Legacy search SQLite has no occurrences table: {self.source_path}"
                )
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(occurrences)")
            }
            required = {"record_type", "payload_json"}
            if not required.issubset(columns):
                raise ValueError(
                    "Legacy search SQLite occurrences table is missing required columns: "
                    + ", ".join(sorted(required - columns))
                )

            def selected(column: str, default_sql: str) -> str:
                return column if column in columns else f"{default_sql} AS {column}"

            query = (
                "SELECT payload_json, "
                + selected("keyword", "''")
                + ", "
                + selected("source", "'unknown'")
                + ", "
                + selected("rank_value", "NULL")
                + ", "
                + selected("provenance_json", "'[]'")
                + ", "
                + selected("updated_at", "''")
                + " FROM occurrences WHERE record_type=? ORDER BY rowid"
            )
            for row in connection.execute(query, (self.record_type,)):
                records_read += 1
                try:
                    payload = json.loads(str(row["payload_json"] or "{}"))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid legacy SQLite payload at occurrence {records_read}: {exc}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise ValueError(
                        f"Invalid legacy SQLite payload at occurrence {records_read}: expected object"
                    )
                legacy_row = dict(payload)
                legacy_row.setdefault("source", str(row["source"] or "unknown"))
                legacy_row.setdefault("keyword", str(row["keyword"] or ""))
                nested_identifiers = payload.get("identifiers")
                if isinstance(nested_identifiers, Mapping):
                    for kind in ("pmcid", "pmid", "arxiv_id"):
                        value = str(nested_identifiers.get(kind) or "").strip()
                        if value:
                            legacy_row.setdefault(kind, value)

                source_value = str(row["source"] or "unknown")
                auth_scope = _source_auth_scope(self.record_type, source_value)
                base = canonical_record_from_legacy_row(
                    legacy_row,
                    self.record_type,
                    source=source_value,
                    observed_at=str(row["updated_at"] or ""),
                    auth_scope=auth_scope,
                )
                provenance = list(base.provenance)
                locators = list(base.locators)
                seen_locator_urls = {locator.normalized_url for locator in locators}
                try:
                    observations = json.loads(str(row["provenance_json"] or "[]"))
                except json.JSONDecodeError:
                    observations = []
                if isinstance(observations, list):
                    for observation in observations:
                        if not isinstance(observation, Mapping):
                            continue
                        provenance.append(
                            Provenance(
                                source=str(row["source"] or "unknown"),
                                keyword=str(row["keyword"] or ""),
                                query_variant=str(
                                    observation.get("query_variant") or "unknown"
                                ),
                                rank=(
                                    int(observation["rank"])
                                    if observation.get("rank") is not None
                                    else int(row["rank_value"])
                                    if row["rank_value"] is not None
                                    else None
                                ),
                                path=str(observation.get("path") or "unknown"),
                                raw_id=str(
                                    observation.get("raw_id")
                                    or payload.get("raw_id")
                                    or ""
                                ),
                            )
                        )
                observed_locator_values: list[tuple[str, str]] = [
                    (str(payload.get("raw_id") or ""), str(row["updated_at"] or ""))
                ]
                if isinstance(observations, list):
                    observed_locator_values.extend(
                        (
                            str(observation.get("locator_url") or observation.get("raw_id") or ""),
                            str(observation.get("observed_at") or row["updated_at"] or ""),
                        )
                        for observation in observations
                        if isinstance(observation, Mapping)
                    )
                for locator_value, observed_at in observed_locator_values:
                    normalized_locator = normalize_http_url(locator_value)
                    if not normalized_locator or normalized_locator in seen_locator_urls:
                        continue
                    # Legacy occurrence evidence does not prove that an HTTP
                    # detail URL is a PDF.  Preserve it conservatively as a
                    # landing locator and let the provider parser discover a
                    # PDF under the exact registry auth scope.
                    locators.append(
                        Locator(
                            kind="landing",
                            url=locator_value.strip(),
                            source=source_value,
                            auth_scope=auth_scope,
                            stability="unknown",
                            observed_at=observed_at,
                        )
                    )
                    seen_locator_urls.add(normalized_locator)
                record = make_canonical_record(
                    self.record_type,
                    base.metadata,
                    identifiers=base.identifiers,
                    locators=locators,
                    provenance=provenance,
                )
                converted += 1
                self.migration_report["records_read"] = records_read
                self.migration_report["records_converted"] = converted
                yield record
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    def iter_rows(self) -> Iterator[dict[str, Any]]:
        for record in self.iter_records():
            row = canonical_record_to_planner_row(record)
            aliases = self.record_aliases.get(record.record_id, ())
            if aliases:
                row["_record_aliases"] = list(aliases)
                row["_record_aliases_json"] = json.dumps(aliases, ensure_ascii=False)
            yield row

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return self.iter_rows()


@dataclass(slots=True)
class ResolvedInputBundle:
    """A set of input contracts backed by one validated handoff snapshot."""

    requested_contract: InputContract
    contracts: dict[RecordType, ResolvedInputContract]
    handoff_evidence: dict[str, Any] = field(default_factory=dict)

    def contract_for(self, record_type: RecordType | str) -> ResolvedInputContract:
        normalized = _validate_record_type(str(record_type))
        try:
            return self.contracts[normalized]
        except KeyError as exc:
            raise KeyError(f"record type {normalized!r} was not requested") from exc

    def records_for(self, record_type: RecordType | str) -> tuple[CanonicalRecord, ...]:
        return tuple(self.contract_for(record_type).iter_records())


def _v2_report(
    *,
    requested: InputContract,
    record_type: RecordType,
    source_path: Path,
    aliases: Mapping[str, Sequence[str]],
    handoff_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "report_schema_version": MIGRATION_REPORT_SCHEMA_VERSION,
        "canonical_schema_version": CANONICAL_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "requested_contract": requested,
        "resolved_contract": "v2",
        "record_type": record_type,
        "non_destructive": True,
        "source": _source_evidence(source_path),
        "records_read": 0,
        "records_converted": 0,
        "unknown_value_policy": (
            "Unprovable values remain unknown; identifiers and locator "
            "capabilities are not guessed."
        ),
        "operation": "none",
        "read_only_source": False,
        "source_modified": False,
        "canonical_jsonl_created": False,
        "record_alias_count": sum(len(values) for values in aliases.values()),
        "handoff_manifest": dict(handoff_evidence),
    }


def _contract_from_validated_bundle(
    *,
    requested: InputContract,
    record_type: RecordType,
    v2_path: Path,
    legacy_csv_path: Path,
    legacy_sqlite_path: Path | None,
    bundle: ValidatedHandoffBundle,
) -> ResolvedInputContract:
    aliases = (
        bundle.aliases_for_target(record_type)
        if bundle.binding_status == "bound"
        else {}
    )
    evidence = dict(bundle.evidence)
    return ResolvedInputContract(
        requested_contract=requested,
        resolved_contract="v2",
        record_type=record_type,
        source_path=v2_path,
        v2_path=v2_path,
        legacy_csv_path=legacy_csv_path,
        legacy_sqlite_path=legacy_sqlite_path,
        record_aliases=aliases,
        migration_report=_v2_report(
            requested=requested,
            record_type=record_type,
            source_path=v2_path,
            aliases=aliases,
            handoff_evidence=evidence,
        ),
        records_snapshot=bundle.records_for(record_type),
    )


def resolve_input_contract(
    input_contract: InputContract | str,
    record_type: RecordType | str,
    v2_path: str | os.PathLike[str],
    legacy_csv_path: str | os.PathLike[str],
    legacy_sqlite_path: str | os.PathLike[str] | None = None,
) -> ResolvedInputContract:
    """Resolve an input source without mutating either candidate path.

    ``auto`` prefers an existing v2 JSONL even when the legacy CSV also exists.
    Explicit modes fail closed when their requested file is absent.
    """

    requested = _validate_contract(str(input_contract))
    normalized_type = _validate_record_type(str(record_type))
    canonical_path = Path(v2_path).expanduser().resolve()
    legacy_path = Path(legacy_csv_path).expanduser().resolve()
    legacy_database_path = (
        Path(legacy_sqlite_path).expanduser().resolve()
        if legacy_sqlite_path is not None
        else None
    )

    if requested != "legacy":
        sibling_canonical_database = (
            canonical_path.parent / CANONICAL_DATABASE_V2_FILENAME
        )
        if sibling_canonical_database.is_file():
            assert_no_uncommitted_schema2_handoff(
                canonical_path.parent,
            )
    formal_manifest_present = (
        canonical_path.parent / HANDOFF_MANIFEST_V2_FILENAME
    ).is_file()
    if requested == "v2":
        resolved: ResolvedContract = "v2"
        selected = canonical_path
    elif requested == "legacy":
        if legacy_path.is_file():
            resolved = "legacy"
            selected = legacy_path
        else:
            resolved = "legacy_sqlite"
            selected = legacy_database_path or legacy_path
    elif formal_manifest_present or canonical_path.is_file():
        resolved = "v2"
        selected = canonical_path
    elif legacy_database_path is not None and legacy_database_path.is_file():
        resolved = "legacy_sqlite"
        selected = legacy_database_path
    else:
        resolved = "legacy"
        selected = legacy_path

    if not selected.is_file():
        if requested == "auto":
            raise FileNotFoundError(
                "No download input found: canonical v2 path "
                f"{canonical_path}, legacy SQLite path {legacy_database_path}, "
                f"and legacy CSV path {legacy_path} are all missing"
            )
        raise FileNotFoundError(f"Requested {resolved} download input does not exist: {selected}")

    report: dict[str, Any] = {
        "report_schema_version": MIGRATION_REPORT_SCHEMA_VERSION,
        "canonical_schema_version": CANONICAL_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "requested_contract": requested,
        "resolved_contract": resolved,
        "record_type": normalized_type,
        "non_destructive": True,
        "source": _source_evidence(selected),
        "records_read": 0,
        "records_converted": 0,
        "unknown_value_policy": "Unprovable values remain unknown; identifiers and locator capabilities are not guessed.",
        "operation": (
            "none"
            if resolved == "v2"
            else "legacy_search_sqlite_to_canonical_v2_in_memory"
            if resolved == "legacy_sqlite"
            else "legacy_csv_to_canonical_v2_in_memory"
        ),
        "read_only_source": resolved == "legacy_sqlite",
        "source_modified": False,
        "canonical_jsonl_created": False,
    }
    records_snapshot: tuple[CanonicalRecord, ...] | None = None
    if resolved == "v2":
        (
            record_aliases,
            handoff_evidence,
            records_snapshot,
            _,
        ) = _handoff_contract_for_v2(
            selected,
            normalized_type,
        )
    else:
        record_aliases, handoff_evidence = {}, {"present": False, "validated": False}
    report["record_alias_count"] = sum(len(values) for values in record_aliases.values())
    report["handoff_manifest"] = handoff_evidence
    return ResolvedInputContract(
        requested_contract=requested,
        resolved_contract=resolved,
        record_type=normalized_type,
        source_path=selected,
        v2_path=canonical_path,
        legacy_csv_path=legacy_path,
        legacy_sqlite_path=legacy_database_path,
        record_aliases=record_aliases,
        migration_report=report,
        records_snapshot=records_snapshot,
    )


def resolve_input_bundle(
    input_contract: InputContract | str,
    literature_v2_path: str | os.PathLike[str],
    patent_v2_path: str | os.PathLike[str],
    literature_legacy_csv_path: str | os.PathLike[str],
    patent_legacy_csv_path: str | os.PathLike[str],
    legacy_sqlite_path: str | os.PathLike[str] | None = None,
    *,
    record_types: Sequence[RecordType | str] = ("literature", "patent"),
) -> ResolvedInputBundle:
    """Resolve selected inputs, validating a formal v2 handoff exactly once.

    Mixed standalone-v2/legacy inputs retain the existing per-type resolution
    behavior. A sibling formal manifest is always consumed as a bundle, so a
    caller can never observe literature and patents from different generations.
    """

    requested = _validate_contract(str(input_contract))
    selected_types: list[RecordType] = []
    for raw_type in record_types:
        normalized = _validate_record_type(str(raw_type))
        if normalized not in selected_types:
            selected_types.append(normalized)
    if not selected_types:
        raise ValueError("record_types must contain literature and/or patent")

    v2_paths: dict[RecordType, Path] = {
        "literature": Path(literature_v2_path).expanduser().resolve(),
        "patent": Path(patent_v2_path).expanduser().resolve(),
    }
    legacy_paths: dict[RecordType, Path] = {
        "literature": Path(literature_legacy_csv_path).expanduser().resolve(),
        "patent": Path(patent_legacy_csv_path).expanduser().resolve(),
    }
    legacy_database_path = (
        Path(legacy_sqlite_path).expanduser().resolve()
        if legacy_sqlite_path is not None
        else None
    )

    formal_root: Path | None = None
    roots = {v2_paths[record_type].parent for record_type in selected_types}
    if len(roots) == 1:
        candidate_root = next(iter(roots))
        if (candidate_root / HANDOFF_MANIFEST_V2_FILENAME).is_file():
            formal_root = candidate_root

    contracts: dict[RecordType, ResolvedInputContract] = {}
    shared_evidence: dict[str, Any] = {}
    should_use_formal = (
        formal_root is not None
        and requested != "legacy"
    )
    if should_use_formal:
        first_type = selected_types[0]
        validated = validate_handoff_bundle(
            v2_paths[first_type],
            first_type,
        )
        shared_evidence = dict(validated.evidence)
        for record_type in selected_types:
            contracts[record_type] = _contract_from_validated_bundle(
                requested=requested,
                record_type=record_type,
                v2_path=v2_paths[record_type],
                legacy_csv_path=legacy_paths[record_type],
                legacy_sqlite_path=legacy_database_path,
                bundle=validated,
            )
    else:
        for record_type in selected_types:
            contracts[record_type] = resolve_input_contract(
                requested,
                record_type,
                v2_paths[record_type],
                legacy_paths[record_type],
                legacy_database_path,
            )
        handoff_evidence = {
            record_type: contracts[record_type].migration_report.get(
                "handoff_manifest",
                {},
            )
            for record_type in selected_types
        }
        shared_evidence = {
            "binding_status": "mixed_or_per_type",
            "per_type": handoff_evidence,
        }
    return ResolvedInputBundle(
        requested_contract=requested,
        contracts=contracts,
        handoff_evidence=shared_evidence,
    )


def write_json_atomic(path: str | os.PathLike[str], payload: Mapping[str, Any]) -> Path:
    """Write a JSON object with flush/fsync followed by same-directory replace."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=str(output_path.parent)
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(dict(payload), handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, output_path)
        return output_path
    finally:
        temp_path.unlink(missing_ok=True)


def write_migration_report_atomic(
    path: str | os.PathLike[str],
    resolved: ResolvedInputContract | Mapping[str, Any],
) -> Path:
    report = resolved.migration_report if isinstance(resolved, ResolvedInputContract) else resolved
    return write_json_atomic(path, report)


__all__ = [
    "INPUT_CONTRACT_VALUES",
    "MIGRATION_REPORT_SCHEMA_VERSION",
    "InputContract",
    "ResolvedContract",
    "ResolvedInputBundle",
    "ResolvedInputContract",
    "canonical_record_to_planner_row",
    "resolve_input_bundle",
    "resolve_input_contract",
    "write_json_atomic",
    "write_migration_report_atomic",
]
