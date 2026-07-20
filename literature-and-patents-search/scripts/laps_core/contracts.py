from __future__ import annotations

"""Canonical v2 handoff contract and deterministic identity helpers."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unicodedata
import urllib.parse
from typing import Any, Iterable, Iterator, Literal, Mapping, Sequence


CANONICAL_SCHEMA_VERSION = 2
LITERATURE_RECORDS_V2_FILENAME = "literature_records.v2.jsonl"
PATENT_RECORDS_V2_FILENAME = "patent_records.v2.jsonl"
HANDOFF_MANIFEST_V2_FILENAME = "handoff_manifest.v2.json"
RecordType = Literal["literature", "patent"]
RetrievalReadiness = Literal[
    "direct_pdf",
    "identifier_resolvable",
    "landing_discoverable",
    "metadata_only",
]

READINESS_VALUES = frozenset(
    {"direct_pdf", "identifier_resolvable", "landing_discoverable", "metadata_only"}
)
DIRECT_PDF_KINDS = frozenset({"direct_pdf", "pdf"})
LANDING_KINDS = frozenset({"landing", "landing_page", "repository", "resolver"})


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return unicodedata.normalize("NFKC", str(value)).strip()


def normalize_doi(value: Any) -> str:
    text = urllib.parse.unquote(_clean(value))
    text = re.sub(r"^(?:doi\s*:\s*|https?://(?:dx\.)?doi\.org/)", "", text, flags=re.I)
    candidate = text.strip().strip("/.,; ").casefold()
    return candidate if re.fullmatch(r"10\.\d{4,9}/\S+", candidate) else ""


def normalize_publication_number(value: Any) -> str:
    text = unicodedata.normalize("NFKC", _clean(value)).upper()
    candidate = re.sub(r"[^A-Z0-9]", "", text)
    return candidate if len(candidate) >= 4 and any(character.isdigit() for character in candidate) else ""


def normalize_http_url(value: Any) -> str:
    text = _clean(value)
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return ""
        scheme = parsed.scheme.casefold()
        host = parsed.hostname.casefold().rstrip(".")
        if ":" in host:
            host = f"[{host}]"
        if parsed.port and not (
            (scheme == "http" and parsed.port == 80)
            or (scheme == "https" and parsed.port == 443)
        ):
            host = f"{host}:{parsed.port}"
        path = urllib.parse.quote(urllib.parse.unquote(parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
        query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query = urllib.parse.urlencode(sorted(query_items), doseq=True)
        return urllib.parse.urlunsplit((scheme, host, path, query, ""))
    except (TypeError, ValueError, UnicodeError):
        return ""


def _normalized_text(value: Any) -> str:
    return re.sub(r"\s+", " ", _clean(value).casefold())


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return str(value)


@dataclass(frozen=True, slots=True)
class Identifier:
    identifier_type: str
    value: str
    source: str = "unknown"
    primary: bool = False

    def __post_init__(self) -> None:
        if not _clean(self.identifier_type):
            raise ValueError("identifier_type must not be empty")
        if not _clean(self.value):
            raise ValueError("identifier value must not be empty")

    @property
    def type(self) -> str:
        return self.identifier_type

    @property
    def normalized_value(self) -> str:
        kind = self.identifier_type.casefold()
        if kind == "doi":
            return normalize_doi(self.value)
        if kind == "publication_number":
            return normalize_publication_number(self.value)
        return _normalized_text(self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.identifier_type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "source": self.source or "unknown",
            "primary": self.primary,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Identifier":
        return cls(
            identifier_type=_clean(value.get("type") or value.get("identifier_type")),
            value=_clean(value.get("value")),
            source=_clean(value.get("source")) or "unknown",
            primary=bool(value.get("primary", False)),
        )


@dataclass(frozen=True, slots=True)
class Locator:
    kind: str
    url: str
    source: str = "unknown"
    auth_scope: str = "unknown"
    stability: str = "unknown"
    observed_at: str = ""

    def __post_init__(self) -> None:
        if not _clean(self.kind):
            raise ValueError("locator kind must not be empty")
        if not _clean(self.url):
            raise ValueError("locator URL must not be empty")

    @property
    def normalized_url(self) -> str:
        return normalize_http_url(self.url) or _clean(self.url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "source": self.source or "unknown",
            "auth_scope": self.auth_scope or "unknown",
            "stability": self.stability or "unknown",
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Locator":
        return cls(
            kind=_clean(value.get("kind")) or "unknown",
            url=_clean(value.get("url")),
            source=_clean(value.get("source")) or "unknown",
            auth_scope=_clean(value.get("auth_scope")) or "unknown",
            stability=_clean(value.get("stability")) or "unknown",
            observed_at=_clean(value.get("observed_at")),
        )


@dataclass(frozen=True, slots=True)
class Provenance:
    source: str
    keyword: str = ""
    query_variant: str = "unknown"
    rank: int | None = None
    path: str = "unknown"
    raw_id: str = ""

    def __post_init__(self) -> None:
        if not _clean(self.source):
            raise ValueError("provenance source must not be empty; use 'unknown'")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source or "unknown",
            "keyword": self.keyword,
            "query_variant": self.query_variant or "unknown",
            "rank": self.rank,
            "path": self.path or "unknown",
            "raw_id": self.raw_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Provenance":
        raw_rank = value.get("rank")
        try:
            rank = int(raw_rank) if raw_rank not in (None, "") else None
        except (TypeError, ValueError):
            rank = None
        return cls(
            source=_clean(value.get("source")) or "unknown",
            keyword=_clean(value.get("keyword")),
            query_variant=_clean(value.get("query_variant")) or "unknown",
            rank=rank,
            path=_clean(value.get("path")) or "unknown",
            raw_id=_clean(value.get("raw_id")),
        )


@dataclass(frozen=True, slots=True)
class CanonicalRecord:
    schema_version: int
    record_id: str
    record_type: RecordType
    metadata: dict[str, Any]
    identifiers: tuple[Identifier, ...]
    locators: tuple[Locator, ...]
    provenance: tuple[Provenance, ...]
    retrieval_readiness: RetrievalReadiness

    def __post_init__(self) -> None:
        if self.schema_version != CANONICAL_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported canonical schema version: {self.schema_version}; "
                f"expected {CANONICAL_SCHEMA_VERSION}"
            )
        if self.record_type not in {"literature", "patent"}:
            raise ValueError(f"Unsupported record_type: {self.record_type!r}")
        if not self.record_id:
            raise ValueError("record_id must not be empty")
        if self.retrieval_readiness not in READINESS_VALUES:
            raise ValueError(f"Unsupported retrieval_readiness: {self.retrieval_readiness!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_id": self.record_id,
            "record_type": self.record_type,
            "metadata": _json_safe(self.metadata),
            "identifiers": [item.to_dict() for item in self.identifiers],
            "locators": [item.to_dict() for item in self.locators],
            "provenance": [item.to_dict() for item in self.provenance],
            "retrieval_readiness": self.retrieval_readiness,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CanonicalRecord":
        metadata = value.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            raise ValueError("metadata must be an object")
        identifiers = _mapping_sequence(value.get("identifiers", ()), "identifiers")
        locators = _mapping_sequence(value.get("locators", ()), "locators")
        provenance = _mapping_sequence(value.get("provenance", ()), "provenance")
        return cls(
            schema_version=int(value.get("schema_version", 0)),
            record_id=_clean(value.get("record_id")),
            record_type=_clean(value.get("record_type")),  # type: ignore[arg-type]
            metadata=dict(_json_safe(metadata)),
            identifiers=tuple(Identifier.from_dict(item) for item in identifiers),
            locators=tuple(Locator.from_dict(item) for item in locators),
            provenance=tuple(Provenance.from_dict(item) for item in provenance),
            retrieval_readiness=_clean(value.get("retrieval_readiness")),  # type: ignore[arg-type]
        )


def _mapping_sequence(value: Any, field_name: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field_name} must be an array")
    if any(not isinstance(item, Mapping) for item in value):
        raise ValueError(f"every {field_name} entry must be an object")
    return tuple(value)


def canonical_records_filename(record_type: RecordType) -> str:
    if record_type == "literature":
        return LITERATURE_RECORDS_V2_FILENAME
    if record_type == "patent":
        return PATENT_RECORDS_V2_FILENAME
    raise ValueError(f"Unsupported record_type: {record_type!r}")


def _preferred_identifier(identifiers: Sequence[Identifier], kind: str) -> Identifier | None:
    matches = [
        identifier
        for identifier in identifiers
        if identifier.identifier_type.casefold() == kind.casefold() and identifier.normalized_value
    ]
    return min(matches, key=lambda item: (not item.primary, item.normalized_value)) if matches else None


def canonical_identity_key(
    record_type: RecordType,
    metadata: Mapping[str, Any],
    identifiers: Sequence[Identifier],
    locators: Sequence[Locator],
    provenance: Sequence[Provenance],
) -> str:
    if record_type == "literature":
        doi = _preferred_identifier(identifiers, "doi")
        if doi:
            return f"literature:doi:{doi.normalized_value}"
        for identifier_type in ("pmcid", "pmid", "arxiv_id"):
            identifier = _preferred_identifier(identifiers, identifier_type)
            if identifier:
                return (
                    f"literature:{identifier_type}:"
                    f"{identifier.normalized_value}"
                )
        stable_pdfs = sorted(
            locator.normalized_url
            for locator in locators
            if locator.kind.casefold() in DIRECT_PDF_KINDS
            and locator.stability.casefold() == "stable"
            and normalize_http_url(locator.url)
        )
        if stable_pdfs:
            return f"literature:pdf:{stable_pdfs[0]}"
    elif record_type == "patent":
        publication = _preferred_identifier(identifiers, "publication_number")
        if publication:
            return f"patent:publication_number:{publication.normalized_value}"
        urls = sorted(
            locator.normalized_url
            for locator in locators
            if normalize_http_url(locator.url)
        )
        if urls:
            return f"patent:url:{urls[0]}"
    else:
        raise ValueError(f"Unsupported record_type: {record_type!r}")

    scoped_raw_ids = sorted(
        (_normalized_text(item.source) or "unknown", _normalized_text(item.raw_id))
        for item in provenance
        if _clean(item.raw_id)
    )
    if scoped_raw_ids:
        source, raw_id = scoped_raw_ids[0]
        return f"{record_type}:source:{source}:raw_id:{raw_id}"

    sources = sorted(
        {_normalized_text(item.source) or "unknown" for item in provenance}
    ) or ["unknown"]
    title = _normalized_text(metadata.get("title") or metadata.get("patent_name"))
    year = _normalized_text(metadata.get("year"))
    if title or year:
        return f"{record_type}:source:{sources[0]}:metadata:{title}|{year}"
    metadata_digest = hashlib.sha256(
        json.dumps(_json_safe(metadata), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{record_type}:source:{sources[0]}:metadata_sha256:{metadata_digest}"


def stable_record_id(
    record_type: RecordType,
    metadata: Mapping[str, Any],
    identifiers: Sequence[Identifier] = (),
    locators: Sequence[Locator] = (),
    provenance: Sequence[Provenance] = (),
) -> str:
    identity = canonical_identity_key(record_type, metadata, identifiers, locators, provenance)
    prefix = "lit" if record_type == "literature" else "pat"
    return f"{prefix}_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]}"


def derive_retrieval_readiness(
    record_type: RecordType,
    identifiers: Sequence[Identifier],
    locators: Sequence[Locator],
) -> RetrievalReadiness:
    if any(locator.kind.casefold() in DIRECT_PDF_KINDS for locator in locators):
        return "direct_pdf"
    if record_type == "literature" and any(
        _preferred_identifier(identifiers, kind)
        for kind in ("doi", "pmid", "pmcid", "arxiv_id")
    ):
        return "identifier_resolvable"
    if record_type == "patent" and _preferred_identifier(identifiers, "publication_number"):
        return "identifier_resolvable"
    if any(locator.kind.casefold() in LANDING_KINDS for locator in locators):
        return "landing_discoverable"
    return "metadata_only"


def make_canonical_record(
    record_type: RecordType,
    metadata: Mapping[str, Any],
    *,
    identifiers: Sequence[Identifier] = (),
    locators: Sequence[Locator] = (),
    provenance: Sequence[Provenance] = (),
    record_id: str = "",
    retrieval_readiness: RetrievalReadiness | None = None,
) -> CanonicalRecord:
    identifier_tuple = tuple(identifiers)
    locator_tuple = tuple(locators)
    provenance_tuple = tuple(provenance)
    safe_metadata = dict(_json_safe(metadata))
    return CanonicalRecord(
        schema_version=CANONICAL_SCHEMA_VERSION,
        record_id=record_id or stable_record_id(
            record_type,
            safe_metadata,
            identifier_tuple,
            locator_tuple,
            provenance_tuple,
        ),
        record_type=record_type,
        metadata=safe_metadata,
        identifiers=identifier_tuple,
        locators=locator_tuple,
        provenance=provenance_tuple,
        retrieval_readiness=retrieval_readiness
        or derive_retrieval_readiness(record_type, identifier_tuple, locator_tuple),
    )


_DOI_KEYS = ("doi", "DOI", "Doi", "article_doi", "paper_doi", "文献DOI", "论文DOI", "数字对象唯一标识符")
_LITERATURE_TITLE_KEYS = ("title", "Title", "article_title", "paper_title", "name", "文献名", "文献标题", "论文名", "论文标题")
_PATENT_TITLE_KEYS = ("patent_name", "title", "Title", "patent_title", "name", "专利名", "专利标题", "名称")
_PUBLICATION_KEYS = ("publication_number", "publication no", "publication_no", "publication", "公开号", "申请号", "专利号")
_SOURCE_KEYS = ("source", "来源")
_KEYWORD_KEYS = ("keyword", "关键词")
_RAW_ID_KEYS = ("raw_id", "source_id", "原始ID")


def _first(row: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in row and _clean(row[key]):
            return row[key]
    return ""


def _legacy_url_items(row: Mapping[str, Any]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, raw in row.items():
        normalized_key = unicodedata.normalize("NFKC", str(key)).casefold()
        if not any(token in normalized_key for token in ("url", "link", "链接")):
            continue
        url = normalize_http_url(raw)
        if url and url not in seen:
            seen.add(url)
            result.append((str(key), url))
    return result


def _legacy_locator_kind(record_type: RecordType, field_name: str, url: str) -> tuple[str, str]:
    key = field_name.casefold()
    parsed = urllib.parse.urlsplit(url)
    volatile_keys = {
        "token", "signature", "sig", "expires", "x-amz-signature",
        "x-amz-credential", "x-amz-security-token", "auth", "authorization",
    }
    query_keys = {name.casefold() for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
    pdf_evidence = "pdf" in key or parsed.path.casefold().endswith(".pdf")
    if pdf_evidence:
        stability = "unknown" if volatile_keys.intersection(query_keys) else "stable"
        return "direct_pdf", stability
    if record_type == "patent":
        return "landing", "unknown"
    return "landing", "unknown"


def canonical_record_from_legacy_row(
    row: Mapping[str, Any],
    record_type: RecordType,
    *,
    source: str = "",
    observed_at: str = "",
    auth_scope: str = "unknown",
) -> CanonicalRecord:
    """Convert without modifying or discarding any legacy field.

    The exact input mapping is retained under ``metadata.legacy_fields``.
    Values that cannot be proven from an explicit legacy field use ``unknown``;
    in particular a generic ``raw_id`` is never guessed to be a DOI,
    publication number, PMCID, PMID, or arXiv identifier.  ``auth_scope`` is
    accepted only as caller-supplied registry evidence for an exact source;
    this converter never guesses it from a URL or title.
    """

    if record_type not in {"literature", "patent"}:
        raise ValueError(f"Unsupported record_type: {record_type!r}")
    legacy_fields = dict(_json_safe(row))
    source_value = _clean(source or _first(row, _SOURCE_KEYS)) or "unknown"
    title_keys = _LITERATURE_TITLE_KEYS if record_type == "literature" else _PATENT_TITLE_KEYS
    title = _clean(_first(row, title_keys))
    metadata: dict[str, Any] = {"legacy_fields": legacy_fields}
    if title:
        metadata["title"] = title
        if record_type == "patent":
            metadata["patent_name"] = title
    for output_key, keys in (
        ("authors", ("authors", "author", "作者")),
        ("year", ("year", "publication_year", "年份", "年")),
        ("journal", ("journal", "container_title", "期刊")),
    ):
        value = _first(row, keys)
        if value not in (None, ""):
            metadata[output_key] = _json_safe(value)

    identifiers: list[Identifier] = []
    if record_type == "literature":
        doi = normalize_doi(_first(row, _DOI_KEYS))
        if doi:
            identifiers.append(Identifier("doi", doi, source_value, primary=True))
        for identifier_type, keys in (
            ("pmcid", ("pmcid", "PMCID", "pmc_id", "PMC")),
            ("pmid", ("pmid", "PMID")),
            ("arxiv_id", ("arxiv_id", "arXiv", "arxiv")),
        ):
            value = _clean(_first(row, keys))
            if value:
                identifiers.append(Identifier(identifier_type, value, source_value))
    else:
        publication_number = normalize_publication_number(_first(row, _PUBLICATION_KEYS))
        if publication_number:
            identifiers.append(Identifier("publication_number", publication_number, source_value, primary=True))

    raw_id = _clean(_first(row, _RAW_ID_KEYS))
    if raw_id:
        identifiers.append(Identifier("raw_id", raw_id, source_value))

    locators = tuple(
        Locator(
            kind=kind,
            url=url,
            source=source_value,
            auth_scope=_clean(auth_scope) or "unknown",
            stability=stability,
            observed_at=observed_at,
        )
        for field_name, url in _legacy_url_items(row)
        for kind, stability in [_legacy_locator_kind(record_type, field_name, url)]
    )
    provenance = (
        Provenance(
            source=source_value,
            keyword=_clean(_first(row, _KEYWORD_KEYS)),
            query_variant="unknown",
            rank=None,
            path="legacy",
            raw_id=raw_id,
        ),
    )
    return make_canonical_record(
        record_type,
        metadata,
        identifiers=identifiers,
        locators=locators,
        provenance=provenance,
    )


legacy_row_to_canonical = canonical_record_from_legacy_row


def canonical_json_dumps(record: CanonicalRecord) -> str:
    return json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def iter_records_jsonl(path: str | os.PathLike[str]) -> Iterator[CanonicalRecord]:
    input_path = Path(path)
    with input_path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, Mapping):
                    raise ValueError("JSONL entry is not an object")
                yield CanonicalRecord.from_dict(value)
            except Exception as exc:
                raise ValueError(f"Invalid canonical JSONL at {input_path}:{line_number}: {exc}") from exc


def read_records_jsonl(path: str | os.PathLike[str]) -> list[CanonicalRecord]:
    return list(iter_records_jsonl(path))


def write_records_jsonl(
    path: str | os.PathLike[str],
    records: Iterable[CanonicalRecord],
    *,
    atomic: bool = True,
) -> int:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    count = 0
    try:
        if atomic:
            descriptor, temp_name = tempfile.mkstemp(
                prefix=f".{output_path.name}.",
                suffix=".tmp",
                dir=str(output_path.parent),
            )
            os.close(descriptor)
            temp_path = Path(temp_name)
            destination = temp_path
        else:
            destination = output_path
        with destination.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                if not isinstance(record, CanonicalRecord):
                    raise TypeError(f"Expected CanonicalRecord, got {type(record).__name__}")
                handle.write(canonical_json_dumps(record))
                handle.write("\n")
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
        if atomic and temp_path is not None:
            os.replace(temp_path, output_path)
            temp_path = None
        return count
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


__all__ = [
    "CANONICAL_SCHEMA_VERSION",
    "LITERATURE_RECORDS_V2_FILENAME",
    "PATENT_RECORDS_V2_FILENAME",
    "HANDOFF_MANIFEST_V2_FILENAME",
    "READINESS_VALUES",
    "Identifier",
    "Locator",
    "Provenance",
    "CanonicalRecord",
    "normalize_doi",
    "normalize_publication_number",
    "normalize_http_url",
    "canonical_records_filename",
    "canonical_identity_key",
    "stable_record_id",
    "derive_retrieval_readiness",
    "make_canonical_record",
    "canonical_record_from_legacy_row",
    "legacy_row_to_canonical",
    "canonical_json_dumps",
    "iter_records_jsonl",
    "read_records_jsonl",
    "write_records_jsonl",
]
