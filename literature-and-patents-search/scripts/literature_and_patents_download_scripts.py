from __future__ import annotations

import argparse
import csv
import email.utils
import errno
import hashlib
import hmac
import html
import http.client
import ipaddress
import importlib
import json
import logging
import os
import random
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter, OrderedDict, defaultdict
from contextlib import closing, contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from threading import BoundedSemaphore, Event, Lock, RLock, Thread, current_thread, local
from typing import Any, Callable, Iterator, Mapping

# Keep --status, --channel-inventory, and --help filesystem-read-only even when
# the installed Skill has no pre-existing bytecode cache.
sys.dont_write_bytecode = True

SCRIPT_IMPORT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_IMPORT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_IMPORT_DIR))

from laps_core import (
    AuthControlStore,
    CANONICAL_SCHEMA_VERSION,
    HANDOFF_MANIFEST_SCHEMA,
    HANDOFF_MANIFEST_VERSION,
    REGISTRY_SCHEMA_VERSION,
    REGISTRY_VERSION,
    WorkflowStatus,
    auth_scope_key,
    build_auth_state_attestation_v2,
    build_verification_request,
    held_auth_scope_lease,
    get_download_adapters,
    get_search_adapters,
    locator_requirements_satisfied,
    normalize_doi as normalize_contract_doi,
    outbound_host_is_public as shared_outbound_host_is_public,
    outbound_http_url_allowed as shared_outbound_http_url_allowed,
    outbound_http_url_syntax_allowed as shared_outbound_http_url_syntax_allowed,
    registry_snapshot,
    read_verification_response,
    resolve_input_bundle,
    resolve_input_contract,
    status_to_exit_code,
    validate_auth_state_attestation_v2,
    validate_verification_response,
    validate_registry,
    verification_file_audit_evidence,
    write_json_atomic,
)
import laps_core.environment as shared_environment


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


configure_stdio()


SCRIPT_PATH = Path(__file__).resolve()
ROOT_DIR = SCRIPT_PATH.parents[1]
SCRIPTS_DIR = ROOT_DIR / "scripts"
TOOLS_DIR = ROOT_DIR / "tools"
PYTHON_PACKAGES_DIR = TOOLS_DIR / "python_packages"
PLAYWRIGHT_BROWSERS_DIR = TOOLS_DIR / "playwright-browsers"
LEGACY_PLAYWRIGHT_BROWSERS_DIR = TOOLS_DIR / "ms-playwright"
SEARCH_SCRIPT_PATH = SCRIPTS_DIR / "literature_and_patents_search_scripts.py"
RUNTIME_CONFIG_FILENAME = "literature_and_patents_search_scripts.json"
RUNTIME_CONFIG_ENV_NAMES = ("LAPS_RUNTIME_CONFIG", "LAPS_AUTH_CONFIG")
USER_CONFIG_DIR = Path.home() / ".config" / "literature-and-patents-search-skills"
CONFIG_PATH = USER_CONFIG_DIR / RUNTIME_CONFIG_FILENAME

METADATA_ROOT = ROOT_DIR / "literature_and_patents_metadata_list"
LITERATURE_METADATA_CSV = METADATA_ROOT / "literature_metadata_list" / "literature_metadata_list.csv"
PATENTS_METADATA_CSV = METADATA_ROOT / "patents_metadata_list" / "patents_metadata_list.csv"

PDF_ROOT = ROOT_DIR / "literature_and_patents_pdf"
LITERATURE_PDF_DIR = PDF_ROOT / "literature_pdf"
PATENTS_PDF_DIR = PDF_ROOT / "patents_pdf"
OUTPUTS_DIR = PDF_ROOT / "outputs"
DOWNLOAD_AUTH_STATE_DIR = OUTPUTS_DIR / "auth_state"
SHARED_AUTH_STATE_DIR = TOOLS_DIR / "auth_state"

CNKI_SOURCE = "CNKI (中国知网)"
WANFANG_SOURCE = "万方数据"
UYANIP_SOURCE = "度衍"
CNKI_HOME = "https://www.cnki.net/"
CNKI_FSSO_HOME = "https://fsso.cnki.net/"
CNKI_PATENT_HOME = "https://kns.cnki.net/res/category/patent"
WANFANG_HOME = "https://c.wanfangdata.com.cn/"
WANFANG_FSSO_HOME = "https://fsso.wanfangdata.com.cn/"
WANFANG_PATENT_HOME = "https://c.wanfangdata.com.cn/patent"
UYANIP_HOME = "https://www.uyanip.com/"
UYANIP_CREDENTIAL_ALLOWED_HOSTS = frozenset({"uyanip.com", "api.duyandb.com"})
UYANIP_INVALID_CREDENTIAL_MARKERS = (
    "账号或密码错误",
    "用户名或密码错误",
    "账户或密码错误",
    "账号不存在",
    "密码不正确",
    "invalid credentials",
    "incorrect password",
)
UYANIP_AUTHENTICATED_MARKERS = ("退出登录", "我的度衍", "logout")
UYANIP_POST_LOGIN_MARKERS = (*UYANIP_AUTHENTICATED_MARKERS, "个人中心")


def local_repository_root() -> Path:
    return ROOT_DIR.parent if ROOT_DIR.name == "literature_and_patents_search_skills" else ROOT_DIR


def ensure_local_git_repository(logger: logging.Logger | None = None) -> dict[str, Any]:
    repo_root = local_repository_root()
    if (repo_root / ".git").exists():
        return {"enabled": True, "status": "existing", "root": str(repo_root)}
    git_exe = shutil.which("git")
    if not git_exe:
        return {"enabled": False, "status": "git_not_found", "root": str(repo_root)}
    try:
        completed = subprocess.run(
            [git_exe, "init"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:
        status = f"git_init_failed:{exc.__class__.__name__}"
        if logger:
            logger.info("Local git repository initialization skipped: %s", status)
        return {"enabled": False, "status": status, "root": str(repo_root)}
    if completed.returncode != 0:
        status = f"git_init_exit_{completed.returncode}"
        if logger:
            logger.info("Local git repository initialization failed: %s", (completed.stderr or status).strip()[:500])
        return {"enabled": False, "status": status, "root": str(repo_root)}
    if logger:
        logger.info("Initialized local git repository at %s", repo_root)
    return {"enabled": True, "status": "initialized", "root": str(repo_root)}


def git_repository_snapshot() -> dict[str, Any]:
    repo_root = local_repository_root()
    return {
        "root": str(repo_root),
        "git_available": bool(shutil.which("git")),
        "initialized": (repo_root / ".git").exists(),
    }


def read_named_environment(name: str) -> str:
    value = os.getenv(name, "").strip()
    if value or os.name != "nt":
        return value
    try:
        import winreg

        locations = (
            (winreg.HKEY_CURRENT_USER, r"Environment"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        )
        for root, subkey in locations:
            try:
                with winreg.OpenKey(root, subkey) as handle:
                    raw, _ = winreg.QueryValueEx(handle, name)
            except OSError:
                continue
            value = str(raw or "").strip()
            if value:
                return os.path.expandvars(value)
    except Exception:
        return ""
    return ""


def get_runtime_config_path() -> Path:
    for env_name in RUNTIME_CONFIG_ENV_NAMES:
        configured = read_named_environment(env_name)
        if configured:
            path = Path(configured).expanduser().resolve()
            if path.exists() and path.is_dir():
                raise ValueError(f"{env_name} must point to a JSON file, not a directory: {path}")
            return path
    return CONFIG_PATH


MIN_PDF_BYTES = 2048
DEFAULT_MAX_PDF_BYTES = 256 * 1024 * 1024
CHUNK_SIZE = 500
DEFAULT_THREAD_NUM = 20
MAX_THREAD_NUM = 64
DOWNLOAD_TIMEOUT = 60
DEFAULT_EXTERNAL_CONTROL_TIMEOUT_SECONDS = 60
DEFAULT_CHROME_CONTROL_TIMEOUT_SECONDS = 180
DEFAULT_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS = 180
DEFAULT_EXTERNAL_HANDOFF_TIMEOUT_SECONDS = 900
DEFAULT_AUTH_CONTROL_VERIFY_SECONDS = 5
DEFAULT_AUTH_MANUAL_TIMEOUT_SECONDS = 180
DEFAULT_VERIFICATION_MANUAL_TIMEOUT_SECONDS = 180
DEFAULT_ENV_COMMAND_TIMEOUT_SECONDS = 600
DEFAULT_ENV_LOCK_TIMEOUT_SECONDS = 900
DOWNLOAD_LEDGER_SCHEMA_VERSION = 3
DOWNLOAD_FINGERPRINT_SCHEMA_VERSION = 1
DOWNLOAD_PLANNER_SEMANTICS_VERSION = "2026-07-20.1"
DOWNLOAD_RUN_HEARTBEAT_SECONDS = 30
DOWNLOAD_RUN_LEASE_SECONDS = 120
ENV_BOOTSTRAP_LOCK_NAME = ".environment_bootstrap.lock"
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
COMMON_BROWSER_ESCALATION_CONTROLLER = "verification_control"
AUTH_STATE_ATTESTATION_SCHEMA = "laps_auth_state_attestation_v2"
AUTH_STATE_ATTESTATION_DEFAULT_TTL_SECONDS = 12 * 60 * 60
AUTH_STATE_ATTESTATION_MIN_TTL_SECONDS = 60 * 60
AUTH_STATE_ATTESTATION_MAX_TTL_SECONDS = 7 * 24 * 60 * 60
AUTH_STATE_ATTESTATION_CONFIRMATION_KINDS = frozenset(
    {"exact_institution_marker", "sso_round_trip", "challenge_recovered", "site_personal_session"}
)
AUTH_STATE_ATTESTATION_FIELDS = frozenset(
    {
        "schema",
        "generation_id",
        "auth_state_scope",
        "auth_mode",
        "principal_digest",
        "confirmation_kind",
        "service_host",
        "confirmed_at",
        "expires_at",
        "state_sha256",
        "browser_name",
        "headful_required",
        "producer_component",
        "producer_operation_id",
    }
)
DOWNLOAD_BROWSER_METHOD_TAGS = frozenset(
    {
        "robot_challenge_possible",
        "landing_page_discovery",
        "public_browser",
        "public_web",
        "restricted_web",
        "restricted_web_fallback",
        "sciencedirect_auth_path",
        "institution_or_carsi_auth_path",
        "google_pdf_fallback",
    }
)


def env_seconds(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def env_milliseconds(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def environment_command_timeout_seconds() -> int:
    return env_seconds("LAPS_ENV_COMMAND_TIMEOUT_SECONDS", DEFAULT_ENV_COMMAND_TIMEOUT_SECONDS, 1)


def environment_lock_timeout_seconds() -> int:
    return env_seconds("LAPS_ENV_LOCK_TIMEOUT_SECONDS", DEFAULT_ENV_LOCK_TIMEOUT_SECONDS, 1)


PAGE_TIMEOUT_MS = env_seconds("LAPS_PAGE_TIMEOUT_SECONDS", 30, 5) * 1000
BROWSER_COOKIE_WARMUP_MS = env_milliseconds("LAPS_BROWSER_COOKIE_WARMUP_MS", 6000, 0)
BROWSER_NETWORK_IDLE_TIMEOUT_MS = env_milliseconds("LAPS_BROWSER_NETWORK_IDLE_TIMEOUT_MS", 10_000, 1000)
BROWSER_TEXT_TIMEOUT_MS = env_milliseconds("LAPS_BROWSER_TEXT_TIMEOUT_MS", 5000, 500)


def download_chunk_size() -> int:
    try:
        return max(1, int(os.getenv("LAPS_DOWNLOAD_CHUNK_SIZE", str(CHUNK_SIZE))))
    except ValueError:
        return CHUNK_SIZE

ATTEMPT_FIELDS = [
    "run_id",
    "invocation_id",
    "record_id",
    "record_type",
    "title",
    "doi",
    "publication_number",
    "metadata_sources",
    "url",
    "planned_channel",
    "channel",
    "executed_adapter",
    "resolver_channel",
    "observation_id",
    "execution_key",
    "locator_id",
    "locator_source",
    "discovery_source",
    "discovery_adapter",
    "delivery_adapter",
    "delivery_source",
    "candidate_origin",
    "auth_scope",
    "session_generation",
    "deduplicated_to_attempt_id",
    "resume_action",
    "candidate_id",
    "attempt_id",
    "stage",
    "channel_url_or_api",
    "attempt_status",
    "reason",
    "reason_code",
    "reason_category",
    "retryable",
    "retry_at",
    "http_status",
    "elapsed_seconds",
    "access_mode",
    "created_at",
]

API_CONFIG_KEYS = (
    "CONTACT_EMAIL",
    "CROSSREF_MAILTO",
    "NCBI_EMAIL",
    "NCBI_TOOL",
    "CLARIVATE_API_KEY",
    "WOS_API_KEY",
    "ELSEVIER_API_KEY",
    "ELSEVIER_INSTTOKEN",
    "IEEE_API_KEY",
    "LENS_API_KEY",
    "LENS_Scholarly_API_KEY",
    "LENS_Patents_API_KEY",
    "SPRINGER_API_KEY",
    "CORE_API_KEY",
    "SEMANTIC_SCHOLAR_API_KEY",
    "NCBI_API_KEY",
    "PUBMED_API_KEY",
    "OPENALEX_API_KEY",
    "OPENAIRE_API_KEY",
    "EPO_OPS_KEY",
    "EPO_OPS_SECRET",
    "USPTO_ODP_API_KEY",
    "PATENTSCOPE_WEBSERVICE_USERNAME",
    "PATENTSCOPE_WEBSERVICE_PASSWORD",
    "PQAI_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
)
API_CONFIG_KEY_SET = set(API_CONFIG_KEYS)
API_CONFIG_VALUES: dict[str, str] = {}
API_KEY_COMPAT_ALIASES = {
    "WOS_API_KEY": "CLARIVATE_API_KEY",
    "PUBMED_API_KEY": "NCBI_API_KEY",
    "NCBI_EMAIL": "CONTACT_EMAIL",
    "CROSSREF_MAILTO": "CONTACT_EMAIL",
    "LENS_API_KEY": "LENS_Scholarly_API_KEY",
}

LITERATURE_URL_ALIASES = (
    "url",
    "URL",
    "link",
    "文献链接",
)
LITERATURE_DOI_ALIASES = (
    "DOI",
    "doi",
    "Doi",
    "article_doi",
    "paper_doi",
    "文献DOI",
    "论文DOI",
    "数字对象唯一标识符",
)
LITERATURE_TITLE_ALIASES = (
    "title",
    "Title",
    "article_title",
    "paper_title",
    "name",
    "文献名",
    "文献标题",
    "论文名",
    "论文标题",
)
PATENT_URL_ALIASES = (
    "URL",
    "url",
    "patent_url",
    "link",
    "patent_link",
    "专利URL",
    "专利链接",
    "链接",
)
PATENT_TITLE_ALIASES = (
    "patent_name",
    "title",
    "Title",
    "patent_title",
    "name",
    "专利名",
    "专利标题",
    "名称",
)
PUBLICATION_NUMBER_ALIASES = (
    "publication_number",
    "publication no",
    "publication_no",
    "publication",
    "公开号",
    "申请号",
    "专利号",
)
PMCID_ALIASES = ("pmcid", "PMCID", "pmc_id", "PMC", "raw_id")
PMID_ALIASES = ("pmid", "PMID")
ARXIV_ID_ALIASES = ("arxiv_id", "arXiv", "arxiv", "raw_id")

# Backward-compatible historic-prefix views.  The versioned registry is the
# only source of channel names/order; the slices retain the pre-CNKI/万方
# constants consumed by older integrations without duplicating channel data.
LITERATURE_DOWNLOAD_CHANNEL_ORDER = tuple(
    spec.display_name for spec in get_download_adapters("literature")[:33]
)
PATENT_DOWNLOAD_CHANNEL_ORDER = tuple(
    spec.display_name for spec in get_download_adapters("patent")[:8]
)


literature_download_path_map: OrderedDict[str, str] = OrderedDict()
patents_download_path_map: OrderedDict[str, str] = OrderedDict()
literature_channel_policy_map: dict[str, dict[str, Any]] = {}
patents_channel_policy_map: dict[str, dict[str, Any]] = {}
DOMAIN_SEMAPHORES: dict[str, BoundedSemaphore] = {}
DOMAIN_LOCK = Lock()
DOMAIN_COOLDOWNS: dict[str, tuple[float, str]] = {}
CHANNEL_COOLDOWNS: dict[str, tuple[float, str]] = {}
CHANNEL_COOLDOWN_LOCK = Lock()
TARGET_LOCKS: dict[str, Lock] = {}
TARGET_LOCKS_GUARD = Lock()
AUTH_SCOPE_LOCKS: dict[str, RLock] = {}
AUTH_SCOPE_LOCKS_GUARD = Lock()
# Compatibility surface for existing offline probes.  The shared validator
# intentionally performs a fresh lookup and does not consume this legacy map.
DNS_SAFETY_CACHE: dict[str, tuple[float, bool]] = {}
DNS_SAFETY_LOCK = Lock()
ATTEMPT_CONTEXT = local()
AUTH_CHECK_SKIP_CACHE: dict[Path, dict[str, str]] = {}
KNOWN_SKIPPED_DOWNLOAD_CHANNELS: dict[str, str] = {}
CURRENT_RUN_ID = ""
CURRENT_INVOCATION_ID = ""
CURRENT_RUN_FINGERPRINT = ""
CURRENT_RUN_RESUMED = False
ACTIVE_DOWNLOAD_LEDGER: "DownloadStateLedger | None" = None
AUTH_CONTROL_STORE: AuthControlStore | None = None
AUTH_CONTROL_STORE_LOCK = Lock()
VERIFICATION_REQUESTS: dict[str, dict[str, Any]] = {}
VERIFICATION_REQUESTS_LOCK = Lock()
INPUT_CONTRACT_REPORTS: dict[str, dict[str, Any]] = {}

LITERATURE_CHANNEL_METHOD_TAGS: dict[str, tuple[str, ...]] = {
    "Sci-Hub": ("doi_form", "open_direct_pdf", "robot_challenge_possible"),
    "arXiv API": ("open_api", "direct_pdf"),
    "bioRxiv / medRxiv": ("open_preprint", "doi_pdf_pattern", "landing_page_discovery"),
    "IACR ePrint": ("open_preprint", "direct_pdf_pattern"),
    "The Lens (lens.org)": ("required_api_key", "metadata_api", "open_access_url_discovery"),
    "Web of Science Starter API (Clarivate)": ("required_api_key", "metadata_api", "restricted_web_fallback"),
    "doi_resolver": ("doi_landing_page", "no_browser_fallback"),
    "Crossref API": ("open_api", "metadata_pdf_link"),
    "OpenAlex API": ("open_api", "open_access_pdf"),
    "Semantic Scholar API": ("open_api", "optional_api_key", "open_access_pdf"),
    "Europe PMC": ("open_api", "full_text_url"),
    "PMC (PubMed Central)": ("open_repository", "direct_pdf"),
    "PubMed": ("open_api", "pmc_fallback"),
    "DOAJ (Directory of Open Access Journals)": ("open_api", "landing_page_discovery"),
    "DataCite Search (search.datacite.org)": ("open_api", "repository_url_discovery", "zenodo_file_api", "figshare_file_api"),
    "OpenReview": ("open_platform", "direct_pdf_pattern"),
    "DBLP": ("open_metadata", "arxiv_pdf_discovery", "landing_page_discovery"),
    "CORE": ("open_api", "optional_api_key", "download_url"),
    "OpenAIRE": ("open_api", "optional_api_key", "access_url"),
    "ChemRxiv": ("openalex_fallback", "landing_page_discovery"),
    "Google Scholar": ("public_browser", "landing_page_discovery"),
    "Crossref Metadata Search (search.crossref.org)": ("metadata_only",),
    "Semantic Scholar": ("metadata_only", "api_preferred"),
    "USENIX": ("open_platform", "system_files_pdf", "landing_page_discovery"),
    "Elsevier": ("required_api_key", "publisher_pdf_api", "sciencedirect_auth_path", "institution_or_carsi_auth_path", "restricted_web_fallback"),
    "SpringerLink": ("required_api_key", "publisher_metadata_api", "direct_pdf_pattern", "restricted_web_fallback"),
    "Springer": ("required_api_key", "publisher_metadata_api", "direct_pdf_pattern", "restricted_web_fallback"),
    "IEEE Xplore API": ("required_api_key", "metadata_api", "restricted_web_fallback"),
    "Nature": ("restricted_web", "direct_pdf_pattern"),
    "ACS Publications": ("restricted_web", "direct_pdf_pattern"),
    "RSC Publishing": ("restricted_web", "landing_page_discovery"),
    "ACM metadata": ("restricted_web", "direct_pdf_pattern"),
    "Annual Reviews": ("restricted_web", "direct_pdf_pattern"),
    CNKI_SOURCE: ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"),
    WANFANG_SOURCE: ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"),
}

PATENT_CHANNEL_METHOD_TAGS: dict[str, tuple[str, ...]] = {
    "Google Patents": ("public_web", "landing_page_discovery", "direct_download_query"),
    "The Lens (lens.org)": ("required_api_key", "metadata_api", "native_locator", "new_identifier_google_resolution"),
    "input_url": ("metadata_field", "landing_page_discovery"),
    "USPTO Open Data Portal": ("metadata_origin", "source_owned_locator"),
    "PQAI API (Patent Quality AI)": ("metadata_origin", "source_owned_locator"),
    "EPO Open Patent Services (OPS) API": ("metadata_origin", "source_owned_locator"),
    "WIPO PATENTSCOPE API": (
        "required_credentials",
        "public_web",
        "landing_page_discovery",
    ),
    "Google BigQuery": ("metadata_origin", "source_owned_locator"),
    CNKI_SOURCE: ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"),
    WANFANG_SOURCE: ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"),
    UYANIP_SOURCE: ("public_browser", "site_personal_auth", "observed_detail_url", "observed_pdf_action"),
}


@dataclass
class DownloadConfig:
    thread_num: int
    path: str
    school: str
    account: str
    password: str
    auth_enabled: bool
    school_aliases: tuple[str, ...] = ()
    uyanip_account: str = ""
    uyanip_password: str = ""
    runtime_config_path: str = ""
    headless: bool = True
    force: bool = False
    no_resume: bool = False
    dry_run: bool = False
    probe_channel_plan: bool = False
    limit: int | None = None
    channel_filters: tuple[str, ...] = ()
    exact_channel_filters: tuple[str, ...] = ()
    disabled_channels: tuple[str, ...] = ()
    input_contract: str = "auto"
    doi_filters: tuple[str, ...] = ()
    publication_filters: tuple[str, ...] = ()
    credential_allowed_hosts: tuple[str, ...] = ()


@dataclass
class DownloadAttempt:
    record_type: str
    title: str
    run_id: str = ""
    record_id: str = ""
    doi: str = ""
    publication_number: str = ""
    metadata_sources: str = ""
    invocation_id: str = ""
    url: str = ""
    planned_channel: str = ""
    channel: str = ""
    executed_adapter: str = ""
    resolver_channel: str = ""
    observation_id: str = ""
    execution_key: str = ""
    locator_id: str = ""
    locator_source: str = ""
    discovery_source: str = ""
    discovery_adapter: str = ""
    delivery_adapter: str = ""
    delivery_source: str = ""
    candidate_origin: str = ""
    auth_scope: str = ""
    session_generation: str = "public"
    deduplicated_to_attempt_id: str = ""
    resume_action: str = ""
    candidate_id: str = ""
    attempt_id: str = ""
    stage: str = "download"
    channel_url_or_api: str = ""
    attempt_status: str = ""
    reason: str = ""
    reason_code: str = ""
    reason_category: str = ""
    retryable: bool = False
    retry_at: str = ""
    http_status: str = ""
    elapsed_seconds: float = 0.0
    access_mode: str = "open"
    created_at: str = ""


@dataclass
class DownloadResult:
    record_type: str
    title: str
    run_id: str = ""
    record_id: str = ""
    doi: str = ""
    publication_number: str = ""
    metadata_sources: list[str] = field(default_factory=list)
    url: str = ""
    status: str = ""
    source_channel: str = ""
    resolver_channel: str = ""
    successful_planned_channel: str = ""
    successful_resolver_channel: str = ""
    successful_delivery_source: str = ""
    pdf_path: str = ""
    file_size_bytes: int = 0
    sha256: str = ""
    access_mode: str = "open"
    attempt_count: int = 0
    failure_reason: str = ""
    attempted_channels: list[str] = field(default_factory=list)
    last_error: str = ""
    original_row: dict[str, Any] = field(default_factory=dict)
    attempts: list[DownloadAttempt] = field(default_factory=list)


class DownloadCandidate(str):
    """A URL-compatible candidate carrying authoritative discovery provenance.

    It intentionally subclasses ``str`` for one release so existing channel
    helpers can continue to use urllib/string operations while parser output is
    migrated away from the former thread-local resolver side channel.
    """

    def __new__(
        cls,
        url: str,
        *,
        sanitized_target: str = "",
        locator_id: str = "",
        locator_kind: str = "",
        locator_source: str = "",
        locator_auth_scope: str = "",
        locator_stability: str = "",
        discovery_source: str = "",
        discovery_adapter: str = "",
        resolver_channel: str = "",
        evidence_type: str = "",
        access_mode: str = "open",
        auth_scope: str = "public",
        auth_session_generation: str = "public",
        parent_locator_id: str = "",
        parent_candidate_id: str = "",
        candidate_origin: str = "browser_discovery",
    ) -> "DownloadCandidate":
        value = str(url or "").strip()
        instance = str.__new__(cls, value)
        instance.sanitized_target = sanitized_target
        instance.locator_id = locator_id
        instance.locator_kind = locator_kind
        instance.locator_source = locator_source
        instance.locator_auth_scope = locator_auth_scope
        instance.locator_stability = locator_stability
        instance.discovery_source = discovery_source
        instance.discovery_adapter = discovery_adapter
        instance.resolver_channel = resolver_channel
        instance.evidence_type = evidence_type
        instance.access_mode = access_mode or "open"
        instance.auth_scope = auth_scope or "public"
        instance.auth_session_generation = auth_session_generation or "public"
        instance.parent_locator_id = parent_locator_id
        instance.parent_candidate_id = parent_candidate_id
        instance.candidate_origin = candidate_origin or "browser_discovery"
        return instance


@dataclass
class RecordStats:
    record_type: str
    total_records: int = 0
    valid_records: int = 0
    duplicate_records: int = 0
    missing_identifier_records: int = 0
    not_downloadable_records: int = 0
    input_contract: str = ""
    input_path: str = ""
    skipped_existing_files: int = 0
    success_count: int = 0
    failure_count: int = 0
    dry_run_count: int = 0
    open_success_count: int = 0
    authenticated_success_count: int = 0
    per_channel_success_count: Counter[str] = field(default_factory=Counter)
    per_channel_failure_count: Counter[str] = field(default_factory=Counter)
    started_at: str = ""
    finished_at: str = ""
    elapsed_seconds: float = 0.0


@dataclass
class PreparedRecordInput:
    record_type: str
    rows: list[dict[str, Any]]
    resolved: Any
    total_records: int = 0
    duplicate_records: int = 0
    plan_sha256: str = ""
    logical_input_sha256: str = ""


@dataclass
class DownloadOutcome:
    success: bool
    reason: str
    http_status: str = ""
    elapsed_seconds: float = 0.0
    retryable: bool = False
    retry_at: str = ""
    final_url: str = ""


class DomainCooldownError(Exception):
    pass


class DownloadStateLedger:
    """Transactional download truth used for restart recovery and audit evidence."""

    SCHEMA_VERSION = DOWNLOAD_LEDGER_SCHEMA_VERSION
    REQUIRED_COLUMNS: dict[str, frozenset[str]] = {
        "runs": frozenset(
            {
                "run_id",
                "started_at",
                "finished_at",
                "status",
                "input_contract",
                "config_json",
                "report_path",
                "run_fingerprint",
                "fingerprint_schema_version",
                "fingerprint_payload_json",
                "lifecycle_status",
                "completion_status",
                "resume_policy",
                "resume_count",
                "heartbeat_at",
                "finalizing_at",
                "finalized_at",
                "report_sha256",
                "termination_reason",
            }
        ),
        "records": frozenset(
            {
                "record_id",
                "record_type",
                "title",
                "doi",
                "publication_number",
                "metadata_sources_json",
                "canonical_json",
                "last_status",
                "updated_at",
            }
        ),
        "attempts": frozenset(
            {
                "attempt_id",
                "run_id",
                "record_id",
                "planned_channel",
                "executed_adapter",
                "resolver_channel",
                "candidate_id",
                "stage",
                "status",
                "reason_code",
                "reason_category",
                "retryable",
                "retry_at",
                "http_status",
                "sanitized_target",
                "created_at",
                "payload_json",
                "invocation_id",
                "observation_id",
                "execution_key",
                "locator_id",
                "locator_source",
                "discovery_source",
                "discovery_adapter",
                "delivery_adapter",
                "delivery_source",
                "candidate_origin",
                "auth_scope",
                "session_generation",
                "deduplicated_to_attempt_id",
                "resume_action",
            }
        ),
        "artifacts": frozenset(
            {
                "artifact_id",
                "record_id",
                "run_id",
                "path",
                "size_bytes",
                "sha256",
                "valid",
                "validation_json",
                "created_at",
            }
        ),
        "cooldowns": frozenset(
            {"scope_type", "scope_key", "reason_code", "retry_at_epoch", "updated_at"}
        ),
        "migrations": frozenset(
            {"migration_id", "source_contract", "source_path", "report_json", "created_at"}
        ),
        "run_invocations": frozenset(
            {
                "invocation_id", "run_id", "owner_token", "resume_mode",
                "started_at", "finished_at", "heartbeat_at", "status",
            }
        ),
        "run_locks": frozenset(
            {
                "lock_key", "run_id", "invocation_id", "owner_token",
                "heartbeat_at", "lease_expires_at",
            }
        ),
        "run_records": frozenset(
            {
                "run_id", "record_id", "input_ordinal", "input_digest",
                "planner_row_json", "state", "artifact_id", "failure_reason",
                "completion_sequence", "started_at", "finished_at",
            }
        ),
        "candidate_states": frozenset(
            {
                "run_id", "record_id", "execution_key", "state", "candidate_id",
                "planned_channel", "stage", "access_mode", "auth_scope",
                "session_generation", "retryable", "retry_at", "artifact_id",
                "last_attempt_id", "recovery_retry_count", "updated_at",
            }
        ),
        "candidate_observations": frozenset(
            {
                "observation_id", "run_id", "record_id", "planned_channel",
                "planned_order", "locator_id", "locator_source", "discovery_source",
                "discovery_adapter", "resolver_channel", "candidate_origin",
                "execution_key", "sanitized_target", "access_mode", "auth_scope",
                "session_generation", "created_at",
            }
        ),
    }

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._owner_token = uuid.uuid4().hex
        self._heartbeat_stop = Event()
        self._heartbeat_thread: Thread | None = None
        self.active_run_id = ""
        self.active_invocation_id = ""
        self.backup_path: Path | None = self._backup_before_first_v3_migration()
        self._prepare()

    def _backup_before_first_v3_migration(self) -> Path | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        existing_version = ""
        try:
            with closing(sqlite3.connect(self.path, timeout=5)) as connection:
                row = connection.execute(
                    "SELECT value FROM ledger_meta WHERE key='schema_version'"
                ).fetchone()
                existing_version = str(row[0]) if row else ""
        except sqlite3.Error:
            existing_version = ""
        if existing_version == str(self.SCHEMA_VERSION) and self._path_has_v3_schema(self.path):
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = self.path.with_name(f"{self.path.name}.pre-v3.{stamp}.bak")
        suffix = 1
        while backup.exists():
            backup = self.path.with_name(f"{self.path.name}.pre-v3.{stamp}.{suffix}.bak")
            suffix += 1
        source = sqlite3.connect(self.path, timeout=30)
        destination = sqlite3.connect(backup, timeout=30)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        return backup

    @classmethod
    def _path_has_v3_schema(cls, path: Path) -> bool:
        try:
            with closing(sqlite3.connect(path, timeout=5)) as connection:
                present = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                for table, required in cls.REQUIRED_COLUMNS.items():
                    if table not in present:
                        return False
                    columns = {
                        str(row[1])
                        for row in connection.execute(
                            f'PRAGMA table_info("{table}")'
                        )
                    }
                    if not required.issubset(columns):
                        return False
                return True
        except sqlite3.Error:
            return False

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _schema_statements() -> tuple[str, ...]:
        return (
                """CREATE TABLE IF NOT EXISTS ledger_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    input_contract TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    report_path TEXT,
                    run_fingerprint TEXT NOT NULL DEFAULT '',
                    fingerprint_schema_version INTEGER NOT NULL DEFAULT 0,
                    fingerprint_payload_json TEXT NOT NULL DEFAULT '{}',
                    lifecycle_status TEXT NOT NULL DEFAULT 'finalized',
                    completion_status TEXT NOT NULL DEFAULT '',
                    resume_policy TEXT NOT NULL DEFAULT 'legacy',
                    resume_count INTEGER NOT NULL DEFAULT 0,
                    heartbeat_at TEXT NOT NULL DEFAULT '',
                    finalizing_at TEXT NOT NULL DEFAULT '',
                    finalized_at TEXT NOT NULL DEFAULT '',
                    report_sha256 TEXT NOT NULL DEFAULT '',
                    termination_reason TEXT NOT NULL DEFAULT ''
                )""",
                """CREATE INDEX IF NOT EXISTS runs_fingerprint_idx
                    ON runs(run_fingerprint, finalized_at, started_at)""",
                """CREATE TABLE IF NOT EXISTS records (
                    record_id TEXT PRIMARY KEY,
                    record_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    doi TEXT NOT NULL DEFAULT '',
                    publication_number TEXT NOT NULL DEFAULT '',
                    metadata_sources_json TEXT NOT NULL DEFAULT '[]',
                    canonical_json TEXT NOT NULL DEFAULT '{}',
                    last_status TEXT NOT NULL DEFAULT 'pending',
                    updated_at TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    planned_channel TEXT NOT NULL,
                    executed_adapter TEXT NOT NULL,
                    resolver_channel TEXT NOT NULL DEFAULT '',
                    candidate_id TEXT NOT NULL DEFAULT '',
                    stage TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason_code TEXT NOT NULL DEFAULT '',
                    reason_category TEXT NOT NULL DEFAULT '',
                    retryable INTEGER NOT NULL DEFAULT 0,
                    retry_at TEXT NOT NULL DEFAULT '',
                    http_status TEXT NOT NULL DEFAULT '',
                    sanitized_target TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    invocation_id TEXT NOT NULL DEFAULT '',
                    observation_id TEXT NOT NULL DEFAULT '',
                    execution_key TEXT NOT NULL DEFAULT '',
                    locator_id TEXT NOT NULL DEFAULT '',
                    locator_source TEXT NOT NULL DEFAULT '',
                    discovery_source TEXT NOT NULL DEFAULT '',
                    discovery_adapter TEXT NOT NULL DEFAULT '',
                    delivery_adapter TEXT NOT NULL DEFAULT '',
                    delivery_source TEXT NOT NULL DEFAULT '',
                    candidate_origin TEXT NOT NULL DEFAULT '',
                    auth_scope TEXT NOT NULL DEFAULT '',
                    session_generation TEXT NOT NULL DEFAULT 'public',
                    deduplicated_to_attempt_id TEXT NOT NULL DEFAULT '',
                    resume_action TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(run_id) REFERENCES runs(run_id),
                    FOREIGN KEY(record_id) REFERENCES records(record_id)
                )""",
                """CREATE INDEX IF NOT EXISTS attempts_record_idx
                    ON attempts(record_id, created_at)""",
                """CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    record_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    valid INTEGER NOT NULL,
                    validation_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    UNIQUE(record_id, sha256),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id),
                    FOREIGN KEY(record_id) REFERENCES records(record_id)
                )""",
                """CREATE TABLE IF NOT EXISTS cooldowns (
                    scope_type TEXT NOT NULL,
                    scope_key TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    retry_at_epoch REAL NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(scope_type, scope_key)
                )""",
                """CREATE TABLE IF NOT EXISTS migrations (
                    migration_id TEXT PRIMARY KEY,
                    source_contract TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS run_invocations (
                    invocation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    owner_token TEXT NOT NULL,
                    resume_mode TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL DEFAULT '',
                    heartbeat_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                )""",
                """CREATE TABLE IF NOT EXISTS run_locks (
                    lock_key TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    invocation_id TEXT NOT NULL,
                    owner_token TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    lease_expires_at REAL NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS run_records (
                    run_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    input_ordinal INTEGER NOT NULL,
                    input_digest TEXT NOT NULL,
                    planner_row_json TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    artifact_id TEXT NOT NULL DEFAULT '',
                    failure_reason TEXT NOT NULL DEFAULT '',
                    completion_sequence INTEGER,
                    started_at TEXT NOT NULL DEFAULT '',
                    finished_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(run_id, record_id),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                )""",
                """CREATE INDEX IF NOT EXISTS run_records_order_idx
                    ON run_records(run_id, input_ordinal)""",
                """CREATE TABLE IF NOT EXISTS candidate_states (
                    run_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    execution_key TEXT NOT NULL,
                    state TEXT NOT NULL,
                    candidate_id TEXT NOT NULL DEFAULT '',
                    planned_channel TEXT NOT NULL DEFAULT '',
                    stage TEXT NOT NULL DEFAULT 'candidate',
                    access_mode TEXT NOT NULL DEFAULT 'open',
                    auth_scope TEXT NOT NULL DEFAULT 'public',
                    session_generation TEXT NOT NULL DEFAULT 'public',
                    retryable INTEGER NOT NULL DEFAULT 0,
                    retry_at TEXT NOT NULL DEFAULT '',
                    artifact_id TEXT NOT NULL DEFAULT '',
                    last_attempt_id TEXT NOT NULL DEFAULT '',
                    recovery_retry_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(run_id, record_id, execution_key),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                )""",
                """CREATE TABLE IF NOT EXISTS candidate_observations (
                    observation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    planned_channel TEXT NOT NULL,
                    planned_order INTEGER NOT NULL DEFAULT 0,
                    locator_id TEXT NOT NULL DEFAULT '',
                    locator_source TEXT NOT NULL DEFAULT '',
                    discovery_source TEXT NOT NULL DEFAULT '',
                    discovery_adapter TEXT NOT NULL DEFAULT '',
                    resolver_channel TEXT NOT NULL DEFAULT '',
                    candidate_origin TEXT NOT NULL DEFAULT '',
                    execution_key TEXT NOT NULL,
                    sanitized_target TEXT NOT NULL DEFAULT '',
                    access_mode TEXT NOT NULL DEFAULT 'open',
                    auth_scope TEXT NOT NULL DEFAULT 'public',
                    session_generation TEXT NOT NULL DEFAULT 'public',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                )""",
                """CREATE INDEX IF NOT EXISTS candidate_observations_execution_idx
                    ON candidate_observations(run_id, record_id, execution_key)""",
        )

    @classmethod
    def _schema_requires_rebuild(cls, connection: sqlite3.Connection) -> bool:
        present = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for table, required in cls.REQUIRED_COLUMNS.items():
            if table not in present:
                continue
            columns = {
                str(row[1])
                for row in connection.execute(f'PRAGMA table_info("{table}")')
            }
            if not required.issubset(columns):
                return True
        return False

    @staticmethod
    def _legacy_value(row: sqlite3.Row, *names: str, default: Any = "") -> Any:
        keys = set(row.keys())
        for name in names:
            if name in keys and row[name] is not None:
                return row[name]
        return default

    @staticmethod
    def _json_text(value: Any, default: str) -> str:
        text = str(value or "").strip()
        if not text:
            return default
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            decoded = {"legacy_value": text}
        return json.dumps(
            sanitize_nested_for_output(decoded),
            ensure_ascii=False,
            sort_keys=True,
        )

    @staticmethod
    def _legacy_text(value: Any, field_name: str = "") -> str:
        """Sanitize every scalar copied from an untrusted legacy ledger."""

        sanitized = sanitize_nested_for_output(value, field_name)
        if isinstance(sanitized, (Mapping, list, tuple, set)):
            return json.dumps(sanitized, ensure_ascii=False, sort_keys=True)
        return "" if sanitized is None else str(sanitized)

    @staticmethod
    def _legacy_bool(value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value == 1
        normalized = str(value or "").strip().casefold()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
        return default

    def _seed_migrated_run(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        created_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO runs(
                run_id, started_at, finished_at, status, input_contract,
                config_json, report_path
            ) VALUES(?, ?, ?, 'partial', 'unknown', '{}', '')
            """,
            (run_id, created_at, created_at),
        )

    def _seed_migrated_record(
        self,
        connection: sqlite3.Connection,
        record_id: str,
        record_type: str,
        created_at: str,
    ) -> None:
        normalized_type = record_type if record_type in {"literature", "patent"} else "unknown"
        connection.execute(
            """
            INSERT OR IGNORE INTO records(
                record_id, record_type, title, doi, publication_number,
                metadata_sources_json, canonical_json, last_status, updated_at
            ) VALUES(?, ?, '', '', '', '[]', '{}', 'unknown', ?)
            """,
            (record_id, normalized_type, created_at),
        )

    def _migrate_legacy_v2_tables(self, connection: sqlite3.Connection) -> None:
        """Rebuild incompatible same-named tables and preserve mappable rows."""

        all_tables = (
            "ledger_meta",
            "runs",
            "records",
            "attempts",
            "artifacts",
            "cooldowns",
            "migrations",
        )
        present = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("BEGIN IMMEDIATE")
        try:
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
            ).fetchall():
                connection.execute(f'DROP INDEX IF EXISTS "{str(row[0]).replace(chr(34), chr(34) * 2)}"')
            legacy_tables: dict[str, str] = {}
            for table in all_tables:
                if table not in present:
                    continue
                legacy_name = f"__laps_legacy_v1_{table}"
                connection.execute(f'DROP TABLE IF EXISTS "{legacy_name}"')
                connection.execute(f'ALTER TABLE "{table}" RENAME TO "{legacy_name}"')
                legacy_tables[table] = legacy_name
            for statement in self._schema_statements():
                connection.execute(statement)

            legacy_meta = legacy_tables.get("ledger_meta")
            if legacy_meta:
                for row in connection.execute(f'SELECT * FROM "{legacy_meta}"'):
                    key = self._legacy_text(
                        self._legacy_value(row, "key", "name", default=""),
                        "ledger_meta_key",
                    ).strip()
                    if key and key != "schema_version":
                        connection.execute(
                            "INSERT OR REPLACE INTO ledger_meta(key, value) VALUES(?, ?)",
                            (
                                key,
                                self._legacy_text(
                                    self._legacy_value(row, "value", default=""),
                                    key,
                                ),
                            ),
                        )

            legacy_runs = legacy_tables.get("runs")
            if legacy_runs:
                for index, row in enumerate(connection.execute(f'SELECT * FROM "{legacy_runs}"')):
                    run_id = self._legacy_text(
                        self._legacy_value(row, "run_id", "id", default=""),
                        "run_id",
                    ).strip() or f"legacy_run_{index}"
                    started = self._legacy_text(
                        self._legacy_value(row, "started_at", "created_at", default=utc_now()),
                        "started_at",
                    )
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO runs(
                            run_id, started_at, finished_at, status,
                            input_contract, config_json, report_path
                        ) VALUES(?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            started,
                            self._legacy_text(self._legacy_value(row, "finished_at", default=""), "finished_at") or None,
                            self._legacy_text(self._legacy_value(row, "status", default="partial"), "status"),
                            self._legacy_text(self._legacy_value(row, "input_contract", default="unknown"), "input_contract"),
                            self._json_text(self._legacy_value(row, "config_json", "config", default="{}"), "{}"),
                            self._legacy_text(self._legacy_value(row, "report_path", default=""), "report_path"),
                        ),
                    )

            legacy_records = legacy_tables.get("records")
            if legacy_records:
                for index, row in enumerate(connection.execute(f'SELECT * FROM "{legacy_records}"')):
                    record_id = self._legacy_text(
                        self._legacy_value(row, "record_id", "id", default=""),
                        "record_id",
                    ).strip() or f"legacy_record_{index}"
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO records(
                            record_id, record_type, title, doi, publication_number,
                            metadata_sources_json, canonical_json, last_status, updated_at
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record_id,
                            self._legacy_text(self._legacy_value(row, "record_type", "type", default="unknown"), "record_type"),
                            self._legacy_text(self._legacy_value(row, "title", default=""), "title"),
                            self._legacy_text(self._legacy_value(row, "doi", default=""), "doi"),
                            self._legacy_text(self._legacy_value(row, "publication_number", default=""), "publication_number"),
                            self._json_text(self._legacy_value(row, "metadata_sources_json", "metadata_sources", default="[]"), "[]"),
                            self._json_text(self._legacy_value(row, "canonical_json", "canonical", default="{}"), "{}"),
                            self._legacy_text(self._legacy_value(row, "last_status", "status", default="unknown"), "last_status"),
                            self._legacy_text(self._legacy_value(row, "updated_at", "created_at", default=utc_now()), "updated_at"),
                        ),
                    )

            legacy_attempts = legacy_tables.get("attempts")
            if legacy_attempts:
                for index, row in enumerate(connection.execute(f'SELECT * FROM "{legacy_attempts}"')):
                    created = self._legacy_text(self._legacy_value(row, "created_at", "updated_at", default=utc_now()), "created_at")
                    run_id = self._legacy_text(self._legacy_value(row, "run_id", default="legacy_run"), "run_id").strip() or "legacy_run"
                    record_id = self._legacy_text(self._legacy_value(row, "record_id", default=f"legacy_record_{index}"), "record_id").strip() or f"legacy_record_{index}"
                    self._seed_migrated_run(connection, run_id, created)
                    self._seed_migrated_record(
                        connection,
                        record_id,
                        self._legacy_text(self._legacy_value(row, "record_type", "type", default="unknown"), "record_type"),
                        created,
                    )
                    target = str(self._legacy_value(row, "sanitized_target", "channel_url_or_api", "url", default=""))
                    candidate_id = self._legacy_text(self._legacy_value(row, "candidate_id", default=""), "candidate_id").strip()
                    if not candidate_id and target:
                        candidate_id = hashlib.sha256(target.encode("utf-8", errors="ignore")).hexdigest()[:24]
                    planned = self._legacy_text(self._legacy_value(row, "planned_channel", "channel", default="unknown"), "planned_channel")
                    reason = self._legacy_text(self._legacy_value(row, "reason_code", "reason", default="unknown"), "reason_code")
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO attempts(
                            attempt_id, run_id, record_id, planned_channel,
                            executed_adapter, resolver_channel, candidate_id,
                            stage, status, reason_code, reason_category,
                            retryable, retry_at, http_status, sanitized_target,
                            created_at, payload_json
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self._legacy_text(self._legacy_value(row, "attempt_id", "id", default=""), "attempt_id").strip() or f"legacy_attempt_{index}_{uuid.uuid4().hex[:12]}",
                            run_id,
                            record_id,
                            planned,
                            self._legacy_text(self._legacy_value(row, "executed_adapter", "adapter", default=planned), "executed_adapter"),
                            self._legacy_text(self._legacy_value(row, "resolver_channel", default=""), "resolver_channel"),
                            candidate_id,
                            self._legacy_text(self._legacy_value(row, "stage", default="candidate" if target else "planning"), "stage"),
                            self._legacy_text(self._legacy_value(row, "status", "attempt_status", default="unknown"), "status"),
                            reason,
                            self._legacy_text(self._legacy_value(row, "reason_category", default="unknown"), "reason_category"),
                            int(self._legacy_bool(self._legacy_value(row, "retryable", default=0))),
                            self._legacy_text(self._legacy_value(row, "retry_at", default=""), "retry_at"),
                            self._legacy_text(self._legacy_value(row, "http_status", default=""), "http_status"),
                            self._legacy_text(target, "sanitized_target"),
                            created,
                            self._json_text(self._legacy_value(row, "payload_json", "payload", default="{}"), "{}"),
                        ),
                    )

            legacy_artifacts = legacy_tables.get("artifacts")
            if legacy_artifacts:
                for index, row in enumerate(connection.execute(f'SELECT * FROM "{legacy_artifacts}"')):
                    created = self._legacy_text(self._legacy_value(row, "created_at", default=utc_now()), "created_at")
                    run_id = self._legacy_text(self._legacy_value(row, "run_id", default="legacy_run"), "run_id").strip() or "legacy_run"
                    record_id = self._legacy_text(self._legacy_value(row, "record_id", default=f"legacy_record_{index}"), "record_id").strip() or f"legacy_record_{index}"
                    self._seed_migrated_run(connection, run_id, created)
                    self._seed_migrated_record(connection, record_id, "unknown", created)
                    artifact_path = self._legacy_text(self._legacy_value(row, "path", "pdf_path", default=""), "path")
                    raw_digest = self._legacy_text(self._legacy_value(row, "sha256", default=""), "sha256").strip().casefold()
                    digest_is_usable = bool(re.fullmatch(r"[0-9a-f]{64}", raw_digest))
                    digest = raw_digest if digest_is_usable else hashlib.sha256(artifact_path.encode("utf-8", errors="ignore")).hexdigest()
                    try:
                        artifact_size = int(self._legacy_value(row, "size_bytes", "file_size_bytes", default=0) or 0)
                    except (TypeError, ValueError):
                        artifact_size = 0
                    legacy_valid = self._legacy_bool(self._legacy_value(row, "valid", default=0))
                    migrated_valid = int(legacy_valid and digest_is_usable and artifact_size > 0)
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO artifacts(
                            artifact_id, record_id, run_id, path, size_bytes,
                            sha256, valid, validation_json, created_at
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self._legacy_text(self._legacy_value(row, "artifact_id", "id", default=""), "artifact_id").strip() or f"legacy_artifact_{index}_{digest[:12]}",
                            record_id,
                            run_id,
                            artifact_path,
                            artifact_size,
                            digest,
                            migrated_valid,
                            self._json_text(self._legacy_value(row, "validation_json", "validation", default="{}"), "{}"),
                            created,
                        ),
                    )

            legacy_cooldowns = legacy_tables.get("cooldowns")
            if legacy_cooldowns:
                for row in connection.execute(f'SELECT * FROM "{legacy_cooldowns}"'):
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO cooldowns(
                            scope_type, scope_key, reason_code,
                            retry_at_epoch, updated_at
                        ) VALUES(?, ?, ?, ?, ?)
                        """,
                        (
                            self._legacy_text(self._legacy_value(row, "scope_type", default="domain"), "scope_type"),
                            self._legacy_text(self._legacy_value(row, "scope_key", "host", "channel", default="unknown"), "scope_key"),
                            self._legacy_text(self._legacy_value(row, "reason_code", "reason", default="unknown"), "reason_code"),
                            float(self._legacy_value(row, "retry_at_epoch", "retry_at", default=0) or 0),
                            self._legacy_text(self._legacy_value(row, "updated_at", default=utc_now()), "updated_at"),
                        ),
                    )

            legacy_migrations = legacy_tables.get("migrations")
            if legacy_migrations:
                for index, row in enumerate(connection.execute(f'SELECT * FROM "{legacy_migrations}"')):
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO migrations(
                            migration_id, source_contract, source_path,
                            report_json, created_at
                        ) VALUES(?, ?, ?, ?, ?)
                        """,
                        (
                            self._legacy_text(self._legacy_value(row, "migration_id", "id", default=""), "migration_id").strip() or f"legacy_migration_{index}",
                            self._legacy_text(self._legacy_value(row, "source_contract", default="unknown"), "source_contract"),
                            self._legacy_text(self._legacy_value(row, "source_path", default="unknown"), "source_path"),
                            self._json_text(self._legacy_value(row, "report_json", "report", default="{}"), "{}"),
                            self._legacy_text(self._legacy_value(row, "created_at", default=utc_now()), "created_at"),
                        ),
                    )

            for legacy_name in reversed(tuple(legacy_tables.values())):
                connection.execute(f'DROP TABLE "{legacy_name}"')
            connection.execute(
                "INSERT OR REPLACE INTO ledger_meta(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )
            connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys=ON")

    @staticmethod
    def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
        return {
            str(row[1])
            for row in connection.execute(f'PRAGMA table_info("{table}")')
        }

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        """Apply the additive v3 ledger migration without rebuilding v2 tables."""

        run_columns = {
            "run_fingerprint": "TEXT NOT NULL DEFAULT ''",
            "fingerprint_schema_version": "INTEGER NOT NULL DEFAULT 0",
            "fingerprint_payload_json": "TEXT NOT NULL DEFAULT '{}'",
            "lifecycle_status": "TEXT NOT NULL DEFAULT 'finalized'",
            "completion_status": "TEXT NOT NULL DEFAULT ''",
            "resume_policy": "TEXT NOT NULL DEFAULT 'legacy'",
            "resume_count": "INTEGER NOT NULL DEFAULT 0",
            "heartbeat_at": "TEXT NOT NULL DEFAULT ''",
            "finalizing_at": "TEXT NOT NULL DEFAULT ''",
            "finalized_at": "TEXT NOT NULL DEFAULT ''",
            "report_sha256": "TEXT NOT NULL DEFAULT ''",
            "termination_reason": "TEXT NOT NULL DEFAULT ''",
        }
        attempt_columns = {
            "invocation_id": "TEXT NOT NULL DEFAULT ''",
            "observation_id": "TEXT NOT NULL DEFAULT ''",
            "execution_key": "TEXT NOT NULL DEFAULT ''",
            "locator_id": "TEXT NOT NULL DEFAULT ''",
            "locator_source": "TEXT NOT NULL DEFAULT ''",
            "discovery_source": "TEXT NOT NULL DEFAULT ''",
            "discovery_adapter": "TEXT NOT NULL DEFAULT ''",
            "delivery_adapter": "TEXT NOT NULL DEFAULT ''",
            "delivery_source": "TEXT NOT NULL DEFAULT ''",
            "candidate_origin": "TEXT NOT NULL DEFAULT ''",
            "auth_scope": "TEXT NOT NULL DEFAULT ''",
            "session_generation": "TEXT NOT NULL DEFAULT 'public'",
            "deduplicated_to_attempt_id": "TEXT NOT NULL DEFAULT ''",
            "resume_action": "TEXT NOT NULL DEFAULT ''",
        }
        connection.execute("BEGIN IMMEDIATE")
        try:
            present_runs = self._table_columns(connection, "runs")
            for name, declaration in run_columns.items():
                if name not in present_runs:
                    connection.execute(f'ALTER TABLE runs ADD COLUMN "{name}" {declaration}')
            present_attempts = self._table_columns(connection, "attempts")
            for name, declaration in attempt_columns.items():
                if name not in present_attempts:
                    connection.execute(f'ALTER TABLE attempts ADD COLUMN "{name}" {declaration}')
            for statement in self._schema_statements():
                connection.execute(statement)
            now = utc_now()
            connection.execute(
                """
                UPDATE runs
                SET lifecycle_status = CASE
                        WHEN finished_at IS NULL OR finished_at='' THEN 'interrupted'
                        ELSE 'finalized'
                    END,
                    completion_status = CASE
                        WHEN finished_at IS NOT NULL AND finished_at<>''
                             AND status IN ('complete','partial','failed') THEN status
                        ELSE ''
                    END,
                    finalized_at = CASE
                        WHEN finished_at IS NOT NULL THEN COALESCE(finished_at, '')
                        ELSE ''
                    END,
                    status = CASE
                        WHEN finished_at IS NULL OR finished_at='' THEN 'partial'
                        ELSE status
                    END,
                    termination_reason = CASE
                        WHEN finished_at IS NULL OR finished_at='' THEN 'legacy_unfingerprinted_run'
                        ELSE termination_reason
                    END,
                    heartbeat_at = CASE WHEN heartbeat_at='' THEN ? ELSE heartbeat_at END
                """,
                (now,),
            )
            connection.execute(
                "INSERT OR REPLACE INTO ledger_meta(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )
            connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _prepare(self) -> None:
        with self._lock:
            connection = self._connect()
            try:
                meta_version = ""
                try:
                    row = connection.execute(
                        "SELECT value FROM ledger_meta WHERE key='schema_version'"
                    ).fetchone()
                    meta_version = str(row[0]) if row else ""
                except sqlite3.Error:
                    meta_version = ""
                if meta_version == "2":
                    self._migrate_v2_to_v3(connection)
                if self._schema_requires_rebuild(connection):
                    self._migrate_legacy_v2_tables(connection)
                with connection:
                    for statement in self._schema_statements():
                        connection.execute(statement)
                    connection.execute(
                        "INSERT OR REPLACE INTO ledger_meta(key, value) VALUES('schema_version', ?)",
                        (str(self.SCHEMA_VERSION),),
                    )
                    connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            finally:
                connection.close()

    def fingerprint_salt(self) -> bytes:
        # The salt is part of the logical run identity.  Initializing it with a
        # read followed by INSERT OR REPLACE lets two first-time processes
        # calculate different fingerprints for the same ledger.  Serialize the
        # read/create/read sequence and always return the value that won in the
        # database.
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT value FROM ledger_meta WHERE key='fingerprint_salt'"
                ).fetchone()
                if row is None:
                    proposed = os.urandom(32).hex()
                    connection.execute(
                        "INSERT INTO ledger_meta(key, value) VALUES('fingerprint_salt', ?) "
                        "ON CONFLICT(key) DO NOTHING",
                        (proposed,),
                    )
                    row = connection.execute(
                        "SELECT value FROM ledger_meta WHERE key='fingerprint_salt'"
                    ).fetchone()
                encoded = str(row[0] or "") if row is not None else ""
                if not re.fullmatch(r"[0-9a-f]{64}", encoded):
                    raise RuntimeError("download_fingerprint_salt_invalid")
                connection.commit()
                return bytes.fromhex(encoded)
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def has_unfinished_runs(self) -> bool:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM runs WHERE finalized_at='' AND lifecycle_status NOT IN ('finalized','abandoned') LIMIT 1"
            ).fetchone()
        return row is not None

    @staticmethod
    def _lease_now() -> tuple[str, float]:
        return utc_now(), time.time()

    def start_or_resume_run(
        self,
        run_fingerprint: str,
        fingerprint_payload: Mapping[str, Any],
        config: "DownloadConfig",
        *,
        resume_policy: str = "auto",
        requested_run_id: str = "",
        report_path: Path | None = None,
    ) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{64}", str(run_fingerprint or "")):
            raise ValueError("run_fingerprint must be a lowercase SHA-256 digest")
        if resume_policy not in {"auto", "no_resume", "force"}:
            raise ValueError(f"Unsupported resume policy: {resume_policy}")
        now_text, now_epoch = self._lease_now()
        invocation_id = uuid.uuid4().hex
        resumed = False
        previous_lifecycle = ""
        abandoned_run_ids: list[str] = []
        payload_json = json.dumps(
            sanitize_nested_for_output(dict(fingerprint_payload)),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                lock_row = connection.execute(
                    "SELECT * FROM run_locks WHERE lock_key='download_state_writer'"
                ).fetchone()
                if lock_row is not None:
                    lease_expires = float(lock_row["lease_expires_at"] or 0)
                    if lease_expires > now_epoch and str(lock_row["owner_token"] or "") != self._owner_token:
                        raise RuntimeError("download_state_busy")
                    stale_invocation = str(lock_row["invocation_id"] or "")
                    stale_run = str(lock_row["run_id"] or "")
                    connection.execute(
                        "UPDATE run_invocations SET status='interrupted', finished_at=? WHERE invocation_id=? AND status='running'",
                        (now_text, stale_invocation),
                    )
                    connection.execute(
                        "UPDATE runs SET lifecycle_status=CASE WHEN lifecycle_status='finalizing' THEN 'finalizing' ELSE 'interrupted' END, "
                        "status=CASE WHEN lifecycle_status='finalizing' THEN status ELSE 'partial' END, "
                        "heartbeat_at=?, termination_reason='stale_writer_lease' "
                        "WHERE run_id=? AND finalized_at=''",
                        (now_text, stale_run),
                    )
                    connection.execute(
                        "DELETE FROM run_locks WHERE lock_key='download_state_writer'"
                    )

                stale_rows = connection.execute(
                    "SELECT run_id FROM runs WHERE finalized_at='' AND run_fingerprint<>'' AND run_fingerprint<>?",
                    (run_fingerprint,),
                ).fetchall()
                for row in stale_rows:
                    abandoned_run_ids.append(str(row[0]))
                if abandoned_run_ids:
                    placeholders = ",".join("?" for _ in abandoned_run_ids)
                    connection.execute(
                        f"UPDATE runs SET lifecycle_status='abandoned', completion_status='partial', "
                        f"status='partial', finished_at=?, finalized_at=?, termination_reason='fingerprint_changed' "
                        f"WHERE run_id IN ({placeholders})",
                        (now_text, now_text, *abandoned_run_ids),
                    )

                if resume_policy in {"no_resume", "force"}:
                    same_fingerprint_rows = connection.execute(
                        "SELECT run_id FROM runs WHERE finalized_at='' AND run_fingerprint=?",
                        (run_fingerprint,),
                    ).fetchall()
                    same_fingerprint_ids = [str(row[0]) for row in same_fingerprint_rows]
                    if same_fingerprint_ids:
                        placeholders = ",".join("?" for _ in same_fingerprint_ids)
                        connection.execute(
                            f"UPDATE runs SET lifecycle_status='abandoned', completion_status='partial', "
                            f"status='partial', finished_at=?, finalized_at=?, termination_reason=? "
                            f"WHERE run_id IN ({placeholders})",
                            (
                                now_text,
                                now_text,
                                f"{resume_policy}_new_run",
                                *same_fingerprint_ids,
                            ),
                        )
                        abandoned_run_ids.extend(
                            run_id
                            for run_id in same_fingerprint_ids
                            if run_id not in abandoned_run_ids
                        )

                selected = None
                if resume_policy == "auto":
                    selected = connection.execute(
                        """
                        SELECT * FROM runs
                        WHERE run_fingerprint=? AND finalized_at=''
                          AND lifecycle_status IN ('planning','running','interrupted','finalizing')
                        ORDER BY started_at DESC LIMIT 1
                        """,
                        (run_fingerprint,),
                    ).fetchone()
                if selected is not None:
                    run_id = str(selected["run_id"])
                    previous_lifecycle = str(selected["lifecycle_status"] or "")
                    resumed = True
                    if previous_lifecycle == "finalizing":
                        connection.execute(
                            """
                            UPDATE runs SET resume_policy='auto',
                                resume_count=resume_count+1, heartbeat_at=?,
                                termination_reason=''
                            WHERE run_id=?
                            """,
                            (now_text, run_id),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE runs SET lifecycle_status='running', status='running',
                                resume_policy='auto', resume_count=resume_count+1,
                                heartbeat_at=?, termination_reason=''
                            WHERE run_id=?
                            """,
                            (now_text, run_id),
                        )
                else:
                    run_id = requested_run_id or uuid.uuid4().hex
                    connection.execute(
                        """
                        INSERT INTO runs(
                            run_id, started_at, finished_at, status, input_contract,
                            config_json, report_path, run_fingerprint,
                            fingerprint_schema_version, fingerprint_payload_json,
                            lifecycle_status, completion_status, resume_policy,
                            resume_count, heartbeat_at, finalizing_at, finalized_at,
                            report_sha256, termination_reason
                        ) VALUES(?, ?, NULL, 'running', ?, ?, ?, ?, ?, ?,
                                 'planning', '', ?, 0, ?, '', '', '', '')
                        """,
                        (
                            run_id,
                            now_text,
                            config.input_contract,
                            json.dumps(sanitize_config(config), ensure_ascii=False, sort_keys=True),
                            relpath(report_path) if report_path is not None else "",
                            run_fingerprint,
                            DOWNLOAD_FINGERPRINT_SCHEMA_VERSION,
                            payload_json,
                            resume_policy,
                            now_text,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO run_invocations(
                        invocation_id, run_id, owner_token, resume_mode,
                        started_at, finished_at, heartbeat_at, status
                    ) VALUES(?, ?, ?, ?, ?, '', ?, 'running')
                    """,
                    (
                        invocation_id,
                        run_id,
                        self._owner_token,
                        "resumed" if resumed else "fresh",
                        now_text,
                        now_text,
                    ),
                )
                connection.execute(
                    """
                    INSERT OR REPLACE INTO run_locks(
                        lock_key, run_id, invocation_id, owner_token,
                        heartbeat_at, lease_expires_at
                    ) VALUES('download_state_writer', ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        invocation_id,
                        self._owner_token,
                        now_text,
                        now_epoch + DOWNLOAD_RUN_LEASE_SECONDS,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        self.active_run_id = run_id
        self.active_invocation_id = invocation_id
        self._start_heartbeat()
        return {
            "run_id": run_id,
            "invocation_id": invocation_id,
            "resumed": resumed,
            "resume_policy": resume_policy,
            "previous_lifecycle": previous_lifecycle,
            "completion_status": (
                str(selected["completion_status"] or "")
                if selected is not None
                else ""
            ),
            "abandoned_run_ids": abandoned_run_ids,
        }

    def start_run(self, run_id: str, config: "DownloadConfig") -> None:
        """Compatibility wrapper for callers that do not yet supply a fingerprint."""

        fingerprint = hashlib.sha256(f"legacy\0{run_id}".encode("utf-8")).hexdigest()
        self.start_or_resume_run(
            fingerprint,
            {"compatibility_start_run": True, "run_id": run_id},
            config,
            resume_policy="no_resume",
            requested_run_id=run_id,
        )

    def _heartbeat_once(self) -> bool:
        if not self.active_run_id or not self.active_invocation_id:
            return False
        with self._lock, self._connection() as connection:
            try:
                self._assert_writer_lease(connection, self.active_run_id)
            except RuntimeError as exc:
                if str(exc) != "download_state_lease_lost":
                    raise
                return False
            now_text, now_epoch = self._lease_now()
            connection.execute(
                "UPDATE run_locks SET heartbeat_at=?, lease_expires_at=? "
                "WHERE lock_key='download_state_writer' AND run_id=? "
                "AND invocation_id=? AND owner_token=?",
                (
                    now_text,
                    now_epoch + DOWNLOAD_RUN_LEASE_SECONDS,
                    self.active_run_id,
                    self.active_invocation_id,
                    self._owner_token,
                ),
            )
            connection.execute(
                "UPDATE run_invocations SET heartbeat_at=? WHERE invocation_id=? AND owner_token=?",
                (now_text, self.active_invocation_id, self._owner_token),
            )
            connection.execute(
                "UPDATE runs SET heartbeat_at=? WHERE run_id=?",
                (now_text, self.active_run_id),
            )
        return True

    def _start_heartbeat(self) -> None:
        self._heartbeat_stop.clear()

        def run() -> None:
            while not self._heartbeat_stop.wait(DOWNLOAD_RUN_HEARTBEAT_SECONDS):
                try:
                    if not self._heartbeat_once():
                        return
                except Exception:
                    # The owner check at every state-changing transaction still
                    # prevents a process that lost its lease from finalizing.
                    continue

        self._heartbeat_thread = Thread(
            target=run,
            name="laps-download-ledger-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def begin_finalization(
        self,
        run_id: str,
        status: str,
        report_path: Path | None = None,
    ) -> None:
        if status not in {"complete", "partial", "failed"}:
            raise ValueError(f"Invalid completion status: {status}")
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, run_id)
            connection.execute(
                "UPDATE runs SET lifecycle_status='finalizing', completion_status=?, status=?, "
                "finalizing_at=?, report_path=CASE WHEN ?<>'' THEN ? ELSE report_path END WHERE run_id=?",
                (
                    status,
                    status,
                    utc_now(),
                    relpath(report_path) if report_path is not None else "",
                    relpath(report_path) if report_path is not None else "",
                    run_id,
                ),
            )

    def finalization_report_evidence(
        self,
        run_id: str,
        report_path: Path,
    ) -> dict[str, Any]:
        """Validate a report left after the atomic materialization phase."""

        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT run_fingerprint, completion_status, lifecycle_status FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
        if row is None or str(row["lifecycle_status"] or "") != "finalizing":
            return {"complete": False, "reason_code": "run_not_finalizing"}
        if not report_path.is_file():
            return {"complete": False, "reason_code": "finalization_report_missing"}
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            return {"complete": False, "reason_code": "finalization_report_invalid"}
        if not isinstance(payload, dict):
            return {"complete": False, "reason_code": "finalization_report_invalid"}
        expected = {
            "run_id": run_id,
            "run_fingerprint": str(row["run_fingerprint"] or ""),
            "status": str(row["completion_status"] or ""),
        }
        for key, value in expected.items():
            if not hmac.compare_digest(str(payload.get(key) or ""), value):
                return {
                    "complete": False,
                    "reason_code": f"finalization_report_{key}_mismatch",
                }
        output_files = payload.get("output_files")
        if not isinstance(output_files, Mapping):
            return {"complete": False, "reason_code": "finalization_outputs_missing"}
        required = (
            "literature_download_success_list.csv",
            "literature_download_failure_list.csv",
            "patents_download_success_list.csv",
            "patents_download_failure_list.csv",
            "download_attempts.csv",
            "download_summary.csv",
            "input_migration_report.v2.json",
        )
        for name in required:
            evidence = output_files.get(name)
            if not isinstance(evidence, Mapping):
                return {"complete": False, "reason_code": "finalization_outputs_missing"}
            candidate = report_path.parent / name
            if not candidate.is_file():
                return {"complete": False, "reason_code": "finalization_output_missing"}
            try:
                if int(evidence.get("size_bytes") or -1) != candidate.stat().st_size:
                    return {"complete": False, "reason_code": "finalization_output_size_mismatch"}
                expected_sha = str(evidence.get("sha256") or "")
                if not re.fullmatch(r"[0-9a-f]{64}", expected_sha) or not hmac.compare_digest(
                    sha256_file(candidate), expected_sha
                ):
                    return {"complete": False, "reason_code": "finalization_output_digest_mismatch"}
            except OSError:
                return {"complete": False, "reason_code": "finalization_output_unreadable"}
        return {
            "complete": True,
            "reason_code": "finalization_report_verified",
            "status": str(row["completion_status"] or ""),
            "report_sha256": sha256_file(report_path),
        }

    def _assert_writer_lease(self, connection: sqlite3.Connection, run_id: str) -> None:
        # BEGIN IMMEDIATE is the fencing boundary: the lease is checked while
        # holding the same SQLite writer lock as the state change that follows.
        # A stale owner therefore cannot pass the check and race a takeover.
        if not connection.in_transaction:
            connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT run_id, invocation_id, owner_token, lease_expires_at "
            "FROM run_locks WHERE lock_key='download_state_writer'"
        ).fetchone()
        if (
            row is None
            or str(row["run_id"] or "") != run_id
            or not self.active_invocation_id
            or str(row["invocation_id"] or "") != self.active_invocation_id
            or not hmac.compare_digest(str(row["owner_token"] or ""), self._owner_token)
            or float(row["lease_expires_at"] or 0) <= time.time()
        ):
            raise RuntimeError("download_state_lease_lost")

    def _assert_maintenance_write_allowed(
        self, connection: sqlite3.Connection
    ) -> None:
        """Fence a ledger repair that is valid only while no writer is active."""

        if not connection.in_transaction:
            connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT lease_expires_at FROM run_locks "
            "WHERE lock_key='download_state_writer'"
        ).fetchone()
        if row is not None and float(row["lease_expires_at"] or 0) > time.time():
            raise RuntimeError("download_state_busy")

    def finish_run(self, run_id: str, status: str, report_path: Path) -> None:
        if status not in {"complete", "partial", "failed"}:
            raise ValueError(f"Invalid completion status: {status}")
        if not report_path.is_file():
            raise RuntimeError("finalization_report_missing")
        report_digest = sha256_file(report_path)
        now = utc_now()
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, run_id)
            connection.execute(
                """
                UPDATE runs SET finished_at=?, status=?, report_path=?,
                    lifecycle_status='finalized', completion_status=?,
                    finalized_at=?, report_sha256=?, termination_reason=''
                WHERE run_id=?
                """,
                (now, status, relpath(report_path), status, now, report_digest, run_id),
            )
            connection.execute(
                "UPDATE run_invocations SET finished_at=?, heartbeat_at=?, status='finished' WHERE invocation_id=?",
                (now, now, self.active_invocation_id),
            )
            connection.execute(
                "DELETE FROM run_locks WHERE lock_key='download_state_writer' AND owner_token=?",
                (self._owner_token,),
            )
        self._stop_heartbeat()

    def interrupt_run(self, run_id: str, reason: str) -> None:
        now = utc_now()
        try:
            with self._lock, self._connection() as connection:
                self._assert_writer_lease(connection, run_id)
                connection.execute(
                    "UPDATE runs SET lifecycle_status=CASE WHEN lifecycle_status='finalizing' THEN 'finalizing' ELSE 'interrupted' END, "
                    "status=CASE WHEN lifecycle_status='finalizing' THEN status ELSE 'partial' END, "
                    "heartbeat_at=?, termination_reason=? "
                    "WHERE run_id=? AND finalized_at=''",
                    (now, sanitize_text_for_output(reason), run_id),
                )
                connection.execute(
                    "UPDATE run_invocations SET finished_at=?, heartbeat_at=?, status='interrupted' WHERE invocation_id=?",
                    (now, now, self.active_invocation_id),
                )
                connection.execute(
                    "DELETE FROM run_locks WHERE lock_key='download_state_writer' "
                    "AND run_id=? AND invocation_id=? AND owner_token=?",
                    (
                        run_id,
                        self.active_invocation_id,
                        self._owner_token,
                    ),
                )
        except RuntimeError as exc:
            if str(exc) != "download_state_lease_lost":
                raise
            # A successor owns the logical run now.  This invocation may stop
            # its local heartbeat, but must not annotate or unlock that owner.
        finally:
            self._stop_heartbeat()

    def _stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread.is_alive() and thread is not current_thread():
            thread.join(timeout=2)
        self._heartbeat_thread = None

    def close(self) -> None:
        self._stop_heartbeat()

    def store_run_plan(
        self,
        run_id: str,
        rows_by_type: Mapping[str, list[dict[str, Any]]],
    ) -> None:
        """Persist the exact filtered planner rows consumed by a logical run."""

        planned: list[tuple[str, str, int, str, str]] = []
        ordinal = 0
        for record_type in ("literature", "patent"):
            for row in rows_by_type.get(record_type, []):
                record_id = str(row.get("record_id") or stable_record_id(record_type, row))
                row_json = json.dumps(
                    sanitize_nested_for_output(row),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                digest = hashlib.sha256(row_json.encode("utf-8")).hexdigest()
                planned.append((record_id, record_type, ordinal, digest, row_json))
                ordinal += 1
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, run_id)
            existing = connection.execute(
                "SELECT record_id, input_ordinal, input_digest FROM run_records WHERE run_id=? ORDER BY input_ordinal",
                (run_id,),
            ).fetchall()
            expected = [(item[0], item[2], item[3]) for item in planned]
            actual = [
                (str(row["record_id"]), int(row["input_ordinal"]), str(row["input_digest"]))
                for row in existing
            ]
            if actual and actual != expected:
                raise RuntimeError("resume_input_plan_mismatch")
            if not actual:
                connection.executemany(
                    """
                    INSERT INTO run_records(
                        run_id, record_id, input_ordinal, input_digest,
                        planner_row_json, state, artifact_id, failure_reason,
                        completion_sequence, started_at, finished_at
                    ) VALUES(?, ?, ?, ?, ?, 'pending', '', '', NULL, '', '')
                    """,
                    [
                        (run_id, record_id, item_ordinal, digest, row_json)
                        for record_id, _record_type, item_ordinal, digest, row_json in planned
                    ],
                )
            connection.execute(
                "UPDATE runs SET lifecycle_status=CASE WHEN lifecycle_status='finalizing' THEN 'finalizing' ELSE 'running' END, heartbeat_at=? WHERE run_id=?",
                (utc_now(), run_id),
            )

    def run_record_snapshots(self, run_id: str) -> list[dict[str, Any]]:
        """Return immutable planner/progress rows for report-only recovery."""

        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT rr.*, records.record_type, records.last_status,
                       artifacts.path AS artifact_path,
                       artifacts.size_bytes AS artifact_size_bytes,
                       artifacts.sha256 AS artifact_sha256,
                       artifacts.valid AS artifact_valid
                FROM run_records rr
                LEFT JOIN records ON records.record_id=rr.record_id
                LEFT JOIN artifacts ON artifacts.artifact_id=rr.artifact_id
                WHERE rr.run_id=?
                ORDER BY CASE WHEN rr.completion_sequence IS NULL THEN 1 ELSE 0 END,
                         rr.completion_sequence, rr.input_ordinal
                """,
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def run_plan_rows(self, run_id: str, record_type: str) -> list[dict[str, Any]]:
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT rr.planner_row_json
                FROM run_records rr
                WHERE rr.run_id=?
                  AND json_extract(rr.planner_row_json, '$.record_type')=?
                ORDER BY rr.input_ordinal
                """,
                (run_id, record_type),
            ).fetchall()
        return [json.loads(str(row[0])) for row in rows]

    def mark_record_started(self, run_id: str, record_id: str) -> None:
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, run_id)
            connection.execute(
                "UPDATE run_records SET state='running', started_at=? WHERE run_id=? AND record_id=? AND state<>'success'",
                (utc_now(), run_id, record_id),
            )

    def mark_record_result(self, result: "DownloadResult") -> None:
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, result.run_id)
            sequence = connection.execute(
                "SELECT COALESCE(MAX(completion_sequence), 0) + 1 FROM run_records WHERE run_id=?",
                (result.run_id,),
            ).fetchone()[0]
            connection.execute(
                """
                UPDATE run_records
                SET state=?, failure_reason=?, finished_at=?,
                    completion_sequence=COALESCE(completion_sequence, ?)
                WHERE run_id=? AND record_id=?
                """,
                (
                    result.status or "failed",
                    sanitize_text_for_output(result.failure_reason),
                    utc_now(),
                    int(sequence or 1),
                    result.run_id,
                    result.record_id,
                ),
            )

    def resumable_record_state(self, run_id: str, record_id: str) -> str:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT state FROM run_records WHERE run_id=? AND record_id=?",
                (run_id, record_id),
            ).fetchone()
        return str(row[0]) if row else "pending"

    def run_snapshot(self, run_id: str) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
            invocation = connection.execute(
                "SELECT * FROM run_invocations WHERE run_id=? ORDER BY started_at DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            resume_reasons = {
                str(item[0]): int(item[1])
                for item in connection.execute(
                    """
                    SELECT COALESCE(resume_action, ''), COUNT(*)
                    FROM attempts WHERE run_id=? AND resume_action<>''
                    GROUP BY resume_action
                    """,
                    (run_id,),
                )
            }
        payload = dict(row) if row is not None else {}
        payload["latest_invocation"] = dict(invocation) if invocation is not None else {}
        payload["resume_reason_counts"] = resume_reasons
        payload.pop("fingerprint_payload_json", None)
        payload.pop("config_json", None)
        return sanitize_nested_for_output(payload)

    def upsert_record(self, result: "DownloadResult") -> None:
        canonical = result.original_row.get("_canonical_record")
        if isinstance(canonical, str):
            try:
                canonical = json.loads(canonical)
            except Exception:
                canonical = {}
        canonical_json = json.dumps(
            sanitize_nested_for_output(canonical or {}),
            ensure_ascii=False,
            sort_keys=True,
        )
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, result.run_id)
            connection.execute(
                """
                INSERT INTO records(record_id, record_type, title, doi, publication_number, metadata_sources_json, canonical_json, last_status, updated_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    title=excluded.title,
                    doi=excluded.doi,
                    publication_number=excluded.publication_number,
                    metadata_sources_json=excluded.metadata_sources_json,
                    canonical_json=excluded.canonical_json,
                    last_status=excluded.last_status,
                    updated_at=excluded.updated_at
                """,
                (
                    result.record_id,
                    result.record_type,
                    result.title,
                    result.doi,
                    result.publication_number,
                    json.dumps(result.metadata_sources, ensure_ascii=False),
                    canonical_json,
                    result.status or "pending",
                    utc_now(),
                ),
            )

    def append_attempt(self, attempt: "DownloadAttempt") -> None:
        if not attempt.record_id or not attempt.run_id:
            return
        payload = sanitize_nested_for_output(attempt.__dict__)
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, attempt.run_id)
            connection.execute(
                """
                INSERT OR IGNORE INTO runs(
                    run_id, started_at, finished_at, status, input_contract,
                    config_json, report_path
                ) VALUES(?, ?, NULL, 'running', 'unknown', '{}', '')
                """,
                (attempt.run_id, attempt.created_at or utc_now()),
            )
            # Attempts are persisted at creation time, before record workers
            # return.  Seed the FK row so a process kill cannot erase evidence
            # merely because the aggregate DownloadResult was never produced.
            connection.execute(
                """
                INSERT INTO records(record_id, record_type, title, doi, publication_number,
                                    metadata_sources_json, canonical_json, last_status, updated_at)
                VALUES(?, ?, ?, ?, ?, ?, '{}', 'running', ?)
                ON CONFLICT(record_id) DO UPDATE SET updated_at=excluded.updated_at
                """,
                (
                    attempt.record_id,
                    attempt.record_type,
                    attempt.title,
                    attempt.doi,
                    attempt.publication_number,
                    json.dumps(
                        [
                            value.strip()
                            for value in attempt.metadata_sources.split(";")
                            if value.strip()
                        ],
                        ensure_ascii=False,
                    ),
                    utc_now(),
                ),
            )

            connection.execute(
                """
                INSERT OR REPLACE INTO attempts(
                    attempt_id, run_id, record_id, planned_channel, executed_adapter,
                    resolver_channel, candidate_id, stage, status, reason_code,
                    reason_category, retryable, retry_at, http_status,
                    sanitized_target, created_at, payload_json, invocation_id,
                    observation_id, execution_key, locator_id, locator_source,
                    discovery_source, discovery_adapter, delivery_adapter,
                    delivery_source, candidate_origin, auth_scope,
                    session_generation, deduplicated_to_attempt_id, resume_action
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.attempt_id,
                    attempt.run_id,
                    attempt.record_id,
                    attempt.planned_channel or attempt.channel,
                    attempt.executed_adapter,
                    attempt.resolver_channel,
                    attempt.candidate_id,
                    attempt.stage,
                    attempt.attempt_status,
                    attempt.reason_code or attempt.reason,
                    attempt.reason_category,
                    int(attempt.retryable),
                    attempt.retry_at,
                    attempt.http_status,
                    attempt.channel_url_or_api,
                    attempt.created_at,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    attempt.invocation_id,
                    attempt.observation_id,
                    attempt.execution_key,
                    attempt.locator_id,
                    attempt.locator_source,
                    attempt.discovery_source,
                    attempt.discovery_adapter,
                    attempt.delivery_adapter,
                    attempt.delivery_source,
                    attempt.candidate_origin,
                    attempt.auth_scope,
                    attempt.session_generation,
                    attempt.deduplicated_to_attempt_id,
                    attempt.resume_action,
                ),
            )
            if attempt.execution_key and not attempt.deduplicated_to_attempt_id:
                previous_claim = connection.execute(
                    """
                    SELECT last_attempt_id FROM candidate_states
                    WHERE run_id=? AND record_id=? AND execution_key=?
                    """,
                    (
                        attempt.run_id,
                        attempt.record_id,
                        attempt.execution_key,
                    ),
                ).fetchone()
                claim_marker = (
                    str(previous_claim[0] or "")
                    if previous_claim is not None
                    else ""
                )
                if claim_marker.startswith("claim:"):
                    connection.execute(
                        """
                        UPDATE attempts
                        SET deduplicated_to_attempt_id=?
                        WHERE run_id=? AND record_id=? AND execution_key=?
                          AND deduplicated_to_attempt_id=?
                        """,
                        (
                            attempt.attempt_id,
                            attempt.run_id,
                            attempt.record_id,
                            attempt.execution_key,
                            claim_marker,
                        ),
                    )
                connection.execute(
                    """
                    UPDATE candidate_states
                    SET state=?, retryable=?, retry_at=?, last_attempt_id=?, updated_at=?
                    WHERE run_id=? AND record_id=? AND execution_key=?
                    """,
                    (
                        attempt.attempt_status or "started",
                        int(attempt.retryable),
                        attempt.retry_at,
                        attempt.attempt_id,
                        attempt.created_at or utc_now(),
                        attempt.run_id,
                        attempt.record_id,
                        attempt.execution_key,
                    ),
                )

    def attempts_for_run(self, run_id: str) -> list[dict[str, Any]]:
        """Return the authoritative attempt stream, including interrupted workers."""

        if not run_id:
            return []
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT payload_json, attempt_id, record_id, planned_channel,
                       executed_adapter, resolver_channel, candidate_id, stage,
                       status, reason_code, reason_category, retryable,
                       retry_at, http_status, sanitized_target, created_at,
                       invocation_id, observation_id, execution_key, locator_id,
                       locator_source, discovery_source, discovery_adapter,
                       delivery_adapter, delivery_source, candidate_origin,
                       auth_scope, session_generation, deduplicated_to_attempt_id,
                       resume_action
                FROM attempts
                WHERE run_id=?
                ORDER BY created_at, rowid
                """,
                (run_id,),
            ).fetchall()
        attempts: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"] or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            fallback = {
                "run_id": run_id,
                "record_id": str(row["record_id"] or ""),
                "planned_channel": str(row["planned_channel"] or ""),
                "channel": str(row["planned_channel"] or ""),
                "executed_adapter": str(row["executed_adapter"] or ""),
                "resolver_channel": str(row["resolver_channel"] or ""),
                "candidate_id": str(row["candidate_id"] or ""),
                "attempt_id": str(row["attempt_id"] or ""),
                "stage": str(row["stage"] or ""),
                "attempt_status": str(row["status"] or ""),
                "reason": str(row["reason_code"] or ""),
                "reason_code": str(row["reason_code"] or ""),
                "reason_category": str(row["reason_category"] or ""),
                "retryable": bool(row["retryable"]),
                "retry_at": str(row["retry_at"] or ""),
                "http_status": str(row["http_status"] or ""),
                "channel_url_or_api": str(row["sanitized_target"] or ""),
                "created_at": str(row["created_at"] or ""),
                "invocation_id": str(row["invocation_id"] or ""),
                "observation_id": str(row["observation_id"] or ""),
                "execution_key": str(row["execution_key"] or ""),
                "locator_id": str(row["locator_id"] or ""),
                "locator_source": str(row["locator_source"] or ""),
                "discovery_source": str(row["discovery_source"] or ""),
                "discovery_adapter": str(row["discovery_adapter"] or ""),
                "delivery_adapter": str(row["delivery_adapter"] or ""),
                "delivery_source": str(row["delivery_source"] or ""),
                "candidate_origin": str(row["candidate_origin"] or ""),
                "auth_scope": str(row["auth_scope"] or ""),
                "session_generation": str(row["session_generation"] or "public"),
                "deduplicated_to_attempt_id": str(row["deduplicated_to_attempt_id"] or ""),
                "resume_action": str(row["resume_action"] or ""),
            }
            payload.update(fallback)
            attempts.append(sanitize_nested_for_output(payload))
        return attempts

    def valid_artifact_path(
        self,
        record_id: str,
        record_type: str = "",
    ) -> Path | None:
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT artifacts.artifact_id, artifacts.path,
                       artifacts.size_bytes, artifacts.sha256
                FROM artifacts
                LEFT JOIN records ON records.record_id=artifacts.record_id
                WHERE artifacts.record_id=? AND artifacts.valid=1
                  AND (?='' OR records.record_type=?)
                ORDER BY artifacts.created_at DESC, artifacts.rowid DESC
                """,
                (record_id, record_type, record_type),
            ).fetchall()
        for row in rows:
            candidate = Path(str(row["path"] or ""))
            if not candidate.is_absolute():
                candidate = ROOT_DIR / candidate
            expected_digest = str(row["sha256"] or "").strip().casefold()
            try:
                expected_size = int(row["size_bytes"])
            except (TypeError, ValueError):
                expected_size = 0
            integrity_matches = False
            try:
                actual_size = (
                    candidate.stat().st_size
                    if candidate.is_file() and not candidate.is_symlink()
                    else -1
                )
                integrity_matches = bool(
                    expected_size > 0
                    and expected_size <= max_pdf_bytes()
                    and actual_size == expected_size
                    and re.fullmatch(r"[0-9a-f]{64}", expected_digest)
                    and sha256_file(candidate).casefold() == expected_digest
                    and is_valid_pdf(candidate)
                )
            except (OSError, ValueError):
                integrity_matches = False
            if integrity_matches:
                return candidate
            with self._lock, self._connection() as connection:
                if self.active_run_id:
                    self._assert_writer_lease(connection, self.active_run_id)
                else:
                    self._assert_maintenance_write_allowed(connection)
                connection.execute(
                    "UPDATE artifacts SET valid=0 WHERE artifact_id=?",
                    (str(row["artifact_id"]),),
                )
        return None

    def claim_candidate(
        self,
        *,
        record_id: str,
        record_type: str,
        planned_channel: str,
        candidate: DownloadCandidate,
        stage: str,
        access_mode: str,
    ) -> dict[str, str]:
        """Persist every observation and atomically claim one network execution."""

        run_id = self.active_run_id or CURRENT_RUN_ID
        invocation_id = self.active_invocation_id or CURRENT_INVOCATION_ID
        if not run_id or not record_id:
            return {"action": "execute", "observation_id": "", "execution_key": ""}
        auth_scope = candidate.auth_scope if access_mode == "authenticated" else "public"
        session_generation = (
            candidate.auth_session_generation
            if access_mode == "authenticated"
            else "public"
        )
        execution_key = candidate_execution_key(
            record_id,
            stage,
            candidate,
            access_mode,
            auth_scope,
            session_generation,
        )
        observation_id = uuid.uuid4().hex
        now = utc_now()
        planned_order = 0
        try:
            planned_order = next(
                spec.order
                for spec in get_download_adapters(record_type)
                if spec.display_name == planned_channel
            )
        except StopIteration:
            planned_order = 0
        claim_marker = f"claim:{invocation_id}"
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, run_id)
            connection.execute(
                """
                INSERT INTO candidate_observations(
                    observation_id, run_id, record_id, planned_channel,
                    planned_order, locator_id, locator_source, discovery_source,
                    discovery_adapter, resolver_channel, candidate_origin,
                    execution_key, sanitized_target, access_mode, auth_scope,
                    session_generation, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    run_id,
                    record_id,
                    planned_channel,
                    planned_order,
                    candidate.locator_id,
                    candidate.locator_source,
                    candidate.discovery_source,
                    candidate.discovery_adapter,
                    candidate.resolver_channel,
                    candidate.candidate_origin,
                    execution_key,
                    candidate.sanitized_target,
                    access_mode,
                    auth_scope,
                    session_generation,
                    now,
                ),
            )
            existing = connection.execute(
                """
                SELECT state, stage, last_attempt_id, recovery_retry_count
                FROM candidate_states
                WHERE run_id=? AND record_id=? AND execution_key=?
                """,
                (run_id, record_id, execution_key),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO candidate_states(
                        run_id, record_id, execution_key, state, candidate_id,
                        planned_channel, stage, access_mode, auth_scope,
                        session_generation, retryable, retry_at, artifact_id,
                        last_attempt_id, recovery_retry_count, updated_at
                    ) VALUES(?, ?, ?, 'started', ?, ?, ?, ?, ?, ?, 0, '', '', ?, 0, ?)
                    """,
                    (
                        run_id,
                        record_id,
                        execution_key,
                        candidate_id_for_url(candidate),
                        planned_channel,
                        stage,
                        access_mode,
                        auth_scope,
                        session_generation,
                        claim_marker,
                        now,
                    ),
                )
                return {
                    "action": "execute",
                    "observation_id": observation_id,
                    "execution_key": execution_key,
                    "resume_action": "first_claim",
                }

            state = str(existing["state"] or "")
            last_attempt_id = str(existing["last_attempt_id"] or "")
            if last_attempt_id == claim_marker:
                return {
                    "action": "deduplicated",
                    "observation_id": observation_id,
                    "execution_key": execution_key,
                    "deduplicated_to_attempt_id": last_attempt_id,
                    "resume_action": "same_invocation_duplicate",
                }
            if (
                CURRENT_RUN_RESUMED
                and state in {"started", "running", "interrupted"}
                and str(existing["stage"] or "") == "candidate"
                and int(existing["recovery_retry_count"] or 0) < 1
            ):
                updated = connection.execute(
                    """
                    UPDATE candidate_states
                    SET last_attempt_id=?, recovery_retry_count=recovery_retry_count+1,
                        updated_at=?
                    WHERE run_id=? AND record_id=? AND execution_key=?
                      AND recovery_retry_count=0
                      AND state IN ('started', 'running', 'interrupted')
                    """,
                    (
                        claim_marker,
                        now,
                        run_id,
                        record_id,
                        execution_key,
                    ),
                )
                if updated.rowcount:
                    return {
                        "action": "execute",
                        "observation_id": observation_id,
                        "execution_key": execution_key,
                        "resume_action": "recovered_interrupted_candidate",
                    }
            return {
                "action": "deduplicated",
                "observation_id": observation_id,
                "execution_key": execution_key,
                "deduplicated_to_attempt_id": last_attempt_id,
                "resume_action": f"existing_{state or 'candidate'}",
            }

    def candidate_resume_decision(
        self,
        record_id: str,
        planned_channel: str,
        candidate_id: str,
        *,
        force: bool = False,
        run_id: str = "",
        execution_key: str = "",
        access_mode: str = "open",
        auth_scope: str = "public",
        session_generation: str = "public",
        resume_action: str = "",
    ) -> dict[str, str]:
        if force or not record_id or not candidate_id:
            return {"action": "attempt", "reason": ""}
        artifact = self.valid_artifact_path(record_id)
        if artifact is not None:
            return {
                "action": "reuse_artifact",
                "reason": "existing_valid_ledger_artifact",
                "path": str(artifact),
            }
        active_run = run_id or self.active_run_id
        if not active_run:
            return {"action": "attempt", "reason": ""}
        selected_execution_key = execution_key or hashlib.sha256(
            "\0".join(
                (
                    record_id,
                    candidate_id,
                    access_mode or "open",
                    auth_scope or "public",
                    session_generation or "public",
                )
            ).encode("utf-8")
        ).hexdigest()
        with self._lock, self._connection() as connection:
            state_row = connection.execute(
                """
                SELECT state AS status, '' AS reason_code, retryable, retry_at,
                       recovery_retry_count
                FROM candidate_states
                WHERE run_id=? AND record_id=? AND execution_key=?
                """,
                (active_run, record_id, selected_execution_key),
            ).fetchone()
            if state_row is not None:
                row = state_row
            else:
                row = connection.execute(
                    """
                    SELECT status, reason_code, retryable, retry_at, 0 AS recovery_retry_count
                    FROM attempts
                    WHERE run_id=? AND record_id=? AND planned_channel=? AND candidate_id=?
                      AND status IN ('success', 'failed', 'skipped')
                      AND stage IN ('candidate', 'challenge_retry', 'browser_cookie_retry')
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT 1
                    """,
                    (active_run, record_id, planned_channel, candidate_id),
                ).fetchone()
        if row is None or str(row["status"]) == "success":
            return {"action": "attempt", "reason": ""}
        if str(row["status"]) in {"started", "running", "interrupted"}:
            if (
                resume_action == "recovered_interrupted_candidate"
                and int(row["recovery_retry_count"] or 0) == 1
            ):
                return {
                    "action": "attempt",
                    "reason": "resume_interrupted_safe_retry",
                }
            if int(row["recovery_retry_count"] or 0) >= 1:
                return {
                    "action": "skip",
                    "reason": "resume_interrupted_retry_exhausted",
                }
            return {
                "action": "attempt",
                "reason": "resume_interrupted_safe_retry",
            }
        if not bool(row["retryable"]):
            return {
                "action": "skip",
                "reason": "resume_nonretryable_terminal_failure",
            }
        retry_at = str(row["retry_at"] or "").strip()
        if retry_at:
            try:
                retry_time = datetime.fromisoformat(retry_at.replace("Z", "+00:00"))
                if retry_time.tzinfo is None:
                    retry_time = retry_time.replace(tzinfo=timezone.utc)
                if retry_time > datetime.now(timezone.utc):
                    return {
                        "action": "skip",
                        "reason": "resume_retry_not_due",
                        "retry_at": retry_time.isoformat(timespec="seconds"),
                    }
            except ValueError:
                pass
        return {"action": "attempt", "reason": ""}

    def add_artifact(self, result: "DownloadResult", path: Path) -> None:
        artifact_id = hashlib.sha256(f"{result.record_id}\0{result.sha256}".encode("utf-8")).hexdigest()
        validation = {"validator": "laps_pdf_structural_v2", "valid": True}
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, result.run_id)
            connection.execute(
                """
                INSERT OR REPLACE INTO artifacts(artifact_id, record_id, run_id, path, size_bytes, sha256, valid, validation_json, created_at)
                VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    artifact_id,
                    result.record_id,
                    result.run_id,
                    relpath(path),
                    result.file_size_bytes,
                    result.sha256,
                    json.dumps(validation, sort_keys=True),
                    utc_now(),
                ),
            )
            connection.execute(
                "UPDATE run_records SET artifact_id=? WHERE run_id=? AND record_id=?",
                (artifact_id, result.run_id, result.record_id),
            )
            connection.execute(
                """
                UPDATE candidate_states
                SET artifact_id=?, updated_at=?
                WHERE run_id=? AND record_id=? AND state='success'
                """,
                (artifact_id, utc_now(), result.run_id, result.record_id),
            )

    def set_cooldown(self, scope_type: str, scope_key: str, reason_code: str, retry_at_epoch: float) -> None:
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, self.active_run_id)
            connection.execute(
                """
                INSERT INTO cooldowns(scope_type, scope_key, reason_code, retry_at_epoch, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(scope_type, scope_key) DO UPDATE SET
                    reason_code=excluded.reason_code,
                    retry_at_epoch=excluded.retry_at_epoch,
                    updated_at=excluded.updated_at
                """,
                (scope_type, scope_key.casefold(), reason_code, retry_at_epoch, utc_now()),
            )

    def cooldown_reason(self, scope_type: str, scope_key: str) -> str:
        now = time.time()
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT reason_code, retry_at_epoch FROM cooldowns WHERE scope_type=? AND scope_key=?",
                (scope_type, scope_key.casefold()),
            ).fetchone()
            if row is None:
                return ""
            if float(row["retry_at_epoch"]) <= now:
                if self.active_run_id:
                    self._assert_writer_lease(connection, self.active_run_id)
                    connection.execute(
                        "DELETE FROM cooldowns WHERE scope_type=? AND scope_key=?",
                        (scope_type, scope_key.casefold()),
                    )
                return ""
            return f"{scope_type}_cooldown:{row['reason_code']}:{int(float(row['retry_at_epoch']) - now)}s"

    def record_migration(self, source_contract: str, source_path: Path, report: dict[str, Any]) -> None:
        migration_id = hashlib.sha256(
            f"{source_contract}\0{source_path.resolve()}\0{source_path.stat().st_mtime_ns if source_path.exists() else 0}".encode("utf-8")
        ).hexdigest()
        with self._lock, self._connection() as connection:
            self._assert_writer_lease(connection, self.active_run_id)
            connection.execute(
                "INSERT OR IGNORE INTO migrations(migration_id, source_contract, source_path, report_json, created_at) VALUES(?, ?, ?, ?, ?)",
                (
                    migration_id,
                    sanitize_text_for_output(source_contract),
                    sanitize_text_for_output(source_path.resolve()),
                    json.dumps(
                        sanitize_nested_for_output(report),
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    utc_now(),
                ),
            )


@dataclass
class BrowserAuthResult:
    ok: bool
    reason: str
    state_reused: bool = False
    external_storage_state_path: str = ""
    legacy_seed_reused: bool = False
    auth_session_generation: str = ""


@dataclass
class AuthCheckTarget:
    record_type: str
    channel: str
    policy: dict[str, Any]


@dataclass
class ChallengeControlResult:
    action: str = "unhandled"
    reason: str = ""
    candidate_urls: list[str] = field(default_factory=list)
    storage_state_path: str = ""
    final_url: str = ""
    preflight_state: str = ""
    protocol_request: dict[str, Any] = field(default_factory=dict)
    legacy_sync: bool = False


@dataclass(frozen=True)
class ChannelLoginProfile:
    entry_url: str = ""
    success_domains: tuple[str, ...] = ()
    institution_selectors: tuple[str, ...] = ()
    institution_labels: tuple[str, ...] = ()
    federation_labels: tuple[str, ...] = ()
    school_selectors: tuple[str, ...] = ()
    strict_school_selectors: bool = False
    school_labels: tuple[str, ...] = ()
    user_selectors: tuple[str, ...] = ()
    password_selectors: tuple[str, ...] = ()
    submit_labels: tuple[str, ...] = ()
    success_markers: tuple[str, ...] = ()


GENERIC_INSTITUTION_LABELS = (
    "Institutional Login",
    "Institutional Sign In",
    "Sign in via institution",
    "Access through your institution",
    "Access through your organization",
    "Find your institution",
    "Find your organization",
    "University Login",
    "Shibboleth",
    "OpenAthens",
    "机构登录",
    "通过机构登录",
    "机构登入",
    "学校登录",
)
GENERIC_FEDERATION_LABELS = ("CARSI", "China CERNET Federation", "中国教育和科研计算机网", "CERNET")
GENERIC_SCHOOL_SELECTORS = (
    "input[type='search']",
    "input[placeholder*='institution' i]",
    "input[placeholder*='organization' i]",
    "input[placeholder*='university' i]",
    "input[placeholder*='school' i]",
    "input[placeholder*='机构']",
    "input[placeholder*='学校']",
    "input[aria-label*='institution' i]",
    "input[aria-label*='organization' i]",
    "input[aria-label*='school' i]",
    "input[type='text']",
)
GENERIC_USER_SELECTORS = (
    "input[type='email']",
    "input[name*='user' i]",
    "input[id*='user' i]",
    "input[name*='account' i]",
    "input[id*='account' i]",
    "input[name*='login' i]",
    "input[id*='login' i]",
    "input[name*='username' i]",
    "input[id*='username' i]",
    "input[placeholder*='账号']",
    "input[placeholder*='用户名']",
    "input[placeholder*='工号']",
    "input[type='text']",
)
GENERIC_PASSWORD_SELECTORS = (
    "input[type='password']",
    "input[name*='password' i]",
    "input[id*='password' i]",
    "input[placeholder*='密码']",
)
GENERIC_ACCOUNT_LOGIN_LABELS = (
    "账号登录",
    "账户登录",
    "密码登录",
    "用户名密码登录",
    "Account login",
    "Password login",
    "Username login",
    "Use password",
    "Sign in with password",
)
GENERIC_SUBMIT_LABELS = ("Sign in", "Log in", "Login", "Submit", "Continue", "登录", "确定", "继续")
GENERIC_SUCCESS_MARKERS = ("logout", "log out", "sign out", "my account", "access provided by", "institutional access", "signed in", "个人中心")


def profile(
    entry_url: str = "",
    *,
    success_domains: tuple[str, ...] = (),
    institution_selectors: tuple[str, ...] = (),
    institution_labels: tuple[str, ...] = (),
    federation_labels: tuple[str, ...] = (),
    school_selectors: tuple[str, ...] = (),
    strict_school_selectors: bool = False,
    school_labels: tuple[str, ...] = (),
    user_selectors: tuple[str, ...] = (),
    password_selectors: tuple[str, ...] = (),
    submit_labels: tuple[str, ...] = (),
    success_markers: tuple[str, ...] = (),
) -> ChannelLoginProfile:
    return ChannelLoginProfile(
        entry_url=entry_url,
        success_domains=success_domains,
        institution_selectors=institution_selectors,
        institution_labels=institution_labels,
        federation_labels=federation_labels,
        school_selectors=school_selectors,
        strict_school_selectors=strict_school_selectors,
        school_labels=school_labels,
        user_selectors=user_selectors,
        password_selectors=password_selectors,
        submit_labels=submit_labels,
        success_markers=success_markers,
    )


CHANNEL_LOGIN_PROFILES: dict[str, ChannelLoginProfile] = {
    "Sci-Hub": profile("https://www.scihub.net.cn/sci-hub/"),
    "doi_resolver": profile("https://doi.org/"),
    "Web of Science Starter API (Clarivate)": profile(
        "https://www.webofscience.com/wos/woscc/basic-search",
        success_domains=("webofscience.com",),
        institution_labels=("Institutional Sign In", "Sign in via institution", "Access through your institution", "机构登录"),
        success_markers=("sign out", "access provided by", "signed in"),
    ),
    "IEEE Xplore API": profile(
        "https://ieeexplore.ieee.org/search/searchresult.jsp",
        institution_selectors=("a.inst-sign-in",),
        institution_labels=("Institutional Sign In", "Access Through Your Institution", "Shibboleth", "OpenAthens"),
        school_selectors=("input[placeholder*='institution' i]", "input[aria-label*='institution' i]", "input[name*='institution' i]"),
        strict_school_selectors=True,
        success_markers=("sign out", "institutional access", "access provided by"),
    ),
    "Google Scholar": profile("https://scholar.google.com/scholar"),
    "OpenAlex API": profile("https://openalex.org/"),
    "Semantic Scholar API": profile("https://www.semanticscholar.org/"),
    "Crossref API": profile("https://search.crossref.org/"),
    "arXiv API": profile("https://arxiv.org/search/"),
    "The Lens (lens.org)": profile(
        "https://www.lens.org/",
        institution_labels=("Institutional Login", "Sign in", "Login"),
        success_markers=("sign out", "signed in"),
    ),
    "Elsevier": profile(
        "https://www.sciencedirect.com/search",
        institution_labels=("Sign in via your institution", "Institutional sign in", "Access through your institution", "Sign in"),
        success_markers=("sign out", "access provided by", "signed in"),
    ),
    "SpringerLink": profile(
        "https://wayf.springernature.com/?redirect_uri=https%3A%2F%2Flink.springer.com%2F",
        institution_labels=("Access via your institution", "Access through your institution", "Find your institution", "Institutional access", "Log in via institution", "Log in"),
        school_selectors=("#searchFormTextInput", "input[name='search']"),
        submit_labels=("Find", "Continue", "Sign in", "Log in"),
        success_markers=("Access provided by", "sign out", "signed in"),
    ),
    "Nature": profile(
        "https://wayf.springernature.com/?redirect_uri=https%3A%2F%2Fwww.nature.com%2Fnature",
        institution_labels=("Access via your institution", "Access through your institution", "Find your institution", "Institutional access", "Log in via institution", "Log in"),
        school_selectors=("#searchFormTextInput", "input[name='search']"),
        submit_labels=("Find", "Continue", "Sign in", "Log in"),
        success_markers=("Access provided by", "sign out", "signed in"),
    ),
    "ACS Publications": profile(
        "https://pubs.acs.org/action/doSearch",
        institution_labels=("Find my institution", "Institutional Login", "Log in via institution", "Shibboleth"),
        success_markers=("sign out", "access provided by", "institutional access"),
    ),
    "RSC Publishing": profile(
        "https://www.rsc.org/rsc-id/account/federatedaccess?returnurl=https%3A%2F%2Fpubs.rsc.org",
        institution_labels=("Login", "Institutional login", "Access through your institution", "Shibboleth"),
        school_selectors=("input[placeholder*='institution' i]", "input[aria-label*='institution' i]", "input[name*='institution' i]"),
        strict_school_selectors=True,
        success_markers=("sign out", "access provided by", "institutional access"),
    ),
    "Annual Reviews": profile(
        "https://www.annualreviews.org/",
        institution_labels=("Access through your institution", "Institutional login", "Log in via institution", "Shibboleth", "OpenAthens", "Sign in", "Log in"),
        success_markers=("sign out", "access provided by", "institutional access"),
    ),
    "bioRxiv / medRxiv": profile("https://www.biorxiv.org/search/"),
    "DOAJ (Directory of Open Access Journals)": profile("https://doaj.org/search/articles"),
    "PMC (PubMed Central)": profile("https://www.ncbi.nlm.nih.gov/pmc/"),
    "PubMed": profile("https://pubmed.ncbi.nlm.nih.gov/"),
    "Europe PMC": profile("https://europepmc.org/search"),
    "Crossref Metadata Search (search.crossref.org)": profile("https://search.crossref.org/"),
    "DataCite Search (search.datacite.org)": profile("https://search.datacite.org/"),
    "ChemRxiv": profile("https://chemrxiv.org/engage/chemrxiv/search-dashboard"),
    "Semantic Scholar": profile("https://www.semanticscholar.org/search"),
    "OpenReview": profile("https://openreview.net/search"),
    "IACR ePrint": profile("https://eprint.iacr.org/search"),
    "DBLP": profile("https://dblp.org/search"),
    "ACM metadata": profile(
        "https://dl.acm.org/action/doSearch",
        institution_labels=("Institutional Sign In", "Access through your institution", "Shibboleth", "OpenAthens"),
        success_markers=("institutional access", "access provided by", "sign out"),
    ),
    "USENIX": profile("https://www.usenix.org/search/site"),
    "CORE": profile("https://core.ac.uk/search"),
    "OpenAIRE": profile("https://explore.openaire.eu/search/find"),
    "Springer": profile(
        "https://wayf.springernature.com/?redirect_uri=https%3A%2F%2Flink.springer.com%2F",
        institution_labels=("Access via your institution", "Access through your institution", "Find your institution", "Institutional access", "Log in via institution", "Log in"),
        school_selectors=("#searchFormTextInput", "input[name='search']"),
        submit_labels=("Find", "Continue", "Sign in", "Log in"),
        success_markers=("Access provided by", "sign out", "signed in"),
    ),
    CNKI_SOURCE: profile(
        CNKI_HOME,
        success_domains=("cnki.net",),
        institution_labels=("校外访问", "机构登录", "CARSI", "高校/机构"),
        school_selectors=(
            "input[placeholder*='学校']",
            "input[placeholder*='机构']",
            "input[placeholder*='institution' i]",
        ),
        strict_school_selectors=True,
        success_markers=("机构用户", "欢迎您", "退出登录", "IP登录"),
    ),
    WANFANG_SOURCE: profile(
        WANFANG_HOME,
        success_domains=("wanfangdata.com.cn",),
        institution_labels=("机构登录", "校外访问", "CARSI", "机构用户"),
        school_selectors=(
            "input[placeholder*='学校']",
            "input[placeholder*='机构']",
            "input[placeholder*='institution' i]",
        ),
        strict_school_selectors=True,
        success_markers=("机构用户", "机构名称", "退出登录", "IP用户"),
    ),
    UYANIP_SOURCE: profile(
        UYANIP_HOME,
        success_domains=("uyanip.com",),
        user_selectors=(
            "input[type='text']",
            "input[name*='user' i]",
            "input[placeholder*='账号']",
            "input[placeholder*='用户名']",
        ),
        password_selectors=("input[type='password']",),
        success_markers=("退出登录", "个人中心", "我的收藏"),
    ),
    "input_url": profile(),
    "Google Patents": profile("https://patents.google.com/"),
    "EPO Open Patent Services (OPS) API": profile("https://worldwide.espacenet.com/"),
    "USPTO Open Data Portal": profile("https://ppubs.uspto.gov/pubwebapp/"),
    "WIPO PATENTSCOPE API": profile("https://patentscope.wipo.int/search/en/search.jsf"),
    "PQAI API (Patent Quality AI)": profile("https://search.projectpq.ai/"),
    "Google BigQuery": profile(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT_DIR)).replace("\\", "/")
    except Exception:
        return str(path)


def safe_batch_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value or "")
    normalized = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", normalized)
    normalized = re.sub(r"\s+", "_", normalized).strip(" ._")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if not normalized or normalized.upper() in reserved:
        normalized = "keywords"
    return normalized[:100]


def exact_path(value: str | None) -> Path | None:
    return Path(value).expanduser().resolve() if value else None


def discover_paths(args: argparse.Namespace | None = None) -> dict[str, Path]:
    raw_batch_name = getattr(args, "batch_name", "") or "" if args is not None else ""
    batch_name = safe_batch_name(raw_batch_name) if raw_batch_name else ""
    metadata_root = exact_path(getattr(args, "metadata_root", "") or "") if args is not None else None
    pdf_root = exact_path(getattr(args, "pdf_root", "") or "") if args is not None else None
    resolved_metadata_root = metadata_root or (METADATA_ROOT / batch_name if batch_name else METADATA_ROOT)
    resolved_pdf_root = pdf_root or (PDF_ROOT / batch_name if batch_name else PDF_ROOT)
    outputs_dir = resolved_pdf_root / "outputs"
    return {
        "root": ROOT_DIR,
        "scripts": SCRIPTS_DIR,
        "tools": TOOLS_DIR,
        "python_packages": PYTHON_PACKAGES_DIR,
        "playwright_browsers": PLAYWRIGHT_BROWSERS_DIR,
        "legacy_playwright_browsers": LEGACY_PLAYWRIGHT_BROWSERS_DIR,
        "search_script": SEARCH_SCRIPT_PATH,
        "config": get_runtime_config_path(),
        "metadata_root": resolved_metadata_root,
        "literature_csv": resolved_metadata_root / "literature_metadata_list" / "literature_metadata_list.csv",
        "patents_csv": resolved_metadata_root / "patents_metadata_list" / "patents_metadata_list.csv",
        "literature_v2": resolved_metadata_root / "literature_records.v2.jsonl",
        "patents_v2": resolved_metadata_root / "patent_records.v2.jsonl",
        "handoff_manifest_v2": resolved_metadata_root / "handoff_manifest.v2.json",
        "legacy_search_state": resolved_metadata_root / "search_state.sqlite3",
        "pdf_root": resolved_pdf_root,
        "literature_pdf": resolved_pdf_root / "literature_pdf",
        "patents_pdf": resolved_pdf_root / "patents_pdf",
        "outputs": outputs_dir,
        "download_state": outputs_dir / "download_state.sqlite3",
        "migration_report": outputs_dir / "input_migration_report.v2.json",
        "download_auth_state": outputs_dir / "auth_state",
    }


def ensure_output_directories(paths: dict[str, Path]) -> None:
    # ``python_packages`` and ``playwright_browsers`` are legacy read-only
    # compatibility locations.  New runs must not recreate either layout; the
    # unified environment gate owns only ``tools/.venv`` and
    # ``tools/ms-playwright``.
    for key in ("pdf_root", "literature_pdf", "patents_pdf", "outputs", "download_auth_state"):
        paths[key].mkdir(parents=True, exist_ok=True)


def setup_logging(outputs_dir: Path) -> logging.Logger:
    outputs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("literature_patents_download")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(outputs_dir / "download.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def setup_environment_logging() -> logging.Logger:
    """Create a console-only logger before business output directories exist."""

    logger = logging.getLogger("literature_patents_download.environment")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.propagate = False
    return logger


def venv_site_packages() -> list[Path]:
    candidates: list[Path] = []
    win = TOOLS_DIR / ".venv" / "Lib" / "site-packages"
    if win.exists():
        candidates.append(win)
    lib_dir = TOOLS_DIR / ".venv" / "lib"
    if lib_dir.exists():
        candidates.extend(path for path in lib_dir.glob("python*/site-packages") if path.exists())
    return candidates


def chromium_installed(path: Path) -> bool:
    if not path.exists():
        return False
    markers = list(path.glob("chromium*/INSTALLATION_COMPLETE"))
    markers.extend(path.glob("chromium*/chrome-win*/chrome.exe"))
    markers.extend(path.glob("chromium*/chrome-linux*/chrome"))
    markers.extend(path.glob("chromium*/chrome-mac*/Chromium.app"))
    markers.extend(path.glob("chromium_headless_shell*/INSTALLATION_COMPLETE"))
    return bool(markers)


def add_package_paths() -> None:
    for path in [PYTHON_PACKAGES_DIR, *venv_site_packages()]:
        text = str(path)
        if path.exists() and text not in sys.path:
            sys.path.insert(0, text)


def load_sync_playwright() -> Any:
    add_package_paths()
    if not os.getenv("PLAYWRIGHT_BROWSERS_PATH"):
        if chromium_installed(PLAYWRIGHT_BROWSERS_DIR):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(PLAYWRIGHT_BROWSERS_DIR)
        elif chromium_installed(LEGACY_PLAYWRIGHT_BROWSERS_DIR):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(LEGACY_PLAYWRIGHT_BROWSERS_DIR)
    return importlib.import_module("playwright.sync_api").sync_playwright


class EnvironmentBootstrapError(RuntimeError):
    def __init__(self, reason: str, message: str, command: list[str] | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.command = command or []


def environment_lock_path() -> Path:
    return TOOLS_DIR / ENV_BOOTSTRAP_LOCK_NAME


def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
    except Exception:
        return True


def environment_lock_owner_running(lock_path: Path) -> bool:
    try:
        raw = lock_path.read_text(encoding="utf-8-sig")
        payload = json.loads(raw) if raw else {}
        return process_is_running(int(payload.get("pid") or 0))
    except Exception:
        return False


def acquire_environment_bootstrap_lock(logger: logging.Logger) -> tuple[Path, str]:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = environment_lock_path()
    token = f"{os.getpid()}-{time.time_ns()}"
    timeout_seconds = environment_lock_timeout_seconds()
    deadline = time.monotonic() + timeout_seconds
    logged_wait = False
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"pid": os.getpid(), "token": token, "created_at": utc_now()}, handle)
            return lock_path, token
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime if lock_path.exists() else 0.0
            except OSError:
                continue
            if age > timeout_seconds and not environment_lock_owner_running(lock_path):
                logger.warning("Removing stale environment bootstrap lock after %.1f seconds: %s", age, lock_path)
                try:
                    lock_path.unlink()
                    continue
                except OSError:
                    pass
            if time.monotonic() >= deadline:
                raise EnvironmentBootstrapError(
                    "environment_bootstrap_lock_timeout",
                    f"Timed out waiting for environment bootstrap lock after {timeout_seconds} seconds: {lock_path}",
                )
            if not logged_wait:
                logger.info("Waiting for environment bootstrap lock: %s", lock_path)
                logged_wait = True
            time.sleep(min(1.0, max(0.2, deadline - time.monotonic())))
        except OSError as exc:
            raise EnvironmentBootstrapError(
                "environment_bootstrap_lock_failed",
                f"Unable to create environment bootstrap lock {lock_path}: {exc}",
            ) from exc


def release_environment_bootstrap_lock(lock_path: Path, token: str, logger: logging.Logger) -> None:
    try:
        raw = lock_path.read_text(encoding="utf-8-sig") if lock_path.exists() else ""
        payload = json.loads(raw) if raw else {}
        if payload.get("token") == token:
            lock_path.unlink()
    except Exception as exc:
        logger.warning("Unable to release environment bootstrap lock %s: %s", lock_path, exc)


def environment_process_group_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def terminate_environment_process_tree(process: subprocess.Popen[Any], logger: logging.Logger) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except Exception as exc:
            logger.warning("Unable to terminate environment process tree %s: %s", process.pid, exc)
    else:
        try:
            import signal

            os.killpg(process.pid, signal.SIGTERM)
        except Exception as exc:
            logger.warning("Unable to terminate environment process group %s: %s", process.pid, exc)
        try:
            process.wait(timeout=5)
        except Exception:
            try:
                import signal

                os.killpg(process.pid, signal.SIGKILL)
            except Exception:
                pass
    try:
        process.wait(timeout=10)
    except Exception:
        pass


def run_command(args: list[str], env: dict[str, str], logger: logging.Logger) -> None:
    timeout_seconds = environment_command_timeout_seconds()
    command_preview = " ".join(args[:4])
    logger.info("Running environment command: %s (timeout=%ss)", command_preview, timeout_seconds)
    try:
        process = subprocess.Popen(
            args,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **environment_process_group_kwargs(),
        )
    except subprocess.TimeoutExpired as exc:
        raise EnvironmentBootstrapError(
            "environment_bootstrap_timeout",
            f"Environment command timed out after {timeout_seconds} seconds: {command_preview}",
            args,
        ) from exc
    except OSError as exc:
        raise EnvironmentBootstrapError(
            "environment_bootstrap_failed",
            f"Environment command could not start: {command_preview}: {exc}",
            args,
        ) from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        terminate_environment_process_tree(process, logger)
        raise EnvironmentBootstrapError(
            "environment_bootstrap_timeout",
            f"Environment command timed out after {timeout_seconds} seconds: {command_preview}",
            args,
        ) from exc
    if process.returncode != 0:
        logger.error("Command failed: %s", (stderr or "").strip() or (stdout or "").strip())
        raise EnvironmentBootstrapError(
            "environment_bootstrap_failed",
            f"Environment command failed with exit code {process.returncode}: {command_preview}",
            args,
        )


def ensure_tools_environment(paths: dict[str, Path], logger: logging.Logger) -> dict[str, Any]:
    """Prepare the shared tools runtime without creating business output paths."""

    try:
        report = shared_environment.check_environment(ROOT_DIR)
        if not shared_environment.required_environment_ready(report):
            logger.info("Canonical tools runtime is incomplete; preparing %s", TOOLS_DIR)
            report = shared_environment.prepare_environment(
                ROOT_DIR,
                command_timeout_seconds=environment_command_timeout_seconds(),
                lock_timeout_seconds=environment_lock_timeout_seconds(),
            )
        if not shared_environment.required_environment_ready(report):
            raise EnvironmentBootstrapError(
                "environment_bootstrap_failed",
                "The canonical tools runtime is still incomplete after preparation.",
            )
        runtime_env = shared_environment.runtime_environment(ROOT_DIR)
    except shared_environment.EnvironmentBootstrapError as exc:
        raise EnvironmentBootstrapError(exc.reason, str(exc), list(exc.command)) from exc

    os.environ.update(runtime_env)
    if not shared_environment.running_in_tools_venv(ROOT_DIR):
        shared_environment.restart_with_tools_python(
            SCRIPT_PATH,
            sys.argv[1:],
            skill_root=ROOT_DIR,
            env=runtime_env,
        )
    add_package_paths()
    return report


def normalize_credential_host(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text if "://" in text else f"https://{text}")
    except ValueError:
        return ""
    host = (parsed.hostname or "").casefold().strip(".")
    if not host or any(character.isspace() for character in host):
        return ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (not address.is_global or address.is_multicast):
        return ""
    return host


def load_config(config_path: Path, args: argparse.Namespace) -> DownloadConfig:
    raw: dict[str, Any] = {
        "thread_num": DEFAULT_THREAD_NUM,
        "path": "institution",
        "school": "",
        "school_aliases": [],
        "account": "",
        "password": "",
        "uyanip_account": "",
        "uyanip_password": "",
        "credential_allowed_hosts": [],
    }
    if config_path.exists():
        with config_path.open("r", encoding="utf-8-sig") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError(f"Runtime config must be a JSON object: {config_path}")
        raw.update({key: value for key, value in loaded.items() if key in raw})
    try:
        thread_num = int(raw.get("thread_num", DEFAULT_THREAD_NUM))
    except Exception:
        thread_num = DEFAULT_THREAD_NUM
    thread_num = min(MAX_THREAD_NUM, max(1, thread_num))
    path = str(raw.get("path", "institution") or "").strip().lower()
    valid_path = path in {"institution", "personal"}
    if not valid_path:
        raise ValueError("Runtime config 'path' must be 'institution' or 'personal'")
    school = str(raw.get("school", "") or "")
    account = str(raw.get("account", "") or "")
    password = str(raw.get("password", "") or "")
    raw_aliases = raw.get("school_aliases")
    if isinstance(raw_aliases, str):
        raw_aliases = [raw_aliases]
    school_aliases = tuple(
        dict.fromkeys(
            str(value).strip()
            for value in (raw_aliases if isinstance(raw_aliases, (list, tuple)) else ())
            if str(value).strip()
        )
    )
    uyanip_account = str(raw.get("uyanip_account", "") or "")
    uyanip_password = str(raw.get("uyanip_password", "") or "")
    raw_credential_hosts = raw.get("credential_allowed_hosts")
    if isinstance(raw_credential_hosts, str):
        raw_credential_hosts = re.split(r"[,;\s]+", raw_credential_hosts)
    environment_credential_hosts = re.split(
        r"[,;\s]+", os.getenv("LAPS_CREDENTIAL_ALLOWED_HOSTS", "")
    )
    credential_allowed_hosts = tuple(
        dict.fromkeys(
            host
            for value in [
                *(raw_credential_hosts if isinstance(raw_credential_hosts, (list, tuple)) else ()),
                *environment_credential_hosts,
            ]
            if (host := normalize_credential_host(value))
        )
    )
    auth_enabled = bool(account and password and valid_path)
    return DownloadConfig(
        thread_num=thread_num,
        path=path if valid_path else "invalid",
        school=school,
        account=account,
        password=password,
        auth_enabled=auth_enabled,
        school_aliases=school_aliases,
        uyanip_account=uyanip_account,
        uyanip_password=uyanip_password,
        runtime_config_path=str(config_path),
        headless=not bool(args.headful),
        force=bool(args.force),
        no_resume=bool(getattr(args, "no_resume", False) or args.force),
        dry_run=bool(args.dry_run),
        probe_channel_plan=bool(args.probe_channel_plan),
        limit=args.limit,
        channel_filters=tuple(
            str(value).casefold()
            for value in getattr(args, "channel", ()) or ()
            if not str(value).casefold().startswith("exact:")
        ),
        exact_channel_filters=tuple(
            [
                str(value)[6:].strip().casefold()
                for value in getattr(args, "channel", ()) or ()
                if str(value).casefold().startswith("exact:") and str(value)[6:].strip()
            ]
            + [str(value).strip().casefold() for value in getattr(args, "exact_channel", ()) or () if str(value).strip()]
        ),
        disabled_channels=tuple(
            dict.fromkeys(
                str(value).strip().casefold()
                for value in getattr(args, "disable_channel", ()) or ()
                if str(value).strip()
            )
        ),
        input_contract=str(getattr(args, "input_contract", "auto") or "auto"),
        doi_filters=tuple(
            normalized
            for value in getattr(args, "doi", ()) or ()
            if (normalized := normalize_doi(value))
        ),
        publication_filters=tuple(
            normalized
            for value in [*(getattr(args, "publication_number", ()) or ()), *(getattr(args, "patent_id", ()) or ())]
            if (normalized := normalize_publication_number(value))
        ),
        credential_allowed_hosts=credential_allowed_hosts,
    )


def mask_value(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


SENSITIVE_FIELD_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "authorization",
    "cookie",
    "session",
)
MASKED_ACCOUNT_FIELD_TOKENS = ("account", "username", "user_name")
TRANSIENT_PDF_QUERY_KEYS = frozenset(
    {
        "access_token",
        "auth",
        "authorization",
        "token",
        "signature",
        "sig",
        "signed",
        "expires",
        "expiry",
        "timestamp",
        "ticket",
        "x-amz-signature",
        "x-amz-credential",
        "x-amz-date",
        "x-amz-expires",
        "x-amz-security-token",
        "security-token",
        "policy",
        "key-pair-id",
    }
)
TRANSIENT_PDF_QUERY_KEY_PREFIXES = ("x-amz-", "x-goog-", "cloudfront-")
SENSITIVE_QUERY_KEYS = frozenset({
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "client_secret",
    "authorization",
    "cookie",
    "session",
    "cursor",
    "continuation_token",
    "page_token",
    "oauth_token",
    "code",
    "state",
}) | TRANSIENT_PDF_QUERY_KEYS


def transient_pdf_query_key(value: str) -> bool:
    lowered = (value or "").casefold()
    return bool(
        lowered in TRANSIENT_PDF_QUERY_KEYS
        or any(lowered.startswith(prefix) for prefix in TRANSIENT_PDF_QUERY_KEY_PREFIXES)
    )


def sensitive_query_key(value: str) -> bool:
    lowered = (value or "").casefold()
    return (
        lowered in SENSITIVE_QUERY_KEYS
        or "cursor" in lowered
        or lowered.endswith("token")
        or transient_pdf_query_key(lowered)
    )


def field_is_sensitive(field_name: str) -> bool:
    lowered = field_name.casefold().replace("-", "_").replace(" ", "_")
    return any(token in lowered for token in SENSITIVE_FIELD_TOKENS)


def field_is_account_like(field_name: str) -> bool:
    lowered = field_name.casefold().replace("-", "_").replace(" ", "_")
    return any(token in lowered for token in MASKED_ACCOUNT_FIELD_TOKENS)


def sanitize_url_for_output(value: str) -> str:
    if not value:
        return ""
    if value.startswith(("laps-browser-download://", "laps-browser-download-failure://")):
        return "<captured_browser_download>"
    try:
        parsed = urllib.parse.urlsplit(value)
    except Exception:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = "***@" + netloc.rsplit("@", 1)[-1]
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    sanitized_query = urllib.parse.urlencode(
        [(key, "***" if sensitive_query_key(key) else val) for key, val in query_pairs],
        doseq=True,
        safe="*",
    )
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, sanitized_query, ""))


def sanitize_output_value(field_name: str, value: Any) -> str:
    text = "" if value is None else str(value)
    if field_is_sensitive(field_name):
        return "***" if text else ""
    if field_is_account_like(field_name):
        return mask_value(text)
    normalized_name = field_name.casefold()
    if "cursor" in normalized_name:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16] if text else ""
    if (
        normalized_name in {"url", "channel_url_or_api"}
        or "url" in normalized_name
        or "link" in normalized_name
        or "链接" in field_name
        or text.strip().startswith(("http://", "https://"))
    ):
        return sanitize_url_for_output(text)
    return text


def sanitize_text_for_output(value: Any) -> str:
    text = "" if value is None else str(value)
    return re.sub(
        r"https?://[^\s\"'<>]+",
        lambda match: sanitize_url_for_output(match.group(0)),
        text,
        flags=re.I,
    )


def sanitize_nested_for_output(value: Any, field_name: str = "") -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): sanitize_nested_for_output(item, str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_nested_for_output(item, field_name) for item in value]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    # A value stored under an innocuous key (for example ``message``) can
    # still embed a signed URL.  Apply field-aware masking first, then scrub
    # URLs occurring anywhere in the remaining free text.
    return sanitize_text_for_output(sanitize_output_value(field_name, value))


def sanitize_csv_value(field_name: str, value: Any) -> Any:
    """Recursively sanitize a CSV cell and serialize nested legacy values."""

    sanitized = sanitize_nested_for_output(value, field_name)
    if isinstance(sanitized, (Mapping, list, tuple, set)):
        return json.dumps(sanitized, ensure_ascii=False, sort_keys=True)
    return sanitized


def sanitize_config(config: DownloadConfig) -> dict[str, Any]:
    return {
        "thread_num": config.thread_num,
        "path": config.path,
        "school_configured": bool(config.school.strip()),
        "school_alias_count": len(config.school_aliases),
        "account": mask_value(config.account),
        "password": "***" if config.password else "",
        "auth_enabled": config.auth_enabled,
        "uyanip_account": mask_value(config.uyanip_account),
        "uyanip_password": "***" if config.uyanip_password else "",
        "uyanip_auth_enabled": bool(config.uyanip_account and config.uyanip_password),
        "headless": config.headless,
        "force": config.force,
        "no_resume": config.no_resume,
        "dry_run": config.dry_run,
        "probe_channel_plan": config.probe_channel_plan,
        "limit": config.limit,
        "chunk_size": download_chunk_size(),
        "channel_filters": list(config.channel_filters),
        "exact_channel_filters": list(config.exact_channel_filters),
        "disabled_channels": list(config.disabled_channels),
        "input_contract": config.input_contract,
        "doi_filters": list(config.doi_filters),
        "publication_filters": list(config.publication_filters),
    }


def get_api_config_path() -> Path | None:
    for name in ("LAPS_API_CONFIG", "LAPS_API_CONFIG_FILE"):
        value = os.getenv(name, "").strip()
        if value:
            return Path(value).expanduser().resolve()
    config_dir = os.getenv("LAPS_API_CONFIG_DIR", "").strip()
    if config_dir:
        return Path(config_dir).expanduser().resolve() / "config.json"
    default_path = Path.home() / ".config" / "literature-and-patents-search-skills" / "config.json"
    return default_path if default_path.exists() else None


def read_api_user_config() -> dict[str, str]:
    path = get_api_config_path()
    if path is None or not path.exists() or path.is_dir():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        return {}
    result: dict[str, str] = {}
    for key, value in loaded.items():
        if key in API_CONFIG_KEY_SET and value is not None:
            result[str(key)] = str(value)
    legacy_lens = str(loaded.get("LENS_API_KEY") or "")
    if legacy_lens:
        result.setdefault("LENS_Scholarly_API_KEY", legacy_lens)
        result.setdefault("LENS_Patents_API_KEY", legacy_lens)
    return {key: value for key, value in result.items() if value}


def load_api_user_config_into_env(logger: logging.Logger) -> None:
    API_CONFIG_VALUES.clear()
    try:
        config = read_api_user_config()
    except Exception as exc:
        logger.warning("Unable to read API user config: %s", exc)
        config = {}
    for key, value in config.items():
        API_CONFIG_VALUES[key] = value
        if key == "GOOGLE_APPLICATION_CREDENTIALS" and not os.getenv(key):
            os.environ[key] = value
    for alias, canonical in API_KEY_COMPAT_ALIASES.items():
        value = os.getenv(alias) or API_CONFIG_VALUES.get(alias, "")
        if value and not (os.getenv(canonical) or API_CONFIG_VALUES.get(canonical)):
            API_CONFIG_VALUES[canonical] = value


def env_value(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
        value = API_CONFIG_VALUES.get(name, "").strip()
        if value:
            return value
    return ""


def contact_email() -> str:
    return env_value("CONTACT_EMAIL", "CROSSREF_MAILTO", "NCBI_EMAIL")


def user_agent() -> str:
    email = contact_email()
    suffix = f"; contact={email}" if email else ""
    return f"literature-and-patents-download-skills/1.0 (PDF retrieval{suffix})"


def normalize_header(value: str) -> str:
    return re.sub(r"[\W_]+", "", unicodedata.normalize("NFKC", value or "").casefold())


def get_field(row: dict[str, Any], aliases: tuple[str, ...]) -> str:
    by_normalized = {normalize_header(str(key)): value for key, value in row.items()}
    for alias in aliases:
        value = by_normalized.get(normalize_header(alias))
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def typed_identifier_value(row: Mapping[str, Any], identifier_kind: str) -> str:
    """Return one explicitly typed identifier without guessing from ``raw_id``."""

    raw_identifiers: Any = row.get("identifiers") or []
    if isinstance(raw_identifiers, str):
        try:
            raw_identifiers = json.loads(raw_identifiers)
        except (json.JSONDecodeError, TypeError):
            raw_identifiers = []
    if isinstance(raw_identifiers, Mapping):
        raw_identifiers = [
            {"identifier_type": kind, "value": value}
            for kind, value in raw_identifiers.items()
        ]
    expected = identifier_kind.strip().casefold()
    for item in raw_identifiers if isinstance(raw_identifiers, list) else []:
        if not isinstance(item, Mapping):
            continue
        kind = str(
            item.get("identifier_type")
            or item.get("type")
            or item.get("kind")
            or ""
        ).strip().casefold()
        value = str(item.get("normalized_value") or item.get("value") or "").strip()
        if kind == expected and value:
            return value
    return ""


def normalize_doi(value: str | None) -> str:
    """Use the canonical v2 DOI parser without truncating valid suffixes."""

    return normalize_contract_doi(value)


def normalize_url(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.startswith("//"):
        text = "https:" + text
    return text


def stable_record_id(record_type: str, row: Mapping[str, Any]) -> str:
    supplied = str(row.get("record_id") or row.get("_record_id") or "").strip()
    if supplied and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", supplied):
        return supplied
    if record_type == "literature":
        doi = normalize_doi(get_field(dict(row), LITERATURE_DOI_ALIASES))
        pdf_url = normalize_literature_pdf_url(get_field(dict(row), LITERATURE_URL_ALIASES))
        identity_kind, identity_value = ("doi", doi) if doi else ("pdf_url", pdf_url)
    else:
        publication_number = normalize_publication_number(
            get_field(dict(row), PUBLICATION_NUMBER_ALIASES)
            or typed_identifier_value(row, "publication_number")
        )
        patent_url = normalize_url(get_field(dict(row), PATENT_URL_ALIASES))
        identity_kind, identity_value = (
            ("publication_number", publication_number)
            if publication_number
            else ("url", patent_url.casefold())
        )
    if not identity_value:
        source = str(row.get("source") or row.get("database") or "unknown").strip().casefold()
        raw_id = str(row.get("raw_id") or row.get("id") or "").strip().casefold()
        title_aliases = LITERATURE_TITLE_ALIASES if record_type == "literature" else PATENT_TITLE_ALIASES
        title = get_field(dict(row), title_aliases).strip().casefold()
        identity_kind = "source_scoped"
        identity_value = "\0".join((source, raw_id, title))
    digest = hashlib.sha256(
        f"laps-record-v2\0{record_type}\0{identity_kind}\0{identity_value}".encode("utf-8", errors="ignore")
    ).hexdigest()
    prefix = "lit" if record_type == "literature" else "pat"
    return f"{prefix}_{digest[:32]}"


def row_record_aliases(record_type: str, row: Mapping[str, Any]) -> list[str]:
    raw: Any = row.get("_record_aliases") or row.get("_record_aliases_json") or []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = [part.strip() for part in raw.split(";") if part.strip()]
    if not isinstance(raw, (list, tuple, set)):
        return []
    expected_prefix = "lit_" if record_type == "literature" else "pat_"
    current = stable_record_id(record_type, row)
    aliases: list[str] = []
    for value in raw:
        alias = str(value or "").strip()
        if (
            alias
            and alias != current
            and alias.startswith(expected_prefix)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", alias)
            and alias not in aliases
        ):
            aliases.append(alias)
    return aliases


def reuse_record_alias_artifact(
    record_type: str,
    row: Mapping[str, Any],
    pdf_directory: Path,
    target_path: Path,
) -> str:
    """Reuse a strong-identity alias artifact without performing network I/O."""

    seen_paths: set[Path] = set()
    for alias in row_record_aliases(record_type, row):
        candidates: list[Path] = []
        if ACTIVE_DOWNLOAD_LEDGER is not None:
            ledger_path = ACTIVE_DOWNLOAD_LEDGER.valid_artifact_path(alias, record_type)
            if ledger_path is not None:
                candidates.append(ledger_path)
        digest = hashlib.sha256(alias.encode("utf-8", errors="ignore")).hexdigest()[:16]
        candidates.extend(sorted(pdf_directory.glob(f"*__{digest}.pdf")))
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, ValueError):
                continue
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            if reuse_valid_artifact(resolved, target_path):
                return alias
    return ""


def row_metadata_sources(row: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    raw = row.get("_metadata_sources") or row.get("metadata_sources") or ""
    if isinstance(raw, (list, tuple, set)):
        values.extend(str(value).strip() for value in raw)
    elif isinstance(raw, str) and raw.strip():
        try:
            decoded = json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, list):
            values.extend(str(value).strip() for value in decoded)
        else:
            values.extend(part.strip() for part in re.split(r"[;,|]", raw))
    source = str(row.get("source") or row.get("database") or "").strip()
    if source:
        values.append(source)
    canonical = row.get("_canonical_record")
    if isinstance(canonical, str) and canonical.strip():
        try:
            canonical = json.loads(canonical)
        except Exception:
            canonical = None
    if isinstance(canonical, Mapping):
        for provenance in canonical.get("provenance") or []:
            if isinstance(provenance, Mapping):
                candidate = str(provenance.get("source") or provenance.get("provider") or "").strip()
                if candidate:
                    values.append(candidate)
    return list(dict.fromkeys(value for value in values if value))


def row_locator_entries(row: Mapping[str, Any], *, direct_pdf_only: bool = False) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    raw = row.get("locators") or []
    if isinstance(raw, str) and raw.strip():
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    for value in raw if isinstance(raw, list) else []:
        if not isinstance(value, Mapping):
            continue
        kind = str(value.get("kind") or "unknown").strip().casefold()
        url = normalize_url(str(value.get("url") or ""))
        if direct_pdf_only and kind not in {"direct_pdf", "pdf"}:
            continue
        if not url or not url.startswith(("http://", "https://")):
            continue
        entries.append(
            {
                "kind": kind,
                "url": url,
                "source": str(value.get("source") or "unknown").strip() or "unknown",
                "auth_scope": str(value.get("auth_scope") or "unknown").strip() or "unknown",
                "stability": str(value.get("stability") or "unknown").strip() or "unknown",
                "observed_at": str(value.get("observed_at") or "").strip(),
            }
        )
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for entry in sorted(
        entries,
        key=lambda item: (
            0 if item["stability"].casefold() == "stable" else 1,
            0 if item["kind"] in {"direct_pdf", "pdf"} else 1,
        ),
    ):
        marker = (entry["url"], entry["auth_scope"].casefold())
        if marker not in seen:
            seen.add(marker)
            unique.append(entry)
    return unique


def reason_details(reason: str, http_status: str = "") -> tuple[str, str, bool]:
    code = (reason or "unknown").split(":", 1)[0].strip().casefold().replace(" ", "_")
    try:
        status = int(http_status or 0)
    except ValueError:
        status = 0
    retryable_codes = {
        "rate_limited",
        "service_unavailable",
        "request_timeout",
        "network_error",
        "domain_cooldown",
        "channel_cooldown",
    }
    retryable = code in retryable_codes or status in {408, 425, 429, 500, 502, 503, 504}
    if code in {"unsafe_network_target", "invalid_pdf", "invalid_browser_capture", "html_instead_of_pdf", "response_too_large", "truncated_pdf", "polyglot_pdf"}:
        category = "security_or_validation"
    elif code in {"access_denied", "manual_auth_required", "subscription_required", "skipped_auth_required"}:
        category = "authentication_or_access"
    elif code.startswith("missing_") or code.startswith("disabled_") or code == "pdf_parser_unavailable":
        category = "configuration"
    elif retryable:
        category = "transient"
    elif code in {
        "no_candidate_url",
        "not_found",
        "missing_required_doi_and_pdf_url",
        "missing_publication_number_or_url",
        "metadata_only_not_downloadable",
    }:
        category = "not_resolvable"
    else:
        category = "permanent_or_unknown"
    return code, category, retryable


def target_lock(path: Path) -> Lock:
    key = str(path.resolve()).casefold()
    with TARGET_LOCKS_GUARD:
        return TARGET_LOCKS.setdefault(key, Lock())


def atomic_replace_file(source: Path, target: Path) -> None:
    """Atomically replace a file, tolerating brief Windows scanner handle races."""
    attempts = 5 if os.name == "nt" else 1
    for attempt in range(attempts):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt + 1 >= attempts:
                raise
            time.sleep(0.02 * (2**attempt))


def auth_scope_lock(scope: str) -> RLock:
    key = (scope or "unknown").casefold()
    with AUTH_SCOPE_LOCKS_GUARD:
        return AUTH_SCOPE_LOCKS.setdefault(key, RLock())


WANFANG_RESOURCE_TYPES = frozenset({"periodical", "thesis", "conference", "nstr"})


def url_has_transient_pdf_query(value: str) -> bool:
    try:
        query_keys = {
            key.casefold()
            for key, _ in urllib.parse.parse_qsl(
                urllib.parse.urlsplit(value).query,
                keep_blank_values=True,
            )
        }
    except ValueError:
        return True
    return any(transient_pdf_query_key(key) for key in query_keys)


def stable_wanfang_pdf_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold()
    path = parsed.path or ""
    lowered_path = path.casefold()
    if parsed.scheme.casefold() not in {"http", "https"} or url_has_transient_pdf_query(value):
        return False
    if (
        host == "oss.wanfangdata.com.cn"
        and lowered_path.startswith("/file/download/")
        and lowered_path.endswith(".aspx")
    ):
        return True
    parts = [part for part in path.split("/") if part]
    return bool(
        host == "f.wanfangdata.com.cn"
        and len(parts) == 4
        and [part.casefold() for part in parts[:2]] == ["download", "pc"]
        and parts[2].casefold() in WANFANG_RESOURCE_TYPES
        and re.fullmatch(r"[A-Za-z0-9._-]+", parts[3])
        and not parsed.query
    )


def normalize_literature_pdf_url(value: str | None) -> str:
    text = normalize_url(value)
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return ""
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    decoded_query = urllib.parse.unquote_plus(parsed.query or "").casefold()
    if url_has_transient_pdf_query(text):
        return ""
    if not url_looks_like_pdf(text) and ".pdf" not in decoded_query and not stable_wanfang_pdf_url(text):
        return ""
    return urllib.parse.urlunsplit(
        (scheme, parsed.netloc.casefold(), parsed.path, parsed.query, "")
    )


def normalize_school_name(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "").casefold()
    return re.sub(r"[\s()（）_\-.,，。]+", "", value)


def normalize_publication_number(value: str | None) -> str:
    if not value:
        return ""
    text = unicodedata.normalize("NFKC", str(value)).upper().strip()
    candidate = re.sub(r"[^A-Z0-9]", "", text)
    return candidate if len(candidate) >= 4 and any(character.isdigit() for character in candidate) else ""


def safe_slug(value: str) -> str:
    text = unicodedata.normalize("NFKC", value or "").casefold()
    text = re.sub(r"[^a-z0-9_-]+", "_", text)
    return text.strip("_") or "default"


def search_auth_safe_slug(value: str) -> str:
    """Mirror the search script's auth-state path slug contract exactly."""
    normalized = unicodedata.normalize("NFKC", value or "").casefold()
    slug = re.sub(r"[^a-z0-9._-]+", "_", normalized).strip("._-")
    return slug[:80] or "default"


def search_auth_school_slug(value: str) -> str:
    return search_auth_safe_slug(re.sub(r"\s+", "", value or "").casefold())


SEARCH_AUTH_SCOPE_BY_CHANNEL = {
    "Web of Science Starter API (Clarivate)": "web_of_science",
    "IEEE Xplore API": "ieee_xplore",
    "Elsevier": "elsevier",
    "SpringerLink": "springerlink",
    "Springer": "springerlink",
    "Nature": "nature",
    "ACS Publications": "acs_publications",
    "RSC Publishing": "rsc_publishing",
    "ACM metadata": "acm_metadata",
    CNKI_SOURCE: "cnki",
    WANFANG_SOURCE: "wanfang_data",
    UYANIP_SOURCE: "uyanip",
}

AUTH_SCOPE_SERVICE_HOST = {
    "web_of_science": "webofscience.com",
    "ieee_xplore": "ieeexplore.ieee.org",
    "elsevier": "sciencedirect.com",
    "springerlink": "link.springer.com",
    "nature": "nature.com",
    "acs_publications": "pubs.acs.org",
    "rsc_publishing": "pubs.rsc.org",
    "acm_metadata": "dl.acm.org",
    "cnki": "cnki.net",
    "wanfang_data": "wanfangdata.com.cn",
    "uyanip": "uyanip.com",
}


def source_auth_state_scope(channel: str, policy: dict[str, Any] | None = None) -> str:
    configured = str((policy or {}).get("auth_state_scope") or "").strip()
    return safe_slug(configured or SEARCH_AUTH_SCOPE_BY_CHANNEL.get(channel, "")) if (
        configured or channel in SEARCH_AUTH_SCOPE_BY_CHANNEL
    ) else ""


def source_auth_mode(config: DownloadConfig, channel: str, policy: dict[str, Any] | None = None) -> str:
    runtime_keys = tuple((policy or {}).get("runtime_personal_credential_keys") or ())
    if channel == UYANIP_SOURCE or runtime_keys == ("uyanip_account", "uyanip_password"):
        return "site_personal"
    return config.path if config.path in {"institution", "personal"} else "invalid"


def auth_enabled_for_channel(config: DownloadConfig, channel: str, policy: dict[str, Any] | None = None) -> bool:
    if channel == UYANIP_SOURCE or tuple((policy or {}).get("runtime_personal_credential_keys") or ()) == (
        "uyanip_account",
        "uyanip_password",
    ):
        return bool(config.uyanip_account and config.uyanip_password)
    return config.auth_enabled


def auth_state_path(config: DownloadConfig, channel: str, paths: dict[str, Path]) -> Path:
    school_part = safe_slug(normalize_school_name(config.school)) if config.path == "institution" else "personal"
    return paths["download_auth_state"] / f"{safe_slug(config.path)}_{school_part}_{safe_slug(channel)}.auth.json"


def shared_auth_state_path(
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any] | None,
    paths: dict[str, Path] | None = None,
) -> Path:
    del paths
    scope = source_auth_state_scope(channel, policy)
    if not scope:
        raise ValueError(f"Channel does not have a shared search authentication scope: {channel}")
    mode = source_auth_mode(config, channel, policy)
    path_mode = "personal" if mode == "site_personal" else mode
    school_part = search_auth_school_slug(config.school) if mode == "institution" else "personal"
    return (
        SHARED_AUTH_STATE_DIR
        / search_auth_safe_slug(path_mode)
        / school_part
        / f"{search_auth_safe_slug(scope)}.json"
    )


def channel_auth_state_path(
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> Path:
    if source_auth_state_scope(channel, policy):
        return shared_auth_state_path(config, channel, policy, paths)
    return auth_state_path(config, channel, paths)


def shared_auth_state_attestation_path(state_path: Path) -> Path:
    return state_path.with_name(f"{state_path.stem}.attestation.json")


def auth_state_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def auth_state_attestation_ttl_seconds() -> int:
    try:
        configured = int(
            os.getenv(
                "LAPS_AUTH_STATE_ATTESTATION_TTL_SECONDS",
                str(AUTH_STATE_ATTESTATION_DEFAULT_TTL_SECONDS),
            )
        )
    except ValueError:
        configured = AUTH_STATE_ATTESTATION_DEFAULT_TTL_SECONDS
    return max(
        AUTH_STATE_ATTESTATION_MIN_TTL_SECONDS,
        min(AUTH_STATE_ATTESTATION_MAX_TTL_SECONDS, configured),
    )


def expected_auth_state_service_host(channel: str, policy: dict[str, Any]) -> str:
    scope = source_auth_state_scope(channel, policy)
    if scope == "cnki":
        return "cnki.net"
    confirmation_url = str(
        policy.get("web_search_url")
        or policy.get("auth_entry_url")
        or literature_download_path_map.get(channel)
        or patents_download_path_map.get(channel)
        or ""
    )
    return (
        urllib.parse.urlsplit(confirmation_url).hostname
        or AUTH_SCOPE_SERVICE_HOST.get(scope, "")
    ).casefold()


def auth_state_attested_host_matches(scope: str, expected_host: str, attested_host: str) -> bool:
    expected = expected_host.casefold().strip(".")
    attested = attested_host.casefold().strip(".")
    if not expected or not attested:
        return False
    if scope == "cnki":
        return attested == expected or attested.endswith(f".{expected}")
    return attested == expected


def auth_state_current_host_matches(scope: str, expected_host: str, current_host: str) -> bool:
    current = current_host.casefold().strip(".")
    expected = expected_host.casefold().strip(".")
    if not current or not expected:
        return False
    if scope in {"cnki", "wanfang_data", "uyanip"}:
        base = AUTH_SCOPE_SERVICE_HOST[scope]
        return current == base or current.endswith(f".{base}")
    return current == expected or current.endswith(f".{expected}")


def auth_state_scope_identity(
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    state_path: Path,
) -> tuple[str, str]:
    scope = source_auth_state_scope(channel, policy) or str(
        policy.get("auth_state_scope") or channel
    )
    mode = source_auth_mode(config, channel, policy)
    principal = challenge_principal_digest(config, channel, mode)
    shared = bool(source_auth_state_scope(channel, policy))
    key = auth_scope_key(
        auth_mode=mode,
        principal_digest=principal,
        auth_state_scope=scope,
        channel=channel,
        state_path_digest=hashlib.sha256(
            str(state_path.resolve()).encode("utf-8")
        ).hexdigest(),
        shared_scope=shared,
    )
    return key, principal


def validate_shared_auth_state_attestation(
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    state_path: Path,
    current_url: str,
    now: datetime | None = None,
) -> tuple[bool, str]:
    policy.pop("_auth_state_generation", None)
    scope = source_auth_state_scope(channel, policy) or safe_slug(
        str(policy.get("auth_state_scope") or channel)
    )
    if not state_path.is_file():
        return False, "auth_state_attestation_prerequisite_missing"
    attestation_path = shared_auth_state_attestation_path(state_path)
    try:
        payload = json.loads(attestation_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False, "auth_state_attestation_missing"
    if not isinstance(payload, dict):
        return False, "auth_state_attestation_invalid"
    expected_mode = source_auth_mode(config, channel, policy)
    expected_service_host = expected_auth_state_service_host(channel, policy)
    current_host = (urllib.parse.urlsplit(current_url or "").hostname or "").casefold()
    if not auth_state_current_host_matches(scope, expected_service_host, current_host):
        return False, "auth_state_attestation_scope_or_host_mismatch"
    scope_key, principal_digest = auth_state_scope_identity(
        config,
        channel,
        policy,
        state_path,
    )
    validation = validate_auth_state_attestation_v2(
        payload,
        state_path,
        expected_scope=scope,
        expected_auth_mode=expected_mode,
        expected_principal_digest=principal_digest,
        expected_service_host=expected_service_host,
        scope_key=scope_key,
        store=shared_auth_control_store(),
        now=now,
    )
    if validation.valid:
        generation_id = str(payload.get("generation_id") or "").strip()
        if not generation_id:
            return False, "auth_state_attestation_generation_missing"
        policy["_auth_state_generation"] = generation_id
    return validation.valid, validation.reason_code


def auth_state_confirmation_kind(reason: str) -> str:
    normalized = str(reason or "").casefold()
    if normalized.endswith("_institution_marker"):
        return "exact_institution_marker"
    if normalized.endswith("_sso_round_trip"):
        return "sso_round_trip"
    if normalized.endswith("_challenge_recovered"):
        return "challenge_recovered"
    return ""


def build_shared_auth_state_attestation_payload(
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    state_path: Path,
    confirmation_kind: str,
    current_url: str,
) -> tuple[dict[str, Any] | None, str]:
    scope = source_auth_state_scope(channel, policy) or safe_slug(
        str(policy.get("auth_state_scope") or channel)
    )
    kind = str(confirmation_kind or "").casefold()
    if not state_path.is_file() or kind not in AUTH_STATE_ATTESTATION_CONFIRMATION_KINDS:
        return None, "auth_state_attestation_prerequisite_missing"
    current_host = (urllib.parse.urlsplit(current_url or "").hostname or "").casefold()
    service_host = expected_auth_state_service_host(channel, policy)
    if not auth_state_current_host_matches(scope, service_host, current_host):
        return None, "auth_state_attestation_scope_or_host_mismatch"
    _scope_key, principal_digest = auth_state_scope_identity(
        config,
        channel,
        policy,
        state_path,
    )
    try:
        payload = build_auth_state_attestation_v2(
            state_path=state_path,
            generation_id=uuid.uuid4().hex,
            auth_state_scope=scope,
            auth_mode=source_auth_mode(config, channel, policy),
            principal_digest=principal_digest,
            confirmation_kind=kind,
            service_host=service_host,
            browser_name="chromium",
            headful_required=not config.headless,
            producer_component="download",
            producer_operation_id=(
                str(policy.get("_auth_scope_operation_id") or "")
                or CURRENT_INVOCATION_ID
                or uuid.uuid4().hex
            ),
            ttl_seconds=auth_state_attestation_ttl_seconds(),
        )
    except (OSError, ValueError) as exc:
        return None, str(exc)
    return payload, ""


def save_shared_auth_state_attestation(
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    state_path: Path,
    confirmation_kind: str,
    current_url: str,
) -> tuple[bool, str]:
    payload, reason = build_shared_auth_state_attestation_payload(
        config,
        channel,
        policy,
        state_path,
        confirmation_kind,
        current_url,
    )
    if payload is None:
        return False, reason
    target = shared_auth_state_attestation_path(state_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, target)
        chmod_secret_file(target)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        return False, f"auth_state_attestation_write_failed:{exc.__class__.__name__}"
    return True, "auth_state_attestation_saved"


def auth_state_is_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        ttl_hours = float(os.getenv("LAPS_AUTH_STATE_TTL_HOURS", "12"))
    except ValueError:
        ttl_hours = 12.0
    age_seconds = time.time() - path.stat().st_mtime
    return age_seconds <= ttl_hours * 3600


def uyanip_saved_state_is_current(config: DownloadConfig, state_path: Path) -> bool:
    if not auth_state_is_fresh(state_path):
        return False
    runtime_path = Path(config.runtime_config_path) if config.runtime_config_path else None
    try:
        return runtime_path is None or not runtime_path.is_file() or state_path.stat().st_mtime_ns >= runtime_path.stat().st_mtime_ns
    except OSError:
        return False


VERIFICATION_CHALLENGE_TYPES = {
    "institution_login",
    "mfa_required",
    "captcha_required",
    "robot_check",
    "cloudflare_or_waf",
    "subscription_required",
    "access_denied",
    "unknown_verification",
}

FORBIDDEN_VERIFICATION_ACTIONS = (
    "do_not_use_unauthorized_credentials",
    "do_not_access_without_user_authorization",
    "do_not_fabricate_unavailable_one_time_codes",
    "do_not_increase_request_rate_to_force_access",
)


def verification_events_root() -> Path:
    configured = os.getenv("CODEX_HOOK_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return TOOLS_DIR / "codex_hooks" / "events"


def shared_auth_control_store() -> AuthControlStore:
    global AUTH_CONTROL_STORE
    with AUTH_CONTROL_STORE_LOCK:
        if AUTH_CONTROL_STORE is None:
            AUTH_CONTROL_STORE = AuthControlStore(
                SHARED_AUTH_STATE_DIR / "auth_control.sqlite3"
            )
        return AUTH_CONTROL_STORE


def challenge_principal_digest(
    config: DownloadConfig,
    channel: str,
    auth_mode: str,
) -> str:
    if auth_mode == "public":
        principal = "public"
    elif channel == UYANIP_SOURCE or auth_mode == "site_personal":
        principal = config.uyanip_account or "site-personal-anonymous"
    elif config.path == "institution":
        principal = config.school or config.account or "institution-anonymous"
    else:
        principal = config.account or "personal-anonymous"
    return shared_auth_control_store().principal_digest(principal)


def verification_event_id(event: str, channel: str) -> str:
    safe_event = safe_slug(event or "verification")
    safe_channel = safe_slug(channel or "unknown")
    digest_basis = f"{event}|{channel}|{time.time()}|{os.getpid()}|{random.random()}"
    digest = hashlib.sha1(digest_basis.encode("utf-8")).hexdigest()[:12]
    return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_event}_{safe_channel}_{digest}"


def verification_artifact_paths(event_id: str) -> dict[str, Path]:
    root = verification_events_root()
    return {
        "screenshot": root / "screenshots" / f"{event_id}.png",
        "storage_state": root / "auth_states" / f"{event_id}.storage_state.json",
        "response": root / "responses" / f"{event_id}.json",
    }


def classify_verification_challenge(text: str = "", reason: str = "", url: str = "") -> str:
    lowered = " ".join((text or "", reason or "", url or "")).casefold()
    if any(token in lowered for token in ("recaptcha", "hcaptcha", "captcha", "验证码")):
        return "captcha_required"
    if any(token in lowered for token in ("mfa", "multi-factor", "two-factor", "verification code", "otp", "短信", "邮箱验证", "二次验证")):
        return "mfa_required"
    if any(token in lowered for token in ("verify you are human", "are you a robot", "robot check", "unusual traffic", "malicious bots")):
        return "robot_check"
    if any(token in lowered for token in ("cloudflare", "performing security verification", "security check", "you have been blocked")) or re.search(r"(?<![a-z0-9])waf(?![a-z0-9])", lowered):
        return "cloudflare_or_waf"
    if any(token in lowered for token in ("subscription required", "purchase this article", "sign in to access", "not subscribed", "subscribe to access")):
        return "subscription_required"
    if any(token in lowered for token in ("access denied", "forbidden", "not authorized", "unauthorized", "permission denied")):
        return "access_denied"
    if "login" in lowered or "institution" in lowered or "机构" in lowered:
        return "institution_login"
    return "unknown_verification"


def capture_verification_screenshot(page: Any, path: Path, logger: logging.Logger) -> str:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path), full_page=True)
        return str(path)
    except Exception as exc:
        logger.debug(
            "Unable to capture verification screenshot %s: %s",
            sanitize_text_for_output(path),
            sanitize_text_for_output(exc),
        )
        return ""


def verification_success_markers(profile: ChannelLoginProfile | None) -> list[str]:
    markers = list(GENERIC_SUCCESS_MARKERS)
    if profile is not None:
        markers.extend(profile.success_markers)
        markers.extend(profile.school_labels)
        markers.extend(profile.success_domains)
    return [marker for marker in dict.fromkeys(marker for marker in markers if marker)]


def browser_escalation_policy_contract() -> dict[str, Any]:
    return {
        "schema": BROWSER_ESCALATION_POLICY_SCHEMA,
        "layers": list(BROWSER_ESCALATION_LAYERS),
        "order_locked": True,
        "advance_on": [
            "verification_loop",
            "timeout",
            "transport_failure",
            "unsupported_browser",
        ],
        "final_failure_action": "cooldown_current_channel",
        "channel_order_unchanged": True,
    }


def control_authorization_contract() -> dict[str, Any]:
    return {
        "schema": BROWSER_CONTROL_AUTHORIZATION_SCHEMA,
        "scope": "literature_and_patent_browser_workflow",
        "preauthorized_action_classes": list(BROWSER_CONTROL_ACTION_CLASSES),
        "verification_action_budget": 1,
        "event_bound": True,
        "requires_unique_visible_target": True,
        "refresh_or_repeat_forbidden": True,
        "user_completed_first_is_accepted": True,
        "user_held_one_time_secrets_remain_user_provided": True,
        "host_enforced_confirmation_may_still_apply": True,
    }


def split_hook_command(value: str) -> list[str]:
    if not value.strip():
        return []
    parts = shlex.split(value, posix=os.name != "nt")
    return [part.strip('"') for part in parts if part.strip('"')]


def bundled_verification_hook_path() -> Path:
    return TOOLS_DIR / "codex_hooks" / "codex_external_control_hook.py"


def verification_hook_command(event: str) -> list[str]:
    if event == "auth_challenge":
        names = (
            "LAPS_AUTH_CONTROL_HOOK",
            "LAPS_LOGIN_HOOK_COMMAND",
            "LAPS_SECURITY_CHALLENGE_HOOK",
            "LAPS_CHALLENGE_HOOK_COMMAND",
        )
    else:
        names = (
            "LAPS_SECURITY_CHALLENGE_HOOK",
            "LAPS_CHALLENGE_HOOK_COMMAND",
        )
    for name in names:
        command = split_hook_command(os.getenv(name, ""))
        if command:
            return command
    default_hook = bundled_verification_hook_path()
    if default_hook.exists():
        return [sys.executable, str(default_hook)]
    return []


def build_verification_payload(
    *,
    event: str,
    event_id: str,
    challenge_type: str,
    channel: str,
    reason: str,
    config: DownloadConfig,
    current_url: str = "",
    entry_url: str = "",
    candidate_url: str = "",
    record_type: str = "",
    title: str = "",
    doi: str = "",
    source_url: str = "",
    access_mode: str = "open",
    screenshot_path: str = "",
    storage_state_path: str = "",
    success_markers: list[str] | None = None,
    timeout_seconds: int | None = None,
    source: str = "",
    search_record_type: str = "",
    auth_state_scope: str = "",
    auth_entry_id: str = "",
    auth_entry_mode: str = "institution",
    resume_url: str = "",
    seed_storage_state_path: str = "",
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timeout_seconds = timeout_seconds if timeout_seconds is not None else verification_manual_timeout_seconds()
    selected_source = source or channel
    selected_record_type = search_record_type or record_type or "literature"
    selected_scope = auth_state_scope or source_auth_state_scope(selected_source, policy)
    is_auth = event == "auth_challenge"
    payload: dict[str, Any] = {
        "event": event,
        "event_id": event_id,
        "challenge_type": challenge_type if challenge_type in VERIFICATION_CHALLENGE_TYPES else "unknown_verification",
        "channel": channel,
        "source": selected_source,
        "reason": reason,
        "auth_path": config.path,
        "school": config.school,
        "account": mask_value(config.account),
        "record_type": "authentication" if is_auth else record_type,
        "search_record_type": selected_record_type,
        "auth_state_scope": selected_scope,
        "auth_entry_id": auth_entry_id,
        "auth_entry_mode": auth_entry_mode,
        "title": title,
        "doi": doi,
        "url": sanitize_url_for_output(source_url),
        "current_url": sanitize_url_for_output(current_url),
        "entry_url": sanitize_url_for_output(entry_url),
        "candidate_url": sanitize_url_for_output(candidate_url),
        "access_mode": access_mode,
        "headless": config.headless,
        "browser_preference": os.getenv("LAPS_EXTERNAL_CONTROL_BROWSER", os.getenv("CODEX_HOOK_BROWSER_CHANNEL", "chromium")).strip() or "chromium",
        "timeout_seconds": timeout_seconds,
        "manual_wait_seconds": verification_manual_timeout_seconds(),
        "response_path": str(verification_artifact_paths(event_id)["response"]),
        "keep_browser_open": True,
        "codex_extension_control_enabled": True,
        "ordinary_chrome_preapproved": os.getenv(
            "LAPS_ORDINARY_CHROME_PREAUTHORIZED", "1"
        ).strip().casefold()
        in {"1", "true", "yes", "on"},
        "computer_use_preapproved": os.getenv(
            "LAPS_CODEX_WINDOWS_CONTROL_PREAUTHORIZED", "1"
        ).strip().casefold()
        in {"1", "true", "yes", "on"},
        "browser_escalation_policy": browser_escalation_policy_contract(),
        "control_authorization": control_authorization_contract(),
        "external_handoff_timeout_seconds": external_handoff_parent_budget_seconds(),
        "automation_level": os.getenv("LAPS_VERIFICATION_AUTOMATION_LEVEL", "assist").strip() or "assist",
        "browser_profile_path": str(verification_events_root() / "browser_profiles"),
        "screenshot_path": screenshot_path,
        "storage_state_path": storage_state_path,
        "success_markers": success_markers or [],
        "school_aliases": list(config.school_aliases),
        "forbidden_actions": list(FORBIDDEN_VERIFICATION_ACTIONS),
        "created_at": utc_now(),
        "expected_stdout_json": {
            "action": "retry|skip|cooldown|manual_pending|unhandled",
            "candidate_urls": ["optional PDF URL after challenge handling"],
            "storage_state_path": "optional Playwright storage_state JSON after authentication",
            "final_url": "optional final browser URL",
            "reason": "optional explanation",
        },
    }
    if resume_url:
        payload["resume_url"] = sanitize_url_for_output(resume_url)
        payload["source_search_url"] = sanitize_url_for_output(resume_url)
        payload["source_resume_url"] = sanitize_url_for_output(resume_url)
    if seed_storage_state_path:
        payload["seed_storage_state_path"] = seed_storage_state_path
    if selected_source == UYANIP_SOURCE:
        payload["auth_path"] = "personal"
        payload["school"] = ""
        payload["school_aliases"] = []
        payload["account"] = mask_value(config.uyanip_account)
        payload["auth_entry_mode"] = "site_personal"
        payload["credential_scope"] = "site_personal"
        payload["credential_allowed_hosts"] = ["uyanip.com", "api.duyandb.com"]
        payload["credential_subdomains_allowed"] = True
        payload["institution_auth_forbidden"] = True
        payload["allowed_auth_modes"] = ["site_personal"]
        payload["runtime_auth_values_available"] = bool(
            config.uyanip_account and config.uyanip_password
        )
    elif is_auth:
        payload["runtime_auth_values_available"] = bool(config.account and config.password)
    attempt_context = getattr(ATTEMPT_CONTEXT, "value", {}) or {}
    record_id = str(attempt_context.get("record_id") or "")
    selected_auth_mode = (
        "public"
        if access_mode == "open" and not is_auth
        else "site_personal"
        if selected_source == UYANIP_SOURCE or auth_entry_mode == "site_personal"
        else config.path
    )
    binding = {
        "run_id": CURRENT_RUN_ID or (f"auth-check-{event_id}" if is_auth else "download-unbound"),
        "search_job_id": "",
        "auth_check_id": (
            auth_entry_id or event_id
            if not record_id
            else ""
        ),
        "record_id": record_id,
        "record_type": selected_record_type,
        "source": selected_source,
        "planned_channel": channel,
        "auth_state_scope": selected_scope,
        "auth_mode": selected_auth_mode,
        "principal_digest": challenge_principal_digest(
            config,
            selected_source,
            selected_auth_mode,
        ),
        "access_mode": access_mode,
        "query_variant": "",
        "query_digest": "",
        "cursor_digest": "",
        "candidate_id": candidate_id_for_url(candidate_url or current_url),
    }
    request = build_verification_request(
        event=event,
        event_id=event_id,
        producer="download",
        binding=binding,
        ttl_seconds=max(1, int(timeout_seconds)),
        public_fields=payload,
        challenge_url=current_url or candidate_url,
        resume_url=resume_url,
    )
    with VERIFICATION_REQUESTS_LOCK:
        VERIFICATION_REQUESTS[event_id] = request
    return request


def verification_manual_timeout_seconds() -> int:
    try:
        fallback = os.getenv("LAPS_AUTH_MANUAL_TIMEOUT_SECONDS", str(DEFAULT_VERIFICATION_MANUAL_TIMEOUT_SECONDS))
        return max(10, int(os.getenv("LAPS_VERIFICATION_MANUAL_TIMEOUT_SECONDS", fallback)))
    except Exception:
        return DEFAULT_VERIFICATION_MANUAL_TIMEOUT_SECONDS


def register_pending_verification_request(request: Mapping[str, Any]) -> str:
    registered, reason_code = shared_auth_control_store().register_verification_request(
        request
    )
    return "" if registered else reason_code


def wait_for_verification_response(
    event_id: str,
    timeout_seconds: int,
    logger: logging.Logger,
    request: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    root = verification_events_root()
    if request is None:
        with VERIFICATION_REQUESTS_LOCK:
            request = dict(VERIFICATION_REQUESTS.get(event_id) or {})
    if not request:
        return {"_protocol_error": "challenge_response_unbound"}
    deadline = time.monotonic() + max(0, timeout_seconds)
    while time.monotonic() < deadline:
        read_result = read_verification_response(root / "responses", request)
        if read_result.payload is not None:
            return read_result.payload
        if read_result.reason_code not in {"challenge_response_missing"}:
            response_sha, responded_at = verification_file_audit_evidence(
                read_result.path
            )
            shared_auth_control_store().mark_verification_rejected(
                request,
                read_result.reason_code,
                response_sha256=response_sha,
                responded_at=responded_at,
            )
            logger.warning(
                "Rejected verification response for %s: %s",
                event_id,
                read_result.reason_code,
            )
            return {"_protocol_error": read_result.reason_code}
        time.sleep(0.5)
    shared_auth_control_store().mark_verification_expired(
        request,
        "challenge_response_timeout",
    )
    return None


def parse_verification_control_response(
    loaded: dict[str, Any],
    *,
    request: Mapping[str, Any] | None = None,
    allow_legacy_sync: bool = True,
    consume: bool = True,
) -> ChallengeControlResult:
    if loaded.get("_protocol_error"):
        return ChallengeControlResult(
            action="unhandled",
            reason=str(loaded.get("_protocol_error") or "challenge_response_unbound"),
            protocol_request=dict(request or {}),
        )
    selected_request = dict(request or {})
    if not selected_request:
        event_id = str(loaded.get("event_id") or "")
        with VERIFICATION_REQUESTS_LOCK:
            selected_request = dict(VERIFICATION_REQUESTS.get(event_id) or {})
    legacy_sync = loaded.get("schema") != "laps_verification_response_v2"
    if not legacy_sync:
        if not selected_request:
            return ChallengeControlResult(
                "unhandled",
                "challenge_response_unbound",
            )
        validation = validate_verification_response(
            selected_request,
            loaded,
            controlled_roots=(
                verification_events_root(),
                SHARED_AUTH_STATE_DIR,
                DOWNLOAD_AUTH_STATE_DIR,
            ),
            url_validator=network_url_allowed,
            replay_store=shared_auth_control_store(),
            consume=consume and str(loaded.get("action") or "") != "manual_pending",
        )
        if not validation.valid or not isinstance(validation.payload, dict):
            return ChallengeControlResult(
                action="unhandled",
                reason=validation.reason_code,
                protocol_request=selected_request,
            )
        loaded = validation.payload
        evidence = loaded.get("evidence") if isinstance(loaded.get("evidence"), Mapping) else {}
    else:
        if not allow_legacy_sync:
            return ChallengeControlResult(
                action="unhandled",
                reason="challenge_response_unbound",
                protocol_request=selected_request,
            )
        evidence = loaded
    urls = evidence.get("candidate_urls") or evidence.get("urls") or []
    if isinstance(urls, str):
        urls = [urls]
    candidate_urls = [normalize_url(str(value)) for value in urls if normalize_url(str(value))]
    action = normalize_challenge_action(str(loaded.get("action") or ""))
    return ChallengeControlResult(
        action=action,
        reason=str(loaded.get("reason") or loaded.get("reason_code") or ""),
        candidate_urls=candidate_urls,
        storage_state_path=str(evidence.get("storage_state_path") or ""),
        final_url=normalize_url(str(evidence.get("final_url") or "")),
        preflight_state=str(loaded.get("preflight_state") or ""),
        protocol_request=selected_request,
        legacy_sync=legacy_sync,
    )


def wait_if_manual_pending(control: ChallengeControlResult, event_id: str, timeout_seconds: int, logger: logging.Logger) -> ChallengeControlResult:
    if control.action != "manual_pending":
        return control
    if control.legacy_sync:
        return ChallengeControlResult(
            action="unhandled",
            reason="challenge_response_unbound",
            protocol_request=control.protocol_request,
            legacy_sync=True,
        )
    setup_states = {
        "chrome_plugin_install_required",
        "chrome_plugin_connect_required",
        "full_cdp_enable_required",
        "preflight_unavailable",
    }
    setup_state = control.preflight_state or (
        control.reason if control.reason in setup_states else ""
    )
    if setup_state in setup_states or control.reason == "codex_chrome_capability_check_required":
        normalized_state = setup_state or "preflight_unavailable"
        logger.warning(
            "Codex ordinary-Chrome setup is required for %s: %s; pausing this path without waiting on the verification page",
            event_id,
            normalized_state,
        )
        return ChallengeControlResult(
            action="unhandled",
            reason=f"codex_chrome_setup_required:{normalized_state}",
            candidate_urls=control.candidate_urls,
            storage_state_path=control.storage_state_path,
            final_url=control.final_url,
            preflight_state=normalized_state,
        )
    logger.info("Verification control for %s returned manual_pending; waiting up to %s seconds for a response file", event_id, timeout_seconds)
    selected_request = control.protocol_request
    loaded = wait_for_verification_response(
        event_id,
        timeout_seconds,
        logger,
        selected_request,
    )
    if loaded is None:
        return ChallengeControlResult(
            "unhandled",
            control.reason or "challenge_response_timeout",
            control.candidate_urls,
            control.storage_state_path,
            control.final_url,
            protocol_request=selected_request,
        )
    return parse_verification_control_response(
        loaded,
        request=selected_request,
        allow_legacy_sync=False,
        consume=True,
    )


def external_storage_state_is_usable(path_value: str) -> str:
    if not path_value:
        return ""
    try:
        path = Path(path_value).expanduser().resolve()
        if path.exists() and path.is_file() and path.stat().st_size > 0:
            return str(path)
    except Exception:
        return ""
    return ""


def hook_result_allows_manual_fallback(result: BrowserAuthResult) -> bool:
    reason = (result.reason or "").casefold()
    return any(
        token in reason
        for token in (
            "timeout",
            "failed",
            "unhandled",
            "empty_stdout",
            "non_json",
            "invalid_json",
            "retry_not_authenticated",
            "manual_pending_timeout",
        )
    )


def chmod_secret_file(path: Path) -> None:
    if os.name != "nt" and path.exists():
        path.chmod(0o600)


def page_text(page: Any) -> str:
    try:
        locator = page.locator("body")
        if hasattr(locator, "count") and locator.count() == 0:
            return ""
        return str(locator.inner_text(timeout=3000))
    except Exception:
        try:
            return str(page.inner_text("body", timeout=3000))
        except Exception:
            try:
                return str(page.evaluate("() => document.body ? document.body.innerText : ''"))
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
    "institution search",
    "organization search",
    "查找您的组织",
    "查找您的机构",
    "选择您的组织",
    "选择您的机构",
    "搜索机构",
    "机构搜索",
)

CAPTCHA_CHALLENGE_MARKERS = (
    "captcha",
    "recaptcha",
    "hcaptcha",
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
    "verify human",
    "are you a robot",
    "robot check",
    "unusual traffic",
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


def auth_prelogin_state(text: str) -> bool:
    lowered = text.casefold()
    return any(token in lowered for token in AUTH_PRELOGIN_MARKERS)


def manual_auth_required(text: str) -> bool:
    lowered = text.casefold()
    return any(token in lowered for token in CAPTCHA_CHALLENGE_MARKERS + MFA_CHALLENGE_MARKERS + ROBOT_CHALLENGE_MARKERS + SLIDER_CHALLENGE_MARKERS)


def security_challenge_required(text: str) -> bool:
    lowered = text.casefold()
    return any(token in lowered for token in CAPTCHA_CHALLENGE_MARKERS + ROBOT_CHALLENGE_MARKERS + SLIDER_CHALLENGE_MARKERS + WAF_CHALLENGE_MARKERS) or bool(re.search(r"(?<![a-z0-9])waf(?![a-z0-9])", lowered))


def current_host_matches(page: Any, domains: tuple[str, ...]) -> bool:
    if not domains:
        return False
    try:
        current = urllib.parse.urlparse(getattr(page, "url", "") or "")
        current_host = (current.hostname or "").casefold()
    except Exception:
        return False
    return any(current_host == domain.casefold() or current_host.endswith(f".{domain.casefold()}") for domain in domains)


def returned_to_success_domain_with_school(page: Any, config: DownloadConfig, text: str, profile: ChannelLoginProfile) -> bool:
    if not current_host_matches(page, profile.success_domains):
        return False
    normalized_text = normalize_school_name(text)
    school_norms = tuple(
        normalize_school_name(value)
        for value in (config.school, *config.school_aliases, *profile.school_labels)
        if value
    )
    return any(value and value in normalized_text for value in school_norms)


AUTHENTICATED_INSTITUTION_SELECTORS_BY_SCOPE: dict[str, tuple[str, ...]] = {
    "cnki": (
        ".ecp_header_login_status1 .ecp_header_unitName",
        ".ecp_header_unitName",
    ),
    "wanfang_data": (
        ".anxs-8qwe-jgName b[title]",
        ".anxs-8qwe-list-jg .anxs-8qwe-jgName",
    ),
}


def normalize_institution_name(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).replace("\u00a0", " ")
    text = re.sub(r"\s+", " ", text).strip(" \t\r\n,;:")
    return re.sub(r"\s*([()])\s*", r"\1", text).casefold()


def configured_institution_name_matches(
    candidate: Any,
    config: DownloadConfig,
) -> bool:
    normalized_candidate = normalize_institution_name(candidate)
    configured = {
        normalize_institution_name(value)
        for value in (config.school, *config.school_aliases)
        if str(value or "").strip()
    }
    return bool(normalized_candidate and normalized_candidate in configured)


def configured_institution_marker_visible(
    page: Any,
    config: DownloadConfig,
    scope: str,
) -> bool:
    if not config.school.strip() or scope not in AUTHENTICATED_INSTITUTION_SELECTORS_BY_SCOPE:
        return False
    text = page_text(page)
    if manual_auth_required(text) or security_challenge_required(text) or page_has_access_blockers(text):
        return False
    for selector in AUTHENTICATED_INSTITUTION_SELECTORS_BY_SCOPE[scope]:
        try:
            locators = page.locator(selector)
            for index in range(min(int(locators.count()), 8)):
                locator = locators.nth(index)
                if hasattr(locator, "is_visible") and not locator.is_visible(timeout=300):
                    continue
                candidates = [str(locator.inner_text(timeout=500) or "")]
                for attribute in ("title", "aria-label"):
                    try:
                        candidates.append(str(locator.get_attribute(attribute) or ""))
                    except Exception:
                        pass
                if any(configured_institution_name_matches(candidate, config) for candidate in candidates):
                    return True
        except Exception:
            continue
    return False


def exact_institution_scope_for_profile(profile: ChannelLoginProfile | None) -> str:
    if profile is None:
        return ""
    domains = {value.casefold().strip(".") for value in profile.success_domains}
    if "cnki.net" in domains:
        return "cnki"
    if "wanfangdata.com.cn" in domains:
        return "wanfang_data"
    return ""


def is_restricted_login_successful(page: Any, config: DownloadConfig, profile: ChannelLoginProfile | None = None) -> bool:
    text = page_text(page)
    lowered = text.casefold()
    if manual_auth_required(text) or security_challenge_required(text):
        return False
    if auth_prelogin_state(text):
        return False
    if page_has_access_blockers(text):
        return False
    exact_scope = exact_institution_scope_for_profile(profile)
    if exact_scope:
        return configured_institution_marker_visible(page, config, exact_scope)
    markers = merge_profile_values(profile.success_markers if profile else (), GENERIC_SUCCESS_MARKERS)
    if any(marker in lowered for marker in markers):
        return True
    if profile and returned_to_success_domain_with_school(page, config, text, profile):
        return True
    if profile and returned_to_channel_after_auth(page, text, profile):
        return True
    return False


def returned_to_channel_after_auth(page: Any, text: str, profile: ChannelLoginProfile) -> bool:
    if page_has_access_blockers(text) or manual_auth_required(text):
        return False
    current_url = getattr(page, "url", "") or ""
    try:
        current = urllib.parse.urlparse(current_url)
        current_host = (current.hostname or "").casefold()
    except Exception:
        return False
    if not current_host or any(token in current_host for token in ("idp", "auth", "login", "wayf")):
        return False
    hosts: set[str] = set()
    try:
        entry = urllib.parse.urlparse(profile.entry_url)
        query = urllib.parse.parse_qs(entry.query)
        if "redirect_uri" not in query:
            return False
        for value in query.get("redirect_uri", []):
            redirect = urllib.parse.urlparse(value)
            redirect_host = (redirect.hostname or "").casefold()
            if redirect_host:
                hosts.add(redirect_host)
    except Exception:
        return False
    return any(current_host == host or current_host.endswith(f".{host}") for host in hosts)


def wait_for_page_settle(page: Any, timeout_ms: int = 1500) -> None:
    try:
        page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass


def external_control_timeout_seconds(env_name: str = "LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS", default: int = DEFAULT_EXTERNAL_CONTROL_TIMEOUT_SECONDS) -> int:
    try:
        fallback = str(default) if env_name == "LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS" else os.getenv("LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS", str(default))
        return max(1, int(os.getenv(env_name, fallback)))
    except Exception:
        return default


def env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().casefold() in {"1", "true", "yes", "on"}


def codex_extension_control_enabled() -> bool:
    return env_truthy("LAPS_CODEX_EXTENSION_CONTROL_ENABLED") or bool(os.getenv("LAPS_CODEX_EXTENSION_CONTROL_HOOK", "").strip())


def codex_extension_control_timeout_seconds() -> int:
    try:
        return max(
            1,
            int(os.getenv("LAPS_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS", str(DEFAULT_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS))),
        )
    except Exception:
        return DEFAULT_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS


def codex_chrome_control_disabled() -> bool:
    mode = os.getenv("LAPS_CODEX_CHROME_CONTROL_MODE", "").strip().casefold()
    if mode in {"off", "disabled", "declined", "false", "0"}:
        return True
    legacy = os.getenv("LAPS_CODEX_EXTENSION_CONTROL_ENABLED")
    return legacy is not None and legacy.strip().casefold() not in {
        "1",
        "true",
        "yes",
        "on",
    }


def codex_chrome_preflight_state_for_budget() -> str:
    if codex_chrome_control_disabled():
        return "codex_chrome_control_declined"
    return (
        os.getenv("LAPS_CODEX_CHROME_PREFLIGHT_STATE", "")
        .strip()
        .casefold()
        .replace("-", "_")
    ) or "preflight_unavailable"


def codex_chrome_setup_parent_budget_seconds() -> int:
    state = codex_chrome_preflight_state_for_budget()
    confirmation = env_seconds(
        "LAPS_CODEX_CHROME_SETUP_CONFIRM_TIMEOUT_SECONDS", 300, 1
    )
    scan = env_seconds("LAPS_CODEX_CHROME_SETUP_SCAN_TIMEOUT_SECONDS", 1800, 1)
    stage_budget = confirmation + scan
    if state in {
        "chrome_plugin_install_required",
        "chrome_plugin_connect_required",
        "preflight_unavailable",
    }:
        connect_settle = env_seconds(
            "LAPS_CODEX_CHROME_CONNECT_SETTLE_SECONDS", 3, 1
        )
        return stage_budget * 2 + connect_settle
    if state == "full_cdp_enable_required":
        return stage_budget
    return 0


def codex_chrome_handoff_confirmation_parent_budget_seconds() -> int:
    return 0


def codex_chrome_extension_may_run() -> bool:
    return codex_chrome_preflight_state_for_budget() in {
        "ready",
        "chrome_plugin_install_required",
        "chrome_plugin_connect_required",
        "full_cdp_enable_required",
        "preflight_unavailable",
    }


def external_handoff_parent_budget_seconds() -> int:
    if not codex_chrome_extension_may_run():
        return 0
    return env_seconds(
        "LAPS_EXTERNAL_HANDOFF_TIMEOUT_SECONDS",
        DEFAULT_EXTERNAL_HANDOFF_TIMEOUT_SECONDS,
        1,
    )


def hook_prefers_chrome() -> bool:
    if os.getenv("CODEX_HOOK_DISABLE_CHROME_FALLBACK", "").strip().casefold() in {"1", "true", "yes", "on"}:
        return False
    explicit = os.getenv("CODEX_HOOK_TRY_CHROME")
    if explicit is not None:
        return explicit.strip().casefold() in {"1", "true", "yes", "on"} and bool(local_chrome_executable())
    values = (
        os.getenv("LAPS_HOOK_TRY_CHROME", ""),
        os.getenv("LAPS_EXTERNAL_CONTROL_BROWSER", ""),
        os.getenv("CODEX_HOOK_BROWSER_CHANNEL", ""),
    )
    normalized = " ".join(value.strip().casefold() for value in values if value)
    if any(token in normalized for token in ("chrome", "google-chrome")) or normalized in {"1", "true", "yes", "on"}:
        return bool(local_chrome_executable())
    return bool(local_chrome_executable())


def local_chrome_executable() -> str:
    configured = os.getenv("CODEX_HOOK_CHROME_EXECUTABLE", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        try:
            if candidate.exists() and candidate.is_file():
                return str(candidate.resolve())
        except Exception:
            pass
        return ""
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
    for candidate in candidates:
        try:
            if candidate.exists() and candidate.is_file():
                return str(candidate.resolve())
        except Exception:
            continue
    return ""


def chrome_control_timeout_seconds() -> int:
    try:
        value = os.getenv("LAPS_CHROME_CONTROL_TIMEOUT_SECONDS", os.getenv("CODEX_HOOK_BROWSER_TIMEOUT_SECONDS", str(DEFAULT_CHROME_CONTROL_TIMEOUT_SECONDS)))
        return max(10, int(value))
    except Exception:
        return DEFAULT_CHROME_CONTROL_TIMEOUT_SECONDS


def chromium_control_timeout_seconds() -> int:
    try:
        fallback = os.getenv("LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS", str(DEFAULT_EXTERNAL_CONTROL_TIMEOUT_SECONDS))
        value = os.getenv("LAPS_CHROMIUM_CONTROL_TIMEOUT_SECONDS", os.getenv("CODEX_HOOK_CHROMIUM_TIMEOUT_SECONDS", fallback))
        return max(10, int(value))
    except Exception:
        return DEFAULT_EXTERNAL_CONTROL_TIMEOUT_SECONDS


def hook_control_timeout_seconds(env_name: str, default: int = DEFAULT_EXTERNAL_CONTROL_TIMEOUT_SECONDS) -> int:
    if os.getenv(env_name):
        return external_control_timeout_seconds(env_name, default)
    if os.getenv("LAPS_HOOK_TOTAL_TIMEOUT_SECONDS"):
        return external_control_timeout_seconds("LAPS_HOOK_TOTAL_TIMEOUT_SECONDS", default)
    manual_wait = verification_manual_timeout_seconds()
    chromium_timeout = chromium_control_timeout_seconds()
    setup_timeout = codex_chrome_setup_parent_budget_seconds()
    extension_timeout = (
        codex_extension_control_timeout_seconds()
        if codex_chrome_extension_may_run()
        else 0
    )
    external_handoff_timeout = external_handoff_parent_budget_seconds()
    if hook_prefers_chrome():
        return (
            chromium_timeout
            + manual_wait
            + chrome_control_timeout_seconds()
            + manual_wait
            + setup_timeout
            + max(extension_timeout, external_handoff_timeout)
            + 15
        )
    return (
        chromium_timeout
        + manual_wait
        + setup_timeout
        + max(extension_timeout, external_handoff_timeout)
        + 15
    )


def manual_auth_timeout_seconds() -> int:
    try:
        return max(10, int(os.getenv("LAPS_AUTH_MANUAL_TIMEOUT_SECONDS", str(DEFAULT_AUTH_MANUAL_TIMEOUT_SECONDS))))
    except Exception:
        return DEFAULT_AUTH_MANUAL_TIMEOUT_SECONDS


def auth_control_hook_timeout_seconds() -> int:
    return hook_control_timeout_seconds("LAPS_AUTH_CONTROL_HOOK_TIMEOUT_SECONDS")


def auth_control_verify_seconds() -> int:
    return external_control_timeout_seconds("LAPS_AUTH_CONTROL_VERIFY_SECONDS", DEFAULT_AUTH_CONTROL_VERIFY_SECONDS)


def auth_control_hook(
    page: Any,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    reason: str,
    profile: ChannelLoginProfile | None = None,
    policy: dict[str, Any] | None = None,
    resume_url: str = "",
    seed_storage_state_path: str = "",
) -> BrowserAuthResult | None:
    command = verification_hook_command("auth_challenge")
    if not command:
        return None
    selected_policy = (
        policy
        or literature_channel_policy_map.get(channel)
        or patents_channel_policy_map.get(channel)
        or {}
    )
    seed_storage_state_path = seed_storage_state_path or str(
        selected_policy.get("_seed_storage_state_path") or ""
    )
    profile = profile or channel_login_profile(channel, selected_policy)
    current_url = getattr(page, "url", "") or ""
    text = page_text(page)
    event_id = verification_event_id("auth_challenge", channel)
    artifacts = verification_artifact_paths(event_id)
    screenshot_path = capture_verification_screenshot(page, artifacts["screenshot"], logger)
    payload = build_verification_payload(
        event="auth_challenge",
        event_id=event_id,
        challenge_type=classify_verification_challenge(text, reason, current_url),
        channel=channel,
        reason=reason,
        config=config,
        current_url=current_url,
        entry_url=profile.entry_url,
        screenshot_path=screenshot_path,
        storage_state_path=str(artifacts["storage_state"]),
        success_markers=verification_success_markers(profile),
        timeout_seconds=auth_control_hook_timeout_seconds(),
        source=channel,
        search_record_type=str(selected_policy.get("_download_record_type") or "literature"),
        auth_state_scope=source_auth_state_scope(channel, selected_policy),
        auth_entry_id=str(selected_policy.get("_active_auth_entry_id") or ""),
        auth_entry_mode=str(
            selected_policy.get("_active_auth_entry_mode")
            or ("site_personal" if channel == UYANIP_SOURCE else "institution")
        ),
        resume_url=resume_url
        or str(selected_policy.get("_current_record_resume_url") or "")
        or current_url,
        seed_storage_state_path=seed_storage_state_path,
        policy=selected_policy,
    )
    generic_allowed_hosts = generic_credential_allowed_hosts(
        config, selected_policy
    )
    if channel != UYANIP_SOURCE:
        payload["credential_scope"] = config.path
        payload["credential_allowed_hosts"] = list(generic_allowed_hosts)
        payload["credential_subdomains_allowed"] = False
    registration_error = register_pending_verification_request(payload)
    if registration_error:
        return BrowserAuthResult(False, registration_error)
    bundled_hook = len(command) >= 2 and Path(command[1]).resolve() == bundled_verification_hook_path().resolve()
    allow_credentials = bundled_hook or os.getenv(
        "LAPS_AUTH_CONTROL_HOOK_ALLOW_CREDENTIALS", ""
    ).strip().casefold() in {"1", "true", "yes", "on"}
    if allow_credentials:
        if channel == UYANIP_SOURCE:
            host = (urllib.parse.urlsplit(current_url or profile.entry_url).hostname or "").casefold()
            if host == "uyanip.com" or host.endswith(".uyanip.com") or host == "api.duyandb.com":
                payload["raw_account"] = config.uyanip_account
                payload["raw_password"] = config.uyanip_password
        elif generic_allowed_hosts:
            payload["raw_account"] = config.account
            payload["raw_password"] = config.password
    if os.getenv("LAPS_AUTH_CONTROL_HOOK_ALLOW_RAW_URL", "").strip().casefold() in {"1", "true", "yes", "on"}:
        payload["raw_current_url"] = current_url
        payload["raw_entry_url"] = profile.entry_url
    logger.info("Authentication control hook invoked for %s: %s", channel, reason)
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=auth_control_hook_timeout_seconds(),
        )
    except subprocess.TimeoutExpired:
        logger.info("Authentication control hook timed out for %s", channel)
        return BrowserAuthResult(False, "external_auth_hook_timeout")
    except Exception as exc:
        logger.info("Authentication control hook failed for %s: %s", channel, exc)
        return BrowserAuthResult(False, f"external_auth_hook_failed:{exc.__class__.__name__}")
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        logger.info("Authentication control hook returned %s for %s: %s", completed.returncode, channel, stderr[:500])
        return BrowserAuthResult(False, f"external_auth_hook_exit_{completed.returncode}")
    if not stdout:
        return BrowserAuthResult(False, "external_auth_hook_empty_stdout")
    try:
        loaded = json.loads(stdout)
    except Exception:
        logger.info("Authentication control hook returned non-JSON stdout for %s", channel)
        return BrowserAuthResult(False, "external_auth_hook_non_json_stdout")
    if not isinstance(loaded, dict):
        return BrowserAuthResult(False, "external_auth_hook_invalid_json")
    control = wait_if_manual_pending(
        parse_verification_control_response(
            loaded,
            request=payload,
            allow_legacy_sync=not bundled_hook,
        ),
        event_id,
        verification_manual_timeout_seconds(),
        logger,
    )
    action = control.action
    hook_reason = control.reason
    if action == "skip":
        return BrowserAuthResult(False, hook_reason or "external_auth_hook_skip")
    if action == "cooldown":
        return BrowserAuthResult(False, hook_reason or "external_auth_hook_cooldown")
    if action != "retry":
        return BrowserAuthResult(False, hook_reason or "external_auth_hook_unhandled")
    storage_state_path = external_storage_state_is_usable(control.storage_state_path)
    if storage_state_path:
        return BrowserAuthResult(True, hook_reason or "external_auth_hook_storage_state", external_storage_state_path=storage_state_path)
    if wait_for_login_success(page, config, profile, timeout_seconds=auth_control_verify_seconds()):
        return BrowserAuthResult(True, hook_reason or "external_auth_hook_succeeded")
    return BrowserAuthResult(False, hook_reason or "external_auth_hook_retry_not_authenticated")


def wait_for_manual_auth_completion(
    page: Any,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    reason: str,
    profile: ChannelLoginProfile | None = None,
    policy: dict[str, Any] | None = None,
    resume_url: str = "",
    seed_storage_state_path: str = "",
) -> BrowserAuthResult:
    hook_result = auth_control_hook(
        page,
        config,
        logger,
        channel,
        reason,
        profile,
        policy,
        resume_url,
        seed_storage_state_path,
    )
    if hook_result is not None:
        if hook_result.ok or config.headless or not hook_result_allows_manual_fallback(hook_result):
            return hook_result
        logger.info("Authentication control hook did not resolve %s (%s); falling back to visible manual wait", channel, hook_result.reason)
    if config.headless:
        return BrowserAuthResult(False, reason)
    timeout_seconds = manual_auth_timeout_seconds()
    logger.info("Manual authentication required for %s; waiting up to %s seconds in the Playwright Chromium window", channel, timeout_seconds)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if is_restricted_login_successful(page, config, profile):
            return BrowserAuthResult(True, "manual_login_succeeded")
        time.sleep(2)
    return BrowserAuthResult(False, reason)


def merge_profile_values(primary: tuple[str, ...], fallback: tuple[str, ...]) -> tuple[str, ...]:
    merged: list[str] = []
    for value in [*primary, *fallback]:
        if value and value not in merged:
            merged.append(value)
    return tuple(merged)


def channel_login_profile(channel: str, policy: dict[str, Any]) -> ChannelLoginProfile:
    base = CHANNEL_LOGIN_PROFILES.get(channel, ChannelLoginProfile())
    entry_url = str(policy.get("auth_entry_url") or base.entry_url or policy.get("web_search_url") or "")
    school_fallback_selectors = () if base.strict_school_selectors else GENERIC_SCHOOL_SELECTORS
    return ChannelLoginProfile(
        entry_url=entry_url,
        success_domains=base.success_domains,
        institution_selectors=base.institution_selectors,
        institution_labels=merge_profile_values(base.institution_labels, GENERIC_INSTITUTION_LABELS),
        federation_labels=merge_profile_values(base.federation_labels, GENERIC_FEDERATION_LABELS),
        school_selectors=merge_profile_values(base.school_selectors, school_fallback_selectors),
        strict_school_selectors=base.strict_school_selectors,
        school_labels=base.school_labels,
        user_selectors=merge_profile_values(base.user_selectors, GENERIC_USER_SELECTORS),
        password_selectors=merge_profile_values(base.password_selectors, GENERIC_PASSWORD_SELECTORS),
        submit_labels=merge_profile_values(base.submit_labels, GENERIC_SUBMIT_LABELS),
        success_markers=merge_profile_values(base.success_markers, GENERIC_SUCCESS_MARKERS),
    )


def click_first_text(page: Any, labels: tuple[str, ...]) -> bool:
    for label in labels:
        try:
            locator = page.get_by_text(label, exact=False).first
            locator.click(timeout=3000)
            wait_for_page_settle(page)
            return True
        except Exception:
            continue
    return False


def click_first_selector(page: Any, selectors: tuple[str, ...], timeout_ms: int = 3000) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if hasattr(locator, "count") and locator.count() == 0:
                continue
            if hasattr(locator, "is_visible") and not locator.is_visible(timeout=500):
                continue
            locator.click(timeout=timeout_ms)
            wait_for_page_settle(page)
            return True
        except Exception:
            continue
    return False


def visible_locator_candidates(page: Any, selector: str, limit: int = 8) -> list[Any]:
    candidates: list[Any] = []
    try:
        locators = page.locator(selector)
        for index in range(min(int(locators.count()), limit)):
            locator = locators.nth(index)
            if not hasattr(locator, "is_visible") or locator.is_visible(timeout=500):
                candidates.append(locator)
    except Exception:
        return []
    return candidates


def unique_visible_locator(page: Any, selector: str) -> tuple[Any | None, int]:
    candidates = visible_locator_candidates(page, selector)
    return (candidates[0] if len(candidates) == 1 else None, len(candidates))


def generic_credential_allowed_hosts(
    config: DownloadConfig,
    policy: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    values: list[Any] = list(config.credential_allowed_hosts)
    configured = (policy or {}).get("credential_allowed_hosts")
    if isinstance(configured, str):
        values.extend(re.split(r"[,;\s]+", configured))
    elif isinstance(configured, (list, tuple, set)):
        values.extend(configured)
    return tuple(
        dict.fromkeys(
            host for value in values if (host := normalize_credential_host(value))
        )
    )


def generic_credential_url_allowed(
    value: str,
    allowed_hosts: Sequence[str],
) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold().strip(".")
    permitted = {
        normalized
        for candidate in allowed_hosts
        if (normalized := normalize_credential_host(candidate))
    }
    return bool(
        parsed.scheme.casefold() == "https"
        and host in permitted
        and network_url_allowed(value)
    )


def generic_login_form_locators(
    page: Any,
    profile: ChannelLoginProfile,
) -> tuple[Any, Any, Any] | None:
    user_selector = ", ".join(profile.user_selectors)
    password_selector = ", ".join(profile.password_selectors)
    submit_selector = ", ".join(
        (
            "#login_submit",
            "a.login-btn",
            "button[type='submit']",
            "input[type='submit']",
        )
    )
    if not user_selector or not password_selector:
        return None
    username, username_count = unique_visible_locator(page, user_selector)
    password, password_count = unique_visible_locator(page, password_selector)
    submit, submit_count = unique_visible_locator(page, submit_selector)
    if (
        username is None
        or password is None
        or submit is None
        or username_count != 1
        or password_count != 1
        or submit_count != 1
    ):
        return None
    return username, password, submit


def generic_login_form_target_allowed(
    page: Any,
    username: Any,
    password: Any,
    submit: Any,
    allowed_hosts: Sequence[str],
) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    bindings = [
        uyanip_form_binding(locator, current_url)
        for locator in (username, password, submit)
    ]
    if any(binding is None for binding in bindings):
        return False
    typed = [binding for binding in bindings if binding is not None]
    if not all(binding["has_form"] for binding in typed):
        return False
    form_indexes = {binding["form_index"] for binding in typed}
    if len(form_indexes) != 1 or -1 in form_indexes:
        return False
    return all(
        generic_credential_url_allowed(binding["action"], allowed_hosts)
        and str(binding.get("target") or "").casefold() in {"", "_self"}
        for binding in typed
    )


def install_generic_credential_route_guard(
    page: Any,
    allowed_hosts: Sequence[str],
    secrets: Sequence[str],
    blocked_urls: list[str],
) -> Callable[[Any, Any], None] | None:
    encoded_secrets = {
        representation
        for secret in secrets
        if secret
        for representation in {
            secret,
            urllib.parse.quote(secret, safe=""),
            urllib.parse.quote_plus(secret),
        }
    }

    def guard(route: Any, request: Any) -> None:
        request_url = str(getattr(request, "url", "") or "")
        try:
            scheme = urllib.parse.urlsplit(request_url).scheme.casefold()
        except ValueError:
            scheme = ""
        if scheme in {"data", "blob", "about"}:
            route.continue_()
            return
        if scheme not in {"http", "https"} or not network_url_allowed(request_url):
            blocked_urls.append(sanitize_url_for_output(request_url))
            route.abort()
            return
        post_data = str(getattr(request, "post_data", "") or "")
        decoded_target = urllib.parse.unquote_plus(f"{request_url}\n{post_data}")
        carries_secret = any(
            value and (value in decoded_target or value in post_data)
            for value in encoded_secrets
        )
        if carries_secret and not generic_credential_url_allowed(
            request_url, allowed_hosts
        ):
            blocked_urls.append(sanitize_url_for_output(request_url))
            route.abort()
            return
        route.continue_()

    try:
        page.route("**/*", guard)
    except Exception:
        return None
    return guard


def submit_generic_credentials_guarded(
    page: Any,
    config: DownloadConfig,
    profile: ChannelLoginProfile,
    policy: Mapping[str, Any] | None = None,
) -> str:
    """Fill and submit credentials only inside an explicitly trusted HTTPS form."""

    allowed_hosts = generic_credential_allowed_hosts(config, policy)
    if not allowed_hosts:
        return "credential_host_allowlist_missing"
    current_url = str(getattr(page, "url", "") or "")
    if not generic_credential_url_allowed(current_url, allowed_hosts):
        return "credential_host_not_allowed"
    login_form = generic_login_form_locators(page, profile)
    if login_form is None:
        return "login_form_not_found_or_ambiguous"
    username, password, submit = login_form
    if not generic_login_form_target_allowed(
        page, username, password, submit, allowed_hosts
    ):
        return "credential_form_target_not_allowed"
    blocked_urls: list[str] = []
    route_guard = install_generic_credential_route_guard(
        page,
        allowed_hosts,
        (config.account, config.password),
        blocked_urls,
    )
    if route_guard is None:
        return "credential_transport_guard_unavailable"
    try:
        try:
            username.fill(config.account, timeout=5000)
            password.fill(config.password, timeout=5000)
            submit.click(timeout=5000)
        except Exception:
            return "login_form_submit_failed"
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10_000)
        except Exception:
            pass
        return "credential_target_not_allowed" if blocked_urls else ""
    finally:
        try:
            page.unroute("**/*", route_guard)
        except Exception:
            pass


def uyanip_credential_url_allowed(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold().strip(".")
    return bool(
        parsed.scheme.casefold() == "https"
        and (
            host in UYANIP_CREDENTIAL_ALLOWED_HOSTS
            or host.endswith(".uyanip.com")
        )
    )


def uyanip_form_binding(locator: Any, current_url: str) -> dict[str, Any] | None:
    try:
        raw = locator.evaluate(
            """(element) => {
                const form = element.closest('form');
                if (!form) return {has_form: false, form_index: -1, action: ''};
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
    if not isinstance(raw, dict):
        return None
    action = str(raw.get("action") or "")
    try:
        form_index = int(raw.get("form_index", -1))
    except (TypeError, ValueError):
        return None
    return {
        "has_form": bool(raw.get("has_form")),
        "form_index": form_index,
        "action": urllib.parse.urljoin(current_url, action) if action else current_url,
        "target": str(raw.get("target") or ""),
    }


def uyanip_login_form_locators(page: Any) -> tuple[Any, Any, Any] | None:
    username, username_count = unique_visible_locator(
        page,
        "#username, #username_xdhy, input[name='username']",
    )
    password, password_count = unique_visible_locator(
        page,
        "#password, #password_xdhy, input[name='password']",
    )
    submit, submit_count = unique_visible_locator(
        page,
        "#login, #login_xdhy, button[type='submit']",
    )
    if (
        username is None
        or password is None
        or submit is None
        or username_count != 1
        or password_count != 1
        or submit_count != 1
    ):
        return None
    return username, password, submit


def uyanip_login_form_target_allowed(
    page: Any,
    username: Any,
    password: Any,
    submit: Any,
) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    bindings = [
        uyanip_form_binding(locator, current_url)
        for locator in (username, password, submit)
    ]
    if any(binding is None for binding in bindings):
        return False
    typed_bindings = [binding for binding in bindings if binding is not None]
    form_bindings = [binding for binding in typed_bindings if binding["has_form"]]
    if form_bindings:
        if len(form_bindings) != len(typed_bindings):
            return False
        form_indexes = {binding["form_index"] for binding in form_bindings}
        if len(form_indexes) != 1 or -1 in form_indexes:
            return False
    return all(uyanip_credential_url_allowed(binding["action"]) for binding in typed_bindings)


def install_uyanip_credential_route_guard(
    page: Any,
    blocked_urls: list[str],
) -> Callable[[Any, Any], None] | None:
    def guard(route: Any, request: Any) -> None:
        request_url = str(getattr(request, "url", "") or "")
        try:
            scheme = urllib.parse.urlsplit(request_url).scheme.casefold()
        except ValueError:
            scheme = ""
        if scheme in {"data", "blob", "about"} or (
            uyanip_credential_url_allowed(request_url)
            and network_url_allowed(request_url)
        ):
            route.continue_()
            return
        blocked_urls.append(sanitize_url_for_output(request_url))
        route.abort()

    try:
        page.route("**/*", guard)
    except Exception:
        return None
    return guard


def uyanip_invalid_credentials(text: str) -> bool:
    lowered = (text or "").casefold()
    return any(marker.casefold() in lowered for marker in UYANIP_INVALID_CREDENTIAL_MARKERS)


def uyanip_login_api_state(response_status: int, payload: Any) -> str:
    """Classify only explicit login API evidence; ambiguous payloads remain pending."""
    if response_status in {400, 401, 403}:
        return "rejected"
    if not 200 <= response_status < 300 or not isinstance(payload, dict):
        return "pending"
    try:
        payload_text = json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:
        payload_text = str(payload)
    if uyanip_invalid_credentials(payload_text):
        return "rejected"

    indicators: list[bool] = []
    error_code = payload.get("errCode")
    if isinstance(error_code, (int, float)) and not isinstance(error_code, bool):
        indicators.append(int(error_code) == 0)
    success = payload.get("success")
    if isinstance(success, bool):
        indicators.append(success)
    code = payload.get("code")
    if isinstance(code, (int, float)) and not isinstance(code, bool):
        indicators.append(int(code) in {0, 200})
    if indicators and all(indicators):
        return "success"
    if indicators and not all(indicators):
        return "rejected"
    return "pending"


def uyanip_login_api_succeeded(response_status: int, payload: Any) -> bool:
    return uyanip_login_api_state(response_status, payload) == "success"


def uyanip_login_api_rejected(response_status: int, payload: Any) -> bool:
    return uyanip_login_api_state(response_status, payload) == "rejected"


def uyanip_login_api_response_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return bool(
        (parsed.hostname or "").casefold() == "api.duyandb.com"
        and (parsed.path or "").casefold().rstrip("/") == "/auth/auth/login"
    )


def uyanip_password_surface_visible(page: Any) -> bool:
    return bool(
        visible_locator_candidates(
            page,
            "#password, #password_xdhy, input[name='password']",
        )
    )


def uyanip_authenticated_marker_visible(text: str) -> bool:
    lowered = (text or "").casefold()
    return bool(
        not uyanip_invalid_credentials(text)
        and any(marker.casefold() in lowered for marker in UYANIP_AUTHENTICATED_MARKERS)
    )


def uyanip_post_login_marker_visible(text: str) -> bool:
    lowered = (text or "").casefold()
    return bool(
        not uyanip_invalid_credentials(text)
        and any(marker.casefold() in lowered for marker in UYANIP_POST_LOGIN_MARKERS)
    )


def uyanip_result_surface_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold().strip(".")
    return bool(
        (host == "uyanip.com" or host.endswith(".uyanip.com"))
        and (parsed.path or "").casefold().rstrip("/") == "/result"
    )


def uyanip_login_timeout_seconds() -> int:
    return min(120, env_seconds("LAPS_UYANIP_LOGIN_TIMEOUT_SECONDS", 60, 1))


def dismiss_common_cookie_banner(page: Any) -> None:
    click_first_selector(
        page,
        (
            "button.osano-cm-dialog__close",
            "button.osano-cm-close",
        ),
        timeout_ms=1000,
    )
    click_first_text(
        page,
        (
            "Reject optional cookies",
            "Reject all",
            "Accept all cookies",
            "Accept all",
            "I agree",
            "同意",
            "接受",
        ),
    )


def switch_to_account_password_login(page: Any) -> bool:
    if click_first_selector(
        page,
        (
            "#userNameLogin_a",
            "#pwdLoginSpan",
            "a:has-text('账号登录')",
            "button:has-text('账号登录')",
            "[role='tab']:has-text('账号登录')",
            "a:has-text('账户登录')",
            "button:has-text('账户登录')",
            "[role='tab']:has-text('账户登录')",
            "a:has-text('Password login')",
            "button:has-text('Password login')",
            "[role='tab']:has-text('Password login')",
            "a:has-text('Account login')",
            "button:has-text('Account login')",
            "[role='tab']:has-text('Account login')",
        ),
    ):
        return True
    return click_first_text(page, GENERIC_ACCOUNT_LOGIN_LABELS)


def handle_saml_consent_if_present(page: Any) -> bool:
    text = page_text(page)
    lowered = text.casefold()
    consent_tokens = ("信息释放", "服务共享", "release", "consent", "attribute")
    if not any(token in lowered for token in consent_tokens):
        return False
    clicked = click_first_selector(
        page,
        (
            "input[type='submit'][value*='同意']",
            "input[type='button'][value*='同意']",
            "button:has-text('同意')",
            "a:has-text('同意')",
            "input[type='submit'][value*='Accept']",
            "input[type='button'][value*='Accept']",
            "button:has-text('Accept')",
            "button:has-text('Continue')",
        ),
        timeout_ms=5000,
    )
    if not clicked:
        clicked = click_first_text(page, ("同意", "Accept", "Continue"))
    if clicked:
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10_000)
        except Exception:
            pass
    return clicked


def select_clarivate_china_cernet(page: Any) -> bool:
    try:
        if page.locator("mat-select").count() == 0:
            return False
        page.locator("mat-select").first.click(timeout=5000)
        option = page.locator("mat-option").filter(has_text="CHINA CERNET").first
        if option.count() == 0:
            option = page.locator("[role='option']").filter(has_text="CHINA CERNET").first
        option.click(timeout=5000)
        wait_for_page_settle(page)
        return click_first_text(page, ("转到机构", "Go to institution", "Go to Institution"))
    except Exception:
        return False


def select_rsc_carsi_school(page: Any, config: DownloadConfig | None = None) -> bool:
    try:
        if page.locator("#FederationsList").count() == 0:
            return False
        page.locator("#FederationsList").select_option(label="China (CARSI) Federation", timeout=5000)
        wait_for_page_settle(page, timeout_ms=3000)
        school_labels = tuple(
            value
            for value in (
                (config.school if config else ""),
                *((config.school_aliases if config else ())),
            )
            if value
        )
        for label in school_labels:
            if click_first_text(page, (label,)):
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=15_000)
                except Exception:
                    pass
                return True
        return False
    except Exception:
        return False


def select_carsi_school(page: Any, config: DownloadConfig) -> bool:
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            if page.locator("#show").count() == 0 or page.locator("#idpSkipButton").count() == 0:
                page.wait_for_load_state("domcontentloaded", timeout=1000)
                time.sleep(0.5)
                continue
            school_values = tuple(
                dict.fromkeys(value for value in (config.school, *config.school_aliases) if value)
            )
            for value in school_values:
                try:
                    page.locator("#show").fill(value, timeout=3000)
                    wait_for_page_settle(page, timeout_ms=1000)
                    normalized_page = normalize_school_name(page_text(page))
                    if normalize_school_name(value) in normalized_page:
                        click_first_text(page, (value,))
                        try:
                            page.keyboard.press("Enter")
                        except Exception:
                            pass
                        break
                except Exception:
                    continue
            clicked = click_first_selector(page, ("#idpSkipButton",), timeout_ms=5000)
            if clicked:
                deadline_after_click = time.monotonic() + 10
                while time.monotonic() < deadline_after_click and "ds.carsi.edu.cn" in (getattr(page, "url", "") or ""):
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=1000)
                    except Exception:
                        pass
                    time.sleep(0.5)
            return clicked
        except Exception:
            time.sleep(0.5)
    return False


def wait_for_login_success(page: Any, config: DownloadConfig, profile: ChannelLoginProfile, timeout_seconds: int = 30) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if is_restricted_login_successful(page, config, profile):
            return True
        try:
            page.wait_for_load_state("domcontentloaded", timeout=1000)
        except Exception:
            pass
        time.sleep(0.5)
    return is_restricted_login_successful(page, config, profile)


def fill_first_locator(page: Any, selectors: tuple[str, ...], value: str) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if hasattr(locator, "count") and locator.count() == 0:
                continue
            if hasattr(locator, "is_visible") and not locator.is_visible(timeout=500):
                continue
            locator.fill(value, timeout=3000)
            return True
        except Exception:
            continue
    return False


def click_submit(page: Any, submit_labels: tuple[str, ...] = GENERIC_SUBMIT_LABELS) -> bool:
    for selector in ("#login_submit", "a.login-btn", "button[type='submit']", "input[type='submit']", "button:has-text('Login')", "button:has-text('登录')"):
        try:
            locator = page.locator(selector).first
            if hasattr(locator, "count") and locator.count() == 0:
                continue
            if hasattr(locator, "is_visible") and not locator.is_visible(timeout=500):
                continue
            locator.click(timeout=3000)
            wait_for_page_settle(page)
            return True
        except Exception:
            continue
    if click_first_text(page, submit_labels):
        return True
    return False


def login_institutional_with_playwright(
    page: Any,
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    logger: logging.Logger,
) -> BrowserAuthResult:
    if config.path != "institution" or not config.school.strip() or not config.account or not config.password:
        return BrowserAuthResult(False, "institutional_auth_config_incomplete")
    login_profile = channel_login_profile(channel, policy)
    entry_url = login_profile.entry_url
    try:
        if entry_url:
            safe_browser_goto(page, entry_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            dismiss_common_cookie_banner(page)
    except Exception as exc:
        logger.info("Institutional login entry navigation failed for %s: %s", channel, exc)
    text = page_text(page)
    exact_scope = source_auth_state_scope(channel, policy)
    if exact_scope in {"cnki", "wanfang_data"} and configured_institution_marker_visible(
        page,
        config,
        exact_scope,
    ):
        return BrowserAuthResult(True, f"{exact_scope}_institution_marker")
    if manual_auth_required(text) or security_challenge_required(text):
        return wait_for_manual_auth_completion(page, config, logger, channel, "manual_intervention_required", login_profile, policy)
    if not click_first_selector(page, login_profile.institution_selectors):
        click_first_text(page, login_profile.institution_labels)
    click_first_text(page, login_profile.federation_labels)
    select_clarivate_china_cernet(page)
    select_rsc_carsi_school(page, config)
    select_carsi_school(page, config)

    school_labels = tuple(
        dict.fromkeys(
            value
            for value in (config.school, *config.school_aliases, *login_profile.school_labels)
            if value
        )
    )
    school_norms = tuple(normalize_school_name(value) for value in school_labels)
    text = page_text(page)
    if manual_auth_required(text) or security_challenge_required(text):
        return wait_for_manual_auth_completion(page, config, logger, channel, "manual_intervention_required", login_profile, policy)
    normalized_text = normalize_school_name(text)
    school_selected = any(value and value in normalized_text for value in school_norms)
    if not school_selected:
        for selector in login_profile.school_selectors:
            try:
                locator = page.locator(selector).first
                if hasattr(locator, "count") and locator.count() == 0:
                    continue
                locator.fill(config.school, timeout=3000)
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
                wait_for_page_settle(page, timeout_ms=3000)
                school_selected = True
                break
            except Exception:
                continue
    if select_rsc_carsi_school(page, config) or select_carsi_school(page, config):
        text = page_text(page)
        normalized_text = normalize_school_name(text)
        school_selected = any(value and value in normalized_text for value in school_norms)
        if security_challenge_required(text) or manual_auth_required(text):
            return wait_for_manual_auth_completion(page, config, logger, channel, "manual_intervention_required", login_profile, policy)
    if school_selected:
        click_first_text(page, school_labels)
    else:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            text = page_text(page)
            normalized_text = normalize_school_name(text)
            if any(value and value in normalized_text for value in school_norms):
                school_selected = True
                break
            time.sleep(0.5)
        if school_selected:
            click_first_text(page, school_labels)
        else:
            return wait_for_manual_auth_completion(page, config, logger, channel, "school_not_found", login_profile, policy)

    switch_to_account_password_login(page)
    text = page_text(page)
    if manual_auth_required(text) or security_challenge_required(text):
        return wait_for_manual_auth_completion(page, config, logger, channel, "manual_intervention_required", login_profile, policy)
    credential_error = submit_generic_credentials_guarded(
        page, config, login_profile, policy
    )
    if credential_error:
        return wait_for_manual_auth_completion(
            page,
            config,
            logger,
            channel,
            credential_error,
            login_profile,
            policy,
        )
    handle_saml_consent_if_present(page)
    if wait_for_login_success(page, config, login_profile):
        if exact_scope in {"cnki", "wanfang_data"} and configured_institution_marker_visible(
            page,
            config,
            exact_scope,
        ):
            return BrowserAuthResult(True, f"{exact_scope}_institution_marker")
        return BrowserAuthResult(True, "login_succeeded")
    if manual_auth_required(page_text(page)) or security_challenge_required(page_text(page)):
        return wait_for_manual_auth_completion(page, config, logger, channel, "manual_intervention_required", login_profile, policy)
    return wait_for_manual_auth_completion(page, config, logger, channel, "login_failed", login_profile, policy)


def login_personal_with_playwright(
    page: Any,
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    logger: logging.Logger,
) -> BrowserAuthResult:
    if config.path != "personal" or not config.account or not config.password:
        return BrowserAuthResult(False, "personal_auth_config_incomplete")
    login_profile = channel_login_profile(channel, policy)
    entry_url = login_profile.entry_url
    try:
        if entry_url:
            safe_browser_goto(page, entry_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            dismiss_common_cookie_banner(page)
    except Exception as exc:
        logger.info("Personal login entry navigation failed for %s: %s", channel, exc)
    text = page_text(page)
    if manual_auth_required(text):
        return wait_for_manual_auth_completion(page, config, logger, channel, "manual_intervention_required", login_profile, policy)
    click_first_text(page, ("Sign in", "Log in", "Login", "My account", "Personal login", "登录"))
    credential_error = submit_generic_credentials_guarded(
        page, config, login_profile, policy
    )
    if credential_error:
        return wait_for_manual_auth_completion(
            page,
            config,
            logger,
            channel,
            credential_error,
            login_profile,
            policy,
        )
    if wait_for_login_success(page, config, login_profile):
        return BrowserAuthResult(True, "login_succeeded")
    if manual_auth_required(page_text(page)):
        return wait_for_manual_auth_completion(page, config, logger, channel, "manual_intervention_required", login_profile, policy)
    return wait_for_manual_auth_completion(page, config, logger, channel, "login_failed", login_profile, policy)


def login_uyanip_with_playwright(
    page: Any,
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    logger: logging.Logger,
) -> BrowserAuthResult:
    if not config.uyanip_account or not config.uyanip_password:
        return BrowserAuthResult(False, "uyanip_credentials_missing")
    login_profile = channel_login_profile(channel, policy)
    entry_url = str(policy.get("auth_entry_url") or login_profile.entry_url or UYANIP_HOME)
    try:
        safe_browser_goto(page, entry_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        dismiss_common_cookie_banner(page)
    except Exception as exc:
        logger.info("Uyan login entry navigation failed: %s", exc)
    initial_body = page_text(page)
    if uyanip_invalid_credentials(initial_body):
        return BrowserAuthResult(False, "uyanip_credentials_invalid")
    if (
        uyanip_authenticated_marker_visible(initial_body)
        and not uyanip_password_surface_visible(page)
    ):
        return BrowserAuthResult(True, "uyanip_state_already_authenticated")
    if security_challenge_required(initial_body):
        return wait_for_manual_auth_completion(
            page,
            config,
            logger,
            channel,
            "uyanip_security_challenge",
            login_profile,
            policy,
            entry_url,
        )
    login_form = uyanip_login_form_locators(page)
    if login_form is None:
        login_entry, login_entry_count = unique_visible_locator(
            page,
            "#login-open, a[href*='login' i], button[data-action*='login' i]",
        )
        if login_entry is None:
            return BrowserAuthResult(
                False,
                "uyanip_login_gate_ambiguous"
                if login_entry_count > 1
                else "uyanip_login_gate_not_found",
            )
        try:
            login_entry.click(timeout=3000)
            wait_for_page_settle(page)
        except Exception:
            return BrowserAuthResult(False, "uyanip_login_gate_not_ready")
        login_form = uyanip_login_form_locators(page)
    if login_form is None:
        return BrowserAuthResult(False, "uyanip_login_form_not_found")
    if not uyanip_credential_url_allowed(str(getattr(page, "url", "") or "")):
        return BrowserAuthResult(False, "uyanip_credential_host_not_allowed")
    username, password, submit = login_form
    if not uyanip_login_form_target_allowed(page, username, password, submit):
        return BrowserAuthResult(False, "uyanip_credential_target_not_allowed")
    blocked_urls: list[str] = []
    route_guard = install_uyanip_credential_route_guard(page, blocked_urls)
    if route_guard is None:
        return BrowserAuthResult(False, "uyanip_credential_transport_guard_unavailable")
    login_response_states: list[str] = []

    def capture_login_response(response: Any) -> None:
        response_url = str(getattr(response, "url", "") or "")
        if not uyanip_login_api_response_url(response_url):
            return
        try:
            payload = response.json()
        except Exception:
            payload = None
        response_status = int(getattr(response, "status", 0) or 0)
        response_state = uyanip_login_api_state(response_status, payload)
        if response_state in {"success", "rejected"}:
            login_response_states.append(response_state)

    try:
        page.on("response", capture_login_response)
    except Exception:
        try:
            page.unroute("**/*", route_guard)
        except Exception:
            pass
        return BrowserAuthResult(False, "uyanip_login_response_guard_unavailable")
    try:
        try:
            username.fill(config.uyanip_account, timeout=5000)
            password.fill(config.uyanip_password, timeout=5000)
        except Exception:
            return BrowserAuthResult(False, "uyanip_login_form_not_found")
        try:
            submit.click(timeout=5000)
        except Exception:
            return BrowserAuthResult(False, "uyanip_login_submit_not_ready")
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10_000)
        except Exception:
            pass
        deadline = time.monotonic() + uyanip_login_timeout_seconds()
        while time.monotonic() < deadline:
            if blocked_urls:
                return BrowserAuthResult(False, "uyanip_credential_target_not_allowed")
            body = page_text(page)
            if uyanip_invalid_credentials(body) or "rejected" in login_response_states:
                return BrowserAuthResult(False, "uyanip_credentials_invalid")
            if security_challenge_required(body):
                return wait_for_manual_auth_completion(
                    page,
                    config,
                    logger,
                    channel,
                    "uyanip_security_challenge",
                    login_profile,
                    policy,
                    entry_url,
                )
            password_visible = uyanip_password_surface_visible(page)
            if "success" in login_response_states and not password_visible:
                return BrowserAuthResult(True, "uyanip_login_succeeded")
            time.sleep(0.25)
        return BrowserAuthResult(False, "uyanip_login_timeout")
    finally:
        try:
            page.remove_listener("response", capture_login_response)
        except Exception:
            try:
                page.off("response", capture_login_response)
            except Exception:
                pass
        try:
            page.unroute("**/*", route_guard)
        except Exception:
            pass


def policy_auth_entries(policy: dict[str, Any]) -> tuple[dict[str, str], ...]:
    entries: list[dict[str, str]] = []
    raw_entries = policy.get("auth_entries") or ()
    for entry in raw_entries if isinstance(raw_entries, (list, tuple)) else ():
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "")
        if not url:
            continue
        entries.append(
            {
                "id": str(entry.get("id") or entry.get("entry_id") or "default_institution"),
                "url": url,
                "mode": str(entry.get("mode") or "institution"),
            }
        )
    if entries:
        return tuple(entries)
    entry_url = str(policy.get("auth_entry_url") or policy.get("web_search_url") or "")
    return ({"id": "default_institution", "url": entry_url, "mode": "institution"},) if entry_url else ()


def login_shared_institution_with_control(
    page: Any,
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    logger: logging.Logger,
) -> BrowserAuthResult:
    if config.path != "institution" or not config.school.strip() or not config.account or not config.password:
        return BrowserAuthResult(False, "institutional_auth_config_incomplete")
    profile = channel_login_profile(channel, policy)
    entry_url = str(policy.get("auth_entry_url") or profile.entry_url or "")
    try:
        if entry_url:
            safe_browser_goto(page, entry_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            dismiss_common_cookie_banner(page)
    except Exception as exc:
        logger.info("Shared institutional entry navigation failed for %s: %s", channel, exc)
    scope = source_auth_state_scope(channel, policy)
    if scope in {"cnki", "wanfang_data"} and configured_institution_marker_visible(
        page,
        config,
        scope,
    ):
        return BrowserAuthResult(True, f"{scope}_institution_marker")
    if scope not in {"cnki", "wanfang_data"} and is_restricted_login_successful(
        page,
        config,
        profile,
    ):
        return BrowserAuthResult(True, "existing_session_unattested")
    return wait_for_manual_auth_completion(
        page,
        config,
        logger,
        channel,
        "institution_auth_required",
        profile,
        policy,
        str(policy.get("_current_record_resume_url") or ""),
        str(policy.get("_seed_storage_state_path") or ""),
    )


def authenticate_if_needed(page: Any, config: DownloadConfig, channel: str, policy: dict[str, Any], logger: logging.Logger) -> BrowserAuthResult:
    if channel == UYANIP_SOURCE:
        return login_uyanip_with_playwright(page, config, channel, policy, logger)
    if not auth_enabled_for_channel(config, channel, policy):
        return BrowserAuthResult(False, "skipped_auth_required")
    if config.path == "institution":
        entries = policy_auth_entries(policy)
        if not entries:
            if source_auth_state_scope(channel, policy):
                return login_shared_institution_with_control(page, config, channel, policy, logger)
            return login_institutional_with_playwright(page, config, channel, policy, logger)
        last_result = BrowserAuthResult(False, "institution_auth_entries_exhausted")
        for entry in entries:
            entry_policy = dict(policy)
            entry_policy["auth_entry_url"] = entry["url"]
            entry_policy["_active_auth_entry_id"] = entry["id"]
            entry_policy["_active_auth_entry_mode"] = entry["mode"]
            last_result = (
                login_shared_institution_with_control(
                    page,
                    config,
                    channel,
                    entry_policy,
                    logger,
                )
                if source_auth_state_scope(channel, entry_policy)
                else login_institutional_with_playwright(
                    page,
                    config,
                    channel,
                    entry_policy,
                    logger,
                )
            )
            if last_result.ok:
                return last_result
        return last_result
    if config.path == "personal":
        return login_personal_with_playwright(page, config, channel, policy, logger)
    return BrowserAuthResult(False, "invalid_auth_path")


def extract_pmcid(row: dict[str, Any]) -> str:
    text = " ".join(str(value or "") for value in [get_field(row, PMCID_ALIASES), row.get("url", ""), row.get("URL", ""), row.get("raw_id", "")])
    match = re.search(r"\bPMC\d+\b", text, flags=re.I)
    if match:
        return match.group(0).upper()
    numeric_match = re.search(r"(?:/pmc/articles/|^)(\d{5,})(?:/|$)", text, flags=re.I)
    return f"PMC{numeric_match.group(1)}" if numeric_match else ""


def extract_pmid(row: dict[str, Any]) -> str:
    explicit = get_field(row, PMID_ALIASES).strip()
    # PubMed identifiers are numeric but older records may contain only one to
    # four digits.  Restrict parsing to the dedicated PMID field so accepting
    # those identifiers cannot accidentally reinterpret a year in free text.
    match = re.fullmatch(r"(?:PMID\s*[:#]?\s*)?(\d{1,10})", explicit, flags=re.I)
    return match.group(1) if match else ""


def extract_arxiv_id(row: dict[str, Any]) -> str:
    values: list[str] = []
    explicit = get_field(row, ARXIV_ID_ALIASES)
    if explicit and "arxiv" in explicit.casefold():
        values.append(explicit)
    for key, value in row.items():
        key_text = str(key).casefold()
        value_text = str(value or "")
        if "arxiv" in key_text or "arxiv" in value_text.casefold():
            values.append(value_text)
    combined = " ".join(values)
    match = re.search(r"(?:arxiv[:/\s])?(\d{4}\.\d{4,5}(?:v\d+)?|[a-z\-]+(?:\.[A-Z]{2})?/\d{7}(?:v\d+)?)", combined, flags=re.I)
    return match.group(1) if match else ""


def make_safe_pdf_filename(record_type: str, title: str, identifier: str) -> str:
    digest = hashlib.sha256((identifier or title or record_type).encode("utf-8", errors="ignore")).hexdigest()[:16]
    normalized = unicodedata.normalize("NFKD", title or "")
    ascii_title = normalized.encode("ascii", "ignore").decode("ascii")
    clean = re.sub(r"[\\/:*?\"<>|]+", " ", ascii_title)
    clean = re.sub(r"\s+", " ", clean).strip()
    clean = re.sub(r"[^A-Za-z0-9 ._()-]+", "", clean).strip(" ._")
    if not clean:
        clean = "literature" if record_type == "literature" else "patent"
    clean = clean[:100].strip(" ._") or record_type
    return f"{clean}__{digest}.pdf"


def pdf_validation_details(path: Path) -> dict[str, Any]:
    details: dict[str, Any] = {
        "valid": False,
        "reason_code": "invalid_pdf",
        "encrypted": False,
        "page_structure": False,
        "eof": False,
        "xref": False,
        "parser": "manual_structural_fallback",
    }
    manual_page_marker = False
    manual_encrypt_marker = False
    try:
        if not path.exists() or not path.is_file():
            details["reason_code"] = "missing_pdf"
            return details
        size = path.stat().st_size
        details["size_bytes"] = size
        if size < MIN_PDF_BYTES:
            details["reason_code"] = "pdf_too_small"
            return details
        if size > max_pdf_bytes():
            details["reason_code"] = "response_too_large"
            return details
        with path.open("rb") as handle:
            head = handle.read(4096)
            header_offset = head.lower().find(b"%pdf-")
            if header_offset < 0 or header_offset > 1024:
                details["reason_code"] = "missing_pdf_header"
                return details
            prefix = head[: max(header_offset, 512)].lower()
            if any(
                token in prefix
                for token in (
                    b"<html",
                    b"<!doctype html",
                    b"<script",
                    b"{\"error",
                    b"captcha",
                )
            ):
                details["reason_code"] = "polyglot_pdf"
                return details
            handle.seek(max(0, size - 65536))
            tail = handle.read()
            eof_index = tail.rfind(b"%%EOF")
            if eof_index < 0 or len(tail) - (eof_index + len(b"%%EOF")) > 4096:
                details["reason_code"] = "truncated_pdf"
                return details
            trailing = tail[eof_index + len(b"%%EOF") :]
            if trailing.strip(b"\x00\t\n\r\f "):
                details["reason_code"] = "polyglot_pdf"
                return details
            details["eof"] = True
            # Cross-reference streams, object streams, and encrypted object
            # bodies need not expose plaintext ``/Type /Page(s)`` tokens.
            # Header/polyglot/EOF checks remain a bounded preflight; the
            # required structural parser below is authoritative.
            handle.seek(0)
            overlap = b""
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                probe = overlap + chunk
                manual_page_marker = manual_page_marker or bool(
                    re.search(rb"/Type\s*/Pages?\b", probe)
                )
                manual_encrypt_marker = manual_encrypt_marker or b"/Encrypt" in probe
                overlap = probe[-128:]
        try:
            from pypdf import PdfReader
        except ImportError:
            # The hand-written checks above are only a bounded preflight.  A
            # structural parser is a required runtime dependency and must not
            # silently degrade to header/xref heuristics.
            details["reason_code"] = "pdf_parser_unavailable"
            return details
        try:
            reader = PdfReader(str(path), strict=True)
            details["parser"] = "pypdf"
            details["encrypted"] = bool(reader.is_encrypted)
            details["xref"] = bool(
                getattr(reader, "xref", None)
                or getattr(reader, "xref_objStm", None)
                or getattr(reader, "trailer", None)
            )
            if reader.is_encrypted:
                # A parser-recognized encrypted document is a valid artifact
                # even when no password is available to enumerate its pages.
                details["page_structure"] = True
            elif len(reader.pages) < 1:
                details["reason_code"] = "missing_pdf_page_structure"
                return details
            else:
                details["page_structure"] = True
        except Exception:
            details["encrypted"] = manual_encrypt_marker
            details["reason_code"] = (
                "missing_pdf_page_structure"
                if not manual_encrypt_marker and not manual_page_marker
                else "pdf_parse_error"
            )
            return details
        details["valid"] = True
        details["reason_code"] = "valid_encrypted_pdf" if details["encrypted"] else "valid_pdf"
        return details
    except (OSError, ValueError):
        details["reason_code"] = "pdf_parse_error"
        return details


def is_valid_pdf(path: Path) -> bool:
    return bool(pdf_validation_details(path).get("valid"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def order_download_channels(channels: Mapping[str, str], priority: tuple[str, ...]) -> OrderedDict[str, str]:
    ordered: OrderedDict[str, str] = OrderedDict()
    for channel in priority:
        if channel in channels:
            ordered[channel] = channels[channel]
    for channel, template in channels.items():
        if channel not in ordered:
            ordered[channel] = template
    return ordered


def channel_strategy_snapshot(path_map: Mapping[str, str], tag_map: dict[str, tuple[str, ...]]) -> list[dict[str, Any]]:
    return [
        {
            "priority": index,
            "channel": channel,
            "template": sanitize_url_for_output(template),
            "method_tags": list(tag_map.get(channel, ("unclassified",))),
        }
        for index, (channel, template) in enumerate(path_map.items(), start=1)
    ]


def policy_required_keys(policy: dict[str, Any]) -> tuple[str, ...]:
    value = policy.get("required_keys") or ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(key) for key in value)
    return ()


def new_source_policy(source: str, record_type: str) -> dict[str, Any]:
    if source == CNKI_SOURCE:
        return {
            "api_kind": "none",
            "requires_auth": True,
            "institutional_web_allowed": True,
            "personal_web_allowed": True,
            "public_browser_allowed": True,
            "browser_default_enabled": True,
            "browser_requires_restricted_access": True,
            "web_search_url": CNKI_PATENT_HOME if record_type == "patent" else CNKI_HOME,
            "auth_entry_url": CNKI_HOME,
            "auth_state_scope": "cnki",
            "auth_entries": (
                {"id": "cnki_home_offcampus", "entry_id": "cnki_home_offcampus", "url": CNKI_HOME, "mode": "institution"},
                {"id": "cnki_fsso", "entry_id": "cnki_fsso", "url": CNKI_FSSO_HOME, "mode": "institution"},
            ),
        }
    if source == WANFANG_SOURCE:
        return {
            "api_kind": "none",
            "requires_auth": True,
            "institutional_web_allowed": True,
            "personal_web_allowed": True,
            "public_browser_allowed": True,
            "browser_default_enabled": True,
            "browser_requires_restricted_access": True,
            "web_search_url": WANFANG_PATENT_HOME if record_type == "patent" else WANFANG_HOME,
            "auth_entry_url": WANFANG_HOME,
            "auth_state_scope": "wanfang_data",
            "auth_entries": (
                {"id": "wanfang_home_institution", "entry_id": "wanfang_home_institution", "url": WANFANG_HOME, "mode": "institution"},
                {"id": "wanfang_fsso", "entry_id": "wanfang_fsso", "url": WANFANG_FSSO_HOME, "mode": "institution"},
            ),
        }
    if source == UYANIP_SOURCE:
        return {
            "api_kind": "none",
            "requires_auth": True,
            "institutional_web_allowed": False,
            "personal_web_allowed": True,
            "public_browser_allowed": True,
            "browser_default_enabled": True,
            "browser_requires_restricted_access": True,
            "web_search_url": UYANIP_HOME,
            "auth_entry_url": UYANIP_HOME,
            "auth_state_scope": "uyanip",
            "runtime_personal_credential_keys": ("uyanip_account", "uyanip_password"),
            "auth_entries": (),
        }
    return {}


def build_fallback_download_maps() -> None:
    load_download_maps_from_search_script(SEARCH_SCRIPT_PATH)


def registry_download_policy(spec: Any) -> dict[str, Any]:
    capabilities = tuple(str(value) for value in spec.capabilities)
    restricted = any(
        value in capabilities
        for value in (
            "restricted_web",
            "restricted_web_fallback",
            "institution_or_carsi_auth_path",
            "site_personal_auth",
        )
    )
    public_browser = any(
        value in capabilities
        for value in (
            "public_browser",
            "public_web",
            "landing_page_discovery",
            "doi_landing_page",
        )
    )
    endpoint = str(spec.endpoint or "")
    return {
        "api_kind": "configured_api" if spec.config_keys else "no_config",
        "kind": "configured_api" if spec.config_keys else "no_config",
        "required_keys": tuple(spec.config_keys),
        "optional_keys": tuple(spec.optional_config_keys),
        "requires_auth": restricted,
        "institutional_web_allowed": restricted,
        "personal_web_allowed": restricted,
        "public_browser_allowed": public_browser,
        "browser_default_enabled": public_browser or restricted,
        "browser_requires_restricted_access": restricted,
        "web_search_url": endpoint if endpoint.startswith(("http://", "https://")) else "",
        "auth_state_scope": str(spec.auth_scope or "unknown"),
        "actual_adapter": str(spec.actual_adapter or ""),
        "fallback_resolver": str(spec.fallback_resolver or ""),
        "capabilities": capabilities,
        "native_capability": "metadata_origin" if "metadata_origin" in capabilities else "locator_discovery",
        "registry_version": REGISTRY_VERSION,
    }


def load_download_maps_from_search_script(search_script_path: Path | None = None) -> tuple[OrderedDict[str, str], OrderedDict[str, str], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Load the shared registry; ``search_script_path`` remains a CLI compatibility argument."""
    del search_script_path
    validate_registry()
    literature_specs = get_download_adapters("literature")
    patent_specs = get_download_adapters("patent")
    literature_download_path_map.clear()
    literature_download_path_map.update(
        (spec.display_name, spec.endpoint) for spec in literature_specs
    )
    patents_download_path_map.clear()
    patents_download_path_map.update(
        (spec.display_name, spec.endpoint) for spec in patent_specs
    )
    literature_channel_policy_map.clear()
    patents_channel_policy_map.clear()
    literature_channel_policy_map.update(
        (spec.display_name, registry_download_policy(spec)) for spec in literature_specs
    )
    patents_channel_policy_map.update(
        (spec.display_name, registry_download_policy(spec)) for spec in patent_specs
    )
    LITERATURE_CHANNEL_METHOD_TAGS.clear()
    LITERATURE_CHANNEL_METHOD_TAGS.update(
        (spec.display_name, tuple(spec.capabilities)) for spec in literature_specs
    )
    PATENT_CHANNEL_METHOD_TAGS.clear()
    PATENT_CHANNEL_METHOD_TAGS.update(
        (spec.display_name, tuple(spec.capabilities)) for spec in patent_specs
    )
    for source in (CNKI_SOURCE, WANFANG_SOURCE):
        parsed = literature_channel_policy_map.get(source, {})
        literature_channel_policy_map[source] = parsed | new_source_policy(source, "literature")
    for source in (CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE):
        parsed = patents_channel_policy_map.get(source, {})
        patents_channel_policy_map[source] = parsed | new_source_policy(source, "patent")
    validate_channel_parser_coverage()
    return literature_download_path_map, patents_download_path_map, literature_channel_policy_map, patents_channel_policy_map


def ensure_literature_download_map_loaded() -> None:
    if not literature_download_path_map:
        load_download_maps_from_search_script(SEARCH_SCRIPT_PATH)


def ensure_patents_download_map_loaded() -> None:
    if not patents_download_path_map:
        load_download_maps_from_search_script(SEARCH_SCRIPT_PATH)


def iter_csv_chunks(csv_path: Path, chunk_size: int | None = None) -> Iterator[list[dict[str, str]]]:
    if chunk_size is None:
        chunk_size = download_chunk_size()
    last_error: Exception | None = None
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            with csv_path.open("r", encoding=encoding, newline="") as handle:
                reader = csv.DictReader(handle)
                chunk: list[dict[str, str]] = []
                for row in reader:
                    chunk.append({str(k): ("" if v is None else str(v)) for k, v in row.items() if k is not None})
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
                if chunk:
                    yield chunk
            return
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
    if last_error:
        raise last_error


def iter_row_chunks(rows: Iterator[dict[str, Any]], chunk_size: int | None = None) -> Iterator[list[dict[str, Any]]]:
    size = chunk_size or download_chunk_size()
    chunk: list[dict[str, Any]] = []
    for row in rows:
        chunk.append(row)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def merge_planner_rows(rows: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Merge duplicate identities before scheduling so alternate locators survive."""
    merged: OrderedDict[str, dict[str, Any]] = OrderedDict()
    readiness_rank = {
        "metadata_only": 0,
        "landing_discoverable": 1,
        "identifier_resolvable": 2,
        "direct_pdf": 3,
    }

    def merge_mapping_list(target: dict[str, Any], key: str, incoming: Any) -> None:
        existing = target.get(key)
        values = list(existing) if isinstance(existing, list) else []
        seen = {
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            for value in values
        }
        for value in incoming if isinstance(incoming, list) else []:
            marker = json.dumps(value, ensure_ascii=False, sort_keys=True)
            if marker not in seen:
                values.append(value)
                seen.add(marker)
        target[key] = values

    for row in rows:
        record_type = str(row.get("record_type") or "").casefold()
        if record_type not in {"literature", "patent"}:
            record_type = "literature" if row.get("doi") or row.get("DOI") else "patent"
        record_id = str(row.get("record_id") or stable_record_id(record_type, row))
        row["record_id"] = record_id
        current = merged.get(record_id)
        if current is None:
            merged[record_id] = row
            continue
        for key in ("identifiers", "locators", "provenance", "metadata_sources", "locator_urls"):
            merge_mapping_list(current, key, row.get(key))
        current_readiness = str(current.get("retrieval_readiness") or "metadata_only")
        incoming_readiness = str(row.get("retrieval_readiness") or "metadata_only")
        if readiness_rank.get(incoming_readiness, 0) > readiness_rank.get(current_readiness, 0):
            current["retrieval_readiness"] = incoming_readiness
        current_canonical = current.get("_canonical_record")
        incoming_canonical = row.get("_canonical_record")
        if isinstance(current_canonical, dict) and isinstance(incoming_canonical, dict):
            for key in ("identifiers", "locators", "provenance"):
                merge_mapping_list(current_canonical, key, incoming_canonical.get(key))
            current_canonical["retrieval_readiness"] = current.get("retrieval_readiness", current_readiness)
        for key, value in row.items():
            if key not in current or current[key] in (None, "", [], {}):
                current[key] = value
    yield from merged.values()


def normalized_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return (parsed.hostname or parsed.netloc or "local").casefold()


def domain_semaphore(url: str) -> BoundedSemaphore:
    host = normalized_domain(url)
    with DOMAIN_LOCK:
        if host not in DOMAIN_SEMAPHORES:
            limit = max(1, int(os.getenv("LAPS_DOWNLOAD_MAX_PER_DOMAIN", "2")))
            DOMAIN_SEMAPHORES[host] = BoundedSemaphore(limit)
        return DOMAIN_SEMAPHORES[host]


def safe_browser_goto(page: Any, url: str, **kwargs: Any) -> Any:
    if not network_url_allowed(url):
        raise UnsafeNetworkTargetError("browser navigation target rejected")
    cooldown_reason = domain_cooldown_reason(url)
    if cooldown_reason:
        raise DomainCooldownError(cooldown_reason)
    polite_delay()
    semaphore = domain_semaphore(url)
    with semaphore:
        cooldown_reason = domain_cooldown_reason(url)
        if cooldown_reason:
            raise DomainCooldownError(cooldown_reason)
        response = page.goto(url, **kwargs)
        final_url = str(getattr(page, "url", "") or url)
        if not network_url_allowed(final_url):
            raise UnsafeNetworkTargetError("browser redirect target rejected")
        return response


def polite_delay() -> None:
    lo = float(os.getenv("LAPS_DOWNLOAD_DELAY_MIN", os.getenv("LAPS_DELAY_MIN", "0.5")))
    hi = float(os.getenv("LAPS_DOWNLOAD_DELAY_MAX", os.getenv("LAPS_DELAY_MAX", "15")))
    lo = max(0.0, lo)
    hi = max(lo, hi)
    if hi:
        time.sleep(random.uniform(lo, hi))


def retry_delay(headers: Any, attempt: int) -> float:
    def capped(delay: float) -> float:
        return min(max(0.0, delay), inline_retry_max_seconds())

    retry_after = ""
    if headers:
        retry_after = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    if retry_after:
        try:
            return capped(float(retry_after))
        except ValueError:
            try:
                retry_at = email.utils.parsedate_to_datetime(retry_after)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return capped((retry_at - datetime.now(timezone.utc)).total_seconds())
            except Exception:
                pass
    return capped((2**attempt) + random.random())


def inline_retry_max_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("LAPS_INLINE_RETRY_MAX_SECONDS", "30")))
    except Exception:
        return 30.0


def retry_after_seconds(headers: Any) -> float | None:
    retry_after = ""
    if headers:
        retry_after = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    if not retry_after:
        return None
    try:
        return max(0.0, float(retry_after))
    except ValueError:
        try:
            retry_at = email.utils.parsedate_to_datetime(retry_after)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())
        except Exception:
            return None


def retry_at_from_headers(headers: Any) -> str:
    """Return a non-sensitive absolute retry time for an HTTP response."""
    seconds = retry_after_seconds(headers)
    if seconds is None:
        return ""
    return datetime.fromtimestamp(
        time.time() + seconds,
        tz=timezone.utc,
    ).isoformat(timespec="seconds")


def retry_at_from_reason(reason: str) -> str:
    """Recover the persisted cooldown deadline encoded in ledger reasons."""
    match = re.search(r":(\d+)s$", str(reason or "").strip(), flags=re.I)
    if not match:
        return ""
    return datetime.fromtimestamp(
        time.time() + int(match.group(1)),
        tz=timezone.utc,
    ).isoformat(timespec="seconds")


def should_inline_retry(headers: Any) -> bool:
    retry_after = retry_after_seconds(headers)
    if retry_after is None:
        return True
    return retry_after <= inline_retry_max_seconds()


RATE_LIMIT_HTTP_STATUSES = {429}
SERVICE_UNAVAILABLE_HTTP_STATUSES = {500, 502, 503, 504, 520, 521, 522, 523, 524}
RETRYABLE_HTTP_STATUSES = RATE_LIMIT_HTTP_STATUSES | SERVICE_UNAVAILABLE_HTTP_STATUSES
SECURITY_CHALLENGE_HOOK_REASONS = {"security_challenge_required"}
RECOVERABLE_CHANNEL_BLOCK_REASONS: set[str] = set()
AUTH_CHANNEL_COOLDOWN_REASONS = {
    "manual_intervention_required",
    "manual_pending_timeout",
    "external_auth_hook_timeout",
    "external_auth_hook_failed",
    "external_auth_hook_unhandled",
    "external_auth_hook_cooldown",
    "login_failed",
    "login_form_not_found",
    "school_not_found",
    "uyanip_credentials_invalid",
    "uyanip_credential_host_not_allowed",
    "uyanip_login_form_not_found",
    "verification_control_unhandled",
    "hook_timeout",
    "hook_empty_stdout",
    "hook_non_json_stdout",
    "hook_invalid_json",
}
AUTH_CHANNEL_COOLDOWN_PREFIXES = (
    "external_auth_hook_",
    "hook_exit_",
    "hook_failed:",
)
CHANNEL_COOLDOWN_REASONS = {"security_challenge_required", "rate_limited", "service_unavailable", "request_timeout", "network_error"} | AUTH_CHANNEL_COOLDOWN_REASONS
DOMAIN_COOLDOWN_REASONS = {
    "rate_limited",
    "access_denied",
    "security_challenge_required",
    "service_unavailable",
    "request_timeout",
    "network_error",
    "unsafe_network_target",
}


def channel_recovery_attempts() -> int:
    try:
        return max(0, int(os.getenv("LAPS_CHANNEL_RECOVERY_ATTEMPTS", "2")))
    except Exception:
        return 2


def channel_recovery_delay(reason: str, attempt: int) -> float:
    base_env = "LAPS_CHANNEL_RATE_LIMIT_COOLDOWN_SECONDS" if reason == "rate_limited" else "LAPS_CHANNEL_ACCESS_DENIED_COOLDOWN_SECONDS"
    try:
        base = max(0.0, float(os.getenv(base_env, os.getenv("LAPS_CHANNEL_RECOVERY_BASE_SECONDS", "60"))))
    except Exception:
        base = 60.0
    try:
        cap = max(base, float(os.getenv("LAPS_CHANNEL_RECOVERY_MAX_SECONDS", "900")))
    except Exception:
        cap = 900.0
    delay = min(cap, base * (2 ** max(0, attempt - 1)))
    return delay + (random.random() if delay else 0.0)


def channel_cooldown_seconds(reason: str) -> float:
    if reason == "security_challenge_required":
        env_name = "LAPS_SECURITY_CHALLENGE_COOLDOWN_SECONDS"
        default = "900"
    elif reason == "service_unavailable":
        env_name = "LAPS_SERVICE_UNAVAILABLE_COOLDOWN_SECONDS"
        default = "300"
    elif reason in {"request_timeout", "network_error"}:
        env_name = "LAPS_NETWORK_ERROR_COOLDOWN_SECONDS"
        default = "120"
    elif reason in AUTH_CHANNEL_COOLDOWN_REASONS or reason.startswith(AUTH_CHANNEL_COOLDOWN_PREFIXES):
        env_name = "LAPS_AUTH_FAILURE_COOLDOWN_SECONDS"
        default = "300"
    else:
        env_name = "LAPS_CHANNEL_COOLDOWN_SECONDS"
        default = "300"
    try:
        return max(0.0, float(os.getenv(env_name, default)))
    except Exception:
        return 900.0 if reason == "security_challenge_required" else 300.0


def domain_cooldown_seconds(reason: str) -> float:
    if reason == "security_challenge_required":
        env_name = "LAPS_SECURITY_CHALLENGE_DOMAIN_COOLDOWN_SECONDS"
        fallback = os.getenv("LAPS_SECURITY_CHALLENGE_COOLDOWN_SECONDS", "900")
    elif reason == "rate_limited":
        env_name = "LAPS_DOMAIN_RATE_LIMIT_COOLDOWN_SECONDS"
        fallback = os.getenv("LAPS_CHANNEL_RATE_LIMIT_COOLDOWN_SECONDS", "300")
    elif reason == "service_unavailable":
        env_name = "LAPS_DOMAIN_SERVICE_UNAVAILABLE_COOLDOWN_SECONDS"
        fallback = os.getenv("LAPS_SERVICE_UNAVAILABLE_COOLDOWN_SECONDS", "300")
    elif reason in {"request_timeout", "network_error"}:
        env_name = "LAPS_DOMAIN_NETWORK_ERROR_COOLDOWN_SECONDS"
        fallback = os.getenv("LAPS_NETWORK_ERROR_COOLDOWN_SECONDS", "120")
    else:
        env_name = "LAPS_DOMAIN_ACCESS_DENIED_COOLDOWN_SECONDS"
        fallback = os.getenv("LAPS_CHANNEL_ACCESS_DENIED_COOLDOWN_SECONDS", "600")
    try:
        return max(0.0, float(os.getenv(env_name, os.getenv("LAPS_DOMAIN_COOLDOWN_SECONDS", fallback))))
    except Exception:
        try:
            return max(0.0, float(fallback))
        except Exception:
            return 600.0


def mark_domain_cooldown(url: str, reason: str, logger: logging.Logger) -> None:
    if reason not in DOMAIN_COOLDOWN_REASONS:
        return
    host = normalized_domain(url)
    seconds = domain_cooldown_seconds(reason)
    if not host or seconds <= 0:
        return
    until = time.monotonic() + seconds
    with DOMAIN_LOCK:
        DOMAIN_COOLDOWNS[host] = (until, reason)
    if ACTIVE_DOWNLOAD_LEDGER is not None:
        ACTIVE_DOWNLOAD_LEDGER.set_cooldown("domain", host, reason, time.time() + seconds)
    logger.warning("Domain %s entered %.0f second cooldown after %s; matching candidate URLs will be skipped", host, seconds, reason)


def domain_cooldown_reason(url: str) -> str:
    host = normalized_domain(url)
    with DOMAIN_LOCK:
        value = DOMAIN_COOLDOWNS.get(host)
        if not value:
            value = None
        else:
            until, reason = value
            remaining = until - time.monotonic()
            if remaining <= 0:
                DOMAIN_COOLDOWNS.pop(host, None)
            else:
                return f"domain_cooldown:{reason}:{int(remaining)}s"
    return ACTIVE_DOWNLOAD_LEDGER.cooldown_reason("domain", host) if ACTIVE_DOWNLOAD_LEDGER is not None else ""


def mark_channel_cooldown(channel: str, reason: str, logger: logging.Logger) -> None:
    if reason not in CHANNEL_COOLDOWN_REASONS and not reason.startswith(AUTH_CHANNEL_COOLDOWN_PREFIXES):
        return
    seconds = channel_cooldown_seconds(reason)
    if seconds <= 0:
        return
    until = time.monotonic() + seconds
    with CHANNEL_COOLDOWN_LOCK:
        CHANNEL_COOLDOWNS[channel.casefold()] = (until, reason)
    if ACTIVE_DOWNLOAD_LEDGER is not None:
        ACTIVE_DOWNLOAD_LEDGER.set_cooldown("channel", channel, reason, time.time() + seconds)
    logger.warning("Channel %s entered %.0f second cooldown after %s; later records will try subsequent channels", channel, seconds, reason)


def channel_cooldown_reason(channel: str) -> str:
    key = channel.casefold()
    with CHANNEL_COOLDOWN_LOCK:
        value = CHANNEL_COOLDOWNS.get(key)
        if value:
            until, reason = value
            remaining = until - time.monotonic()
            if remaining <= 0:
                CHANNEL_COOLDOWNS.pop(key, None)
            else:
                return f"channel_cooldown:{reason}:{int(remaining)}s"
    return ACTIVE_DOWNLOAD_LEDGER.cooldown_reason("channel", key) if ACTIVE_DOWNLOAD_LEDGER is not None else ""


def channel_cooldown_snapshot() -> dict[str, dict[str, Any]]:
    now = time.monotonic()
    snapshot: dict[str, dict[str, Any]] = {}
    with CHANNEL_COOLDOWN_LOCK:
        expired = [key for key, (until, _) in CHANNEL_COOLDOWNS.items() if until <= now]
        for key in expired:
            CHANNEL_COOLDOWNS.pop(key, None)
        for key, (until, reason) in CHANNEL_COOLDOWNS.items():
            snapshot[key] = {"reason": reason, "remaining_seconds": max(0, int(until - now))}
    return snapshot


def domain_cooldown_snapshot() -> dict[str, dict[str, Any]]:
    now = time.monotonic()
    snapshot: dict[str, dict[str, Any]] = {}
    with DOMAIN_LOCK:
        expired = [key for key, (until, _) in DOMAIN_COOLDOWNS.items() if until <= now]
        for key in expired:
            DOMAIN_COOLDOWNS.pop(key, None)
        for key, (until, reason) in DOMAIN_COOLDOWNS.items():
            snapshot[key] = {"reason": reason, "remaining_seconds": max(0, int(until - now))}
    return snapshot


def challenge_hook_timeout_seconds() -> int:
    return hook_control_timeout_seconds("LAPS_SECURITY_CHALLENGE_HOOK_TIMEOUT_SECONDS")


def normalize_challenge_action(value: str) -> str:
    action = (value or "").strip().casefold()
    aliases = {
        "resolved": "retry",
        "continue": "retry",
        "try_again": "retry",
        "switch": "skip",
        "switch_source": "skip",
        "next": "skip",
        "unable": "unhandled",
        "failed": "unhandled",
    }
    return aliases.get(action, action if action in {"retry", "skip", "cooldown", "manual_pending", "unhandled"} else "unhandled")


def security_challenge_control(
    record_type: str,
    title: str,
    doi: str,
    url: str,
    channel: str,
    candidate_url: str,
    reason: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str = "open",
    policy: dict[str, Any] | None = None,
    resume_url: str = "",
) -> ChallengeControlResult:
    command = verification_hook_command("security_challenge")
    if not command:
        return ChallengeControlResult()
    event_id = verification_event_id("security_challenge", channel)
    artifacts = verification_artifact_paths(event_id)
    selected_policy = policy or (
        patents_channel_policy_map.get(channel, {})
        if record_type == "patent"
        else literature_channel_policy_map.get(channel, {})
    )
    payload = build_verification_payload(
        event="security_challenge",
        event_id=event_id,
        challenge_type=classify_verification_challenge("", reason, candidate_url or url),
        channel=channel,
        reason=reason,
        config=config,
        current_url=candidate_url,
        candidate_url=candidate_url,
        record_type=record_type,
        title=title,
        doi=doi,
        source_url=url,
        access_mode=access_mode,
        screenshot_path=str(artifacts["screenshot"]),
        storage_state_path=str(artifacts["storage_state"]),
        timeout_seconds=challenge_hook_timeout_seconds(),
        source=channel,
        search_record_type=record_type,
        auth_state_scope=source_auth_state_scope(channel, selected_policy),
        auth_entry_id=str(selected_policy.get("_active_auth_entry_id") or ""),
        auth_entry_mode=str(
            selected_policy.get("_active_auth_entry_mode")
            or ("site_personal" if channel == UYANIP_SOURCE else "institution")
        ),
        resume_url=resume_url
        or str(selected_policy.get("_current_record_resume_url") or "")
        or candidate_url
        or url,
        seed_storage_state_path=str(selected_policy.get("_seed_storage_state_path") or ""),
        policy=selected_policy,
    )
    if os.getenv("LAPS_SECURITY_CHALLENGE_HOOK_ALLOW_RAW_URL", "").strip().casefold() in {"1", "true", "yes", "on"}:
        payload["raw_url"] = url
        payload["raw_candidate_url"] = candidate_url
    registration_error = register_pending_verification_request(payload)
    if registration_error:
        return ChallengeControlResult("unhandled", registration_error)
    bundled_hook = (
        len(command) >= 2
        and Path(command[1]).resolve() == bundled_verification_hook_path().resolve()
    )
    logger.info("Security challenge hook invoked for %s/%s: %s", record_type, channel, reason)
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=challenge_hook_timeout_seconds(),
        )
    except subprocess.TimeoutExpired:
        logger.warning("Security challenge hook timed out for %s/%s", record_type, channel)
        return ChallengeControlResult("unhandled", "hook_timeout")
    except Exception as exc:
        logger.warning("Security challenge hook failed for %s/%s: %s", record_type, channel, exc)
        return ChallengeControlResult("unhandled", f"hook_failed:{exc.__class__.__name__}")
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        logger.warning("Security challenge hook returned %s for %s/%s: %s", completed.returncode, record_type, channel, stderr[:500])
        return ChallengeControlResult("unhandled", f"hook_exit_{completed.returncode}")
    if not stdout:
        return ChallengeControlResult("unhandled", "hook_empty_stdout")
    try:
        loaded = json.loads(stdout)
    except Exception:
        logger.warning("Security challenge hook returned non-JSON stdout for %s/%s", record_type, channel)
        return ChallengeControlResult("unhandled", "hook_non_json_stdout")
    if not isinstance(loaded, dict):
        return ChallengeControlResult("unhandled", "hook_invalid_json")
    control = wait_if_manual_pending(
        parse_verification_control_response(
            loaded,
            request=payload,
            allow_legacy_sync=not bundled_hook,
        ),
        event_id,
        verification_manual_timeout_seconds(),
        logger,
    )
    logger.info("Security challenge hook action for %s/%s: %s", record_type, channel, control.action)
    return control


def pdf_blocker_reason(body: bytes) -> str:
    lowered = body[:4096].lower()
    if any(
        token in lowered
        for token in (
            b"pow_challenge",
            b"cloudpmc-viewer-pow",
            b"preparing to download",
            b"are you a robot",
            b"are you are robot",
            b"verify you are human",
            b"robot check",
            b"malicious bots",
            b"checking your browser",
            b"cloudflare",
            b"attention required",
            b"altcha",
        )
    ):
        return "security_challenge_required"
    if any(token in lowered for token in (b"too many requests", b"rate limit", b"rate-limit", b"retry later", b"unusual traffic")):
        return "rate_limited"
    if any(token in lowered for token in (b"access denied", b"forbidden", b"not authorized", b"unauthorized")):
        return "access_denied"
    return ""


def http_failure_reason(status: int, headers: Any = None, body: bytes = b"") -> str:
    if status in RATE_LIMIT_HTTP_STATUSES:
        return "rate_limited"
    lowered = body[:4096].lower()
    if any(token in lowered for token in (b"too many requests", b"rate limit", b"rate-limit", b"retry later")):
        return "rate_limited"
    if status in SERVICE_UNAVAILABLE_HTTP_STATUSES:
        return "service_unavailable"
    if status in {401, 403}:
        return "access_denied"
    if status >= 400:
        return "http_error"
    return ""


def request_exception_reason(exc: Exception) -> str:
    text = f"{exc.__class__.__name__}: {exc}".casefold()
    if "resume_input_unverifiable" in text:
        return "resume_input_unverifiable"
    if isinstance(exc, UnsafeNetworkTargetError):
        return "unsafe_network_target"
    if isinstance(exc, ResponseTooLargeError):
        return "response_too_large"
    if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
        return "request_timeout"
    if isinstance(exc, urllib.error.URLError):
        if isinstance(getattr(exc, "reason", None), UnsafeNetworkTargetError):
            return "unsafe_network_target"
        return "network_error"
    if any(token in text for token in ("connection reset", "connection aborted", "temporary failure", "name resolution", "getaddrinfo", "remote end closed")):
        return "network_error"
    return f"{exc.__class__.__name__}: {exc}"


def download_timeout_seconds() -> int:
    try:
        return max(5, int(os.getenv("LAPS_DOWNLOAD_TIMEOUT_SECONDS", str(DOWNLOAD_TIMEOUT))))
    except Exception:
        return DOWNLOAD_TIMEOUT


def max_pdf_bytes() -> int:
    try:
        configured_mib = int(os.getenv("LAPS_MAX_PDF_MIB", "256"))
    except ValueError:
        configured_mib = 256
    return max(MIN_PDF_BYTES, configured_mib * 1024 * 1024)


def max_discovery_bytes() -> int:
    """Maximum materialized HTML/JSON discovery response size.

    The PDF ceiling is the backwards-compatible default and remains the hard
    upper bound.  A smaller discovery-specific ceiling can be selected for
    deployments that do not expect unusually large metadata pages.
    """

    try:
        configured_mib = int(os.getenv("LAPS_MAX_DISCOVERY_MIB", "32"))
    except ValueError:
        configured_mib = 256
    return min(max_pdf_bytes(), max(MIN_PDF_BYTES, configured_mib * 1024 * 1024))


def max_json_bytes() -> int:
    try:
        configured_mib = int(os.getenv("LAPS_MAX_JSON_MIB", "32"))
    except ValueError:
        configured_mib = 32
    return min(max_discovery_bytes(), max(MIN_PDF_BYTES, configured_mib * 1024 * 1024))


def repository_candidate_budget_seconds() -> float:
    try:
        return max(5.0, float(os.getenv("LAPS_REPOSITORY_CANDIDATE_BUDGET_SECONDS", "60")))
    except Exception:
        return 60.0


def repository_max_candidates() -> int:
    try:
        return max(1, int(os.getenv("LAPS_REPOSITORY_MAX_CANDIDATES", "3")))
    except Exception:
        return 3


class UnsafeNetworkTargetError(ValueError):
    pass


class ResponseTooLargeError(ValueError):
    pass


class ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, validator: Callable[[str], bool]) -> None:
        super().__init__()
        self.validator = validator

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> urllib.request.Request | None:
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        if not self.validator(resolved):
            raise urllib.error.URLError(
                UnsafeNetworkTargetError("redirect target rejected")
            )
        redirected = super().redirect_request(req, fp, code, msg, headers, resolved)
        if redirected is not None and request_origin(req.full_url) != request_origin(resolved):
            strip_cross_origin_sensitive_headers(redirected)
        return redirected


def public_socket_addresses(
    host: str,
    port: int,
) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    """Resolve once and reject the answer set if any address is non-public."""

    normalized = str(host or "").casefold().strip().rstrip(".")
    if not normalized:
        raise UnsafeNetworkTargetError("empty connection host")
    try:
        resolved = socket.getaddrinfo(
            normalized,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise UnsafeNetworkTargetError("connection host resolution failed") from exc
    addresses: list[tuple[int, int, int, tuple[Any, ...]]] = []
    seen: set[tuple[int, int, int, tuple[Any, ...]]] = set()
    for family, socktype, proto, _canonname, sockaddr in resolved:
        try:
            address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        except (ValueError, IndexError) as exc:
            raise UnsafeNetworkTargetError("connection address rejected") from exc
        if not address.is_global or address.is_multicast:
            raise UnsafeNetworkTargetError("connection address rejected")
        item = (family, socktype, proto, sockaddr)
        if item not in seen:
            seen.add(item)
            addresses.append(item)
    if not addresses:
        raise UnsafeNetworkTargetError("connection host has no public address")
    return addresses


def create_pinned_public_socket(
    host: str,
    port: int,
    timeout: Any,
    source_address: Any = None,
) -> socket.socket:
    """Connect to a validated numeric sockaddr without a second DNS lookup."""

    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in public_socket_addresses(host, port):
        candidate: socket.socket | None = None
        try:
            candidate = socket.socket(family, socktype, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                candidate.settimeout(timeout)
            if source_address:
                candidate.bind(source_address)
            candidate.connect(sockaddr)
            try:
                candidate.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            return candidate
        except OSError as exc:
            last_error = exc
            if candidate is not None:
                candidate.close()
    if last_error is not None:
        raise last_error
    raise UnsafeNetworkTargetError("public connection unavailable")


class PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = create_pinned_public_socket(
            self.host,
            self.port,
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        PinnedHTTPConnection.connect(self)
        server_hostname = self._tunnel_host or self.host
        assert self.sock is not None
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=server_hostname,
        )


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request: urllib.request.Request) -> Any:
        return self.do_open(PinnedHTTPConnection, request)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request: urllib.request.Request) -> Any:
        return self.do_open(
            PinnedHTTPSConnection,
            request,
            context=self._context,
        )


def build_validated_network_opener(
    validator: Callable[[str], bool],
) -> Any:
    """Build a no-proxy opener pinned to its validated public DNS answer."""

    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        PinnedHTTPHandler(),
        PinnedHTTPSHandler(),
        ValidatedRedirectHandler(validator),
    )


SENSITIVE_REDIRECT_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookie2",
        "api-key",
        "apikey",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-goog-api-key",
        "x-els-apikey",
        "x-els-insttoken",
    }
)


def request_origin(value: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(value)
    scheme = parsed.scheme.casefold()
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, (parsed.hostname or "").casefold().rstrip("."), port


def strip_cross_origin_sensitive_headers(request: urllib.request.Request) -> None:
    for container_name in ("headers", "unredirected_hdrs"):
        container = getattr(request, container_name, None)
        if not isinstance(container, dict):
            continue
        for key in list(container):
            if str(key).casefold().replace("_", "-") in SENSITIVE_REDIRECT_HEADERS:
                container.pop(key, None)


def response_looks_like_pdf(content_type: str, final_url: str, headers: Any) -> bool:
    disposition = str(headers.get("Content-Disposition") or "") if headers else ""
    return bool(
        "pdf" in str(content_type or "").casefold()
        or url_looks_like_pdf(final_url)
        or re.search(r"filename\*?\s*=.*\.pdf(?:[;\s]|$)", disposition, flags=re.I)
    )


def bounded_response_read(response: Any, limit: int) -> bytes:
    content_length = str(response.headers.get("Content-Length") or "").strip()
    if content_length.isdigit() and int(content_length) > limit:
        raise ResponseTooLargeError("response exceeds configured maximum")
    body = bytearray()
    while len(body) <= limit:
        remaining = limit + 1 - len(body)
        chunk = response.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        body.extend(chunk)
    if len(body) > limit:
        raise ResponseTooLargeError("response exceeds configured maximum")
    return bytes(body)


def response_peer_address(response: Any) -> str:
    """Best-effort peer extraction across urllib/http.client implementations."""

    queue = [response]
    seen: set[int] = set()
    for _ in range(24):
        if not queue:
            break
        current = queue.pop(0)
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        getpeername = getattr(current, "getpeername", None)
        if callable(getpeername):
            try:
                peer = getpeername()
                if isinstance(peer, tuple) and peer:
                    return str(peer[0]).split("%", 1)[0]
            except Exception:
                pass
        for name in ("fp", "raw", "_sock", "sock", "connection", "_connection"):
            child = getattr(current, name, None)
            if child is not None:
                queue.append(child)
    return ""


def validate_response_peer(
    response: Any,
    final_url: str,
    *,
    connection_pinned: bool = False,
) -> None:
    peer = response_peer_address(response)
    if not peer:
        if connection_pinned:
            return
        raise UnsafeNetworkTargetError("response peer address unavailable")
    try:
        address = ipaddress.ip_address(peer)
    except ValueError as exc:
        raise UnsafeNetworkTargetError("response peer address rejected") from exc
    if not address.is_global or address.is_multicast:
        mark_domain_cooldown(
            final_url,
            "unsafe_network_target",
            logging.getLogger("literature_patents_download"),
        )
        raise UnsafeNetworkTargetError("response peer address rejected")


def request_url(
    url: str,
    timeout: int | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 3,
    url_validator: Callable[[str], bool] | None = None,
) -> tuple[int, str, bytes, str]:
    if timeout is None:
        timeout = download_timeout_seconds()
    req_headers = {
        "User-Agent": user_agent(),
        "Accept": "application/pdf, application/octet-stream;q=0.9, text/html;q=0.8, application/json;q=0.7, */*;q=0.5",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    }
    if headers:
        req_headers.update(headers)
    if url_validator is None:
        url_validator = network_url_allowed
    if not url_validator(url):
        raise UnsafeNetworkTargetError("request target rejected")
    req = urllib.request.Request(url, headers=req_headers)
    opener = build_validated_network_opener(url_validator)
    last_error: Exception | None = None
    max_retries = max(1, retries)
    for attempt in range(1, max_retries + 1):
        try:
            cooldown_reason = domain_cooldown_reason(url)
            if cooldown_reason:
                raise DomainCooldownError(cooldown_reason)
            polite_delay()
            sem = domain_semaphore(url)
            with sem:
                cooldown_reason = domain_cooldown_reason(url)
                if cooldown_reason:
                    raise DomainCooldownError(cooldown_reason)
                response_context = opener.open(req, timeout=timeout)
                with response_context as response:
                    status = int(getattr(response, "status", 200) or 200)
                    response_headers = response.headers
                    content_type = response_headers.get("Content-Type", "")
                    final_url = response.geturl()
                    if not url_validator(final_url):
                        raise UnsafeNetworkTargetError("final response target rejected")
                    validate_response_peer(response, final_url, connection_pinned=True)
                    if response_looks_like_pdf(content_type, final_url, response_headers):
                        content_length = str(response_headers.get("Content-Length") or "").strip()
                        if content_length.isdigit() and int(content_length) > max_pdf_bytes():
                            raise ResponseTooLargeError("PDF response exceeds configured maximum")
                        # Discovery only needs a signature preview and final
                        # locator.  The candidate is streamed exactly once by
                        # the artifact downloader rather than materialized in
                        # memory here and then downloaded again.
                        body = response.read(min(65536, max_discovery_bytes()))
                    else:
                        body = bounded_response_read(response, max_discovery_bytes())
            if status in RETRYABLE_HTTP_STATUSES and attempt < max_retries and should_inline_retry(response_headers):
                time.sleep(retry_delay(response_headers, attempt))
                continue
            return status, content_type, body, final_url
        except DomainCooldownError:
            raise
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
            final_url = exc.geturl()
            if not url_validator(final_url):
                raise UnsafeNetworkTargetError("error response target rejected")
            error_limit = min(max_discovery_bytes(), 8 * 1024 * 1024)
            validate_response_peer(exc, final_url, connection_pinned=True)
            body = bounded_response_read(exc, error_limit)
            if status in RETRYABLE_HTTP_STATUSES and attempt < max_retries and should_inline_retry(exc.headers):
                time.sleep(retry_delay(exc.headers, attempt))
                continue
            return status, content_type, body, final_url
        except Exception as exc:
            last_error = exc
            if isinstance(exc, (UnsafeNetworkTargetError, ResponseTooLargeError)) or (
                isinstance(exc, urllib.error.URLError)
                and isinstance(getattr(exc, "reason", None), UnsafeNetworkTargetError)
            ):
                raise
            if attempt < max_retries:
                time.sleep(retry_delay(None, attempt))
                continue
            raise
    if last_error:
        raise last_error
    raise RuntimeError("request failed")


def request_form_url(
    url: str,
    form: dict[str, str],
    timeout: int | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, bytes, str]:
    if timeout is None:
        timeout = download_timeout_seconds()
    req_headers = {
        "User-Agent": user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url,
    }
    if headers:
        req_headers.update(headers)
    data = urllib.parse.urlencode(form).encode("utf-8")
    if not network_url_allowed(url):
        raise UnsafeNetworkTargetError("form target rejected")
    req = urllib.request.Request(url, data=data, headers=req_headers)
    opener = build_validated_network_opener(network_url_allowed)
    try:
        cooldown_reason = domain_cooldown_reason(url)
        if cooldown_reason:
            raise DomainCooldownError(cooldown_reason)
        polite_delay()
        sem = domain_semaphore(url)
        with sem:
            cooldown_reason = domain_cooldown_reason(url)
            if cooldown_reason:
                raise DomainCooldownError(cooldown_reason)
            with opener.open(req, timeout=timeout) as response:
                final_url = response.geturl()
                if not network_url_allowed(final_url):
                    raise UnsafeNetworkTargetError("form response target rejected")
                validate_response_peer(response, final_url, connection_pinned=True)
                content_type = response.headers.get("Content-Type", "")
                if response_looks_like_pdf(content_type, final_url, response.headers):
                    content_length = str(response.headers.get("Content-Length") or "").strip()
                    if content_length.isdigit() and int(content_length) > max_pdf_bytes():
                        raise ResponseTooLargeError("PDF response exceeds configured maximum")
                    body = response.read(min(65536, max_discovery_bytes()))
                else:
                    body = bounded_response_read(response, max_discovery_bytes())
                return (
                    int(getattr(response, "status", 200) or 200),
                    content_type,
                    body,
                    final_url,
                )
    except DomainCooldownError:
        raise
    except urllib.error.HTTPError as exc:
        if not network_url_allowed(exc.geturl()):
            raise UnsafeNetworkTargetError("form error response target rejected")
        validate_response_peer(exc, exc.geturl(), connection_pinned=True)
        error_limit = min(max_discovery_bytes(), 8 * 1024 * 1024)
        body = bounded_response_read(exc, error_limit)
        return (
            int(exc.code),
            exc.headers.get("Content-Type", "") if exc.headers else "",
            body,
            exc.geturl(),
        )


def write_temp_and_validate(body: bytes, target_path: Path) -> bool:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if len(body) > max_pdf_bytes():
        return False
    descriptor: int | None
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{target_path.stem}.",
        suffix=".part",
        dir=target_path.parent,
    )
    part_path = Path(raw_path)
    try:
        open_descriptor = descriptor
        descriptor = None
        with os.fdopen(open_descriptor, "wb") as handle:
            for offset in range(0, len(body), 1024 * 1024):
                handle.write(body[offset : offset + 1024 * 1024])
            handle.flush()
            os.fsync(handle.fileno())
        if not is_valid_pdf(part_path):
            return False
        with target_lock(target_path):
            atomic_replace_file(part_path, target_path)
        return True
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        except OSError:
            pass
        part_path.unlink(missing_ok=True)


def download_pdf_from_url(
    url: str,
    target_path: Path,
    logger: logging.Logger,
    channel: str = "",
    request_headers: Mapping[str, str] | None = None,
) -> DownloadOutcome:
    start = time.monotonic()
    validator = lambda value: candidate_allowed_for_channel(channel, value)
    if not validator(url):
        return DownloadOutcome(False, "unsafe_network_target", elapsed_seconds=time.monotonic() - start)
    headers = {
        "User-Agent": user_agent(),
        "Accept": "application/pdf, application/octet-stream;q=0.9, */*;q=0.2",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    }
    for key, value in (request_headers or {}).items():
        normalized_key = str(key).strip()
        normalized_value = str(value).strip()
        if (
            normalized_key
            and normalized_key.casefold() not in {"host", "content-length"}
            and "\r" not in normalized_key
            and "\n" not in normalized_key
            and "\r" not in normalized_value
            and "\n" not in normalized_value
        ):
            headers[normalized_key] = normalized_value
    request = urllib.request.Request(url, headers=headers)
    opener = build_validated_network_opener(validator)
    max_bytes = max_pdf_bytes()
    last_reason = "network_error"
    last_status = ""
    for attempt_number in range(1, 4):
        part_path: Path | None = None
        descriptor: int | None = None
        try:
            cooldown_reason = domain_cooldown_reason(url)
            if cooldown_reason:
                raise DomainCooldownError(cooldown_reason)
            polite_delay()
            target_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, raw_path = tempfile.mkstemp(
                prefix=f".{target_path.stem}.",
                suffix=".part",
                dir=target_path.parent,
            )
            part_path = Path(raw_path)
            sem = domain_semaphore(url)
            with sem:
                with opener.open(request, timeout=download_timeout_seconds()) as response:
                    status = int(getattr(response, "status", 200) or 200)
                    last_status = str(status)
                    content_type = response.headers.get("Content-Type", "")
                    final_url = response.geturl()
                    if not validator(final_url):
                        raise UnsafeNetworkTargetError("final response target rejected")
                    validate_response_peer(response, final_url, connection_pinned=True)
                    content_length = str(response.headers.get("Content-Length") or "").strip()
                    if content_length.isdigit() and int(content_length) > max_bytes:
                        raise ResponseTooLargeError("PDF response exceeds configured maximum")
                    preview = bytearray()
                    written = 0
                    with os.fdopen(descriptor, "wb") as handle:
                        descriptor = None
                        while True:
                            chunk = response.read(1024 * 1024)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > max_bytes:
                                raise ResponseTooLargeError("PDF response exceeds configured maximum")
                            if len(preview) < 65536:
                                preview.extend(chunk[: 65536 - len(preview)])
                            handle.write(chunk)
                        handle.flush()
                        os.fsync(handle.fileno())
            classification = classify_candidate_pdf_response(
                channel=channel,
                url=url,
                status=status,
                content_type=content_type,
                body=bytes(preview),
            )
            if classification:
                last_reason = classification
                return DownloadOutcome(
                    False,
                    classification,
                    last_status,
                    time.monotonic() - start,
                    retryable=reason_details(classification, last_status)[2],
                    final_url=final_url,
                )
            validation = pdf_validation_details(part_path)
            if not validation.get("valid"):
                last_reason = str(validation.get("reason_code") or "invalid_pdf")
                return DownloadOutcome(False, last_reason, last_status, time.monotonic() - start, final_url=final_url)
            with target_lock(target_path):
                atomic_replace_file(part_path, target_path)
            if final_url != url:
                logger.info(
                    "Downloaded PDF via redirect: %s -> %s",
                    sanitize_url_for_output(url),
                    sanitize_url_for_output(final_url),
                )
            return DownloadOutcome(True, "success", last_status, time.monotonic() - start, final_url=final_url)
        except urllib.error.HTTPError as exc:
            last_status = str(exc.code)
            if not validator(exc.geturl()):
                last_reason = "unsafe_network_target"
            else:
                try:
                    validate_response_peer(exc, exc.geturl(), connection_pinned=True)
                except UnsafeNetworkTargetError:
                    last_reason = "unsafe_network_target"
                else:
                    preview = exc.read(65536)
                    last_reason = http_failure_reason(int(exc.code), exc.headers, preview) or "http_error"
            retryable = reason_details(last_reason, last_status)[2]
            retry_at = retry_at_from_headers(exc.headers) if retryable else ""
            if retryable and attempt_number < 3 and should_inline_retry(exc.headers):
                time.sleep(retry_delay(exc.headers, attempt_number))
                continue
            return DownloadOutcome(
                False,
                last_reason,
                last_status,
                time.monotonic() - start,
                retryable=retryable,
                retry_at=retry_at,
            )
        except DomainCooldownError as exc:
            last_reason = str(exc)
            return DownloadOutcome(False, last_reason, last_status, time.monotonic() - start, retryable=True)
        except Exception as exc:
            last_reason = request_exception_reason(exc)
            retryable = reason_details(last_reason, last_status)[2]
            if retryable and attempt_number < 3:
                time.sleep(retry_delay(None, attempt_number))
                continue
            return DownloadOutcome(False, last_reason, last_status, time.monotonic() - start, retryable=retryable)
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if part_path is not None:
                part_path.unlink(missing_ok=True)
    return DownloadOutcome(False, last_reason, last_status, time.monotonic() - start, retryable=True)


def playwright_context_cookie_headers(context: Any, url: str) -> dict[str, str]:
    """Project browser cookies into the bounded streaming HTTP downloader.

    Playwright's APIResponse exposes only ``body()``, which materializes the
    complete response before a size check.  Cookie projection preserves the
    authenticated session while the common urllib path enforces Content-Length
    and actual-byte limits during streaming.
    """
    try:
        cookies = context.cookies([url])
    except (AttributeError, TypeError):
        try:
            cookies = context.cookies(url)
        except Exception:
            cookies = []
    except Exception:
        cookies = []
    pairs: list[str] = []
    for cookie in cookies or []:
        if not isinstance(cookie, Mapping):
            continue
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "").strip()
        if name and "\r" not in name and "\n" not in name and "\r" not in value and "\n" not in value:
            pairs.append(f"{name}={value}")
    return {"Cookie": "; ".join(pairs)} if pairs else {}


def download_pdf_with_playwright_context(context: Any, url: str, target_path: Path, channel: str = "") -> DownloadOutcome:
    if not candidate_allowed_for_channel(channel, url):
        return DownloadOutcome(False, "unsafe_network_target")
    return download_pdf_from_url(
        url,
        target_path,
        logging.getLogger("literature_patents_download"),
        channel,
        request_headers=playwright_context_cookie_headers(context, url),
    )


def download_pdf_after_browser_cookie(url: str, target_path: Path, config: DownloadConfig, logger: logging.Logger) -> DownloadOutcome:
    start = time.monotonic()
    if not network_url_allowed(url):
        return DownloadOutcome(False, "unsafe_network_target", "", time.monotonic() - start)
    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        return DownloadOutcome(False, f"playwright_unavailable: {exc}", "", time.monotonic() - start)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=config.headless)
            context = browser.new_context(
                accept_downloads=True,
                locale="en-US,zh-CN",
                service_workers="block",
                extra_http_headers={"Accept": "application/pdf,text/html;q=0.8,*/*;q=0.5"},
            )
            blocked_network_urls: list[str] = []
            page = new_guarded_browser_page(
                context,
                "browser_cookie",
                blocked_network_urls,
            )
            try:
                safe_browser_goto(page, url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                if BROWSER_COOKIE_WARMUP_MS:
                    page.wait_for_timeout(BROWSER_COOKIE_WARMUP_MS)
            except Exception as exc:
                logger.debug(
                    "Browser cookie warmup failed for %s: %s",
                    sanitize_url_for_output(url),
                    sanitize_text_for_output(exc),
                )
            blocker_reason = browser_page_blocker_reason(page_text(page))
            if blocker_reason:
                context.close()
                browser.close()
                return DownloadOutcome(
                    False,
                    blocker_reason,
                    "",
                    time.monotonic() - start,
                )
            outcome = download_pdf_with_playwright_context(context, url, target_path)
            context.close()
            browser.close()
            if outcome.elapsed_seconds:
                outcome.elapsed_seconds = time.monotonic() - start
            return outcome
    except Exception as exc:
        return DownloadOutcome(False, f"{exc.__class__.__name__}: {exc}", "", time.monotonic() - start)


def api_timeout_seconds() -> int:
    try:
        return max(5, int(os.getenv("LAPS_API_TIMEOUT_SECONDS", "12")))
    except Exception:
        return 12


def fetch_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    status, content_type, body, _ = request_url(url, timeout=api_timeout_seconds(), headers=req_headers, retries=1)
    if status >= 400:
        raise RuntimeError(f"HTTP {status}")
    if "json" not in content_type.casefold() and not body.strip().startswith((b"{", b"[")):
        raise RuntimeError("non-json response")
    loaded = json.loads(body.decode("utf-8", errors="replace"))
    return loaded if isinstance(loaded, dict) else {"data": loaded}


def post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    req_headers = {
        "User-Agent": user_agent(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if headers:
        req_headers.update(headers)
    if not network_url_allowed(url):
        raise UnsafeNetworkTargetError("JSON endpoint rejected")
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    opener = build_validated_network_opener(network_url_allowed)
    try:
        polite_delay()
        sem = domain_semaphore(url)
        with sem:
            with opener.open(req, timeout=api_timeout_seconds()) as response:
                if not network_url_allowed(response.geturl()):
                    raise UnsafeNetworkTargetError("JSON response target rejected")
                validate_response_peer(
                    response,
                    response.geturl(),
                    connection_pinned=True,
                )
                status = int(getattr(response, "status", 200) or 200)
                content_type = response.headers.get("Content-Type", "")
                body = bounded_response_read(response, max_json_bytes())
    except urllib.error.HTTPError as exc:
        if not network_url_allowed(exc.geturl()):
            raise UnsafeNetworkTargetError("JSON error response target rejected")
        validate_response_peer(exc, exc.geturl(), connection_pinned=True)
        status = int(exc.code)
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        error_limit = min(max_json_bytes(), 8 * 1024 * 1024)
        body = bounded_response_read(exc, error_limit)
    if status >= 400:
        raise RuntimeError(f"HTTP {status}")
    if "json" not in content_type.casefold() and not body.strip().startswith((b"{", b"[")):
        raise RuntimeError("non-json response")
    loaded = json.loads(body.decode("utf-8", errors="replace"))
    return loaded if isinstance(loaded, dict) else {"data": loaded}


def append_query_params(url: str, params: Mapping[str, str]) -> str:
    if not params:
        return url
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.extend((key, value) for key, value in params.items() if value)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment))


PDF_FIELD_HINTS = (
    "pdf",
    "download",
    "downloadurl",
    "download_url",
    "fulltext",
    "full_text",
    "full-text",
    "fulltexturl",
    "full_text_url",
    "contenturl",
    "content_url",
    "oa_url",
    "openaccess",
    "open_access",
)
LANDING_FIELD_HINTS = ("url", "link", "record", "landing", "html", "article", "sourcefulltexturls")


def normalize_json_url(value: Any, base_url: str = "") -> str:
    if not isinstance(value, str):
        return ""
    text = html.unescape(value.strip())
    if not text:
        return ""
    if text.startswith("//"):
        text = "https:" + text
    if base_url and text.startswith("/"):
        text = urllib.parse.urljoin(base_url, text)
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return text


def collect_json_urls(value: Any, *, pdf_only: bool = True, key_hint: str = "", base_url: str = "") -> list[str]:
    candidates: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            next_hint = f"{key_hint}.{key}" if key_hint else str(key)
            candidates.extend(collect_json_urls(item, pdf_only=pdf_only, key_hint=next_hint, base_url=base_url))
        return candidates
    if isinstance(value, list):
        for item in value:
            candidates.extend(collect_json_urls(item, pdf_only=pdf_only, key_hint=key_hint, base_url=base_url))
        return candidates
    url_value = normalize_json_url(value, base_url)
    if not url_value:
        return []
    hint = normalize_header(key_hint)
    if url_looks_like_pdf(url_value) or any(token in hint for token in PDF_FIELD_HINTS):
        return [url_value]
    if not pdf_only and any(token in hint for token in LANDING_FIELD_HINTS) and not url_looks_like_api_metadata(url_value):
        return [url_value]
    return []


def collect_json_strings_for_keys(value: Any, key_tokens: tuple[str, ...], key_hint: str = "") -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            next_hint = f"{key_hint}.{key}" if key_hint else str(key)
            values.extend(collect_json_strings_for_keys(item, key_tokens, next_hint))
        return values
    if isinstance(value, list):
        for item in value:
            values.extend(collect_json_strings_for_keys(item, key_tokens, key_hint))
        return values
    if isinstance(value, str) and any(token in normalize_header(key_hint) for token in key_tokens):
        text = value.strip()
        if text:
            values.append(text)
    return values


def add_direct_pdf_patterns(channel: str, doi: str, row: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    if channel == "IACR ePrint":
        values = " ".join(str(value or "") for value in row.values())
        match = re.search(
            r"(?:eprint\.iacr\.org/)?(20\d{2})[/:](\d+)",
            values,
            flags=re.I,
        )
        if match:
            candidates.append(
                f"https://eprint.iacr.org/{match.group(1)}/{match.group(2)}.pdf"
            )
    if not doi:
        return candidates
    encoded = urllib.parse.quote(doi, safe="")
    suffix = doi.split("/", 1)[1] if "/" in doi else ""
    if doi.startswith("10.1101/"):
        candidates.extend(
            [
                f"https://www.biorxiv.org/content/{doi}.full.pdf",
                f"https://www.medrxiv.org/content/{doi}.full.pdf",
            ]
        )
    if doi.startswith(("10.1007/", "10.1038/")):
        candidates.append(f"https://link.springer.com/content/pdf/{encoded}.pdf")
    if doi.startswith("10.1038/"):
        if suffix:
            candidates.append(f"https://www.nature.com/articles/{urllib.parse.quote(suffix, safe='')}.pdf")
    if doi.startswith("10.1016/"):
        api_key = env_value("ELSEVIER_API_KEY")
        if api_key:
            params = {"apiKey": api_key, "httpAccept": "application/pdf"}
            if env_value("ELSEVIER_INSTTOKEN"):
                params["insttoken"] = env_value("ELSEVIER_INSTTOKEN")
            candidates.append(append_query_params(f"https://api.elsevier.com/content/article/doi/{encoded}", params))
    if doi.startswith("10.1021/"):
        candidates.append(f"https://pubs.acs.org/doi/pdf/{doi}")
    if doi.startswith("10.1146/"):
        candidates.append(f"https://www.annualreviews.org/doi/pdf/{doi}")
    if doi.startswith("10.1145/"):
        candidates.append(f"https://dl.acm.org/doi/pdf/{doi}")
    if doi.startswith("10.1109/"):
        article_number = get_field(row, ("article_number", "Article Number", "raw_id"))
        article_number_match = re.search(r"\b\d{5,}\b", article_number)
        if article_number_match:
            candidates.append(f"https://ieeexplore.ieee.org/stampPDF/getPDF.jsp?tp=&arnumber={article_number_match.group(0)}")
    return dedupe_urls(candidates)


def openreview_pdf_candidates(row: dict[str, Any], url: str) -> list[str]:
    values = " ".join(str(value or "") for value in [url, row.get("raw_id", ""), *row.values()])
    match = re.search(r"(?:forum\?id=|openreview\.net/pdf\?id=)([A-Za-z0-9_-]+)", values)
    if match:
        return [f"https://openreview.net/pdf?id={match.group(1)}"]
    raw_id = str(row.get("raw_id") or "").strip()
    if raw_id and re.fullmatch(r"[A-Za-z0-9_-]+", raw_id):
        return [f"https://openreview.net/pdf?id={raw_id}"]
    return []


def arxiv_pdf_candidates_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    patterns = (
        r"arxiv\.org/(?:abs|pdf)/([0-9]{4}\.[0-9]{4,5}(?:v\d+)?|[a-z\-]+(?:\.[A-Z]{2})?/\d{7}(?:v\d+)?)",
        r"10\.48550/arxiv\.([0-9]{4}\.[0-9]{4,5}(?:v\d+)?|[a-z\-]+(?:\.[A-Z]{2})?/\d{7}(?:v\d+)?)",
        r"arxiv[:\s]+([0-9]{4}\.[0-9]{4,5}(?:v\d+)?|[a-z\-]+(?:\.[A-Z]{2})?/\d{7}(?:v\d+)?)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.I):
            arxiv_id = match.group(1).rstrip(".")
            candidates.append(f"https://arxiv.org/pdf/{arxiv_id}.pdf")
    return dedupe_urls(candidates)


def zenodo_record_id(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.netloc.casefold().endswith("zenodo.org"):
        return ""
    match = re.search(r"/record(?:s)?/(\d+)", parsed.path, flags=re.I)
    return match.group(1) if match else ""


def figshare_article_id(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if "figshare.com" not in parsed.netloc.casefold():
        return ""
    match = re.search(r"/(\d+)(?:/|$)", parsed.path)
    return match.group(1) if match else ""


def repository_pdf_candidates_from_url(url: str, logger: logging.Logger) -> list[str]:
    candidates: list[str] = []
    zenodo_id = zenodo_record_id(url)
    if not zenodo_id and urllib.parse.urlsplit(url).netloc.casefold().endswith("zenodo.org"):
        try:
            status, content_type, body, final_url = request_url(url, timeout=download_timeout_seconds(), retries=1)
            del status, content_type
            zenodo_id = zenodo_record_id(final_url)
            if not zenodo_id:
                match = re.search(rb"/records/(\d+)", body)
                if match:
                    zenodo_id = match.group(1).decode("ascii", errors="ignore")
        except Exception as exc:
            logger.debug(
                "Zenodo DOI landing discovery failed for %s: %s",
                sanitize_url_for_output(url),
                sanitize_text_for_output(exc),
            )
    if zenodo_id:
        try:
            data = fetch_json(f"https://zenodo.org/api/records/{zenodo_id}")
            file_candidates: list[str] = []
            for file_entry in data.get("files") or []:
                if isinstance(file_entry, dict):
                    if str(file_entry.get("key") or "").casefold().endswith(".pdf"):
                        file_candidates.extend(collect_json_urls(file_entry, pdf_only=False))
            candidates.extend(file_candidates)
            candidates.extend(
                candidate
                for candidate in collect_json_urls(data, pdf_only=True)
                if "/iiif/" not in urllib.parse.urlsplit(candidate).path.casefold()
            )
        except Exception as exc:
            logger.debug(
                "Zenodo file discovery failed for %s: %s",
                sanitize_url_for_output(url),
                sanitize_text_for_output(exc),
            )
    figshare_id = figshare_article_id(url)
    if figshare_id:
        try:
            data = fetch_json(f"https://api.figshare.com/v2/articles/{figshare_id}")
            file_candidates = []
            for file_entry in data.get("files") or []:
                if isinstance(file_entry, dict):
                    if str(file_entry.get("name") or file_entry.get("key") or "").casefold().endswith(".pdf"):
                        file_candidates.extend(collect_json_urls(file_entry, pdf_only=False))
            candidates.extend(file_candidates)
            candidates.extend(collect_json_urls(data, pdf_only=True))
        except Exception as exc:
            logger.debug(
                "figshare file discovery failed for %s: %s",
                sanitize_url_for_output(url),
                sanitize_text_for_output(exc),
            )
    return dedupe_urls(candidates)


def repository_candidate_rank_key(candidate: str) -> tuple[int, str]:
    parsed = urllib.parse.urlsplit(candidate)
    host = parsed.netloc.casefold()
    path = urllib.parse.unquote(parsed.path).casefold()
    lowered = urllib.parse.unquote(candidate).casefold()
    if url_looks_like_pdf(candidate) or path.endswith(".pdf") or ".pdf" in path:
        return (0, lowered)
    if "figshare.com" in host and "/ndownloader/files/" in path:
        return (1, lowered)
    if "zenodo.org" in host and "/api/records/" in path:
        return (2, lowered)
    if any(token in host for token in ("figshare.com", "zenodo.org", "datacite.org")):
        return (3, lowered)
    return (4, lowered)


def rank_repository_candidates(candidates: list[str]) -> list[str]:
    return sorted(dedupe_urls(candidates), key=repository_candidate_rank_key)


def limit_repository_candidates(candidates: list[str]) -> tuple[list[str], list[str]]:
    ranked = rank_repository_candidates(candidates)
    max_candidates = repository_max_candidates()
    limited = ranked[:max_candidates]
    reasons: list[str] = []
    if len(ranked) > len(limited):
        reasons.append(f"repository_candidate_limit_exceeded: kept {len(limited)} of {len(ranked)}")
    if not limited and candidates:
        reasons.append("repository_no_pdf_file")
    return limited, reasons


def is_figshare_file_candidate(candidate: str) -> bool:
    parsed = urllib.parse.urlsplit(candidate)
    host = parsed.netloc.casefold()
    path = parsed.path.casefold()
    return "figshare.com" in host or "figshare" in path or "amazonaws.com" in host


def repository_attempt_reason(candidate: str, reason: str) -> str:
    if reason == "access_denied" and is_figshare_file_candidate(candidate):
        return "figshare_file_access_denied"
    return reason


def google_patents_pdf_candidates(publication_number: str) -> list[str]:
    if not publication_number:
        return []
    encoded = urllib.parse.quote(publication_number, safe="")
    return [
        f"https://patents.google.com/patent/{encoded}/en?download=1",
        f"https://patentimages.storage.googleapis.com/pdfs/{encoded}.pdf",
    ]


def discover_pdf_urls_from_html(body: str, base_url: str) -> list[str]:
    candidates: list[str] = []
    pdf_text_tokens = (
        ".pdf",
        "/pdf",
        "download pdf",
        "full text pdf",
        "article-pdf",
        "viewpdf",
        "publication pdf",
        "original document",
        "paper pdf",
        "download the paper",
        "/system/files/",
    )
    for script_match in re.finditer(r'<script[^>]+type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>', body, flags=re.I | re.S):
        try:
            loaded = json.loads(html.unescape(script_match.group(1)).strip())
            candidates.extend(collect_json_urls(loaded, pdf_only=True, base_url=base_url))
        except Exception:
            continue
    for pattern in (
        r'<meta[^>]+name\s*=\s*["\'](?:citation_pdf_url|bepress_citation_pdf_url)["\'][^>]+content\s*=\s*["\']([^"\']+)["\']',
        r'<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]+name\s*=\s*["\'](?:citation_pdf_url|bepress_citation_pdf_url)["\']',
        r'<(?:iframe|embed)[^>]+src\s*=\s*["\']([^"\']+)["\']',
        r'<object[^>]+data\s*=\s*["\']([^"\']+)["\']',
        r'<a[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    ):
        for match in re.finditer(pattern, body, flags=re.I | re.S):
            href = match.group(1)
            text = match.group(2) if len(match.groups()) > 1 else ""
            joined = urllib.parse.urljoin(base_url, html.unescape(href))
            haystack = f"{joined} {html.unescape(text)}".casefold()
            if url_looks_like_pdf(joined) or any(token in haystack for token in pdf_text_tokens):
                candidates.append(joined)
    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def nature_landing_pdf_candidates_from_html(body: str, base_url: str) -> list[str]:
    candidates = discover_pdf_urls_from_html(body, base_url)
    for pattern in (
        r'<meta[^>]+name\s*=\s*["\']citation_fulltext_html_url["\'][^>]+content\s*=\s*["\']([^"\']+)["\']',
        r'<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]+name\s*=\s*["\']citation_fulltext_html_url["\']',
        r'https?://media\.springernature\.com/[^\s"\'<>]+',
    ):
        for match in re.finditer(pattern, body, flags=re.I | re.S):
            href = match.group(1) if match.groups() else match.group(0)
            joined = urllib.parse.urljoin(base_url, html.unescape(href))
            if "media.springernature.com" in urllib.parse.urlsplit(joined).netloc.casefold() or url_looks_like_pdf(joined):
                candidates.append(joined)
    return dedupe_urls(candidates)


CAPTURED_BROWSER_DOWNLOAD_PREFIX = "laps-browser-download://"
CAPTURED_BROWSER_DOWNLOAD_FAILURE_PREFIX = "laps-browser-download-failure://"
CAPTURED_BROWSER_DOWNLOAD_FAILURE_REASONS = frozenset(
    {"response_too_large", "invalid_browser_capture"}
)
PDF_ACTION_LABELS = frozenset(
    {
        "pdf",
        "pdf下载",
        "下载pdf",
        "下载全文",
        "全文下载",
        "整篇下载",
        "full text pdf",
        "download pdf",
    }
)


def captured_browser_download_candidate(path: Path) -> str:
    return CAPTURED_BROWSER_DOWNLOAD_PREFIX + urllib.parse.quote(str(path.resolve()), safe="")


def captured_browser_download_failure_candidate(reason: str) -> str:
    normalized = str(reason or "").strip().casefold()
    if normalized not in CAPTURED_BROWSER_DOWNLOAD_FAILURE_REASONS:
        normalized = "invalid_browser_capture"
    return CAPTURED_BROWSER_DOWNLOAD_FAILURE_PREFIX + urllib.parse.quote(
        normalized,
        safe="",
    )


def captured_browser_download_failure_reason(candidate: str) -> str:
    if not candidate.startswith(CAPTURED_BROWSER_DOWNLOAD_FAILURE_PREFIX):
        return ""
    reason = urllib.parse.unquote(
        candidate[len(CAPTURED_BROWSER_DOWNLOAD_FAILURE_PREFIX) :]
    ).strip().casefold()
    return reason if reason in CAPTURED_BROWSER_DOWNLOAD_FAILURE_REASONS else ""


def captured_browser_download_path(candidate: str) -> Path | None:
    if not candidate.startswith(CAPTURED_BROWSER_DOWNLOAD_PREFIX):
        return None
    raw = urllib.parse.unquote(candidate[len(CAPTURED_BROWSER_DOWNLOAD_PREFIX) :])
    if not raw:
        return None
    original = Path(raw)
    try:
        configured_root = TOOLS_DIR / "captured_downloads"
        if configured_root.is_symlink() or original.is_symlink():
            return None
        captured_root = configured_root.resolve(strict=True)
        resolved = original.resolve(strict=True)
        resolved.relative_to(captured_root)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def network_host_is_public(host: str) -> bool:
    return shared_outbound_host_is_public(host)


def network_url_syntax_allowed(value: str) -> bool:
    return shared_outbound_http_url_syntax_allowed(value)


def network_url_allowed(value: str) -> bool:
    return shared_outbound_http_url_allowed(value)


def new_source_network_url_allowed(value: str) -> bool:
    """Backward-compatible alias retained for existing probes."""
    return network_url_allowed(value)


def candidate_allowed_for_channel(channel: str, candidate: str) -> bool:
    if not candidate:
        return False
    if candidate.startswith(CAPTURED_BROWSER_DOWNLOAD_FAILURE_PREFIX):
        return bool(captured_browser_download_failure_reason(candidate))
    if candidate.startswith(CAPTURED_BROWSER_DOWNLOAD_PREFIX):
        return captured_browser_download_path(candidate) is not None
    if candidate.startswith("repository:"):
        return True
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return False
    if not network_url_allowed(candidate):
        return False
    if channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}:
        return bool(
            not (channel == CNKI_SOURCE and cnki_order_action_url(candidate))
            and not url_has_transient_pdf_query(candidate)
        )
    return parsed.scheme.casefold() in {"http", "https"}


def candidate_rejection_reason(channel: str, candidate: str) -> str:
    """Return a stable reason code for a candidate rejected before I/O."""
    if channel == CNKI_SOURCE and cnki_order_action_url(candidate):
        return "forbidden_order_action"
    if url_has_transient_pdf_query(candidate):
        return "transient_pdf_url_rejected"
    captured_failure = captured_browser_download_failure_reason(candidate)
    if captured_failure:
        return captured_failure
    if candidate.startswith(CAPTURED_BROWSER_DOWNLOAD_PREFIX):
        return "captured_browser_download_rejected"
    return "unsafe_network_target"


def install_browser_network_route_guard(
    target: Any,
    channel: str,
    blocked_urls: list[str],
) -> Callable[[Any, Any], None] | None:
    """Fail closed on every browser HTTP(S) request, including redirects.

    Playwright invokes route handlers for document redirects and subresources.
    The shared network predicate resolves the hostname on every request and
    rejects loopback, private, link-local and cloud-metadata destinations.
    Browser-internal data/blob/about resources remain available.
    """

    def guard(route: Any, request: Any) -> None:
        request_url = str(getattr(request, "url", "") or "")
        try:
            scheme = urllib.parse.urlsplit(request_url).scheme.casefold()
        except ValueError:
            scheme = ""
        if scheme in {"data", "blob", "about"} or (
            scheme in {"http", "https"} and network_url_allowed(request_url)
        ):
            route.continue_()
            return
        blocked_urls.append(sanitize_url_for_output(request_url))
        route.abort()

    try:
        target.route("**/*", guard)
    except Exception:
        return None
    return guard


def install_new_source_network_route_guard(
    page: Any,
    channel: str,
    blocked_urls: list[str],
) -> Callable[[Any, Any], None] | None:
    """Compatibility alias for older probes and integrations."""

    return install_browser_network_route_guard(page, channel, blocked_urls)


def new_guarded_browser_page(
    context: Any,
    channel: str,
    blocked_urls: list[str],
) -> Any:
    """Create a page only when the common outbound guard is installed."""

    # Context-level interception is installed before page creation so popup
    # first requests, redirects, workers, and subresources cannot race a
    # page-level route.  Browser contexts are created with service workers
    # blocked throughout this module.
    if install_browser_network_route_guard(context, channel, blocked_urls) is None:
        raise UnsafeNetworkTargetError("browser network route guard unavailable")
    return context.new_page()


def bind_observed_pdf_response_capture(
    page: Any,
    channel: str,
    observed: list[str],
) -> None:
    if channel not in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}:
        return

    def observe(response: Any) -> None:
        try:
            candidate = str(getattr(response, "url", "") or "")
            status = int(getattr(response, "status", 0) or 0)
            headers = getattr(response, "headers", {}) or {}
            content_type = str(headers.get("content-type") or headers.get("Content-Type") or "")
            if (
                200 <= status < 400
                and network_url_syntax_allowed(candidate)
                and not (channel == CNKI_SOURCE and cnki_order_action_url(candidate))
                and not url_has_transient_pdf_query(candidate)
                and ("pdf" in content_type.casefold() or url_looks_like_pdf(candidate))
                and candidate not in observed
            ):
                observed.append(candidate)
        except Exception:
            return

    try:
        page.on("response", observe)
    except Exception:
        return


def capture_visible_pdf_action(page: Any, channel: str, logger: logging.Logger) -> list[str]:
    if channel not in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}:
        return []
    try:
        controls = page.locator("a:visible, button:visible, [role='button']:visible")
        count = min(int(controls.count()), 100)
    except Exception:
        return []
    matching_controls: list[Any] = []
    for index in range(count):
        try:
            control = controls.nth(index)
            label = re.sub(
                r"\s+",
                " ",
                str(control.inner_text(timeout=500) or control.get_attribute("aria-label") or ""),
            ).strip().casefold()
            if label in PDF_ACTION_LABELS:
                matching_controls.append(control)
        except Exception:
            continue
    if len(matching_controls) != 1:
        logger.debug(
            "Observed PDF action skipped for %s: expected one visible target, found %s",
            channel,
            len(matching_controls),
        )
        return []
    control = matching_controls[0]
    observed_responses: list[str] = []
    bind_observed_pdf_response_capture(page, channel, observed_responses)
    try:
        before_url = str(getattr(page, "url", "") or "")
        try:
            with page.expect_download(timeout=5000) as download_info:
                control.click(timeout=3000)
            download = download_info.value
            captured_root = TOOLS_DIR / "captured_downloads"
            captured_root.mkdir(parents=True, exist_ok=True)
            if captured_root.is_symlink():
                raise OSError("captured browser download directory must not be a symlink")
            captured_root = captured_root.resolve(strict=True)
            suggested = Path(str(getattr(download, "suggested_filename", "") or ""))
            suffix = ".pdf" if suggested.suffix.casefold() == ".pdf" else ".download"
            size_limit = max_pdf_bytes()

            # Playwright's Python Download API exposes a completed browser-owned
            # path/save_as operation, but no portable byte-progress callback that
            # can cancel this native transfer at the configured boundary.  When
            # the browser path is locally visible, reject it before making a
            # workflow-owned copy.  Otherwise save once into an exclusive,
            # controlled temporary file and enforce the boundary immediately.
            browser_path_method = getattr(download, "path", None)
            if callable(browser_path_method):
                try:
                    browser_path = Path(str(browser_path_method())).resolve(strict=True)
                    if browser_path.stat().st_size > size_limit:
                        delete_method = getattr(download, "delete", None)
                        if callable(delete_method):
                            try:
                                delete_method()
                            except Exception:
                                pass
                        logger.warning(
                            "Browser-native download rejected after Playwright-managed transfer: "
                            "response_too_large (limit=%s bytes); this API path has no "
                            "portable streaming cancellation callback",
                            size_limit,
                        )
                        return [
                            captured_browser_download_failure_candidate(
                                "response_too_large"
                            )
                        ]
                except Exception:
                    # Remote browser connections may intentionally make
                    # Download.path unavailable.  The controlled save below is
                    # still checked immediately and never copied unboundedly.
                    pass

            descriptor, raw_target = tempfile.mkstemp(
                prefix=f".{safe_slug(channel)}.",
                suffix=f"{suffix}.part",
                dir=captured_root,
            )
            os.close(descriptor)
            target = Path(raw_target)
            keep_capture = False
            try:
                download.save_as(str(target))
                capture_failure = (
                    "invalid_browser_capture"
                    if target.is_symlink() or not target.is_file()
                    else (
                        "response_too_large"
                        if target.stat().st_size > size_limit
                        else ""
                    )
                )
                if capture_failure:
                    delete_method = getattr(download, "delete", None)
                    if callable(delete_method):
                        try:
                            delete_method()
                        except Exception:
                            pass
                    logger.warning(
                        "Browser-native download rejected immediately after controlled save: "
                        "%s (limit=%s bytes); this API "
                        "path has no portable streaming cancellation callback",
                        capture_failure,
                        size_limit,
                    )
                    return [
                        captured_browser_download_failure_candidate(
                            capture_failure
                        )
                    ]
                with target.open("rb+") as captured_handle:
                    os.fsync(captured_handle.fileno())
                chmod_secret_file(target)
                keep_capture = True
                return [captured_browser_download_candidate(target)]
            finally:
                if not keep_capture:
                    target.unlink(missing_ok=True)
        except Exception:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
            if observed_responses:
                return list(dict.fromkeys(observed_responses))
            after_url = str(getattr(page, "url", "") or "")
            if (
                after_url != before_url
                and url_looks_like_pdf(after_url)
                and candidate_allowed_for_channel(channel, after_url)
            ):
                return [after_url]
            observed = [
                candidate
                for candidate in extract_pdf_candidates_from_loaded_page(page)
                if candidate_allowed_for_channel(channel, candidate)
            ]
            return observed
    except Exception as exc:
        logger.debug(
            "Observed PDF action capture failed for %s: %s",
            channel,
            sanitize_text_for_output(exc),
        )
        return []


def classify_candidate_pdf_response(
    *,
    channel: str,
    url: str,
    status: int,
    content_type: str,
    body: bytes,
) -> str:
    non_pdf_html_response = "non_pdf_html_response"
    failure_reason = http_failure_reason(status, None, body)
    if failure_reason:
        return failure_reason
    head = body[:1024].lower()
    blocker_reason = pdf_blocker_reason(body)
    if blocker_reason:
        return blocker_reason
    try:
        candidate_host = (urllib.parse.urlsplit(url).hostname or "").casefold()
    except ValueError:
        candidate_host = ""
    if candidate_host == "wanfangdata.com.cn" or candidate_host.endswith(
        ".wanfangdata.com.cn"
    ):
        wanfang_reason = browser_page_blocker_reason(
            body[:64_000].decode("utf-8", errors="replace"),
            WANFANG_SOURCE,
        )
        if wanfang_reason == "wanfang_personal_account_required":
            return wanfang_reason
    if b"<html" in head or b"<!doctype html" in head:
        if channel == "Nature":
            return "nature_pdf_pattern_non_pdf" if url_looks_like_pdf(url) else non_pdf_html_response
        return "html_instead_of_pdf"
    if "pdf" not in content_type.casefold() and b"%pdf-" not in head:
        return "invalid_pdf"
    return ""


def page_has_access_blockers(text: str) -> bool:
    lowered = text.casefold()
    return any(
        token in lowered
        for token in (
            "captcha",
            "mfa",
            "verify you are human",
            "unusual traffic",
            "access denied",
            "robot check",
            "are you a robot",
            "performing security verification",
            "malicious bots",
            "cloudflare",
            "you have been blocked",
            "sign in to access",
            "subscription required",
            "purchase this article",
        )
    )


def browser_page_blocker_reason(text: str, channel: str = "") -> str:
    lowered = text.casefold()
    if security_challenge_required(text):
        return "security_challenge_required"
    if (
        channel == WANFANG_SOURCE
        and any(token in lowered for token in ("科技报告", "nstr", "science and technology report"))
        and any(
            token in lowered
            for token in ("个人账号登录", "个人用户登录", "个人登录", "personal account required")
        )
    ):
        return "wanfang_personal_account_required"
    if any(
        token in lowered
        for token in (
            "subscription required",
            "purchase this article",
            "not subscribed",
            "subscribe to access",
        )
    ):
        return "subscription_required"
    if manual_auth_required(text) or "sign in to access" in lowered or (
        channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}
        and any(token in lowered for token in ("请登录后下载", "登录后下载", "登录后查看全文", "请先登录"))
    ):
        return "manual_auth_required"
    if page_has_access_blockers(text):
        return "access_denied"
    return ""


def download_record_type_for_channel(channel: str, policy: dict[str, Any] | None = None) -> str:
    selected = str((policy or {}).get("_download_record_type") or "").casefold()
    if selected in {"literature", "patent"}:
        return selected
    if channel in patents_download_path_map and channel not in literature_download_path_map:
        return "patent"
    return "literature"


def resolve_pdf_discovery_challenge(
    url: str,
    current_url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    access_mode: str,
    reason: str = "security_challenge_required",
    policy: dict[str, Any] | None = None,
) -> list[str]:
    selected_policy = policy or {}
    control = security_challenge_control(
        download_record_type_for_channel(channel, selected_policy),
        "",
        "",
        url,
        channel or "landing_page_discovery",
        current_url or url,
        reason,
        config,
        logger,
        access_mode,
        selected_policy,
        current_url or url,
    )
    selected_policy["last_discovery_control_action"] = control.action
    selected_policy["last_discovery_control_reason"] = control.reason
    control_candidates = dedupe_urls(
        [*control.candidate_urls, control.final_url]
    )
    if control.action != "retry":
        cleanup_unconsumed_captured_candidates(control_candidates)
        if control.action in {"cooldown", "unhandled"}:
            mark_channel_cooldown(
                channel,
                "verification_control_unhandled",
                logger,
            )
        return []
    candidates = [
        candidate
        for candidate in control_candidates
        if candidate_allowed_for_channel(channel, candidate)
        and (
            captured_browser_download_path(candidate) is not None
            or bool(captured_browser_download_failure_reason(candidate))
            or url_looks_like_pdf(candidate)
        )
    ]
    cleanup_unconsumed_captured_candidates(
        [candidate for candidate in control_candidates if candidate not in candidates]
    )
    if candidates:
        return list(dict.fromkeys(candidates))
    storage_state_path = external_storage_state_is_usable(control.storage_state_path)
    if storage_state_path:
        return discover_pdf_urls_with_storage_state(
            control.final_url or current_url or url,
            storage_state_path,
            config,
            logger,
            channel,
        )
    return []


def discover_pdf_urls_from_page(
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    allow_playwright: bool = True,
    *,
    channel: str = "landing_page_discovery",
    access_mode: str = "open",
    discovery_state: dict[str, Any] | None = None,
) -> list[str]:
    candidates: list[str] = []
    try:
        status, content_type, body, final_url = request_url(
            url,
            timeout=download_timeout_seconds(),
            url_validator=(
                lambda value: candidate_allowed_for_channel(channel, value)
            )
            if channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}
            else None,
        )
        text = body.decode("utf-8", errors="replace")
        if status < 400:
            if "pdf" in content_type.casefold() or b"%pdf-" in body[:1024].lower():
                return [final_url] if candidate_allowed_for_channel(channel, final_url) else []
            candidates.extend(discover_pdf_urls_from_html(text, final_url))
            candidates = [
                candidate
                for candidate in candidates
                if candidate_allowed_for_channel(channel, candidate)
            ]
            if candidates:
                return candidates
        observed_blocker = browser_page_blocker_reason(text, channel)
        blocker_reason = observed_blocker or ("access_denied" if status in {401, 403} else "")
        if blocker_reason and discovery_state is not None:
            discovery_state["last_discovery_blocker"] = blocker_reason
        if blocker_reason == "security_challenge_required":
            return resolve_pdf_discovery_challenge(
                url,
                final_url,
                config,
                logger,
                channel,
                access_mode,
                policy=discovery_state,
            )
        if blocker_reason:
            return []
    except Exception as exc:
        logger.debug(
            "Initial HTML PDF discovery failed for %s: %s",
            sanitize_url_for_output(url),
            sanitize_text_for_output(exc),
        )
        if discovery_state is not None:
            discovery_state["last_discovery_blocker"] = "transport_failure"

    if candidates:
        return candidates
    if not allow_playwright:
        return []

    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        logger.debug(
            "Playwright unavailable for PDF discovery: %s",
            sanitize_text_for_output(exc),
        )
        return []

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=config.headless)
            context = browser.new_context(
                accept_downloads=True,
                locale="en-US,zh-CN",
                service_workers="block",
            )
            blocked_network_urls: list[str] = []
            page = new_guarded_browser_page(
                context,
                channel,
                blocked_network_urls,
            )
            bind_observed_pdf_response_capture(page, channel, candidates)
            safe_browser_goto(page, url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            try:
                page.wait_for_load_state("networkidle", timeout=BROWSER_NETWORK_IDLE_TIMEOUT_MS)
            except Exception:
                pass
            text = page.locator("body").inner_text(timeout=BROWSER_TEXT_TIMEOUT_MS) if page.locator("body").count() else ""
            meta_urls = page.locator("meta[name='citation_pdf_url'], meta[name='bepress_citation_pdf_url']").evaluate_all(
                "(els) => els.map((e) => e.content).filter(Boolean)"
            )
            embedded_urls = page.locator("iframe[src], embed[src], object[data]").evaluate_all(
                """(els) => els.map((e) => (
                    e.src || e.data || e.getAttribute('src') || e.getAttribute('data') || ''
                )).filter(Boolean)"""
            )
            hrefs = page.locator("a[href]").evaluate_all(
                """(els) => els.map((a) => ({
                    href: a.href,
                    text: (a.innerText || a.getAttribute('aria-label') || a.getAttribute('title') || '')
                }))"""
            )
            for value in meta_urls:
                if isinstance(value, str) and value:
                    candidates.append(urllib.parse.urljoin(page.url, value))
            for value in embedded_urls:
                if isinstance(value, str) and value and url_looks_like_pdf(value):
                    candidates.append(urllib.parse.urljoin(page.url, value))
            for item in hrefs:
                if not isinstance(item, dict):
                    continue
                href = str(item.get("href") or "")
                text_value = str(item.get("text") or "")
                haystack = f"{href} {text_value}".casefold()
                if url_looks_like_pdf(href) or any(token in haystack for token in (".pdf", "/pdf", "download pdf", "full text pdf", "viewpdf", "article-pdf", "publication pdf", "original document", "paper pdf", "download the paper", "/system/files/")):
                    observed_candidate = urllib.parse.urljoin(page.url, href)
                    if candidate_allowed_for_channel(channel, observed_candidate):
                        candidates.append(observed_candidate)
            blocker_reason = browser_page_blocker_reason(text, channel)
            if blocked_network_urls:
                blocker_reason = "unsafe_network_target"
            if blocker_reason and discovery_state is not None:
                discovery_state["last_discovery_blocker"] = blocker_reason
            if not candidates and not blocker_reason:
                candidates.extend(capture_visible_pdf_action(page, channel, logger))
            if not candidates and blocker_reason:
                current_page_url = str(getattr(page, "url", "") or "")
                context.close()
                browser.close()
                if blocker_reason == "security_challenge_required":
                    return resolve_pdf_discovery_challenge(
                        url,
                        current_page_url,
                        config,
                        logger,
                        channel,
                        access_mode,
                        policy=discovery_state,
                    )
                return []
            context.close()
            browser.close()
    except Exception as exc:
        logger.debug(
            "Playwright PDF discovery failed for %s: %s",
            sanitize_url_for_output(url),
            sanitize_text_for_output(exc),
        )
        if candidates:
            return list(dict.fromkeys(candidate for candidate in candidates if candidate_allowed_for_channel(channel, candidate)))
        if discovery_state is not None:
            discovery_state["last_discovery_blocker"] = "transport_failure"
        if channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}:
            return resolve_pdf_discovery_challenge(
                url,
                url,
                config,
                logger,
                channel,
                access_mode,
                "transport_failure",
                discovery_state,
            )
    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        if candidate_allowed_for_channel(channel, candidate) and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def extract_pdf_candidates_from_loaded_page(page: Any) -> list[str]:
    candidates: list[str] = []
    meta_urls = page.locator("meta[name='citation_pdf_url'], meta[name='bepress_citation_pdf_url']").evaluate_all(
        "(els) => els.map((e) => e.content).filter(Boolean)"
    )
    embedded_urls = page.locator("iframe[src], embed[src], object[data]").evaluate_all(
        """(els) => els.map((e) => (
            e.src || e.data || e.getAttribute('src') || e.getAttribute('data') || ''
        )).filter(Boolean)"""
    )
    hrefs = page.locator("a[href]").evaluate_all(
        """(els) => els.map((a) => ({
            href: a.href,
            text: (a.innerText || a.getAttribute('aria-label') || a.getAttribute('title') || '')
        }))"""
    )
    for value in meta_urls:
        if isinstance(value, str) and value:
            candidates.append(urllib.parse.urljoin(page.url, value))
    for value in embedded_urls:
        if isinstance(value, str) and value and url_looks_like_pdf(value):
            candidates.append(urllib.parse.urljoin(page.url, value))
    for item in hrefs:
        if not isinstance(item, dict):
            continue
        href = str(item.get("href") or "")
        text_value = str(item.get("text") or "")
        haystack = f"{href} {text_value}".casefold()
        if url_looks_like_pdf(href) or any(token in haystack for token in (".pdf", "/pdf", "download pdf", "full text pdf", "viewpdf", "article-pdf", "publication pdf", "original document", "paper pdf", "download the paper", "/system/files/")):
            candidates.append(urllib.parse.urljoin(page.url, href))
    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def discover_pdf_urls_with_storage_state(
    url: str,
    storage_state_path: str,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str = "landing_page_discovery",
) -> list[str]:
    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        logger.debug(
            "Playwright unavailable for storage-state PDF resume: %s",
            sanitize_text_for_output(exc),
        )
        return []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=config.headless)
            context = browser.new_context(
                accept_downloads=True,
                storage_state=storage_state_path,
                locale="en-US,zh-CN",
                service_workers="block",
            )
            blocked_network_urls: list[str] = []
            page = new_guarded_browser_page(
                context,
                channel,
                blocked_network_urls,
            )
            safe_browser_goto(page, url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            try:
                page.wait_for_load_state(
                    "networkidle",
                    timeout=BROWSER_NETWORK_IDLE_TIMEOUT_MS,
                )
            except Exception:
                pass
            text = page_text(page)
            candidates = (
                []
                if blocked_network_urls or browser_page_blocker_reason(text, channel)
                else extract_pdf_candidates_from_loaded_page(page)
            )
            context.close()
            browser.close()
            return [
                candidate
                for candidate in candidates
                if candidate_allowed_for_channel(channel, candidate)
            ]
    except Exception as exc:
        logger.debug(
            "Storage-state PDF resume failed for %s: %s",
            sanitize_url_for_output(url),
            sanitize_text_for_output(exc),
        )
        return []


def page_has_visible_password_input(page: Any) -> bool:
    try:
        locators = page.locator("input[type='password']")
        for index in range(min(int(locators.count()), 8)):
            locator = locators.nth(index)
            if not hasattr(locator, "is_visible") or locator.is_visible(timeout=300):
                return True
    except Exception:
        pass
    return False


def authenticated_page_confirmation_kind(
    page: Any,
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    reason: str,
) -> str:
    scope = source_auth_state_scope(channel, policy)
    if scope in {"cnki", "wanfang_data"} and configured_institution_marker_visible(
        page,
        config,
        scope,
    ):
        return "exact_institution_marker"
    text = page_text(page)
    current_url = str(getattr(page, "url", "") or "")
    expected_host = expected_auth_state_service_host(channel, policy)
    current_host = (urllib.parse.urlsplit(current_url).hostname or "").casefold()
    if (
        page_has_visible_password_input(page)
        or browser_page_blocker_reason(text, channel)
        or not auth_state_current_host_matches(scope, expected_host, current_host)
    ):
        return ""
    if channel == UYANIP_SOURCE:
        if uyanip_invalid_credentials(text) or uyanip_password_surface_visible(page):
            return ""
        if uyanip_authenticated_marker_visible(text):
            return "site_personal_session"
    return auth_state_confirmation_kind(reason)


AUTH_STATE_REPLACE_LOCKS_GUARD = Lock()
AUTH_STATE_REPLACE_LOCKS: dict[str, Any] = {}


def auth_state_replace_lock(target_state: Path) -> Any:
    key = str(target_state.resolve()).casefold() if os.name == "nt" else str(target_state.resolve())
    with AUTH_STATE_REPLACE_LOCKS_GUARD:
        lock = AUTH_STATE_REPLACE_LOCKS.get(key)
        if lock is None:
            lock = Lock()
            AUTH_STATE_REPLACE_LOCKS[key] = lock
        return lock


def _replace_staged_auth_state_unlocked(
    staged_state: Path,
    target_state: Path,
    staged_attestation: Path,
    *,
    attestation_payload: Mapping[str, Any],
    scope_key: str,
    owner_token: str,
    operation_id: str,
) -> tuple[bool, str]:
    target_attestation = shared_auth_state_attestation_path(target_state)
    return shared_auth_control_store().publish_auth_generation(
        scope_key,
        attestation_payload,
        staged_state_path=staged_state,
        target_state_path=target_state,
        staged_attestation_path=staged_attestation,
        target_attestation_path=target_attestation,
        owner_token=owner_token,
        operation_id=operation_id,
    )


def replace_staged_auth_state(
    staged_state: Path,
    target_state: Path,
    staged_attestation: Path,
    *,
    attestation_payload: Mapping[str, Any],
    scope_key: str,
    owner_token: str,
    operation_id: str,
) -> tuple[bool, str]:
    with auth_state_replace_lock(target_state):
        return _replace_staged_auth_state_unlocked(
            staged_state,
            target_state,
            staged_attestation,
            attestation_payload=attestation_payload,
            scope_key=scope_key,
            owner_token=owner_token,
            operation_id=operation_id,
        )


def persist_authenticated_context_state(
    context: Any,
    config: DownloadConfig,
    channel: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
    confirmation_kind: str,
    current_url: str,
    logger: logging.Logger,
) -> bool:
    target_state = channel_auth_state_path(config, channel, policy, paths)
    target_state.parent.mkdir(parents=True, exist_ok=True)
    token = hashlib.sha256(f"{channel}|{time.time_ns()}".encode("utf-8")).hexdigest()[:16]
    staged_state = target_state.with_name(f".{target_state.name}.{token}.tmp")
    staged_attestation: Path | None = None
    attestation_payload: dict[str, Any] | None = None
    attestation_scope = source_auth_state_scope(channel, policy) or safe_slug(
        str(policy.get("auth_state_scope") or channel)
    )
    try:
        context.storage_state(path=str(staged_state))
        chmod_secret_file(staged_state)
        scope_key = str(policy.get("_auth_scope_key") or "")
        owner_token = str(policy.get("_auth_scope_owner_token") or "")
        operation_id = str(policy.get("_auth_scope_operation_id") or "")
        if scope_key and owner_token and not operation_id:
            active_lease = shared_auth_control_store().current_scope_lease(scope_key)
            if (
                active_lease is not None
                and hmac.compare_digest(
                    str(active_lease.get("owner_token") or ""), owner_token
                )
            ):
                operation_id = str(active_lease.get("operation_id") or "")
        if not scope_key or not owner_token or not operation_id:
            logger.info(
                "Auth state generation for %s was not committed: auth_scope_lease_missing",
                channel,
            )
            staged_state.unlink(missing_ok=True)
            return False
        policy["_auth_scope_operation_id"] = operation_id
        payload, reason = build_shared_auth_state_attestation_payload(
            config,
            channel,
            policy,
            staged_state,
            confirmation_kind,
            current_url,
        )
        if payload is None:
            logger.info(
                "Auth state for %s (%s) was not persisted: %s",
                channel,
                attestation_scope,
                reason,
            )
            staged_state.unlink(missing_ok=True)
            return False
        attestation_payload = payload
        target_attestation = shared_auth_state_attestation_path(target_state)
        staged_attestation = target_attestation.with_name(
            f".{target_attestation.name}.{token}.tmp"
        )
        staged_attestation.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )
        chmod_secret_file(staged_attestation)
        committed, commit_reason = replace_staged_auth_state(
            staged_state,
            target_state,
            staged_attestation,
            attestation_payload=attestation_payload,
            scope_key=scope_key,
            owner_token=owner_token,
            operation_id=operation_id,
        )
        if not committed:
            logger.info(
                "Auth state generation for %s was not committed: %s",
                channel,
                commit_reason,
            )
            staged_state.unlink(missing_ok=True)
            staged_attestation.unlink(missing_ok=True)
            return False
        policy["_auth_state_generation"] = str(
            attestation_payload.get("generation_id") or ""
        )
        return True
    except Exception as exc:
        staged_state.unlink(missing_ok=True)
        if staged_attestation is not None:
            staged_attestation.unlink(missing_ok=True)
        logger.info("Unable to persist authenticated state for %s: %s", channel, exc)
        return False


def _open_authenticated_browser_context_unlocked(
    playwright: Any,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
    *,
    allow_state_reuse: bool = True,
) -> tuple[Any | None, Any | None, BrowserAuthResult]:
    state_path = channel_auth_state_path(config, channel, policy, paths)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    browser = playwright.chromium.launch(headless=config.headless)
    shared_scope = source_auth_state_scope(channel, policy)
    state_reuse_allowed = False
    state_reason = ""
    state_is_current = (
        not state_path.is_symlink()
        and (
        uyanip_saved_state_is_current(config, state_path)
        if channel == UYANIP_SOURCE
        else auth_state_is_fresh(state_path)
        )
    )
    if allow_state_reuse and state_is_current:
        state_reuse_allowed, state_reason = validate_shared_auth_state_attestation(
            config,
            channel,
            policy,
            state_path,
            str(policy.get("_current_record_resume_url") or policy.get("web_search_url") or policy.get("auth_entry_url") or ""),
        )
    if state_reuse_allowed:
        try:
            context = browser.new_context(
                accept_downloads=True,
                storage_state=str(state_path),
                locale="en-US,zh-CN",
                service_workers="block",
            )
            return browser, context, BrowserAuthResult(
                True,
                state_reason or "storage_state_reused",
                state_reused=True,
                auth_session_generation=str(
                    policy.get("_auth_state_generation") or ""
                ),
            )
        except Exception as exc:
            logger.info("Stored authentication state for %s could not be reused: %s", channel, exc)

    seed_candidates: list[Path] = []
    if allow_state_reuse and state_is_current and not state_reuse_allowed:
        seed_candidates.append(state_path)
    legacy_seed = auth_state_path(config, channel, paths) if shared_scope else None
    if (
        legacy_seed is not None
        and legacy_seed != state_path
        and not legacy_seed.is_symlink()
        and auth_state_is_fresh(legacy_seed)
    ):
        seed_candidates.append(legacy_seed)
    for seed_path in dict.fromkeys(seed_candidates):
        policy["_seed_storage_state_path"] = str(seed_path)
        context = None
        try:
            context = browser.new_context(
                accept_downloads=True,
                storage_state=str(seed_path),
                locale="en-US,zh-CN",
                service_workers="block",
            )
            blocked_network_urls: list[str] = []
            page = new_guarded_browser_page(context, channel, blocked_network_urls)
            resume_url = str(
                policy.get("_current_record_resume_url")
                or policy.get("web_search_url")
                or policy.get("auth_entry_url")
                or ""
            )
            if not resume_url:
                raise RuntimeError("auth_state_seed_unconfirmed")
            if (
                channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}
                and not new_source_network_url_allowed(resume_url)
            ):
                raise UnsafeNetworkTargetError("resume target rejected")
            safe_browser_goto(
                page,
                resume_url,
                wait_until="domcontentloaded",
                timeout=PAGE_TIMEOUT_MS,
            )
            if blocked_network_urls:
                raise UnsafeNetworkTargetError("resume redirect target rejected")
            confirmation_kind = authenticated_page_confirmation_kind(
                page,
                config,
                channel,
                policy,
                "legacy_seed_confirmation",
            )
            if not confirmation_kind:
                raise RuntimeError("auth_state_seed_unconfirmed")
            if not persist_authenticated_context_state(
                context,
                config,
                channel,
                policy,
                paths,
                confirmation_kind,
                str(getattr(page, "url", "") or resume_url),
                logger,
            ):
                raise RuntimeError("auth_state_seed_upgrade_failed")
            return browser, context, BrowserAuthResult(
                True,
                "legacy_seed_confirmed_and_upgraded",
                state_reused=True,
                legacy_seed_reused=True,
                auth_session_generation=str(
                    policy.get("_auth_state_generation") or ""
                ),
            )
        except Exception as exc:
            logger.info(
                "Legacy authentication seed for %s was not confirmed: %s",
                channel,
                sanitize_text_for_output(exc),
            )
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass

    if not auth_enabled_for_channel(config, channel, policy):
        browser.close()
        return None, None, BrowserAuthResult(False, state_reason or "skipped_auth_required")

    context = browser.new_context(
        accept_downloads=True,
        locale="en-US,zh-CN",
        service_workers="block",
    )
    blocked_network_urls: list[str] = []
    page = new_guarded_browser_page(context, channel, blocked_network_urls)
    auth_result = authenticate_if_needed(page, config, channel, policy, logger)
    if not auth_result.ok:
        context.close()
        browser.close()
        return None, None, auth_result

    external_state = external_storage_state_is_usable(auth_result.external_storage_state_path)
    if external_state:
        try:
            context.close()
            context = browser.new_context(
                accept_downloads=True,
                storage_state=external_state,
                locale="en-US,zh-CN",
                service_workers="block",
            )
            blocked_network_urls: list[str] = []
            page = new_guarded_browser_page(
                context,
                channel,
                blocked_network_urls,
            )
            resume_url = str(
                policy.get("_current_record_resume_url")
                or policy.get("web_search_url")
                or policy.get("auth_entry_url")
                or ""
            )
            if resume_url:
                if (
                    channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}
                    and not new_source_network_url_allowed(resume_url)
                ):
                    raise UnsafeNetworkTargetError("resume target rejected")
                safe_browser_goto(page, resume_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                if blocked_network_urls:
                    raise UnsafeNetworkTargetError("resume redirect target rejected")
            confirmation_kind = authenticated_page_confirmation_kind(
                page,
                config,
                channel,
                policy,
                auth_result.reason,
            )
            if not confirmation_kind or not persist_authenticated_context_state(
                context,
                config,
                channel,
                policy,
                paths,
                confirmation_kind,
                str(getattr(page, "url", "") or resume_url),
                logger,
            ):
                raise RuntimeError("external_auth_state_unconfirmed")
            return browser, context, BrowserAuthResult(
                True,
                auth_result.reason,
                external_storage_state_path=external_state,
                auth_session_generation=str(
                    policy.get("_auth_state_generation") or ""
                ),
            )
        except Exception as exc:
            logger.info("Unable to apply external authentication state for %s: %s", channel, exc)
            try:
                context.close()
            except Exception:
                pass
            browser.close()
            return None, None, BrowserAuthResult(False, f"external_auth_state_failed:{exc.__class__.__name__}")

    confirmation_kind = authenticated_page_confirmation_kind(
        page,
        config,
        channel,
        policy,
        auth_result.reason,
    )
    if confirmation_kind:
        persisted = persist_authenticated_context_state(
            context,
            config,
            channel,
            policy,
            paths,
            confirmation_kind,
            str(getattr(page, "url", "") or policy.get("web_search_url") or ""),
            logger,
        )
        if not persisted:
            context.close()
            browser.close()
            return None, None, BrowserAuthResult(False, "auth_state_generation_commit_failed")
        auth_result.auth_session_generation = str(
            policy.get("_auth_state_generation") or ""
        )
    return browser, context, auth_result


def open_authenticated_browser_context(
    playwright: Any,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
    *,
    allow_state_reuse: bool = True,
) -> tuple[Any | None, Any | None, BrowserAuthResult]:
    scope = source_auth_state_scope(channel, policy) or str(policy.get("auth_state_scope") or channel)
    with auth_scope_lock(scope):
        state_path = channel_auth_state_path(config, channel, policy, paths)
        scope_key, _principal_digest = auth_state_scope_identity(
            config,
            channel,
            policy,
            state_path,
        )
        owner_token = uuid.uuid4().hex
        operation_id = CURRENT_INVOCATION_ID or uuid.uuid4().hex
        deadline = time.monotonic() + max(
            manual_auth_timeout_seconds(),
            auth_control_hook_timeout_seconds(),
            download_timeout_seconds(),
        )
        with held_auth_scope_lease(
            shared_auth_control_store(),
            scope_key,
            owner_token=owner_token,
            operation_id=operation_id,
            deadline=deadline,
        ) as (lease, lost):
            if not lease.acquired:
                return None, None, BrowserAuthResult(
                    False,
                    lease.reason_code or "auth_scope_lease_timeout",
                )
            policy["_auth_scope_key"] = scope_key
            policy["_auth_scope_owner_token"] = owner_token
            policy["_auth_scope_operation_id"] = operation_id
            try:
                if lost.is_set():
                    return None, None, BrowserAuthResult(False, "auth_scope_lease_lost")
                result = _open_authenticated_browser_context_unlocked(
                    playwright,
                    config,
                    logger,
                    channel,
                    policy,
                    paths,
                    allow_state_reuse=allow_state_reuse,
                )
                if lost.is_set():
                    browser, context, _auth = result
                    try:
                        if context is not None:
                            context.close()
                    finally:
                        if browser is not None:
                            browser.close()
                    return None, None, BrowserAuthResult(False, "auth_scope_lease_lost")
                return result
            finally:
                policy.pop("_auth_scope_key", None)
                policy.pop("_auth_scope_owner_token", None)
                policy.pop("_auth_scope_operation_id", None)


def close_browser_resources_safely(
    context: Any,
    browser: Any,
    logger: logging.Logger,
    channel: str,
) -> None:
    for resource_name, resource in (("context", context), ("browser", browser)):
        try:
            if resource is not None:
                resource.close()
        except Exception as exc:
            logger.debug(
                "Unable to close authenticated browser %s for %s: %s",
                resource_name,
                channel,
                sanitize_text_for_output(exc),
            )


def discover_pdf_urls_from_authenticated_page(
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    state_path = channel_auth_state_path(config, channel, policy, paths)
    state_is_current = (
        uyanip_saved_state_is_current(config, state_path)
        if channel == UYANIP_SOURCE
        else auth_state_is_fresh(state_path)
    )
    if not auth_enabled_for_channel(config, channel, policy) and not state_is_current:
        logger.info("Authenticated PDF discovery skipped for %s: auth is disabled", channel)
        return []
    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        logger.info("Authenticated PDF discovery skipped for %s: Playwright unavailable: %s", channel, exc)
        return []

    state_path.parent.mkdir(parents=True, exist_ok=True)

    def parse_with_context(context: Any, auth_reason: str = "") -> tuple[list[str], bool, str]:
        candidates: list[str] = []
        try:
            blocked_network_urls: list[str] = []
            page = new_guarded_browser_page(
                context,
                channel,
                blocked_network_urls,
            )
            bind_observed_pdf_response_capture(page, channel, candidates)
            try:
                safe_browser_goto(page, url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            except Exception:
                if candidates:
                    return candidates, False, ""
                raise
            try:
                page.wait_for_load_state("networkidle", timeout=BROWSER_NETWORK_IDLE_TIMEOUT_MS)
            except Exception:
                pass
            text = page_text(page)
            blocker_reason = (
                "unsafe_network_target"
                if blocked_network_urls
                else browser_page_blocker_reason(text, channel)
            )
            if blocker_reason:
                policy["last_discovery_blocker"] = blocker_reason
                cleanup_unconsumed_captured_candidates(candidates)
                return [], blocker_reason in {
                    "manual_auth_required",
                    "access_denied",
                    "subscription_required",
                }, ""
            confirmation_kind = authenticated_page_confirmation_kind(
                page,
                config,
                channel,
                policy,
                auth_reason,
            )
            candidates.extend(extract_pdf_candidates_from_loaded_page(page))
            candidates = [
                candidate
                for candidate in candidates
                if candidate_allowed_for_channel(channel, candidate)
            ]
            if not candidates:
                candidates.extend(capture_visible_pdf_action(page, channel, logger))
                candidates = [
                    candidate
                    for candidate in candidates
                    if candidate_allowed_for_channel(channel, candidate)
                ]
            return candidates, False, confirmation_kind
        except Exception:
            cleanup_unconsumed_captured_candidates(candidates)
            raise

    browser: Any = None
    context: Any = None
    candidates: list[str] = []
    try:
        with sync_playwright() as playwright:
            browser, context, auth_result = open_authenticated_browser_context(playwright, config, logger, channel, policy, paths)
            if not auth_result.ok or browser is None or context is None:
                logger.info("Authenticated PDF discovery skipped for %s: %s", channel, auth_result.reason)
                mark_channel_cooldown(channel, auth_result.reason, logger)
                return []
            if auth_result.state_reused:
                candidates, auth_blocked, confirmation_kind = parse_with_context(
                    context,
                    auth_result.reason,
                )
                if auth_result.legacy_seed_reused and confirmation_kind:
                    persist_authenticated_context_state(
                        context,
                        config,
                        channel,
                        policy,
                        paths,
                        confirmation_kind,
                        url,
                        logger,
                    )
                close_browser_resources_safely(context, None, logger, channel)
                if candidates:
                    close_browser_resources_safely(None, browser, logger, channel)
                    logger.info("Reused authenticated storage state for %s", channel)
                    return candidates
                close_browser_resources_safely(None, browser, logger, channel)
                if auth_blocked:
                    logger.info("Stored authentication state for %s appears blocked; preserving it and retrying authentication once", channel)
                    if not source_auth_state_scope(channel, policy):
                        try:
                            state_path.unlink(missing_ok=True)
                        except Exception:
                            pass
                    browser, context, auth_result = open_authenticated_browser_context(
                        playwright,
                        config,
                        logger,
                        channel,
                        policy,
                        paths,
                        allow_state_reuse=False,
                    )
                    if not auth_result.ok or browser is None or context is None:
                        logger.info("Authenticated PDF discovery skipped for %s after reauth attempt: %s", channel, auth_result.reason)
                        mark_channel_cooldown(channel, auth_result.reason, logger)
                        return []
                    candidates, auth_blocked, _ = parse_with_context(context, auth_result.reason)
                    close_browser_resources_safely(
                        context,
                        browser,
                        logger,
                        channel,
                    )
                    if candidates:
                        logger.info("Reauthenticated storage state for %s", channel)
                        return candidates
                    if auth_blocked:
                        logger.info("Authenticated PDF discovery skipped for %s: reauthenticated state still appears blocked", channel)
                        mark_channel_cooldown(channel, "login_failed", logger)
                    else:
                        logger.info("Reauthenticated storage state for %s; no PDF links found", channel)
                else:
                    logger.info("Reused authenticated storage state for %s; no PDF links found", channel)
                return []
            candidates, _, _ = parse_with_context(context, auth_result.reason)
            close_browser_resources_safely(context, browser, logger, channel)
            return candidates
    except Exception as exc:
        cleanup_unconsumed_captured_candidates(candidates)
        close_browser_resources_safely(context, browser, logger, channel)
        logger.info("Authenticated PDF discovery failed for %s: %s", channel, exc)
        return []


def discover_pdf_urls_for_channel(
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    if access_mode == "authenticated":
        return discover_pdf_urls_from_authenticated_page(url, config, logger, channel, policy, paths)
    allow_playwright = channel not in {"doi_resolver"}
    return discover_pdf_urls_from_page(
        url,
        config,
        logger,
        allow_playwright=allow_playwright,
        channel=channel,
        access_mode=access_mode,
        discovery_state=policy,
    )


def template_values(row: dict[str, Any], *, doi: str = "", url: str = "", title: str = "", publication_number: str = "") -> dict[str, str]:
    return {
        "doi": doi,
        "encoded_doi": urllib.parse.quote(doi, safe=""),
        "url": url,
        "encoded_url": urllib.parse.quote(url, safe=""),
        "title": title,
        "encoded_title": urllib.parse.quote(title, safe=""),
        "publication_number": publication_number,
        "encoded_publication_number": urllib.parse.quote(publication_number, safe=""),
        "pmcid": extract_pmcid(row),
        "arxiv_id": extract_arxiv_id(row),
    }


def required_template_fields(template: str) -> set[str]:
    return {match.group(1) for match in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template)}


def format_download_template(template: str, values: dict[str, str]) -> str:
    if not template or template.startswith("metadata:"):
        return ""
    missing = [field for field in required_template_fields(template) if not values.get(field, "")]
    if missing:
        return ""
    try:
        return template.format(**values)
    except Exception:
        return ""


def build_channel_search_url(base_url: str, policy: dict[str, Any], query: str) -> str:
    if not base_url or not query:
        return ""
    parsed = urllib.parse.urlsplit(base_url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    query_param = str(policy.get("web_query_param") or "").strip() or "q"
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    params.append((query_param, query))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(params), parsed.fragment))


def url_looks_like_pdf(url: str) -> bool:
    if not url:
        return False
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(parsed.path or "").casefold()
    query = urllib.parse.unquote(parsed.query or "").casefold()
    if path.endswith(".pdf") or path.endswith("/pdf") or path.endswith("/pdfft"):
        return True
    pdf_path_tokens = (
        ".pdf/",
        "/pdf/",
        "/pdf?",
        "/doi/pdf/",
        "/article-pdf/",
        "/content/pdf/",
        "/download/pdf/",
        "/full.pdf",
        ".full.pdf",
    )
    if any(token in path for token in pdf_path_tokens):
        return True
    return (
        "download=pdf" in query
        or "format=pdf" in query
        or "type=pdf" in query
        or "content-type=pdf" in query
        or "httpaccept=application/pdf" in query
        or "download=1" in query and "patents.google.com" in parsed.netloc.casefold()
        or stable_wanfang_pdf_url(url)
    )


def url_looks_like_api_metadata(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc.casefold()
    path = parsed.path.casefold()
    return (
        host.startswith("api.")
        or ".api." in host
        or "/api/" in path
        or "/content/abstract/" in path
        or "/content/search/" in path
    )


def source_url_is_discoverable_page(url: str) -> bool:
    return bool(url) and (url_looks_like_pdf(url) or not url_looks_like_api_metadata(url))


def discover_from_page_or_direct_pdf(
    candidate_url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    if not candidate_allowed_for_channel(channel, candidate_url):
        return []
    if url_looks_like_pdf(candidate_url):
        return [candidate_url]
    return discover_pdf_urls_for_channel(candidate_url, config, logger, channel, access_mode, policy, paths)


def template_url_is_discoverable(template: str, template_url: str) -> bool:
    if not template_url:
        return False
    host = urllib.parse.urlsplit(template_url).netloc.casefold()
    if not required_template_fields(template) and not url_looks_like_pdf(template_url):
        return False
    if "api." in host and not required_template_fields(template):
        return False
    return True


def policy_allows_public_browser_search(policy: dict[str, Any], channel: str = "") -> bool:
    if policy.get("public_browser_allowed") is False:
        return False
    if bool(policy.get("browser_requires_restricted_access")) and channel not in {
        CNKI_SOURCE,
        WANFANG_SOURCE,
        UYANIP_SOURCE,
    }:
        return False
    return bool(policy.get("public_browser_allowed") or policy.get("browser_default_enabled") or policy.get("web_search_url"))


LiteratureChannelParser = Callable[
    [str, str, dict[str, Any], str, str, str, DownloadConfig, logging.Logger, str, dict[str, Any], dict[str, Path]],
    list[DownloadCandidate],
]
PatentChannelParser = Callable[
    [str, str, dict[str, Any], str, str, str, DownloadConfig, logging.Logger, str, dict[str, Any], dict[str, Path]],
    list[DownloadCandidate],
]


def locator_id_for_entry(locator: Mapping[str, Any]) -> str:
    payload = "\0".join(
        (
            str(locator.get("kind") or "unknown").casefold(),
            str(locator.get("source") or "unknown").casefold(),
            str(locator.get("auth_scope") or "unknown").casefold(),
            str(locator.get("url") or ""),
        )
    )
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:24]


def make_download_candidate(
    value: str | DownloadCandidate,
    *,
    planned_channel: str = "",
    access_mode: str = "open",
    policy: Mapping[str, Any] | None = None,
    locator: Mapping[str, Any] | None = None,
    discovery_source: str = "",
    discovery_adapter: str = "",
    resolver_channel: str = "",
    evidence_type: str = "",
    candidate_origin: str = "browser_discovery",
    parent_locator_id: str = "",
    parent_candidate_id: str = "",
) -> DownloadCandidate:
    """Coerce legacy string output into the structured candidate contract."""

    raw = str(value or "").strip()
    if isinstance(value, DownloadCandidate):
        existing = value
    else:
        existing = None
    policy = policy or {}
    locator = locator or {}
    registered = registered_candidate_metadata(planned_channel, raw)
    registered_resolver = str(registered.get("resolver_channel") or "")
    existing_scope = str(existing.auth_scope if existing is not None else "").strip()
    if access_mode == "authenticated" and existing_scope.casefold() in {
        "",
        "public",
        "unknown",
    }:
        existing_scope = ""
    scope = str(
        existing_scope
        or locator.get("auth_scope")
        or policy.get("_locator_auth_scope")
        or policy.get("auth_state_scope")
        or ("public" if access_mode != "authenticated" else "unknown")
    )
    existing_generation = str(
        existing.auth_session_generation if existing is not None else ""
    ).strip()
    if access_mode == "authenticated" and existing_generation.casefold() in {
        "",
        "public",
        "unknown",
    }:
        existing_generation = ""
    generation = str(
        existing_generation
        or policy.get("_auth_state_generation")
        or ("public" if access_mode != "authenticated" else "unknown")
    )
    return DownloadCandidate(
        raw,
        sanitized_target=(
            existing.sanitized_target
            if existing is not None and existing.sanitized_target
            else sanitize_output_value("channel_url_or_api", raw)
        ),
        locator_id=(
            existing.locator_id
            if existing is not None and existing.locator_id
            else parent_locator_id or (locator_id_for_entry(locator) if locator else "")
        ),
        locator_kind=(
            existing.locator_kind
            if existing is not None and existing.locator_kind
            else str(locator.get("kind") or "")
        ),
        locator_source=(
            existing.locator_source
            if existing is not None and existing.locator_source
            else str(locator.get("source") or policy.get("locator_source") or "")
        ),
        locator_auth_scope=(
            existing.locator_auth_scope
            if existing is not None and existing.locator_auth_scope
            else str(locator.get("auth_scope") or policy.get("_locator_auth_scope") or "")
        ),
        locator_stability=(
            existing.locator_stability
            if existing is not None and existing.locator_stability
            else str(locator.get("stability") or "")
        ),
        discovery_source=(
            existing.discovery_source
            if existing is not None and existing.discovery_source
            else discovery_source or str(registered.get("discovery_source") or planned_channel)
        ),
        discovery_adapter=(
            existing.discovery_adapter
            if existing is not None and existing.discovery_adapter
            else discovery_adapter or str(registered.get("discovery_adapter") or "")
        ),
        resolver_channel=(
            existing.resolver_channel
            if existing is not None and existing.resolver_channel
            else resolver_channel or registered_resolver
        ),
        evidence_type=(
            existing.evidence_type
            if existing is not None and existing.evidence_type
            else evidence_type or str(registered.get("evidence_type") or "")
        ),
        access_mode=access_mode or (existing.access_mode if existing is not None else "open"),
        auth_scope=scope,
        auth_session_generation=generation,
        parent_locator_id=(
            existing.parent_locator_id
            if existing is not None and existing.parent_locator_id
            else parent_locator_id
        ),
        parent_candidate_id=(
            existing.parent_candidate_id
            if existing is not None and existing.parent_candidate_id
            else parent_candidate_id
        ),
        candidate_origin=(
            existing.candidate_origin
            if existing is not None and existing.candidate_origin
            else candidate_origin or str(registered.get("candidate_origin") or "browser_discovery")
        ),
    )


def structure_download_candidates(
    candidates: Iterable[str | DownloadCandidate],
    *,
    planned_channel: str,
    access_mode: str,
    policy: Mapping[str, Any] | None,
    discovery_source: str,
    discovery_adapter: str,
    resolver_channel: str = "",
    candidate_origin: str = "browser_discovery",
) -> list[DownloadCandidate]:
    return dedupe_urls(
        [
            make_download_candidate(
                candidate,
                planned_channel=planned_channel,
                access_mode=access_mode,
                policy=policy,
                discovery_source=discovery_source,
                discovery_adapter=discovery_adapter,
                resolver_channel=resolver_channel,
                candidate_origin=candidate_origin,
            )
            for candidate in candidates
            if candidate
        ]
    )


def normalized_candidate_target_identity(candidate: str | DownloadCandidate) -> str:
    raw = str(candidate or "").strip()
    if not raw:
        return "empty"
    structured = candidate if isinstance(candidate, DownloadCandidate) else None
    parent_identity = ""
    if structured is not None:
        parent_identity = structured.parent_locator_id or structured.locator_id
    if captured_browser_download_path(raw) is not None or captured_browser_download_failure_reason(raw):
        capture_identity = parent_identity or candidate_id_for_url(raw)
        return f"capture:{capture_identity}"
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return "opaque:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    query_names = {name.casefold() for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
    signed_query_names = {
        "signature", "sig", "token", "access_token", "x-amz-signature",
        "x-goog-signature", "expires", "x-amz-credential", "x-goog-credential",
    }
    if query_names.intersection(signed_query_names):
        if parent_identity:
            return f"signed-parent:{parent_identity}"
        return "signed-url:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold()
    port = parsed.port
    authority = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        authority = f"{host}:{port}"
    path = parsed.path or "/"
    normalized_query = urllib.parse.urlencode(
        sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)),
        doseq=True,
    )
    return urllib.parse.urlunsplit((scheme, authority, path, normalized_query, ""))


def candidate_execution_key(
    record_id: str,
    stage: str,
    candidate: str | DownloadCandidate,
    access_mode: str,
    auth_scope: str,
    session_generation: str,
) -> str:
    return hashlib.sha256(
        "\0".join(
            (
                record_id,
                stage or "candidate",
                normalized_candidate_target_identity(candidate),
                access_mode or "open",
                auth_scope or "public",
                session_generation or "public",
            )
        ).encode("utf-8", errors="ignore")
    ).hexdigest()


def dedupe_urls(candidates: Iterable[str | DownloadCandidate]) -> list[DownloadCandidate]:
    seen: dict[tuple[str, ...], int] = {}
    unique: list[DownloadCandidate] = []
    for candidate in candidates:
        if not candidate:
            continue
        structured = (
            candidate
            if isinstance(candidate, DownloadCandidate)
            else make_download_candidate(candidate)
        )
        target_key = str(
            urllib.parse.urldefrag(candidate)[0]
            if url_looks_like_pdf(candidate)
            else candidate
        )
        key = (
            target_key,
            structured.locator_id,
            structured.discovery_source,
            structured.discovery_adapter,
            structured.resolver_channel,
            structured.candidate_origin,
            structured.auth_scope,
            structured.auth_session_generation,
        )
        existing_index = seen.get(key)
        if existing_index is None:
            seen[key] = len(unique)
            unique.append(structured)
            continue
        existing = unique[existing_index]
        if not urllib.parse.urlsplit(existing).fragment and urllib.parse.urlsplit(candidate).fragment:
            unique[existing_index] = structured
    return unique


def row_source_matches_channel(row: dict[str, Any], channel: str) -> bool:
    if str(row.get("source") or "") == channel:
        return True
    channel_key = channel.casefold()
    if any(source.casefold() == channel_key for source in row_metadata_sources(row)):
        return True
    return any(
        str(locator.get("source") or "").casefold() == channel_key
        for locator in (row.get("locators") or [])
        if isinstance(locator, Mapping)
    )


SOURCE_SCOPED_OBSERVED_DOWNLOAD_ADAPTERS = frozenset(
    {
        "parse_literature_cnki_observed",
        "parse_literature_wanfang_observed",
        "parse_patent_cnki_observed",
        "parse_patent_wanfang_observed",
        "parse_patent_uyanip_observed",
    }
)


def available_download_locator_tokens(
    record_type: str,
    row: Mapping[str, Any],
) -> frozenset[str]:
    """Project one planner row into the registry's structural token vocabulary."""

    tokens: set[str] = set()
    raw_identifiers: Any = row.get("identifiers") or []
    if isinstance(raw_identifiers, str):
        try:
            raw_identifiers = json.loads(raw_identifiers)
        except Exception:
            raw_identifiers = []
    if isinstance(raw_identifiers, Mapping):
        raw_identifiers = [
            {"identifier_type": kind, "value": value}
            for kind, value in raw_identifiers.items()
        ]
    for item in raw_identifiers if isinstance(raw_identifiers, list) else []:
        if not isinstance(item, Mapping):
            continue
        kind = str(
            item.get("identifier_type")
            or item.get("type")
            or item.get("kind")
            or ""
        ).strip().casefold()
        value = str(item.get("value") or item.get("normalized_value") or "").strip()
        if kind and value:
            tokens.add(f"identifier:{kind}")

    if normalize_doi(get_field(row, LITERATURE_DOI_ALIASES)):
        tokens.add("identifier:doi")
    if str(row.get("raw_id") or row.get("source_id") or "").strip():
        tokens.add("identifier:raw_id")
    if record_type == "literature":
        if extract_pmid(dict(row)):
            tokens.add("identifier:pmid")
        if extract_pmcid(dict(row)):
            tokens.add("identifier:pmcid")
        explicit_arxiv = get_field(row, ("arxiv_id", "arXiv", "arxiv"))
        if explicit_arxiv and extract_arxiv_id({"arxiv_id": explicit_arxiv}):
            tokens.add("identifier:arxiv_id")
        title = get_field(row, LITERATURE_TITLE_ALIASES)
        candidate_url = get_field(row, LITERATURE_URL_ALIASES)
    else:
        if normalize_publication_number(
            get_field(row, PUBLICATION_NUMBER_ALIASES)
            or typed_identifier_value(row, "publication_number")
        ):
            tokens.add("identifier:publication_number")
        title = get_field(row, PATENT_TITLE_ALIASES)
        candidate_url = get_field(row, PATENT_URL_ALIASES)
    if title.strip():
        tokens.add("metadata:title")

    for locator in row_locator_entries(row):
        kind = locator["kind"].casefold()
        if kind in {"direct_pdf", "pdf"}:
            tokens.add("locator:direct_pdf")
        elif kind in {"landing", "landing_page", "repository", "resolver"}:
            tokens.add("locator:landing")
    normalized_candidate_url = normalize_url(candidate_url)
    if normalized_candidate_url:
        tokens.add(
            "locator:direct_pdf"
            if url_looks_like_pdf(normalized_candidate_url)
            else "locator:landing"
        )
    return frozenset(tokens)


STRONG_CROSS_PROVIDER_DOWNLOAD_TOKENS = frozenset(
    {
        "identifier:doi",
        "identifier:pmid",
        "identifier:pmcid",
        "identifier:arxiv_id",
        "identifier:publication_number",
    }
)
GENERIC_TITLE_DISCOVERY_CHANNELS = frozenset(
    {"Google Scholar", "WIPO PATENTSCOPE API"}
)
GENERIC_LOCATOR_DISCOVERY_CHANNELS = frozenset({"input_url"})


def source_matches_download_spec(source: str, spec: Any) -> bool:
    source_key = str(source or "").strip().casefold()
    if not source_key:
        return False
    if source_key == str(spec.display_name).casefold():
        return True
    record_type = str(spec.record_type)
    for candidate in (
        *get_search_adapters(record_type),
        *get_download_adapters(record_type),
    ):
        if str(candidate.display_name).casefold() == source_key:
            return str(candidate.provider_id) == str(spec.provider_id)
    return False


def row_source_matches_download_spec(row: Mapping[str, Any], spec: Any) -> bool:
    sources = list(row_metadata_sources(row))
    sources.extend(
        locator["source"]
        for locator in row_locator_entries(row)
        if locator.get("source")
    )
    return any(source_matches_download_spec(source, spec) for source in sources)


def raw_identifier_owned_by_spec(row: Mapping[str, Any], spec: Any) -> bool:
    raw_identifiers: Any = row.get("identifiers") or []
    if isinstance(raw_identifiers, str):
        try:
            raw_identifiers = json.loads(raw_identifiers)
        except Exception:
            raw_identifiers = []
    if isinstance(raw_identifiers, Mapping):
        raw_identifiers = [
            {"identifier_type": kind, "value": value}
            for kind, value in raw_identifiers.items()
        ]
    observed_raw = False
    for item in raw_identifiers if isinstance(raw_identifiers, list) else []:
        if not isinstance(item, Mapping):
            continue
        kind = str(
            item.get("identifier_type")
            or item.get("type")
            or item.get("kind")
            or ""
        ).strip().casefold()
        value = str(item.get("value") or item.get("normalized_value") or "").strip()
        if kind != "raw_id" or not value:
            continue
        observed_raw = True
        source = str(item.get("source") or "").strip()
        if source_matches_download_spec(source, spec):
            return True
    if observed_raw or str(row.get("raw_id") or row.get("source_id") or "").strip():
        return row_source_matches_download_spec(row, spec)
    return False


def locator_entry_owned_by_spec(locator: Mapping[str, Any], spec: Any) -> bool:
    source_owned = source_matches_download_spec(
        str(locator.get("source") or ""),
        spec,
    )
    locator_scope = str(locator.get("auth_scope") or "unknown").casefold()
    spec_scope = str(getattr(spec, "auth_scope", "unknown") or "unknown").casefold()
    scope_owned = (
        locator_scope not in {"", "unknown", "public"}
        and spec_scope not in {"", "unknown", "public"}
        and locator_scope == spec_scope
    )
    return source_owned or scope_owned


def locator_token_owned_by_spec(
    row: Mapping[str, Any],
    spec: Any,
    token: str,
) -> bool:
    expected_direct = token == "locator:direct_pdf"
    for locator in row_locator_entries(row):
        kind = locator["kind"].casefold()
        is_direct = kind in {"direct_pdf", "pdf"}
        is_landing = kind in {"landing", "landing_page", "repository", "resolver"}
        if (expected_direct and not is_direct) or (not expected_direct and not is_landing):
            continue
        if locator_entry_owned_by_spec(locator, spec):
            return True

    aliases = LITERATURE_URL_ALIASES if spec.record_type == "literature" else PATENT_URL_ALIASES
    scalar_url = normalize_url(get_field(row, aliases))
    if scalar_url and url_looks_like_pdf(scalar_url) == expected_direct:
        return row_source_matches_download_spec(row, spec)
    return False


def effective_download_locator_tokens(
    spec: Any,
    row: Mapping[str, Any],
    available_tokens: frozenset[str],
) -> frozenset[str]:
    effective: set[str] = set()
    for token in available_tokens:
        if token in STRONG_CROSS_PROVIDER_DOWNLOAD_TOKENS:
            effective.add(token)
        elif token == "identifier:raw_id":
            if raw_identifier_owned_by_spec(row, spec):
                effective.add(token)
        elif token == "metadata:title":
            if (
                str(spec.display_name) in GENERIC_TITLE_DISCOVERY_CHANNELS
                or row_source_matches_download_spec(row, spec)
            ):
                effective.add(token)
        elif token in {"locator:landing", "locator:direct_pdf"}:
            if (
                str(spec.display_name) in GENERIC_LOCATOR_DISCOVERY_CHANNELS
                or locator_token_owned_by_spec(row, spec, token)
            ):
                effective.add(token)
        else:
            effective.add(token)
    return frozenset(effective)


def download_channel_structurally_applicable(
    spec: Any,
    row: Mapping[str, Any],
    available_tokens: frozenset[str],
) -> bool:
    """Apply registry requirements with identifier/locator ownership."""

    effective_tokens = effective_download_locator_tokens(spec, row, available_tokens)
    if not locator_requirements_satisfied(spec, effective_tokens):
        return False
    if (
        str(getattr(spec, "actual_adapter", ""))
        in SOURCE_SCOPED_OBSERVED_DOWNLOAD_ADAPTERS
        and not row_source_matches_download_spec(row, spec)
    ):
        return False
    return True


def structurally_applicable_download_specs(
    record_type: str,
    row: Mapping[str, Any],
) -> tuple[Any, ...]:
    available_tokens = available_download_locator_tokens(record_type, row)
    return tuple(
        spec
        for spec in get_download_adapters(record_type)
        if download_channel_structurally_applicable(spec, row, available_tokens)
    )


def locator_owner_download_spec(
    record_type: str,
    locator: Mapping[str, Any],
) -> Any | None:
    return next(
        (
            spec
            for spec in get_download_adapters(record_type)
            if locator_entry_owned_by_spec(locator, spec)
        ),
        None,
    )


def cnki_order_action_url(value: Any) -> bool:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold().strip(".")
    path = (parsed.path or "").casefold().rstrip("/")
    return bool(
        (host == "cnki.net" or host.endswith(".cnki.net"))
        and path.endswith("/bar/download/order")
    )


def cnki_detail_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or raw.casefold().startswith(("javascript:", "#")):
        return ""
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return ""
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme.casefold() != "https"
        or not (host == "cnki.net" or host.endswith(".cnki.net"))
        or (parsed.path or "").casefold().rstrip("/") != "/kcms2/article/abstract"
    ):
        return ""
    return urllib.parse.urlunsplit(
        ("https", parsed.netloc.casefold(), parsed.path, parsed.query, "")
    )


def wanfang_literature_detail_url(value: Any) -> str:
    raw = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return ""
    path_parts = [part.casefold() for part in (parsed.path or "").split("/") if part]
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or (parsed.hostname or "").casefold() != "d.wanfangdata.com.cn"
        or not path_parts
        or path_parts[0] not in WANFANG_RESOURCE_TYPES
    ):
        return ""
    return urllib.parse.urlunsplit(
        (parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path, parsed.query, "")
    )


def wanfang_patent_detail_url(value: Any) -> str:
    raw = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return ""
    parts = [part for part in (parsed.path or "").split("/") if part]
    if (
        parsed.scheme.casefold() != "https"
        or (parsed.hostname or "").casefold() != "d.wanfangdata.com.cn"
        or len(parts) < 2
        or parts[0].casefold() != "patent"
    ):
        return ""
    return urllib.parse.urlunsplit(
        ("https", parsed.netloc.casefold(), parsed.path, parsed.query, "")
    )


def uyanip_patent_detail_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or raw.casefold().startswith(("javascript:", "#")):
        return ""
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return ""
    host = (parsed.hostname or "").casefold().strip(".")
    path = parsed.path or ""
    lowered_path = path.casefold().rstrip("/")
    if (
        parsed.scheme.casefold() != "https"
        or not (host == "uyanip.com" or host.endswith(".uyanip.com"))
        or lowered_path in {"", "/"}
        or lowered_path.startswith(("/result", "/login", "/register", "/user", "/space", "/search", "/auth", "/download"))
    ):
        return ""
    path_parts = [part.casefold() for part in path.split("/") if part]
    if lowered_path == "/detail":
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        if not str(query.get("aid", [""])[0]).strip():
            return ""
    elif not (path_parts and path_parts[0] == "patent" and len(path_parts) >= 2):
        return ""
    return urllib.parse.urlunsplit(("https", parsed.netloc.casefold(), path, parsed.query, ""))


def observed_row_locator(row: dict[str, Any], validator: Callable[[Any], str]) -> str:
    for field in ("raw_id", "url", "URL"):
        candidate = validator(row.get(field))
        if candidate:
            return candidate
    for locator in row.get("locators") or []:
        if not isinstance(locator, Mapping):
            continue
        candidate = validator(locator.get("url"))
        if candidate:
            return candidate
    return ""


def parse_literature_cnki_observed(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    del template, title, doi
    if not row_source_matches_channel(row, channel):
        return []
    candidates: list[str] = []
    direct_pdf = normalize_literature_pdf_url(url)
    if direct_pdf and candidate_allowed_for_channel(channel, direct_pdf):
        policy["_current_record_resume_url"] = direct_pdf
        candidates.extend(discover_from_page_or_direct_pdf(direct_pdf, config, logger, channel, access_mode, policy, paths))
    detail = observed_row_locator(row, cnki_detail_url)
    if detail:
        policy["_current_record_resume_url"] = detail
        candidates.extend(discover_from_page_or_direct_pdf(detail, config, logger, channel, access_mode, policy, paths))
    return dedupe_urls(candidates)


def parse_literature_wanfang_observed(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    del template, title, doi
    if not row_source_matches_channel(row, channel):
        return []
    candidates: list[str] = []
    direct_pdf = normalize_literature_pdf_url(url)
    if direct_pdf:
        policy["_current_record_resume_url"] = direct_pdf
        candidates.extend(discover_from_page_or_direct_pdf(direct_pdf, config, logger, channel, access_mode, policy, paths))
    detail = observed_row_locator(row, wanfang_literature_detail_url)
    if detail:
        policy["_current_record_resume_url"] = detail
        candidates.extend(discover_from_page_or_direct_pdf(detail, config, logger, channel, access_mode, policy, paths))
    return dedupe_urls(candidates)


def parse_patent_cnki_observed(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    del template, title, publication_number
    if not row_source_matches_channel(row, channel):
        return []
    detail = cnki_detail_url(url) or observed_row_locator(row, cnki_detail_url)
    if detail:
        policy["_current_record_resume_url"] = detail
    return discover_from_page_or_direct_pdf(detail, config, logger, channel, access_mode, policy, paths) if detail else []


def parse_patent_wanfang_observed(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    del template, title, publication_number
    if not row_source_matches_channel(row, channel):
        return []
    detail = wanfang_patent_detail_url(url) or observed_row_locator(row, wanfang_patent_detail_url)
    if detail:
        policy["_current_record_resume_url"] = detail
    return discover_from_page_or_direct_pdf(detail, config, logger, channel, access_mode, policy, paths) if detail else []


def parse_patent_uyanip_observed(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    del template, title, publication_number
    if not row_source_matches_channel(row, channel):
        return []
    detail = uyanip_patent_detail_url(url) or observed_row_locator(row, uyanip_patent_detail_url)
    if detail:
        policy["_current_record_resume_url"] = detail
    return discover_from_page_or_direct_pdf(detail, config, logger, channel, access_mode, policy, paths) if detail else []


def parse_literature_api_pdf(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    raw_candidates = literature_api_pdf_candidates(channel, doi, row, url, logger)
    if row_source_matches_channel(row, channel) and source_url_is_discoverable_page(url):
        raw_candidates.append(url)
    candidates: list[str] = []
    for candidate in dedupe_urls(raw_candidates):
        if url_looks_like_pdf(candidate):
            candidates.append(candidate)
        else:
            candidates.extend(discover_from_page_or_direct_pdf(candidate, config, logger, channel, access_mode, policy, paths))
    return dedupe_urls(candidates)


def decode_scihub_action_url(value: str) -> str:
    text = (value or "").strip().strip("'\"")
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text
    if "_" not in text:
        return ""
    first, rest = text.split("_", 1)
    return f"{first}://{rest.replace('_', '.')}".casefold()


def scihub_form_url_from_template(template: str) -> str:
    if not template:
        return "https://www.scihub.net.cn/sci-hub/"
    stripped = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "", template).rstrip("/")
    if stripped.endswith("/sci-hub"):
        return stripped + "/"
    return stripped or "https://www.scihub.net.cn/sci-hub/"


def scihub_template_is_form_shell(template: str) -> bool:
    host = urllib.parse.urlsplit(template).netloc.casefold()
    return host.endswith("scihub.net.cn")


def discover_literature_scihub_form_candidates(
    form_url: str,
    doi: str,
    logger: logging.Logger,
    config: DownloadConfig,
    *,
    title: str = "",
    source_url: str = "",
    access_mode: str = "open",
) -> list[str]:
    candidates: list[str] = []
    try:
        status, content_type, body, final_url = request_url(form_url, timeout=download_timeout_seconds(), retries=1)
    except Exception as exc:
        logger.debug(
            "Sci-Hub form page discovery failed for %s: %s",
            sanitize_url_for_output(form_url),
            sanitize_text_for_output(exc),
        )
        return []
    if status >= 500:
        return []
    text = body.decode("utf-8", errors="replace")
    action_url = ""
    action_match = re.search(r"var\s+ACTION_URL\s*=\s*['\"]([^'\"]+)['\"]", text, flags=re.I)
    if action_match:
        action_url = decode_scihub_action_url(action_match.group(1))
    if not action_url:
        form_match = re.search(r"<form[^>]+action\s*=\s*['\"]([^'\"]+)['\"]", text, flags=re.I)
        if form_match:
            action_url = urllib.parse.urljoin(final_url, html.unescape(form_match.group(1)))
    if not action_url:
        action_url = final_url
    try:
        status, content_type, body, final_url = request_form_url(
            action_url,
            {"request": doi, "sci-hub-plugin-check": ""},
            timeout=download_timeout_seconds(),
            headers={"Referer": form_url},
        )
    except Exception as exc:
        logger.debug(
            "Sci-Hub form POST failed for %s: %s",
            sanitize_url_for_output(action_url),
            sanitize_text_for_output(exc),
        )
        return []
    if status >= 500:
        return []
    head = body[:1024].lower()
    blocker_reason = pdf_blocker_reason(body)
    if blocker_reason in CHANNEL_COOLDOWN_REASONS:
        control = security_challenge_control("literature", title, doi, source_url, "Sci-Hub", action_url, blocker_reason, config, logger, access_mode)
        if control.action == "retry":
            return dedupe_urls(control.candidate_urls)
        if control.action == "skip":
            return []
        mark_channel_cooldown("Sci-Hub", blocker_reason, logger)
        return []
    if "pdf" in content_type.casefold() or b"%pdf-" in head:
        return [final_url]
    text = body.decode("utf-8", errors="replace")
    candidates.extend(discover_pdf_urls_from_html(text, final_url))
    return dedupe_urls(candidates)


def parse_literature_scihub(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    if not doi:
        return []
    values = template_values(row, doi=doi, url=url, title=title)
    values["doi"] = values["encoded_doi"]
    scihub_url = format_download_template(template, values) or f"https://www.scihub.net.cn/sci-hub/{urllib.parse.quote(doi, safe='')}"
    form_url = scihub_form_url_from_template(template)
    if scihub_template_is_form_shell(template):
        candidates = discover_from_page_or_direct_pdf(scihub_url, config, logger, channel, access_mode, policy, paths)
        candidates.extend(discover_literature_scihub_form_candidates(form_url, doi, logger, config, title=title, source_url=url, access_mode=access_mode))
        return dedupe_urls(candidates)
    candidates = discover_from_page_or_direct_pdf(scihub_url, config, logger, channel, access_mode, policy, paths)
    if candidates:
        return candidates
    candidates = discover_literature_scihub_form_candidates(form_url, doi, logger, config, title=title, source_url=url, access_mode=access_mode)
    return dedupe_urls(candidates)

def parse_literature_doi_resolver(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    doi_url = f"https://doi.org/{urllib.parse.quote(doi, safe='')}" if doi else ""
    return discover_from_page_or_direct_pdf(doi_url, config, logger, channel, access_mode, policy, paths)


def parse_literature_template_or_search(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    candidates: list[str] = []
    if row_source_matches_channel(row, channel):
        if source_url_is_discoverable_page(url):
            candidates.extend(discover_from_page_or_direct_pdf(url, config, logger, channel, access_mode, policy, paths))
    if not required_template_fields(template) and not row_source_matches_channel(row, channel) and not policy_allows_public_browser_search(policy, channel):
        return dedupe_urls(candidates)
    # Structural applicability is decided by the shared registry before this
    # parser is called.  In particular, metadata:title is a declared input for
    # Google Scholar and USENIX, so a record need not originate from that
    # provider (or require an exact-channel CLI filter) to use title discovery.
    values = template_values(row, doi=doi, url=url, title=title)
    template_url = format_download_template(template, values)
    if template_url_is_discoverable(template, template_url):
        candidates.extend(discover_from_page_or_direct_pdf(template_url, config, logger, channel, access_mode, policy, paths))
    if access_mode == "open" and not policy_allows_public_browser_search(policy, channel):
        return dedupe_urls(candidates)

    search_base = str(policy.get("web_search_url") or "")
    if not search_base and template.startswith(("http://", "https://")) and "api." not in urllib.parse.urlsplit(template).netloc.casefold():
        search_base = template
    search_query = doi or title
    search_url = build_channel_search_url(search_base, policy, search_query)
    if search_url:
        candidates.extend(discover_from_page_or_direct_pdf(search_url, config, logger, channel, access_mode, policy, paths))
    return dedupe_urls(candidates)


def parse_literature_usenix(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    candidates: list[str] = []
    if source_url_is_discoverable_page(url) and "usenix.org" in urllib.parse.urlsplit(url).netloc.casefold():
        candidates.extend(discover_from_page_or_direct_pdf(url, config, logger, channel, access_mode, policy, paths))
    candidates.extend(parse_literature_template_or_search(channel, template, row, title, doi, url, config, logger, access_mode, policy, paths))
    return dedupe_urls(candidates)


def parse_patent_input_url(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[DownloadCandidate]:
    locators = row_locator_entries(row)
    if url and all(url != item["url"] for item in locators):
        locators.insert(
            0,
            {
                "url": url,
                "kind": "direct_pdf" if url_looks_like_pdf(url) else "landing",
                "source": str(row.get("source") or "unknown"),
                "auth_scope": "unknown",
                "stability": "unknown",
                "observed_at": "",
                "_legacy": "true",
            },
        )
    candidates: list[DownloadCandidate] = []
    for locator in locators:
        locator_url = locator["url"]
        locator_candidates = discover_from_page_or_direct_pdf(
            locator_url,
            config,
            logger,
            channel,
            access_mode,
            policy,
            paths,
        )
        source = str(locator.get("source") or "unknown")
        resolver = (
            "Google Patents"
            if any(google_patents_network_url(item) for item in locator_candidates)
            else source if source.casefold() not in {"", "unknown"} else "input_url"
        )
        candidates.extend(
            make_download_candidate(
                item,
                planned_channel=channel,
                access_mode=access_mode,
                policy=policy,
                locator=locator,
                discovery_source=source,
                discovery_adapter="parse_patent_input_url",
                resolver_channel=("Google Patents" if google_patents_network_url(item) else resolver),
                evidence_type=str(locator.get("kind") or "locator"),
                candidate_origin=(
                    "metadata_locator"
                    if locator.get("_legacy") == "true"
                    else "canonical_locator"
                ),
                parent_locator_id=locator_id_for_entry(locator),
            )
            for item in locator_candidates
        )
    return dedupe_urls(candidates)


def google_patents_network_url(value: str) -> bool:
    try:
        host = (urllib.parse.urlsplit(str(value or "")).hostname or "").casefold()
    except ValueError:
        return False
    return bool(
        host == "patents.google.com"
        or host.endswith(".patents.google.com")
        or host == "patentimages.storage.googleapis.com"
    )


def register_patent_candidate_origins(
    planned_channel: str,
    candidates: list[str],
    native_resolver: str,
) -> None:
    native_candidates = [
        candidate
        for candidate in candidates
        if not google_patents_network_url(candidate)
    ]
    google_candidates = [
        candidate
        for candidate in candidates
        if google_patents_network_url(candidate)
    ]
    register_candidate_resolver(
        planned_channel,
        native_candidates,
        native_resolver,
    )


def patent_channel_owned_locators(
    row: Mapping[str, Any],
    channel: str,
    legacy_url: str = "",
) -> list[dict[str, str]]:
    spec = next(
        (
            item
            for item in get_download_adapters("patent")
            if item.display_name == channel
        ),
        None,
    )
    owned = [
        locator
        for locator in row_locator_entries(row)
        if spec is not None and locator_entry_owned_by_spec(locator, spec)
    ]
    if legacy_url and row_source_matches_channel(dict(row), channel) and all(
        item["url"] != legacy_url for item in owned
    ):
        owned.append(
            {
                "url": legacy_url,
                "kind": "direct_pdf" if url_looks_like_pdf(legacy_url) else "landing",
                "source": channel,
                "auth_scope": str(getattr(spec, "auth_scope", "unknown") or "unknown"),
                "stability": "unknown",
                "observed_at": "",
                "_legacy": "true",
            }
        )
    return owned


def known_patent_publication_numbers(
    row: Mapping[str, Any], publication_number: str
) -> set[str]:
    values = {normalize_publication_number(publication_number)} if publication_number else set()
    identifiers: Any = row.get("identifiers") or []
    if isinstance(identifiers, str):
        try:
            identifiers = json.loads(identifiers)
        except (TypeError, ValueError, json.JSONDecodeError):
            identifiers = []
    for item in identifiers if isinstance(identifiers, list) else []:
        if not isinstance(item, Mapping):
            continue
        kind = str(
            item.get("identifier_type") or item.get("type") or item.get("kind") or ""
        ).casefold()
        if kind not in {"publication_number", "publication", "patent_number"}:
            continue
        normalized = normalize_publication_number(
            str(item.get("normalized_value") or item.get("value") or "")
        )
        if normalized:
            values.add(normalized)
    values.discard("")
    return values
    register_candidate_resolver(
        planned_channel,
        google_candidates,
        "Google Patents",
    )


def parse_patent_google_patents(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[DownloadCandidate]:
    if not publication_number:
        return []
    candidates: list[str] = []
    patent_url = f"https://patents.google.com/patent/{urllib.parse.quote(publication_number, safe='')}/en"
    candidates.extend(discover_from_page_or_direct_pdf(patent_url, config, logger, channel, access_mode, policy, paths))
    candidates.extend(google_patents_pdf_candidates(publication_number))
    return structure_download_candidates(
        candidates,
        planned_channel=channel,
        access_mode=access_mode,
        policy=policy,
        discovery_source="Google Patents",
        discovery_adapter="parse_patent_google_patents",
        resolver_channel="Google Patents",
        candidate_origin="identifier_derived",
    )


def parse_patent_lens(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[DownloadCandidate]:
    candidates: list[DownloadCandidate] = []
    api_key = env_value("LENS_Patents_API_KEY")
    if api_key and publication_number:
        try:
            data = post_json(
                "https://api.lens.org/patent/search",
                {"query": {"match": {"publication_number": publication_number}}, "size": 3},
                headers={"Authorization": f"Bearer {api_key}"},
            )
            native_candidates = structure_download_candidates(
                collect_json_urls(data, pdf_only=True),
                planned_channel=channel,
                access_mode=access_mode,
                policy=policy,
                discovery_source="The Lens (lens.org)",
                discovery_adapter="parse_patent_lens.api",
                resolver_channel="The Lens (lens.org)",
                candidate_origin="native_api_locator",
            )
            candidates.extend(native_candidates)
            known_numbers = known_patent_publication_numbers(row, publication_number)
            emitted_numbers: set[str] = set()
            for value in collect_json_strings_for_keys(data, ("publicationnumber", "publication_number")):
                discovered_number = normalize_publication_number(value)
                if (
                    not discovered_number
                    or discovered_number in known_numbers
                    or discovered_number in emitted_numbers
                ):
                    continue
                emitted_numbers.add(discovered_number)
                google_candidates = structure_download_candidates(
                    google_patents_pdf_candidates(discovered_number),
                    planned_channel=channel,
                    access_mode=access_mode,
                    policy=policy,
                    discovery_source="The Lens (lens.org)",
                    discovery_adapter="parse_patent_lens.api_identifier",
                    resolver_channel="Google Patents",
                    candidate_origin="identifier_derived",
                )
                candidates.extend(google_candidates)
        except Exception as exc:
            logger.debug(
                "Lens patent API discovery failed for %s: %s",
                sanitize_text_for_output(publication_number),
                sanitize_text_for_output(exc),
            )
    for locator in patent_channel_owned_locators(row, channel, url):
        metadata_candidates = discover_from_page_or_direct_pdf(
            locator["url"], config, logger, channel, access_mode, policy, paths
        )
        candidates.extend(
            make_download_candidate(
                item,
                planned_channel=channel,
                access_mode=access_mode,
                policy=policy,
                locator=locator,
                discovery_source=str(locator.get("source") or channel),
                discovery_adapter="parse_patent_lens.canonical_locator",
                resolver_channel=(
                    "Google Patents" if google_patents_network_url(item) else channel
                ),
                evidence_type=str(locator.get("kind") or "locator"),
                candidate_origin=(
                    "metadata_locator"
                    if locator.get("_legacy") == "true"
                    else "canonical_locator"
                ),
                parent_locator_id=locator_id_for_entry(locator),
            )
            for item in metadata_candidates
        )
    return dedupe_urls(candidates)


def parse_patent_metadata_origin(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[DownloadCandidate]:
    candidates: list[DownloadCandidate] = []
    for locator in patent_channel_owned_locators(row, channel, url):
        metadata_candidates = discover_from_page_or_direct_pdf(
            locator["url"],
            config,
            logger,
            channel,
            access_mode,
            policy,
            paths,
        )
        candidates.extend(
            make_download_candidate(
                item,
                planned_channel=channel,
                access_mode=access_mode,
                policy=policy,
                locator=locator,
                discovery_source=str(locator.get("source") or channel),
                discovery_adapter="parse_patent_metadata_origin",
                resolver_channel=(
                    "Google Patents" if google_patents_network_url(item) else channel
                ),
                evidence_type=str(locator.get("kind") or "locator"),
                candidate_origin=(
                    "metadata_locator"
                    if locator.get("_legacy") == "true"
                    else "canonical_locator"
                ),
                parent_locator_id=locator_id_for_entry(locator),
            )
            for item in metadata_candidates
        )
    return dedupe_urls(candidates)


def parse_patent_api_google_fallback(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[DownloadCandidate]:
    """Deprecated compatibility alias; no unconditional Google fallback."""

    return parse_patent_metadata_origin(
        channel, template, row, title, url, publication_number,
        config, logger, access_mode, policy, paths,
    )


def parse_patent_template_or_search(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    candidates: list[str] = []
    if row_source_matches_channel(row, channel):
        candidates.extend(discover_from_page_or_direct_pdf(url, config, logger, channel, access_mode, policy, paths))
    if not required_template_fields(template) and not row_source_matches_channel(row, channel) and not policy_allows_public_browser_search(policy, channel):
        return dedupe_urls(candidates)
    values = template_values(row, url=url, title=title, publication_number=publication_number)
    template_url = format_download_template(template, values)
    if template_url_is_discoverable(template, template_url):
        candidates.extend(discover_from_page_or_direct_pdf(template_url, config, logger, channel, access_mode, policy, paths))
    if access_mode == "open" and not policy_allows_public_browser_search(policy, channel):
        return dedupe_urls(candidates)

    search_base = str(policy.get("web_search_url") or "")
    if not search_base and template.startswith(("http://", "https://")) and "api." not in urllib.parse.urlsplit(template).netloc.casefold():
        search_base = template
    search_query = publication_number or title
    search_url = build_channel_search_url(search_base, policy, search_query)
    if search_url:
        candidates.extend(discover_from_page_or_direct_pdf(search_url, config, logger, channel, access_mode, policy, paths))
    return dedupe_urls(candidates)


def structured_literature_parser(
    parser: LiteratureChannelParser,
) -> LiteratureChannelParser:
    """Make the production parser boundary return only DownloadCandidate."""

    @wraps(parser)
    def wrapped(
        channel: str,
        template: str,
        row: dict[str, Any],
        title: str,
        doi: str,
        url: str,
        config: DownloadConfig,
        logger: logging.Logger,
        access_mode: str,
        policy: dict[str, Any],
        paths: dict[str, Path],
    ) -> list[DownloadCandidate]:
        return structure_download_candidates(
            parser(
                channel,
                template,
                row,
                title,
                doi,
                url,
                config,
                logger,
                access_mode,
                policy,
                paths,
            ),
            planned_channel=channel,
            access_mode=access_mode,
            policy=policy,
            discovery_source=channel,
            discovery_adapter=parser.__name__,
            resolver_channel="",
            candidate_origin="browser_discovery",
        )

    setattr(wrapped, "_laps_structured_candidate_parser", True)
    return wrapped


def structured_patent_parser(
    parser: PatentChannelParser,
) -> PatentChannelParser:
    """Make the production patent parser boundary return only DownloadCandidate."""

    @wraps(parser)
    def wrapped(
        channel: str,
        template: str,
        row: dict[str, Any],
        title: str,
        url: str,
        publication_number: str,
        config: DownloadConfig,
        logger: logging.Logger,
        access_mode: str,
        policy: dict[str, Any],
        paths: dict[str, Path],
    ) -> list[DownloadCandidate]:
        return structure_download_candidates(
            parser(
                channel,
                template,
                row,
                title,
                url,
                publication_number,
                config,
                logger,
                access_mode,
                policy,
                paths,
            ),
            planned_channel=channel,
            access_mode=access_mode,
            policy=policy,
            discovery_source=channel,
            discovery_adapter=parser.__name__,
            resolver_channel=("Google Patents" if channel == "Google Patents" else ""),
            candidate_origin=(
                "identifier_derived"
                if channel == "Google Patents"
                else "browser_discovery"
            ),
        )

    setattr(wrapped, "_laps_structured_candidate_parser", True)
    return wrapped


LITERATURE_CHANNEL_PARSERS: dict[str, LiteratureChannelParser] = {
    "Sci-Hub": parse_literature_scihub,
    "doi_resolver": parse_literature_doi_resolver,
    "OpenAlex API": parse_literature_api_pdf,
    "Crossref API": parse_literature_api_pdf,
    "Semantic Scholar API": parse_literature_api_pdf,
    "Europe PMC": parse_literature_api_pdf,
    "PMC (PubMed Central)": parse_literature_api_pdf,
    "arXiv API": parse_literature_api_pdf,
    "Web of Science Starter API (Clarivate)": parse_literature_api_pdf,
    "IEEE Xplore API": parse_literature_api_pdf,
    "Google Scholar": parse_literature_template_or_search,
    "The Lens (lens.org)": parse_literature_api_pdf,
    "Elsevier": parse_literature_api_pdf,
    "SpringerLink": parse_literature_api_pdf,
    "Nature": parse_literature_api_pdf,
    "ACS Publications": parse_literature_api_pdf,
    "RSC Publishing": parse_literature_template_or_search,
    "Annual Reviews": parse_literature_api_pdf,
    "bioRxiv / medRxiv": parse_literature_api_pdf,
    "DOAJ (Directory of Open Access Journals)": parse_literature_api_pdf,
    "PubMed": parse_literature_api_pdf,
    "Crossref Metadata Search (search.crossref.org)": parse_literature_api_pdf,
    "DataCite Search (search.datacite.org)": parse_literature_api_pdf,
    "ChemRxiv": parse_literature_api_pdf,
    "Semantic Scholar": parse_literature_api_pdf,
    "OpenReview": parse_literature_api_pdf,
    "IACR ePrint": parse_literature_api_pdf,
    "DBLP": parse_literature_api_pdf,
    "ACM metadata": parse_literature_api_pdf,
    "USENIX": parse_literature_usenix,
    "CORE": parse_literature_api_pdf,
    "OpenAIRE": parse_literature_api_pdf,
    "Springer": parse_literature_api_pdf,
    CNKI_SOURCE: parse_literature_cnki_observed,
    WANFANG_SOURCE: parse_literature_wanfang_observed,
}
PATENT_CHANNEL_PARSERS: dict[str, PatentChannelParser] = {
    "input_url": parse_patent_input_url,
    "Google Patents": parse_patent_google_patents,
    "The Lens (lens.org)": parse_patent_lens,
    "EPO Open Patent Services (OPS) API": parse_patent_metadata_origin,
    "USPTO Open Data Portal": parse_patent_metadata_origin,
    "WIPO PATENTSCOPE API": parse_patent_template_or_search,
    "PQAI API (Patent Quality AI)": parse_patent_metadata_origin,
    "Google BigQuery": parse_patent_metadata_origin,
    CNKI_SOURCE: parse_patent_cnki_observed,
    WANFANG_SOURCE: parse_patent_wanfang_observed,
    UYANIP_SOURCE: parse_patent_uyanip_observed,
}

# Compatibility conversion is confined to parser registration.  Every parser
# callable exposed to production planning now has a structured return contract;
# downstream execution may therefore reject accidental bare-string adapters.
LITERATURE_CHANNEL_PARSERS = {
    channel: structured_literature_parser(parser)
    for channel, parser in LITERATURE_CHANNEL_PARSERS.items()
}
PATENT_CHANNEL_PARSERS = {
    channel: structured_patent_parser(parser)
    for channel, parser in PATENT_CHANNEL_PARSERS.items()
}


def validate_channel_parser_coverage() -> None:
    missing_literature = [channel for channel in literature_download_path_map if channel not in LITERATURE_CHANNEL_PARSERS]
    missing_patents = [channel for channel in patents_download_path_map if channel not in PATENT_CHANNEL_PARSERS]
    if not missing_literature and not missing_patents:
        return
    parts = []
    if missing_literature:
        parts.append(f"literature={', '.join(missing_literature)}")
    if missing_patents:
        parts.append(f"patents={', '.join(missing_patents)}")
    raise RuntimeError(f"Missing channel parser(s): {'; '.join(parts)}")


def literature_channel_candidates(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[DownloadCandidate]:
    parser = LITERATURE_CHANNEL_PARSERS.get(channel, parse_literature_template_or_search)
    if not bool(getattr(parser, "_laps_structured_candidate_parser", False)):
        parser = structured_literature_parser(parser)
    candidates = parser(
        channel, template, row, title, doi, url, config, logger,
        access_mode, policy, paths,
    )
    if any(not isinstance(candidate, DownloadCandidate) for candidate in candidates):
        raise TypeError("production_parser_returned_unstructured_candidate")
    return candidates


def patent_channel_candidates(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[DownloadCandidate]:
    parser = PATENT_CHANNEL_PARSERS.get(channel, parse_patent_template_or_search)
    if not bool(getattr(parser, "_laps_structured_candidate_parser", False)):
        parser = structured_patent_parser(parser)
    candidates = parser(
        channel, template, row, title, url, publication_number, config, logger,
        access_mode, policy, paths,
    )
    if any(not isinstance(candidate, DownloadCandidate) for candidate in candidates):
        raise TypeError("production_parser_returned_unstructured_candidate")
    return candidates


def missing_required_key_reason(policy: dict[str, Any]) -> str:
    required = policy_required_keys(policy)
    missing = [key for key in required if not env_value(key)]
    return f"missing_api_key_or_required_parameter: {'/'.join(missing)}" if missing else ""


def missing_api_substep_reason(policy: Mapping[str, Any]) -> str:
    missing = [key for key in policy_required_keys(dict(policy)) if not env_value(key)]
    if not missing:
        return ""
    code = (
        "missing_api_key"
        if any("API_KEY" in key.upper() or key.upper().endswith("TOKEN") for key in missing)
        else "missing_required_parameter"
    )
    return f"{code}: {'/'.join(missing)}"


def channel_has_web_script(channel: str, policy: dict[str, Any]) -> bool:
    login_profile = channel_login_profile(channel, policy)
    return bool(login_profile.entry_url or policy.get("web_search_url"))


def should_try_open_web_discovery(channel: str, policy: dict[str, Any], missing_reason: str) -> bool:
    if missing_reason and not bool(policy.get("public_browser_allowed") or policy.get("browser_default_enabled")):
        return False
    if policy.get("public_browser_allowed") is False:
        return False
    if bool(policy.get("browser_requires_restricted_access")) and channel not in {
        CNKI_SOURCE,
        WANFANG_SOURCE,
        UYANIP_SOURCE,
    }:
        return False
    if policy and not bool(policy.get("public_browser_allowed") or policy.get("browser_default_enabled") or policy.get("web_search_url")):
        return False
    return True


def should_try_authenticated_web(channel: str, policy: dict[str, Any], config: DownloadConfig) -> bool:
    return should_try_authenticated_web_with_state(channel, policy, config, None)


def should_try_authenticated_web_with_state(
    channel: str,
    policy: dict[str, Any],
    config: DownloadConfig,
    paths: dict[str, Path] | None,
) -> bool:
    state_available = False
    if paths is not None and (
        source_auth_state_scope(channel, policy) or "download_auth_state" in paths
    ):
        selected_state_path = channel_auth_state_path(config, channel, policy, paths)
        state_available = (
            uyanip_saved_state_is_current(config, selected_state_path)
            if channel == UYANIP_SOURCE
            else auth_state_is_fresh(selected_state_path)
        )
    if not (auth_enabled_for_channel(config, channel, policy) or state_available) or not channel_has_web_script(channel, policy):
        return False
    if not bool(policy.get("requires_auth")):
        return False
    if channel == UYANIP_SOURCE:
        return bool(policy.get("personal_web_allowed") or policy.get("browser_requires_restricted_access"))
    if config.path == "institution":
        return bool(policy.get("institutional_web_allowed") or policy.get("browser_requires_restricted_access"))
    if config.path == "personal":
        return bool(policy.get("personal_web_allowed") or policy.get("browser_requires_restricted_access"))
    return False


def doi_matches_authenticated_channel(doi: str, channel: str) -> bool:
    lowered = channel.casefold()
    doi = doi.casefold()
    prefix_map = (
        ("10.1016/", ("sciencedirect", "elsevier")),
        ("10.1007/", ("springer",)),
        ("10.1038/", ("nature", "springer")),
        ("10.1021/", ("acs publications",)),
        ("10.1039/", ("rsc publishing",)),
        ("10.1145/", ("acm",)),
        ("10.1109/", ("ieee",)),
        ("10.1146/", ("annual reviews",)),
    )
    return any(doi.startswith(prefix) and any(token in lowered for token in tokens) for prefix, tokens in prefix_map)


def authenticated_web_relevant(channel: str, row: dict[str, Any], doi: str, config: DownloadConfig) -> bool:
    if has_channel_filter(config):
        return True
    return row_source_matches_channel(row, channel) or doi_matches_authenticated_channel(doi, channel)


def explicit_auth_boundary_observed(channel: str, policy: dict[str, Any]) -> bool:
    if channel not in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}:
        return True
    return str(policy.get("last_discovery_blocker") or "") in {
        "manual_auth_required",
        "access_denied",
        "subscription_required",
    }


def auth_check_skip_reason(channel: str, paths: dict[str, Path]) -> str:
    report_path = paths["outputs"] / "auth_check_report.csv"
    if not report_path.exists():
        return ""
    cached = AUTH_CHECK_SKIP_CACHE.get(report_path)
    if cached is None:
        cached = {}
        try:
            with report_path.open("r", encoding="utf-8-sig", newline="") as handle:
                for row in csv.DictReader(handle):
                    status = str(row.get("status") or "").strip().casefold()
                    if status not in {"failure", "skipped"}:
                        continue
                    report_channel = str(row.get("channel") or "")
                    reason = str(row.get("reason") or status)
                    if report_channel:
                        cached[report_channel.casefold()] = f"auth_check_{status}:{reason}"
        except Exception:
            cached = {}
        AUTH_CHECK_SKIP_CACHE[report_path] = cached
    return cached.get(channel.casefold(), "")


def parser_already_handles_literature_web_discovery(channel: str) -> bool:
    parser = LITERATURE_CHANNEL_PARSERS.get(channel)
    return channel in {"Sci-Hub", "doi_resolver", CNKI_SOURCE, WANFANG_SOURCE} or parser is parse_literature_template_or_search


def parser_already_handles_patent_web_discovery(channel: str) -> bool:
    parser = PATENT_CHANNEL_PARSERS.get(channel)
    return channel in {
        "input_url",
        "Google Patents",
        "The Lens (lens.org)",
        CNKI_SOURCE,
        WANFANG_SOURCE,
        UYANIP_SOURCE,
    } or parser is parse_patent_template_or_search


def has_channel_filter(config: DownloadConfig) -> bool:
    return bool(config.channel_filters or config.exact_channel_filters)


def channel_selected(channel: str, config: DownloadConfig) -> bool:
    if channel.casefold() in config.disabled_channels:
        return False
    if not has_channel_filter(config):
        return True
    lowered = channel.casefold()
    if lowered in config.exact_channel_filters:
        return True
    return any(filter_value in lowered for filter_value in config.channel_filters)


def selected_channels(channel_map: OrderedDict[str, str], config: DownloadConfig) -> list[str]:
    return [channel for channel in channel_map if channel_selected(channel, config)]


def validate_channel_filters(config: DownloadConfig) -> None:
    available = [*literature_download_path_map.keys(), *patents_download_path_map.keys()]
    available_keys = {channel.casefold() for channel in available}
    unknown_disabled = [channel for channel in config.disabled_channels if channel not in available_keys]
    if unknown_disabled:
        raise ValueError(
            "Unknown --disable-channel value(s): "
            + ", ".join(unknown_disabled)
            + ". Available channels: "
            + ", ".join(dict.fromkeys(available))
        )
    if not has_channel_filter(config):
        return
    matched = [channel for channel in available if channel_selected(channel, config)]
    if matched:
        return
    raise ValueError(
        "No download channels matched --channel/--exact-channel. Available channels: "
        + ", ".join(dict.fromkeys(available))
    )


def probe_record_type_enabled(record_type: str, args: argparse.Namespace, config: DownloadConfig, logger: logging.Logger) -> bool:
    if record_type == "literature":
        if args.patents_only:
            return False
        channel_map = literature_download_path_map
        explicit_only = bool(args.literature_only)
    else:
        if args.literature_only:
            return False
        channel_map = patents_download_path_map
        explicit_only = bool(args.patents_only)
    if not config.probe_channel_plan or not has_channel_filter(config):
        return True
    matched = selected_channels(channel_map, config)
    if matched:
        return True
    available = ", ".join(channel_map.keys())
    if explicit_only:
        raise ValueError(
            f"No {record_type} channels matched --channel/--exact-channel for --probe-channel-plan. "
            f"Available {record_type} channels: {available}"
        )
    logger.warning(
        "Skipping %s records for --probe-channel-plan because the selected channel filters do not match that record type.",
        record_type,
    )
    return False


def channel_disabled_reason(channel: str) -> str:
    if channel == "CORE":
        if os.getenv("LAPS_DISABLE_CORE", "").strip().casefold() in {"1", "true", "yes", "on"}:
            return "disabled_core_channel"
        allow_anonymous = os.getenv("LAPS_CORE_ALLOW_UNAUTHENTICATED", "").strip().casefold() in {"1", "true", "yes", "on"}
        if not env_value("CORE_API_KEY") and not allow_anonymous:
            return "missing_core_api_key"
    return ""


def literature_web_channel_candidates(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    doi: str,
    url: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    if channel == "doi_resolver":
        doi_url = f"https://doi.org/{urllib.parse.quote(doi, safe='')}" if doi else ""
        return discover_from_page_or_direct_pdf(doi_url, config, logger, channel, access_mode, policy, paths)

    values = template_values(row, doi=doi, url=url, title=title)
    template_url = format_download_template(template, values)
    if template_url_is_discoverable(template, template_url):
        return discover_from_page_or_direct_pdf(template_url, config, logger, channel, access_mode, policy, paths)

    login_profile = channel_login_profile(channel, policy)
    search_base = str(policy.get("web_search_url") or login_profile.entry_url or "")
    if not search_base and template.startswith(("http://", "https://")) and "api." not in urllib.parse.urlsplit(template).netloc.casefold():
        search_base = template
    search_url = build_channel_search_url(search_base, policy, doi or title)
    if search_url:
        return discover_from_page_or_direct_pdf(search_url, config, logger, channel, access_mode, policy, paths)
    return []


def patent_web_channel_candidates(
    channel: str,
    template: str,
    row: dict[str, Any],
    title: str,
    url: str,
    publication_number: str,
    config: DownloadConfig,
    logger: logging.Logger,
    access_mode: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    if channel == "input_url":
        return discover_from_page_or_direct_pdf(url, config, logger, channel, access_mode, policy, paths)
    if channel == "Google Patents" and publication_number:
        patent_url = f"https://patents.google.com/patent/{urllib.parse.quote(publication_number, safe='')}/en"
        return discover_from_page_or_direct_pdf(patent_url, config, logger, channel, access_mode, policy, paths)

    values = template_values(row, url=url, title=title, publication_number=publication_number)
    template_url = format_download_template(template, values)
    if template_url_is_discoverable(template, template_url):
        return discover_from_page_or_direct_pdf(template_url, config, logger, channel, access_mode, policy, paths)

    login_profile = channel_login_profile(channel, policy)
    search_base = str(policy.get("web_search_url") or login_profile.entry_url or "")
    if not search_base and template.startswith(("http://", "https://")) and "api." not in urllib.parse.urlsplit(template).netloc.casefold():
        search_base = template
    search_url = build_channel_search_url(search_base, policy, publication_number or title)
    if search_url:
        return discover_from_page_or_direct_pdf(search_url, config, logger, channel, access_mode, policy, paths)
    return []


def candidate_set(values: list[str]) -> set[str]:
    return {value for value in values if value}


def should_try_browser_cookie_download(channel: str, candidate: str, outcome: DownloadOutcome) -> bool:
    if outcome.reason != "html_instead_of_pdf":
        return False
    parsed = urllib.parse.urlsplit(candidate)
    host = parsed.netloc.casefold()
    if "pmc.ncbi.nlm.nih.gov" in host or "ncbi.nlm.nih.gov" in host and "/pmc/" in parsed.path.casefold():
        return channel in {"PMC (PubMed Central)", "Europe PMC", "PubMed"}
    return False


def download_pdf_from_url_authenticated(
    url: str,
    target_path: Path,
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> DownloadOutcome:
    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        return DownloadOutcome(False, f"playwright_unavailable: {exc}")

    auth_channel = str(policy.get("_auth_channel") or channel)
    with sync_playwright() as playwright:
        browser, context, auth_result = open_authenticated_browser_context(
            playwright,
            config,
            logger,
            auth_channel,
            policy,
            paths,
        )
        if not auth_result.ok or browser is None or context is None:
            return DownloadOutcome(False, auth_result.reason)
        outcome = download_pdf_with_playwright_context(context, url, target_path, channel)
        context.close()
        browser.close()
        if outcome.success:
            return outcome
        if auth_result.state_reused and outcome.reason in {"html_instead_of_pdf", "access_denied", "manual_auth_required"}:
            browser, context, auth_result = open_authenticated_browser_context(
                playwright,
                config,
                logger,
                auth_channel,
                policy,
                paths,
                allow_state_reuse=False,
            )
            if not auth_result.ok or browser is None or context is None:
                return DownloadOutcome(False, auth_result.reason)
            outcome = download_pdf_with_playwright_context(context, url, target_path, channel)
            context.close()
            browser.close()
        return outcome


def ensure_authenticated_session_generation(
    config: DownloadConfig,
    logger: logging.Logger,
    channel: str,
    policy: dict[str, Any],
    paths: dict[str, Path],
) -> tuple[str, str]:
    """Return the attested generation that must bind authenticated candidates.

    Candidate claims happen before PDF delivery.  When discovery produced a
    direct URL without opening a browser, establish (or validate) the session
    here so the execution key never falls back to an unbound ``unknown`` value.
    """

    current = str(policy.get("_auth_state_generation") or "").strip()
    if current and current.casefold() != "unknown":
        return current, "auth_state_generation_already_bound"

    state_path = channel_auth_state_path(config, channel, policy, paths)
    resume_url = str(
        policy.get("_current_record_resume_url")
        or policy.get("web_search_url")
        or policy.get("auth_entry_url")
        or ""
    )
    valid, validation_reason = validate_shared_auth_state_attestation(
        config,
        channel,
        policy,
        state_path,
        resume_url,
    )
    if valid:
        generation = str(policy.get("_auth_state_generation") or "").strip()
        if generation:
            return generation, validation_reason

    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        return "", f"playwright_unavailable:{exc.__class__.__name__}"

    browser = None
    context = None
    try:
        with sync_playwright() as playwright:
            browser, context, auth_result = open_authenticated_browser_context(
                playwright,
                config,
                logger,
                channel,
                policy,
                paths,
            )
            if not auth_result.ok:
                return "", auth_result.reason or validation_reason
            generation = str(
                auth_result.auth_session_generation
                or policy.get("_auth_state_generation")
                or ""
            ).strip()
            if not generation or generation.casefold() == "unknown":
                return "", "auth_state_generation_missing"
            return generation, auth_result.reason or "auth_state_generation_bound"
    except Exception as exc:
        return "", f"auth_state_generation_failed:{exc.__class__.__name__}"
    finally:
        close_browser_resources_safely(context, browser, logger, channel)


def download_pdf_with_external_storage_state(
    url: str,
    target_path: Path,
    config: DownloadConfig,
    channel: str,
    storage_state_path: str,
) -> DownloadOutcome:
    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        return DownloadOutcome(False, f"playwright_unavailable: {exc}")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=config.headless)
            context = browser.new_context(
                accept_downloads=True,
                storage_state=storage_state_path,
                locale="en-US,zh-CN",
                service_workers="block",
            )
            outcome = download_pdf_with_playwright_context(context, url, target_path, channel)
            context.close()
            browser.close()
            return outcome
    except Exception as exc:
        return DownloadOutcome(False, f"external_auth_state_failed:{exc.__class__.__name__}")


def register_candidate_resolver(
    planned_channel: str,
    candidates: Iterable[str | DownloadCandidate],
    resolver_channel: str,
) -> None:
    """Compatibility bridge for legacy helpers that still emit URL strings.

    Production parser boundaries immediately convert these entries to
    ``DownloadCandidate`` objects; the thread-local map is no longer the
    execution contract or the audit authority.
    """

    context = getattr(ATTEMPT_CONTEXT, "value", None)
    if not isinstance(context, dict):
        context = {}
        ATTEMPT_CONTEXT.value = context
    resolver_map = context.setdefault("candidate_resolvers", {})
    if not isinstance(resolver_map, dict):
        resolver_map = {}
        context["candidate_resolvers"] = resolver_map
    metadata_map = context.setdefault("candidate_metadata", {})
    if not isinstance(metadata_map, dict):
        metadata_map = {}
        context["candidate_metadata"] = metadata_map
    for candidate in candidates:
        value = str(candidate or "").strip()
        if value:
            resolver_map.setdefault((planned_channel, value), resolver_channel)
            metadata_map.setdefault(
                (planned_channel, value),
                {"resolver_channel": resolver_channel},
            )


def register_candidate_metadata(
    planned_channel: str,
    candidates: Iterable[str | DownloadCandidate],
    **metadata: str,
) -> None:
    context = getattr(ATTEMPT_CONTEXT, "value", None)
    if not isinstance(context, dict):
        context = {}
        ATTEMPT_CONTEXT.value = context
    metadata_map = context.setdefault("candidate_metadata", {})
    if not isinstance(metadata_map, dict):
        metadata_map = {}
        context["candidate_metadata"] = metadata_map
    for candidate in candidates:
        value = str(candidate or "").strip()
        if not value:
            continue
        current = dict(metadata_map.get((planned_channel, value)) or {})
        for key, item in metadata.items():
            if item and not current.get(key):
                current[key] = item
        metadata_map[(planned_channel, value)] = current


def registered_candidate_metadata(
    planned_channel: str,
    candidate: str | DownloadCandidate,
) -> dict[str, str]:
    if isinstance(candidate, DownloadCandidate):
        return {
            "resolver_channel": candidate.resolver_channel,
            "discovery_source": candidate.discovery_source,
            "discovery_adapter": candidate.discovery_adapter,
            "evidence_type": candidate.evidence_type,
            "candidate_origin": candidate.candidate_origin,
        }
    context = getattr(ATTEMPT_CONTEXT, "value", {}) or {}
    metadata_map = context.get("candidate_metadata") or {}
    if not isinstance(metadata_map, Mapping):
        metadata_map = {}
    value = str(candidate or "")
    metadata = metadata_map.get((planned_channel, value))
    if not metadata and value.endswith("#browser_cookie"):
        metadata = metadata_map.get(
            (planned_channel, value[: -len("#browser_cookie")])
        )
    if isinstance(metadata, Mapping):
        return {str(key): str(item or "") for key, item in metadata.items()}
    resolver = registered_candidate_resolver(planned_channel, value)
    return {"resolver_channel": resolver} if resolver else {}


def registered_candidate_resolver(planned_channel: str, candidate: str) -> str:
    if isinstance(candidate, DownloadCandidate):
        return candidate.resolver_channel
    context = getattr(ATTEMPT_CONTEXT, "value", {}) or {}
    resolver_map = context.get("candidate_resolvers") or {}
    if not isinstance(resolver_map, Mapping):
        return ""
    value = str(candidate or "")
    resolver = resolver_map.get((planned_channel, value))
    if not resolver and value.endswith("#browser_cookie"):
        resolver = resolver_map.get(
            (planned_channel, value[: -len("#browser_cookie")])
        )
    return str(resolver or "")


def candidate_id_for_url(candidate: Any) -> str:
    raw = str(candidate or "")
    return (
        hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]
        if raw
        else ""
    )


def make_attempt(
    record_type: str,
    title: str,
    doi: str,
    url: str,
    channel: str,
    channel_url_or_api: str | DownloadCandidate,
    status: str,
    reason: str,
    elapsed_seconds: float = 0.0,
    http_status: str = "",
    access_mode: str = "open",
    retryable: bool | None = None,
    retry_at: str = "",
    stage: str = "",
    *,
    observation_id: str = "",
    execution_key: str = "",
    deduplicated_to_attempt_id: str = "",
    resume_action: str = "",
    delivery_adapter: str = "",
    delivery_source_url: str = "",
) -> DownloadAttempt:
    context = getattr(ATTEMPT_CONTEXT, "value", {}) or {}
    safe_reason = sanitize_text_for_output(reason)
    reason_code, reason_category, derived_retryable = reason_details(safe_reason, http_status)
    effective_retryable = derived_retryable if retryable is None else bool(retryable)
    effective_retry_at = str(retry_at or "").strip()
    if effective_retryable and not effective_retry_at:
        effective_retry_at = retry_at_from_reason(safe_reason)
    raw_candidate = str(channel_url_or_api or "")
    effective_stage = sanitize_text_for_output(stage) or (
        "candidate" if raw_candidate else "planning"
    )
    candidate_metadata = registered_candidate_metadata(channel, channel_url_or_api)
    structured_candidate = make_download_candidate(
        channel_url_or_api,
        planned_channel=channel,
        access_mode=access_mode,
        discovery_source=str(candidate_metadata.get("discovery_source") or channel),
        discovery_adapter=str(candidate_metadata.get("discovery_adapter") or ""),
        resolver_channel=str(candidate_metadata.get("resolver_channel") or ""),
        evidence_type=str(candidate_metadata.get("evidence_type") or ""),
        candidate_origin=str(candidate_metadata.get("candidate_origin") or "browser_discovery"),
    ) if raw_candidate else None
    candidate_id = candidate_id_for_url(raw_candidate)
    parser_map = PATENT_CHANNEL_PARSERS if record_type == "patent" else LITERATURE_CHANNEL_PARSERS
    parser = parser_map.get(channel)
    executed_adapter = getattr(parser, "__name__", "") if parser else (
        "metadata_pdf_url" if channel == "input_pdf_url" else channel
    )
    if channel == "input_landing_url":
        executed_adapter = "metadata_landing_url"
    resolver_channel = (
        structured_candidate.resolver_channel if structured_candidate is not None else ""
    ) or registered_candidate_resolver(channel, raw_candidate)
    candidate_host = (urllib.parse.urlsplit(raw_candidate).hostname or "").casefold()
    if not resolver_channel and channel in {"input_landing_url", "input_pdf_url"}:
        resolver_channel = "metadata_locator"
    elif not resolver_channel and record_type == "patent" and (
        candidate_host == "patents.google.com"
        or candidate_host.endswith(".patents.google.com")
        or candidate_host == "patentimages.storage.googleapis.com"
    ):
        resolver_channel = "Google Patents"
    execution_context = context.get("candidate_execution") or {}
    execution_evidence: Mapping[str, Any] = {}
    if isinstance(execution_context, Mapping):
        execution_evidence = execution_context.get(
            (raw_candidate, effective_stage, access_mode), {}
        ) or execution_context.get((raw_candidate, "candidate", access_mode), {}) or {}
        if not execution_evidence and structured_candidate is not None:
            execution_evidence = execution_context.get(
                (raw_candidate, effective_stage, structured_candidate.access_mode), {}
            ) or execution_context.get(
                (raw_candidate, "candidate", structured_candidate.access_mode), {}
            ) or {}
    selected_observation_id = observation_id or str(execution_evidence.get("observation_id") or "")
    selected_execution_key = execution_key or str(execution_evidence.get("execution_key") or "")
    selected_deduplicated_attempt = deduplicated_to_attempt_id or str(
        execution_evidence.get("deduplicated_to_attempt_id") or ""
    )
    selected_resume_action = resume_action or str(execution_evidence.get("resume_action") or "")
    candidate_auth_scope = (
        structured_candidate.auth_scope if structured_candidate is not None else "public"
    )
    candidate_generation = (
        structured_candidate.auth_session_generation
        if structured_candidate is not None
        else "public"
    )
    if access_mode != "authenticated":
        candidate_auth_scope = "public"
        candidate_generation = "public"
    if not selected_execution_key and raw_candidate and effective_stage in {
        "candidate", "challenge_retry", "browser_cookie_retry"
    }:
        selected_execution_key = candidate_execution_key(
            str(context.get("record_id") or ""),
            effective_stage,
            structured_candidate or raw_candidate,
            access_mode,
            candidate_auth_scope,
            candidate_generation,
        )
    selected_delivery_adapter = delivery_adapter
    if not selected_delivery_adapter and raw_candidate:
        if captured_browser_download_path(raw_candidate) is not None or captured_browser_download_failure_reason(raw_candidate):
            selected_delivery_adapter = "browser_capture"
        elif effective_stage == "browser_cookie_retry":
            selected_delivery_adapter = "browser_cookie"
        elif access_mode == "authenticated":
            selected_delivery_adapter = "authenticated_browser"
        else:
            selected_delivery_adapter = "http_stream"
    try:
        delivery_source = (
            urllib.parse.urlsplit(delivery_source_url or raw_candidate).hostname or ""
        ).casefold()
    except ValueError:
        delivery_source = ""
    attempt = DownloadAttempt(
        run_id=str(context.get("run_id") or CURRENT_RUN_ID),
        invocation_id=str(context.get("invocation_id") or CURRENT_INVOCATION_ID),
        record_id=str(context.get("record_id") or ""),
        record_type=record_type,
        title=title,
        doi=doi,
        publication_number=str(context.get("publication_number") or ""),
        metadata_sources="; ".join(context.get("metadata_sources") or []),
        url=sanitize_output_value("url", url),
        planned_channel=channel,
        channel=channel,
        executed_adapter=executed_adapter,
        resolver_channel=resolver_channel,
        observation_id=selected_observation_id,
        execution_key=selected_execution_key,
        locator_id=(structured_candidate.locator_id if structured_candidate is not None else ""),
        locator_source=(structured_candidate.locator_source if structured_candidate is not None else ""),
        discovery_source=(structured_candidate.discovery_source if structured_candidate is not None else ""),
        discovery_adapter=(structured_candidate.discovery_adapter if structured_candidate is not None else ""),
        delivery_adapter=selected_delivery_adapter,
        delivery_source=delivery_source,
        candidate_origin=(structured_candidate.candidate_origin if structured_candidate is not None else ""),
        auth_scope=candidate_auth_scope,
        session_generation=candidate_generation,
        deduplicated_to_attempt_id=selected_deduplicated_attempt,
        resume_action=selected_resume_action,
        candidate_id=candidate_id,
        attempt_id=uuid.uuid4().hex,
        stage=effective_stage,
        channel_url_or_api=sanitize_output_value("channel_url_or_api", channel_url_or_api),
        attempt_status=status,
        reason=safe_reason,
        reason_code=reason_code,
        reason_category=reason_category,
        retryable=effective_retryable,
        retry_at=sanitize_text_for_output(effective_retry_at),
        http_status=http_status,
        elapsed_seconds=round(elapsed_seconds, 3),
        access_mode=access_mode,
        created_at=utc_now(),
    )
    if ACTIVE_DOWNLOAD_LEDGER is not None:
        ACTIVE_DOWNLOAD_LEDGER.append_attempt(attempt)
    return attempt


def channel_has_required_credentials(policy: dict[str, Any]) -> bool:
    required = policy_required_keys(policy)
    return all(env_value(key) for key in required)


def skipped_download_channel_reason(channel: str) -> str:
    return KNOWN_SKIPPED_DOWNLOAD_CHANNELS.get(channel, "")


def should_skip_channel_for_policy(channel: str, policy_map: dict[str, dict[str, Any]], config: DownloadConfig) -> tuple[bool, str, str]:
    skipped_reason = skipped_download_channel_reason(channel)
    if skipped_reason:
        return True, skipped_reason, "skipped"
    policy = policy_map.get(channel, {})
    api_kind = str(policy.get("api_kind") or policy.get("kind") or "")
    required = policy_required_keys(policy)
    if required and not channel_has_required_credentials(policy):
        missing = "/".join(key for key in required if not env_value(key))
        if bool(policy.get("requires_auth")):
            if not auth_enabled_for_channel(config, channel, policy):
                return True, "skipped_auth_required", "authenticated"
            return False, "authenticated_route_available", "authenticated"
        return True, f"missing_api_key_or_required_parameter: {missing}", "open"
    if bool(policy.get("requires_auth")) and api_kind == "none":
        if not auth_enabled_for_channel(config, channel, policy) and not bool(policy.get("public_browser_allowed")):
            return True, "skipped_auth_required", "authenticated"
        return False, "authenticated_route_available", "authenticated"
    return False, "", "open"


def probe_channel_plan_attempts(
    record_type: str,
    title: str,
    doi: str,
    url: str,
    channel_map: OrderedDict[str, str],
    policy_map: dict[str, dict[str, Any]],
    config: DownloadConfig,
) -> list[DownloadAttempt]:
    attempts: list[DownloadAttempt] = []
    for channel, template in channel_map.items():
        if not channel_selected(channel, config):
            continue
        reason = channel_disabled_reason(channel) if record_type == "literature" else ""
        if not reason:
            reason = skipped_download_channel_reason(channel)
        if not reason:
            reason = missing_required_key_reason(policy_map.get(channel, {}))
        if not reason:
            reason = "dry_run_channel_probe"
        attempts.append(make_attempt(record_type, title, doi, url, channel, template, "skipped", reason, access_mode="probe"))
    return attempts


def finish_probe_result(result: DownloadResult, attempts: list[DownloadAttempt]) -> DownloadResult:
    result.status = "dry_run"
    result.failure_reason = last_failure_reason(attempts)
    result.last_error = result.failure_reason
    result.attempt_count = len(attempts)
    result.attempted_channels = [attempt.channel for attempt in attempts]
    return result


def consume_captured_browser_download(candidate: str, target_path: Path) -> DownloadOutcome:
    captured_failure = captured_browser_download_failure_reason(candidate)
    if captured_failure:
        return DownloadOutcome(False, captured_failure)
    source_path = captured_browser_download_path(candidate)
    if source_path is None or not source_path.is_file():
        return DownloadOutcome(False, "captured_browser_download_missing")
    started = time.monotonic()
    try:
        source_size = source_path.stat().st_size
        if source_size > max_pdf_bytes():
            return DownloadOutcome(
                False,
                "response_too_large",
                elapsed_seconds=time.monotonic() - started,
            )
        validation = pdf_validation_details(source_path)
        if not validation.get("valid"):
            return DownloadOutcome(
                False,
                str(validation.get("reason_code") or "invalid_pdf"),
                elapsed_seconds=time.monotonic() - started,
            )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with target_lock(target_path):
            # The controlled capture is already a unique temporary artifact on
            # the repository volume.  Commit it directly so browser-native
            # downloads are never duplicated through an unbounded copy.
            try:
                atomic_replace_file(source_path, target_path)
            except OSError as exc:
                if exc.errno != errno.EXDEV and getattr(exc, "winerror", None) != 17:
                    raise
                # A user-selected PDF root may reside on another volume.  The
                # cross-volume fallback is explicitly chunk-bounded, fsynced,
                # structurally revalidated and atomically committed from the
                # destination directory.
                descriptor, raw_temporary = tempfile.mkstemp(
                    prefix=f".{target_path.stem}.",
                    suffix=".part",
                    dir=target_path.parent,
                )
                temporary = Path(raw_temporary)
                try:
                    written = 0
                    with source_path.open("rb") as source_handle, os.fdopen(
                        descriptor,
                        "wb",
                    ) as target_handle:
                        descriptor = -1
                        while True:
                            chunk = source_handle.read(1024 * 1024)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > max_pdf_bytes():
                                raise ResponseTooLargeError(
                                    "captured browser download exceeds configured maximum"
                                )
                            target_handle.write(chunk)
                        target_handle.flush()
                        os.fsync(target_handle.fileno())
                    copied_validation = pdf_validation_details(temporary)
                    if not copied_validation.get("valid"):
                        return DownloadOutcome(
                            False,
                            str(
                                copied_validation.get("reason_code")
                                or "invalid_pdf"
                            ),
                            elapsed_seconds=time.monotonic() - started,
                        )
                    atomic_replace_file(temporary, target_path)
                finally:
                    if descriptor >= 0:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                    temporary.unlink(missing_ok=True)
        return DownloadOutcome(True, "downloaded_browser_event", elapsed_seconds=time.monotonic() - started)
    except ResponseTooLargeError:
        return DownloadOutcome(
            False,
            "response_too_large",
            elapsed_seconds=time.monotonic() - started,
        )
    except OSError as exc:
        return DownloadOutcome(False, f"file_error:{exc.__class__.__name__}", elapsed_seconds=time.monotonic() - started)
    finally:
        source_path.unlink(missing_ok=True)


def reuse_valid_artifact(source_path: Path, target_path: Path) -> bool:
    """Validate and atomically project an existing artifact to a new target."""

    try:
        source = source_path.resolve(strict=True)
        target = target_path.resolve(strict=False)
        if not source.is_file() or not is_valid_pdf(source):
            return False
        if source == target:
            return True
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{target.stem}.",
            suffix=".part",
            dir=target.parent,
        )
        temporary = Path(raw_temporary)
        try:
            with source.open("rb") as source_handle, os.fdopen(descriptor, "wb") as target_handle:
                descriptor = -1
                shutil.copyfileobj(source_handle, target_handle, length=1024 * 1024)
                target_handle.flush()
                os.fsync(target_handle.fileno())
            if not is_valid_pdf(temporary):
                return False
            with target_lock(target):
                atomic_replace_file(temporary, target)
            return True
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            temporary.unlink(missing_ok=True)
    except (OSError, ValueError):
        return False


def cleanup_unconsumed_captured_candidates(candidates: list[str]) -> None:
    for candidate in candidates:
        source_path = captured_browser_download_path(candidate)
        if source_path is not None:
            source_path.unlink(missing_ok=True)


def register_candidate_execution_context(
    candidate: str | DownloadCandidate,
    stage: str,
    access_mode: str,
    evidence: Mapping[str, Any],
) -> None:
    context = getattr(ATTEMPT_CONTEXT, "value", None)
    if not isinstance(context, dict):
        context = {}
        ATTEMPT_CONTEXT.value = context
    execution_map = context.setdefault("candidate_execution", {})
    if not isinstance(execution_map, dict):
        execution_map = {}
        context["candidate_execution"] = execution_map
    execution_map[(str(candidate), stage, access_mode)] = dict(evidence)


def claim_candidate_execution(
    record_type: str,
    channel: str,
    candidate: DownloadCandidate,
    stage: str,
    access_mode: str,
    config: DownloadConfig,
) -> dict[str, str]:
    context = getattr(ATTEMPT_CONTEXT, "value", {}) or {}
    record_id = str(context.get("record_id") or "")
    auth_scope = candidate.auth_scope if access_mode == "authenticated" else "public"
    session_generation = (
        candidate.auth_session_generation
        if access_mode == "authenticated"
        else "public"
    )
    evidence: dict[str, str]
    if (
        ACTIVE_DOWNLOAD_LEDGER is None
        or config.dry_run
        or not hasattr(ACTIVE_DOWNLOAD_LEDGER, "claim_candidate")
    ):
        evidence = {
            "action": "execute",
            "observation_id": "",
            "execution_key": candidate_execution_key(
                record_id,
                stage,
                candidate,
                access_mode,
                auth_scope,
                session_generation,
            ),
            "resume_action": "dry_run" if config.dry_run else "unpersisted_claim",
        }
    else:
        evidence = ACTIVE_DOWNLOAD_LEDGER.claim_candidate(
            record_id=record_id,
            record_type=record_type,
            planned_channel=channel,
            candidate=candidate,
            stage=stage,
            access_mode=access_mode,
        )
    register_candidate_execution_context(candidate, stage, access_mode, evidence)
    return evidence


def _try_candidate_urls(
    record_type: str,
    title: str,
    doi: str,
    url: str,
    channel: str,
    candidates: list[str | DownloadCandidate],
    target_path: Path,
    config: DownloadConfig,
    logger: logging.Logger,
    attempts: list[DownloadAttempt],
    access_mode: str = "open",
    policy: dict[str, Any] | None = None,
    paths: dict[str, Path] | None = None,
) -> bool:
    parser_map = PATENT_CHANNEL_PARSERS if record_type == "patent" else LITERATURE_CHANNEL_PARSERS
    parser = parser_map.get(channel)
    if (
        access_mode == "authenticated"
        and candidates
        and policy is not None
        and paths is not None
        and not config.dry_run
    ):
        generation, generation_reason = ensure_authenticated_session_generation(
            config,
            logger,
            channel,
            policy,
            paths,
        )
        if not generation:
            attempts.append(
                make_attempt(
                    record_type,
                    title,
                    doi,
                    url,
                    channel,
                    "",
                    "failed",
                    generation_reason or "auth_state_generation_missing",
                    access_mode="authenticated",
                    stage="auth_session_binding",
                )
            )
            return False
        policy["_auth_state_generation"] = generation
    candidates = structure_download_candidates(
        candidates,
        planned_channel=channel,
        access_mode=access_mode,
        policy=policy,
        discovery_source=channel,
        discovery_adapter=getattr(parser, "__name__", "") if parser else channel,
        resolver_channel=("Google Patents" if channel == "Google Patents" else ""),
        candidate_origin=("identifier_derived" if channel == "Google Patents" else "browser_discovery"),
    )
    if not candidates:
        attempts.append(make_attempt(record_type, title, doi, url, channel, "", "skipped", channel_cooldown_reason(channel) or "no_candidate_url", access_mode=access_mode))
        return False

    def resume_candidate(
        candidate: DownloadCandidate,
        claim: Mapping[str, str],
    ) -> str:
        if ACTIVE_DOWNLOAD_LEDGER is None or config.dry_run:
            return "attempt"
        decision = ACTIVE_DOWNLOAD_LEDGER.candidate_resume_decision(
            str((getattr(ATTEMPT_CONTEXT, "value", {}) or {}).get("record_id") or ""),
            channel,
            candidate_id_for_url(candidate),
            force=config.force,
            run_id=CURRENT_RUN_ID,
            execution_key=str(claim.get("execution_key") or ""),
            access_mode=access_mode,
            auth_scope=(candidate.auth_scope if access_mode == "authenticated" else "public"),
            session_generation=(candidate.auth_session_generation if access_mode == "authenticated" else "public"),
            resume_action=str(claim.get("resume_action") or ""),
        )
        action = str(decision.get("action") or "attempt")
        if action == "reuse_artifact":
            source_path = Path(str(decision.get("path") or ""))
            if reuse_valid_artifact(source_path, target_path):
                register_candidate_resolver(
                    channel,
                    [candidate],
                    "existing_ledger_artifact",
                )
                attempts.append(
                    make_attempt(
                        record_type,
                        title,
                        doi,
                        url,
                        channel,
                        candidate,
                        "success",
                        "existing_valid_ledger_artifact",
                        access_mode="existing",
                    )
                )
                return "success"
            attempts.append(
                make_attempt(
                    record_type,
                    title,
                    doi,
                    url,
                    channel,
                    candidate,
                    "failed",
                    "ledger_artifact_reuse_failed",
                    access_mode="existing",
                )
            )
            return "attempt"
        if action == "skip":
            retry_at = str(decision.get("retry_at") or "")
            attempts.append(
                make_attempt(
                    record_type,
                    title,
                    doi,
                    url,
                    channel,
                    candidate,
                    "skipped",
                    str(decision.get("reason") or "resume_terminal_skip"),
                    access_mode=access_mode,
                    retryable=bool(retry_at),
                    retry_at=retry_at,
                )
            )
            return "skip"
        return "attempt"

    def claim_ready(
        candidate: DownloadCandidate,
        stage: str,
        *,
        delivery_adapter: str = "",
    ) -> dict[str, str] | None:
        claim = claim_candidate_execution(
            record_type,
            channel,
            candidate,
            stage,
            access_mode,
            config,
        )
        if claim.get("action") != "deduplicated":
            return claim
        attempts.append(
            make_attempt(
                record_type,
                title,
                doi,
                url,
                channel,
                candidate,
                "skipped",
                "candidate_already_executed",
                access_mode=access_mode,
                stage=stage,
                observation_id=str(claim.get("observation_id") or ""),
                execution_key=str(claim.get("execution_key") or ""),
                deduplicated_to_attempt_id=str(
                    claim.get("deduplicated_to_attempt_id") or ""
                ),
                resume_action=str(claim.get("resume_action") or "deduplicated"),
                delivery_adapter=delivery_adapter,
            )
        )
        return None

    def try_challenge_hook(reason: str, candidate: DownloadCandidate) -> tuple[bool, bool]:
        attempts.append(
            make_attempt(
                record_type,
                title,
                doi,
                url,
                channel,
                candidate,
                "started",
                "challenge_control_started",
                access_mode=access_mode,
                stage="challenge_control",
            )
        )
        control = security_challenge_control(
            record_type,
            title,
            doi,
            url,
            channel,
            candidate,
            reason,
            config,
            logger,
            access_mode,
            policy,
            str((policy or {}).get("_current_record_resume_url") or url or candidate),
        )
        attempts.append(
            make_attempt(
                record_type,
                title,
                doi,
                url,
                channel,
                candidate,
                "success" if control.action == "retry" else "skipped",
                control.reason or f"challenge_control_{control.action or 'unresolved'}",
                access_mode=access_mode,
                stage="challenge_control",
                resume_action=(
                    "legacy_sync_hook_response" if control.legacy_sync else ""
                ),
            )
        )
        control_cleanup_candidates = dedupe_urls(
            [*control.candidate_urls, control.final_url]
        )
        if control.action == "skip":
            cleanup_unconsumed_captured_candidates(control_cleanup_candidates)
            attempts.append(make_attempt(record_type, title, doi, url, channel, candidate, "skipped", control.reason or "challenge_hook_skip", access_mode=access_mode))
            return False, True
        if control.action == "cooldown":
            cleanup_unconsumed_captured_candidates(control_cleanup_candidates)
            attempts.append(make_attempt(record_type, title, doi, url, channel, candidate, "skipped", control.reason or "challenge_hook_cooldown", access_mode=access_mode))
            mark_domain_cooldown(candidate, "security_challenge_required", logger)
            mark_channel_cooldown(channel, "security_challenge_required", logger)
            return False, True
        if control.action != "retry":
            cleanup_unconsumed_captured_candidates(control_cleanup_candidates)
            return False, False
        external_state = (
            external_storage_state_is_usable(control.storage_state_path)
            if access_mode == "authenticated" and control.storage_state_path
            else ""
        )
        retry_candidates = [
            make_download_candidate(
                item,
                planned_channel=channel,
                access_mode=access_mode,
                policy=policy,
                discovery_source=channel,
                discovery_adapter="security_challenge_control",
                resolver_channel=candidate.resolver_channel,
                evidence_type="challenge_response_candidate",
                candidate_origin=(
                    "captured_download"
                    if captured_browser_download_path(str(item)) is not None
                    else "browser_discovery"
                ),
                parent_locator_id=candidate.locator_id,
                parent_candidate_id=candidate_id_for_url(candidate),
            )
            for item in dedupe_urls(
                [
                *control.candidate_urls,
                *(
                    [control.final_url]
                    if control.final_url
                    and (
                        captured_browser_download_path(control.final_url) is not None
                        or bool(
                            captured_browser_download_failure_reason(
                                control.final_url
                            )
                        )
                        or url_looks_like_pdf(control.final_url)
                    )
                    else []
                ),
            ]
                or [candidate]
            )
        ]
        for retry_candidate in retry_candidates:
            claim = claim_ready(
                retry_candidate,
                "challenge_retry",
                delivery_adapter="challenge_hook",
            )
            if claim is None:
                continue
            if not candidate_allowed_for_channel(channel, retry_candidate):
                attempts.append(
                    make_attempt(
                        record_type,
                        title,
                        doi,
                        url,
                        channel,
                        retry_candidate,
                        "skipped",
                        candidate_rejection_reason(channel, retry_candidate),
                        access_mode=access_mode,
                    )
                )
                continue
            domain_reason = domain_cooldown_reason(retry_candidate)
            if domain_reason:
                attempts.append(make_attempt(record_type, title, doi, url, channel, retry_candidate, "skipped", domain_reason, access_mode=access_mode))
                continue
            resume_action = resume_candidate(
                retry_candidate,
                claim,
            )
            if resume_action == "success":
                cleanup_unconsumed_captured_candidates(retry_candidates)
                return True, True
            if resume_action == "skip":
                continue
            attempts.append(
                make_attempt(
                    record_type,
                    title,
                    doi,
                    url,
                    channel,
                    retry_candidate,
                    "started",
                    "challenge_retry_started",
                    access_mode=access_mode,
                    stage="challenge_retry",
                )
            )
            captured_path = captured_browser_download_path(retry_candidate)
            captured_failure = captured_browser_download_failure_reason(
                retry_candidate
            )
            if captured_path is not None or captured_failure:
                retry_outcome = consume_captured_browser_download(
                    retry_candidate,
                    target_path,
                )
            elif external_state:
                retry_outcome = download_pdf_with_external_storage_state(
                    retry_candidate,
                    target_path,
                    config,
                    channel,
                    external_state,
                )
            elif access_mode == "authenticated" and policy is not None and paths is not None:
                retry_outcome = download_pdf_from_url_authenticated(retry_candidate, target_path, config, logger, channel, policy, paths)
            else:
                retry_outcome = download_pdf_from_url(retry_candidate, target_path, logger, channel)
            attempts.append(
                make_attempt(
                    record_type,
                    title,
                    doi,
                    url,
                    channel,
                    retry_candidate,
                    "success" if retry_outcome.success else "failed",
                    retry_outcome.reason or control.reason or "challenge_hook_retry_failed",
                    retry_outcome.elapsed_seconds,
                    retry_outcome.http_status,
                    access_mode,
                    retryable=retry_outcome.retryable,
                    retry_at=retry_outcome.retry_at,
                    stage="challenge_retry",
                    delivery_source_url=retry_outcome.final_url,
                )
            )
            if retry_outcome.success:
                cleanup_unconsumed_captured_candidates(retry_candidates)
                return True, True
            mark_domain_cooldown(retry_candidate, retry_outcome.reason, logger)
        cleanup_unconsumed_captured_candidates(retry_candidates)
        return False, False

    for candidate in candidates:
        claim = claim_ready(candidate, "candidate")
        if claim is None:
            continue
        recovery_budget = channel_recovery_attempts()
        recovery_try = 0
        while True:
            if not candidate_allowed_for_channel(channel, candidate):
                attempts.append(
                    make_attempt(
                        record_type,
                        title,
                        doi,
                        url,
                        channel,
                        candidate,
                        "skipped",
                        candidate_rejection_reason(channel, candidate),
                        access_mode=access_mode,
                    )
                )
                break
            if candidate.startswith("repository:"):
                attempts.append(make_attempt(record_type, title, doi, url, channel, candidate, "skipped", candidate.split(":", 1)[1], access_mode=access_mode))
                break
            if config.dry_run:
                attempts.append(make_attempt(record_type, title, doi, url, channel, candidate, "skipped", "dry_run", access_mode=access_mode))
                break
            captured_path = captured_browser_download_path(candidate)
            captured_failure = captured_browser_download_failure_reason(candidate)
            if captured_path is not None or captured_failure:
                attempts.append(make_attempt(record_type, title, doi, url, channel, candidate, "started", "candidate_attempt_started", access_mode=access_mode, delivery_adapter="browser_capture"))
                outcome = consume_captured_browser_download(candidate, target_path)
                attempts.append(
                    make_attempt(
                        record_type,
                        title,
                        doi,
                        url,
                        channel,
                        candidate,
                        "success" if outcome.success else "failed",
                        outcome.reason,
                        outcome.elapsed_seconds,
                        outcome.http_status,
                        access_mode,
                        retryable=outcome.retryable,
                        retry_at=outcome.retry_at,
                        delivery_adapter="browser_capture",
                        delivery_source_url=outcome.final_url,
                    )
                )
                if outcome.success:
                    return True
                break
            resume_action = resume_candidate(
                candidate,
                claim,
            )
            if resume_action == "success":
                return True
            if resume_action == "skip":
                break
            domain_reason = domain_cooldown_reason(candidate)
            if domain_reason:
                attempts.append(make_attempt(record_type, title, doi, url, channel, candidate, "skipped", domain_reason, access_mode=access_mode))
                break
            attempts.append(make_attempt(record_type, title, doi, url, channel, candidate, "started", "candidate_attempt_started", access_mode=access_mode))
            if access_mode == "authenticated" and policy is not None and paths is not None:
                outcome = download_pdf_from_url_authenticated(candidate, target_path, config, logger, channel, policy, paths)
            else:
                outcome = download_pdf_from_url(candidate, target_path, logger, channel)
            attempt_reason = repository_attempt_reason(candidate, outcome.reason)
            attempts.append(
                make_attempt(
                    record_type,
                    title,
                    doi,
                    url,
                    channel,
                    candidate,
                    "success" if outcome.success else "failed",
                    attempt_reason,
                    outcome.elapsed_seconds,
                    outcome.http_status,
                    access_mode,
                    retryable=outcome.retryable,
                    retry_at=outcome.retry_at,
                    delivery_source_url=outcome.final_url,
                )
            )
            if outcome.success:
                return True
            new_source_open_auth_boundary = bool(
                access_mode == "open"
                and channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}
                and outcome.reason in {"access_denied", "manual_auth_required", "subscription_required"}
            )
            if new_source_open_auth_boundary and policy is not None:
                policy["last_discovery_blocker"] = outcome.reason
            if should_try_browser_cookie_download(channel, candidate, outcome):
                browser_claim = claim_ready(
                    candidate,
                    "browser_cookie_retry",
                    delivery_adapter="browser_cookie",
                )
                if browser_claim is None:
                    break
                attempts.append(
                    make_attempt(
                        record_type,
                        title,
                        doi,
                        url,
                        channel,
                        candidate,
                        "started",
                        "browser_cookie_retry_started",
                        access_mode=access_mode,
                        stage="browser_cookie_retry",
                    )
                )
                browser_outcome = download_pdf_after_browser_cookie(candidate, target_path, config, logger)
                attempts.append(
                    make_attempt(
                        record_type,
                        title,
                        doi,
                        url,
                        channel,
                        candidate,
                        "success" if browser_outcome.success else "failed",
                        browser_outcome.reason,
                        browser_outcome.elapsed_seconds,
                        browser_outcome.http_status,
                        access_mode,
                        retryable=browser_outcome.retryable,
                        retry_at=browser_outcome.retry_at,
                        stage="browser_cookie_retry",
                        delivery_adapter="browser_cookie",
                        delivery_source_url=browser_outcome.final_url,
                    )
                )
                if browser_outcome.success:
                    return True
                if browser_outcome.reason in CHANNEL_COOLDOWN_REASONS:
                    if browser_outcome.reason in SECURITY_CHALLENGE_HOOK_REASONS:
                        hook_success, hook_handled = try_challenge_hook(browser_outcome.reason, candidate)
                        if hook_success:
                            return True
                        if hook_handled:
                            return False
                    mark_domain_cooldown(candidate, browser_outcome.reason, logger)
                    mark_channel_cooldown(channel, browser_outcome.reason, logger)
                    return False
            if outcome.reason in CHANNEL_COOLDOWN_REASONS:
                if outcome.reason in SECURITY_CHALLENGE_HOOK_REASONS:
                    hook_success, hook_handled = try_challenge_hook(outcome.reason, candidate)
                    if hook_success:
                        return True
                    if hook_handled:
                        return False
                mark_domain_cooldown(candidate, outcome.reason, logger)
                mark_channel_cooldown(channel, outcome.reason, logger)
                return False
            if outcome.reason in DOMAIN_COOLDOWN_REASONS and not new_source_open_auth_boundary:
                mark_domain_cooldown(candidate, outcome.reason, logger)
            if outcome.reason in RECOVERABLE_CHANNEL_BLOCK_REASONS and recovery_try < recovery_budget:
                recovery_try += 1
                delay = channel_recovery_delay(outcome.reason, recovery_try)
                logger.warning(
                    "Channel %s hit %s for %s; cooling down %.1f seconds before retry %s/%s",
                    channel,
                    outcome.reason,
                    sanitize_url_for_output(candidate),
                    delay,
                    recovery_try,
                    recovery_budget,
                )
                time.sleep(delay)
                continue
            break
    return False


def try_candidate_urls(
    record_type: str,
    title: str,
    doi: str,
    url: str,
    channel: str,
    candidates: list[str],
    target_path: Path,
    config: DownloadConfig,
    logger: logging.Logger,
    attempts: list[DownloadAttempt],
    access_mode: str = "open",
    policy: dict[str, Any] | None = None,
    paths: dict[str, Path] | None = None,
) -> bool:
    try:
        return _try_candidate_urls(
            record_type,
            title,
            doi,
            url,
            channel,
            candidates,
            target_path,
            config,
            logger,
            attempts,
            access_mode,
            policy,
            paths,
        )
    finally:
        cleanup_unconsumed_captured_candidates(candidates)


def literature_api_pdf_candidates(channel: str, doi: str, row: dict[str, Any], url: str, logger: logging.Logger) -> list[str]:
    encoded_doi = urllib.parse.quote(doi, safe="")
    candidates: list[str] = add_direct_pdf_patterns(channel, doi, row)
    if channel == "OpenReview":
        candidates.extend(openreview_pdf_candidates(row, url))
    try:
        if channel == "OpenAlex API":
            if not doi:
                return []
            url = f"https://api.openalex.org/works/doi:{encoded_doi}"
            params = {}
            if env_value("OPENALEX_API_KEY"):
                params["api_key"] = env_value("OPENALEX_API_KEY")
            if contact_email():
                params["mailto"] = contact_email()
            if params:
                url += "?" + urllib.parse.urlencode(params)
            data = fetch_json(url)
            for location in [data.get("primary_location") or {}, data.get("best_oa_location") or {}, *(data.get("locations") or [])]:
                if not isinstance(location, dict):
                    continue
                pdf_value = location.get("pdf_url")
                if isinstance(pdf_value, str) and pdf_value:
                    candidates.append(pdf_value)
                landing_value = location.get("landing_page_url")
                if isinstance(landing_value, str) and url_looks_like_pdf(landing_value):
                    candidates.append(landing_value)
            oa_url = (data.get("open_access") or {}).get("oa_url")
            if isinstance(oa_url, str) and url_looks_like_pdf(oa_url):
                candidates.append(oa_url)
            candidates.extend(collect_json_urls(data, pdf_only=True))
        elif channel == "Crossref API":
            if not doi:
                return []
            data = fetch_json(f"https://api.crossref.org/works/{encoded_doi}")
            message = data.get("message") or {}
            for link in message.get("link") or []:
                if not isinstance(link, dict):
                    continue
                value = str(link.get("URL") or "")
                content_type = str(link.get("content-type") or "")
                if value and ("pdf" in content_type.casefold() or value.casefold().endswith(".pdf")):
                    candidates.append(value)
            resource = (message.get("resource") or {}).get("primary", {}).get("URL")
            if isinstance(resource, str) and url_looks_like_pdf(resource):
                candidates.append(resource)
            candidates.extend(collect_json_urls(message, pdf_only=True))
        elif channel == "Semantic Scholar API":
            if not doi:
                return []
            fields = "openAccessPdf,url,externalIds"
            key = env_value("SEMANTIC_SCHOLAR_API_KEY")
            headers = {"x-api-key": key} if key else None
            data = fetch_json(f"https://api.semanticscholar.org/graph/v1/paper/DOI:{encoded_doi}?fields={fields}", headers=headers)
            pdf_url = (data.get("openAccessPdf") or {}).get("url")
            if isinstance(pdf_url, str) and pdf_url:
                candidates.append(pdf_url)
            candidates.extend(collect_json_urls(data, pdf_only=True))
        elif channel == "Europe PMC":
            pmcid = extract_pmcid(row)
            if doi:
                query_expression = f'DOI:"{doi}"'
            elif pmcid:
                query_expression = f"EXT_ID:{pmcid}"
            else:
                return []
            query = urllib.parse.urlencode({"query": query_expression, "format": "json", "pageSize": "1", "resultType": "core"})
            data = fetch_json(f"https://www.ebi.ac.uk/europepmc/webservices/rest/search?{query}")
            results = ((data.get("resultList") or {}).get("result") or [])
            for result in results:
                for item in ((result or {}).get("fullTextUrlList") or {}).get("fullTextUrl") or []:
                    value = item.get("url") if isinstance(item, dict) else ""
                    if value:
                        candidates.append(value)
            candidates.extend(collect_json_urls(data, pdf_only=True))
        elif channel == "PMC (PubMed Central)":
            pmcid = extract_pmcid(row)
            if pmcid:
                candidates.append(f"https://www.ncbi.nlm.nih.gov/pmc/articles/{pmcid}/pdf/")
            elif doi:
                query = urllib.parse.urlencode({"query": f'DOI:"{doi}"', "format": "json", "pageSize": "1", "resultType": "core"})
                data = fetch_json(f"https://www.ebi.ac.uk/europepmc/webservices/rest/search?{query}")
                for result in ((data.get("resultList") or {}).get("result") or []):
                    pmcid_value = str((result or {}).get("pmcid") or "")
                    if pmcid_value:
                        candidates.append(f"https://www.ncbi.nlm.nih.gov/pmc/articles/{pmcid_value}/pdf/")
        elif channel == "arXiv API":
            arxiv_id = extract_arxiv_id(row)
            if arxiv_id:
                candidates.append(f"https://arxiv.org/pdf/{arxiv_id}.pdf")
        elif channel == "bioRxiv / medRxiv":
            if doi:
                query = urllib.parse.urlencode({"query": f'DOI:"{doi}" AND SRC:PPR', "format": "json", "pageSize": "1", "resultType": "core"})
                data = fetch_json(f"https://www.ebi.ac.uk/europepmc/webservices/rest/search?{query}")
                europe_pmc_candidates = collect_json_urls(data, pdf_only=True)
                register_candidate_resolver(
                    channel,
                    europe_pmc_candidates,
                    "Europe PMC",
                )
                candidates.extend(europe_pmc_candidates)
        elif channel == "IACR ePrint":
            candidates.extend(add_direct_pdf_patterns(channel, doi, row))
        elif channel == "The Lens (lens.org)":
            api_key = env_value("LENS_Scholarly_API_KEY")
            if not api_key or not doi:
                return candidates
            headers = {"Authorization": f"Bearer {api_key}"}
            payloads = [
                {"query": {"match": {"doi": doi}}, "size": 3},
                {"query": {"match": {"external_ids": doi}}, "size": 3},
            ]
            for payload in payloads:
                try:
                    data = post_json("https://api.lens.org/scholarly/search", payload, headers=headers)
                except Exception:
                    continue
                candidates.extend(collect_json_urls(data, pdf_only=False))
                if candidates:
                    break
        elif channel == "Web of Science Starter API (Clarivate)":
            api_key = env_value("CLARIVATE_API_KEY", "WOS_API_KEY")
            if not api_key or not doi:
                return candidates
            data = fetch_json(
                append_query_params(
                    "https://api.clarivate.com/apis/wos-starter/v1/documents",
                    {"q": f'DO="{doi}"', "limit": "1", "page": "1"},
                ),
                headers={"X-ApiKey": api_key},
            )
            candidates.extend(collect_json_urls(data, pdf_only=True))
        elif channel == "Elsevier":
            api_key = env_value("ELSEVIER_API_KEY")
            if not api_key or not doi:
                return candidates
            headers = {"X-ELS-APIKey": api_key, "Accept": "application/json"}
            if env_value("ELSEVIER_INSTTOKEN"):
                headers["X-ELS-Insttoken"] = env_value("ELSEVIER_INSTTOKEN")
            search_url = "https://api.elsevier.com/content/search/sciencedirect"
            query = f'doi("{doi}")'
            data = fetch_json(append_query_params(search_url, {"query": query, "count": "3"}), headers=headers)
            candidates.extend(collect_json_urls(data, pdf_only=True))
        elif channel in {"SpringerLink", "Springer"}:
            api_key = env_value("SPRINGER_API_KEY")
            if not api_key or not doi:
                return candidates
            endpoint = "https://api.springernature.com/meta/v2/json" if channel == "SpringerLink" else "https://api.springernature.com/metadata/json"
            data = fetch_json(append_query_params(endpoint, {"q": f"doi:{doi}", "p": "3", "api_key": api_key}))
            candidates.extend(collect_json_urls(data, pdf_only=False))
        elif channel == "Nature":
            if doi:
                nature_suffix = doi.split("/", 1)[1] if "/" in doi else ""
                landing_url = str(row.get("url") or "")
                if "nature.com" not in urllib.parse.urlsplit(landing_url).netloc.casefold() and nature_suffix:
                    landing_url = f"https://www.nature.com/articles/{nature_suffix}"
                if landing_url:
                    try:
                        status, content_type, body, final_url = request_url(landing_url, timeout=download_timeout_seconds(), retries=1)
                        if status < 400 and "pdf" not in content_type.casefold():
                            candidates.extend(nature_landing_pdf_candidates_from_html(body.decode("utf-8", errors="replace"), final_url))
                    except Exception as exc:
                        logger.debug(
                            "Nature landing-page PDF discovery failed for %s: %s",
                            sanitize_url_for_output(landing_url),
                            sanitize_text_for_output(exc),
                        )
        elif channel == "IEEE Xplore API":
            api_key = env_value("IEEE_API_KEY")
            if not api_key or not doi:
                return candidates
            data = fetch_json(
                append_query_params(
                    "https://ieeexploreapi.ieee.org/api/v1/search/articles",
                    {"querytext": f'"{doi}"', "max_records": "3", "apikey": api_key, "format": "json"},
                )
            )
            candidates.extend(collect_json_urls(data, pdf_only=True))
        elif channel == "PubMed":
            pmid = extract_pmid(row)
            if doi:
                query_expression = f'DOI:"{doi}"'
            elif pmid:
                query_expression = f"EXT_ID:{pmid} AND SRC:MED"
            else:
                return candidates
            query = urllib.parse.urlencode({"query": query_expression, "format": "json", "pageSize": "1", "resultType": "core"})
            data = fetch_json(f"https://www.ebi.ac.uk/europepmc/webservices/rest/search?{query}")
            for result in ((data.get("resultList") or {}).get("result") or []):
                europe_pmc_candidates: list[str] = []
                for item in ((result or {}).get("fullTextUrlList") or {}).get("fullTextUrl") or []:
                    value = item.get("url") if isinstance(item, dict) else ""
                    if value:
                        europe_pmc_candidates.append(value)
                register_candidate_resolver(
                    channel,
                    europe_pmc_candidates,
                    "Europe PMC",
                )
                candidates.extend(europe_pmc_candidates)
                pmcid_value = extract_pmcid({"pmcid": str((result or {}).get("pmcid") or "")})
                if pmcid_value:
                    pmc_candidate = (
                        f"https://www.ncbi.nlm.nih.gov/pmc/articles/{pmcid_value}/pdf/"
                    )
                    register_candidate_resolver(
                        channel,
                        [pmc_candidate],
                        "PMC (PubMed Central)",
                    )
                    candidates.append(pmc_candidate)
            remaining_europe_pmc_candidates = collect_json_urls(data, pdf_only=True)
            register_candidate_resolver(
                channel,
                remaining_europe_pmc_candidates,
                "Europe PMC",
            )
            candidates.extend(remaining_europe_pmc_candidates)
        elif channel == "DOAJ (Directory of Open Access Journals)":
            if not doi:
                return candidates
            data = fetch_json(f"https://doaj.org/api/v4/search/articles/doi:{encoded_doi}")
            candidates.extend(collect_json_urls(data, pdf_only=False))
        elif channel == "DataCite Search (search.datacite.org)":
            if not doi:
                return candidates
            data = fetch_json(f"https://api.datacite.org/dois/{encoded_doi}")
            datacite_urls = collect_json_urls(data, pdf_only=False)
            repository_candidates: list[str] = []
            repository_reason_candidates: list[str] = []
            repository_started = time.monotonic()
            budget_seconds = repository_candidate_budget_seconds()
            for repository_url in datacite_urls:
                if time.monotonic() - repository_started > budget_seconds:
                    repository_reason_candidates.append("repository:repository_candidate_budget_exceeded")
                    break
                repository_candidates.extend(repository_pdf_candidates_from_url(repository_url, logger))
            limited_repository_candidates, repository_limit_reasons = limit_repository_candidates(repository_candidates)
            if repository_candidates and not limited_repository_candidates:
                repository_reason_candidates.append("repository:repository_no_pdf_file")
            repository_reason_candidates.extend(f"repository:{reason}" for reason in repository_limit_reasons)
            candidates.extend(limited_repository_candidates)
            candidates.extend(repository_reason_candidates)
            candidates.extend(datacite_urls)
        elif channel == "CORE":
            api_key = env_value("CORE_API_KEY")
            allow_anonymous = os.getenv("LAPS_CORE_ALLOW_UNAUTHENTICATED", "").strip().casefold() in {"1", "true", "yes", "on"}
            if not api_key and not allow_anonymous:
                return candidates
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
            query = doi or str(row.get("raw_id") or "")
            if not query:
                return candidates
            data = post_json("https://api.core.ac.uk/v3/search/works", {"q": query, "limit": 3}, headers=headers)
            candidates.extend(collect_json_urls(data, pdf_only=False))
        elif channel == "OpenAIRE":
            api_key = env_value("OPENAIRE_API_KEY")
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
            query = doi or str(row.get("raw_id") or "")
            if not query:
                return candidates
            data = fetch_json(
                append_query_params("https://api.openaire.eu/graph/researchProducts", {"search": query, "page": "0", "size": "3"}),
                headers=headers,
            )
            candidates.extend(collect_json_urls(data, pdf_only=False))
        elif channel in {"ChemRxiv", "Semantic Scholar", "Crossref Metadata Search (search.crossref.org)"}:
            if doi:
                openalex_candidates = literature_api_pdf_candidates(
                    "OpenAlex API",
                    doi,
                    row,
                    url,
                    logger,
                )
                register_candidate_resolver(
                    channel,
                    openalex_candidates,
                    "OpenAlex API",
                )
                candidates.extend(openalex_candidates)
                if channel == "Semantic Scholar":
                    semantic_candidates = literature_api_pdf_candidates(
                        "Semantic Scholar API",
                        doi,
                        row,
                        url,
                        logger,
                    )
                    register_candidate_resolver(
                        channel,
                        semantic_candidates,
                        "Semantic Scholar API",
                    )
                    candidates.extend(semantic_candidates)
                if channel == "Crossref Metadata Search (search.crossref.org)":
                    crossref_candidates = literature_api_pdf_candidates(
                        "Crossref API",
                        doi,
                        row,
                        url,
                        logger,
                    )
                    register_candidate_resolver(
                        channel,
                        crossref_candidates,
                        "Crossref API",
                    )
                    candidates.extend(crossref_candidates)
        elif channel in {"Nature", "ACS Publications", "ACM metadata", "Annual Reviews"}:
            candidates.extend(add_direct_pdf_patterns(channel, doi, row))
        elif channel in {"OpenReview"}:
            candidates.extend(openreview_pdf_candidates(row, url))
        elif channel == "DBLP":
            query = doi or str(row.get("raw_id") or "")
            if query:
                data = fetch_json(append_query_params("https://dblp.org/search/publ/api", {"q": query, "format": "json"}))
                candidates.extend(arxiv_pdf_candidates_from_text(" ".join([doi, url, json.dumps(data, ensure_ascii=False)])))
                candidates.extend(collect_json_urls(data, pdf_only=False))
    except Exception as exc:
        logger.debug(
            "API PDF discovery failed for %s/%s: %s",
            channel,
            sanitize_text_for_output(doi),
            sanitize_text_for_output(exc),
        )
    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique[:20]


def process_literature_record(row: dict[str, str], config: DownloadConfig, paths: dict[str, Path], logger: logging.Logger) -> DownloadResult:
    ensure_literature_download_map_loaded()
    title = get_field(row, LITERATURE_TITLE_ALIASES) or "Untitled literature"
    doi = normalize_doi(get_field(row, LITERATURE_DOI_ALIASES))
    all_locators = row_locator_entries(row)
    direct_locators = [
        locator
        for locator in all_locators
        if locator["kind"] in {"direct_pdf", "pdf"}
    ]
    discovery_locators = [
        locator
        for locator in all_locators
        if locator["kind"] not in {"direct_pdf", "pdf"}
    ]
    legacy_pdf_url = normalize_literature_pdf_url(get_field(row, LITERATURE_URL_ALIASES))
    if legacy_pdf_url and all(item["url"] != legacy_pdf_url for item in direct_locators):
        direct_locators.append(
            {
                "kind": "direct_pdf",
                "url": legacy_pdf_url,
                "source": str(row.get("source") or "unknown"),
                "auth_scope": "unknown",
                "stability": "stable",
                "observed_at": "",
            }
        )
    url = legacy_pdf_url or (
        direct_locators[0]["url"]
        if direct_locators
        else discovery_locators[0]["url"]
        if discovery_locators
        else ""
    )
    record_id = stable_record_id("literature", row)
    available_tokens = available_download_locator_tokens("literature", row)
    applicable_specs = tuple(
        spec
        for spec in get_download_adapters("literature")
        if download_channel_structurally_applicable(
            spec,
            row,
            available_tokens,
        )
    )
    typed_identifiers = row.get("identifiers") or []
    if isinstance(typed_identifiers, str):
        try:
            typed_identifiers = json.loads(typed_identifiers)
        except Exception:
            typed_identifiers = []
    identifier = doi or (
        record_id
        if direct_locators
        or discovery_locators
        or any(isinstance(item, Mapping) and item.get("value") for item in typed_identifiers)
        or applicable_specs
        else ""
    )
    metadata_sources = row_metadata_sources(row)
    ATTEMPT_CONTEXT.value = {
        "run_id": CURRENT_RUN_ID,
        "invocation_id": CURRENT_INVOCATION_ID,
        "record_id": record_id,
        "metadata_sources": metadata_sources,
        "publication_number": "",
        "candidate_resolvers": {},
        "candidate_metadata": {},
        "candidate_execution": {},
    }
    attempts: list[DownloadAttempt] = []
    result = DownloadResult(
        run_id=CURRENT_RUN_ID,
        record_id=record_id,
        record_type="literature",
        title=title,
        doi=doi,
        metadata_sources=metadata_sources,
        url=url,
        original_row=row,
        attempts=attempts,
    )

    if not identifier:
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                url,
                "input_validation",
                "",
                "failed",
                "missing_required_doi_and_pdf_url",
            )
        )
        result.status = "failed"
        result.failure_reason = "missing_required_doi_and_pdf_url"
        result.last_error = "missing_required_doi_and_pdf_url"
        result.attempt_count = len(attempts)
        return result

    target_path = paths["literature_pdf"] / make_safe_pdf_filename("literature", "literature", record_id)
    if config.probe_channel_plan:
        attempts.extend(
            probe_channel_plan_attempts(
                "literature",
                title,
                doi,
                url,
                literature_download_path_map,
                literature_channel_policy_map,
                config,
            )
        )
        return finish_probe_result(result, attempts)

    if target_path.exists() and is_valid_pdf(target_path) and not config.force:
        if CURRENT_RUN_RESUMED and str(row.get("_resume_record_state") or "") == "running":
            attempts.append(
                make_attempt(
                    "literature",
                    title,
                    doi,
                    url,
                    "recovered_target_after_interrupt",
                    str(target_path),
                    "success",
                    "recovered_target_after_interrupt",
                    access_mode="existing",
                    stage="artifact_recovery",
                )
            )
            return successful_result(
                result,
                target_path,
                "recovered_target_after_interrupt",
                attempts,
                "existing",
            )
        result.status = "success"
        result.source_channel = "existing_file"
        result.pdf_path = relpath(target_path)
        result.file_size_bytes = target_path.stat().st_size
        result.sha256 = sha256_file(target_path)
        result.attempt_count = 0
        return result

    alias_record_id = (
        reuse_record_alias_artifact(
            "literature",
            row,
            paths["literature_pdf"],
            target_path,
        )
        if not config.force
        else ""
    )
    if alias_record_id:
        register_candidate_resolver("existing_alias", [alias_record_id], "existing_alias")
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                url,
                "existing_alias",
                alias_record_id,
                "success",
                "existing_valid_alias_artifact",
                access_mode="existing",
            )
        )
        return successful_result(result, target_path, "existing_alias", attempts, "existing")

    if config.dry_run:
        existing_reason = "dry_run_not_downloaded"
        attempts.append(make_attempt("literature", title, doi, url, "dry_run", "", "skipped", existing_reason))
        result.status = "dry_run"
        result.failure_reason = existing_reason
        result.last_error = existing_reason
        result.attempt_count = len(attempts)
        return result

    adapter_specs = {
        spec.display_name: spec for spec in get_download_adapters("literature")
    }
    for channel, template in literature_download_path_map.items():
        if not channel_selected(channel, config):
            continue
        spec = adapter_specs.get(channel)
        if spec is not None and not download_channel_structurally_applicable(
            spec,
            row,
            available_tokens,
        ):
            continue
        source_matches = (
            row_source_matches_download_spec(row, spec)
            if spec is not None
            else row_source_matches_channel(row, channel)
        )
        channel_discovery_urls = [
            locator["url"]
            for locator in discovery_locators
            if (
                locator_entry_owned_by_spec(locator, spec)
                if spec is not None
                else locator["source"].casefold() == channel.casefold()
            )
        ]
        if not channel_discovery_urls and source_matches:
            channel_discovery_urls = [
                locator["url"]
                for locator in discovery_locators
                if locator["source"].casefold() in {"", "unknown"}
            ]
        channel_url = channel_discovery_urls[0] if channel_discovery_urls else ""
        attempt_start = len(attempts)
        disabled_reason = channel_disabled_reason(channel)
        if disabled_reason:
            attempts.append(make_attempt("literature", title, doi, url, channel, template, "skipped", disabled_reason, access_mode="skipped"))
            continue
        skipped_reason = skipped_download_channel_reason(channel)
        if skipped_reason:
            attempts.append(make_attempt("literature", title, doi, url, channel, template, "skipped", skipped_reason, access_mode="skipped"))
            continue
        cooldown_reason = channel_cooldown_reason(channel)
        if cooldown_reason:
            attempts.append(make_attempt("literature", title, doi, url, channel, template, "skipped", cooldown_reason, access_mode="skipped"))
            continue
        policy = dict(literature_channel_policy_map.get(channel, {}))
        policy["_download_record_type"] = "literature"
        missing_reason = missing_required_key_reason(policy)
        open_candidates: list[str] = []
        if missing_reason:
            attempts.append(make_attempt("literature", title, doi, url, channel, template, "skipped", missing_api_substep_reason(policy), access_mode="api_substep", stage="api_substep"))
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                url,
                channel,
                channel_url or template,
                "started",
                "discovery_attempt_started",
                access_mode="open",
                stage="discovery",
            )
        )
        open_candidates = literature_channel_candidates(
            channel,
            template,
            row,
            title,
            doi,
            channel_url,
            config,
            logger,
            "open",
            policy,
            paths,
        )
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                url,
                channel,
                channel_url or template,
                "success" if open_candidates else "skipped",
                "discovery_candidates_found" if open_candidates else "no_candidate_url",
                access_mode="open",
                stage="discovery",
            )
        )
        if try_candidate_urls("literature", title, doi, url, channel, open_candidates, target_path, config, logger, attempts, "open", policy, paths):
            return successful_result(result, target_path, channel, attempts, "open")

        if should_try_open_web_discovery(channel, policy, missing_reason) and not parser_already_handles_literature_web_discovery(channel):
            attempts.append(
                make_attempt(
                    "literature",
                    title,
                    doi,
                    url,
                    channel,
                    channel_url or template,
                    "started",
                    "web_discovery_attempt_started",
                    access_mode="open",
                    stage="web_discovery",
                )
            )
            web_candidates = literature_web_channel_candidates(
                channel,
                template,
                row,
                title,
                doi,
                channel_url,
                config,
                logger,
                "open",
                policy,
                paths,
            )
            attempts.append(
                make_attempt(
                    "literature",
                    title,
                    doi,
                    url,
                    channel,
                    channel_url or template,
                    "success" if web_candidates else "skipped",
                    "web_discovery_candidates_found" if web_candidates else "no_candidate_url",
                    access_mode="open",
                    stage="web_discovery",
                )
            )
            web_candidates = [candidate for candidate in web_candidates if candidate not in candidate_set(open_candidates)]
            if web_candidates and try_candidate_urls("literature", title, doi, url, channel, web_candidates, target_path, config, logger, attempts, "open", policy, paths):
                return successful_result(result, target_path, channel, attempts, "open")

        if (
            should_try_authenticated_web_with_state(channel, policy, config, paths)
            and authenticated_web_relevant(channel, row, doi, config)
            and explicit_auth_boundary_observed(channel, policy)
        ):
            attempts.append(
                make_attempt(
                    "literature",
                    title,
                    doi,
                    url,
                    channel,
                    channel_url or template,
                    "started",
                    "authenticated_discovery_attempt_started",
                    access_mode="authenticated",
                    stage="authenticated_discovery",
                )
            )
            auth_candidates = (
                literature_channel_candidates(
                    channel,
                    template,
                    row,
                    title,
                    doi,
                    channel_url,
                    config,
                    logger,
                    "authenticated",
                    policy,
                    paths,
                )
                if channel in {CNKI_SOURCE, WANFANG_SOURCE}
                else literature_web_channel_candidates(
                    channel,
                    template,
                    row,
                    title,
                    doi,
                    channel_url,
                    config,
                    logger,
                    "authenticated",
                    policy,
                    paths,
                )
            )
            attempts.append(
                make_attempt(
                    "literature",
                    title,
                    doi,
                    url,
                    channel,
                    channel_url or template,
                    "success" if auth_candidates else "skipped",
                    "authenticated_discovery_candidates_found" if auth_candidates else "no_candidate_url",
                    access_mode="authenticated",
                    stage="authenticated_discovery",
                )
            )
            if try_candidate_urls("literature", title, doi, url, channel, auth_candidates, target_path, config, logger, attempts, "authenticated", policy, paths):
                return successful_result(result, target_path, channel, attempts, "authenticated")
        elif bool(policy.get("requires_auth")):
            blocker_reason = str(policy.get("last_discovery_blocker") or "")
            reason = (
                "wanfang_personal_account_required"
                if blocker_reason == "wanfang_personal_account_required"
                else "authenticated_web_not_relevant"
                if auth_enabled_for_channel(config, channel, policy) and channel_has_web_script(channel, policy)
                else "skipped_auth_required"
            )
            attempts.append(make_attempt("literature", title, doi, url, channel, template, "skipped", reason, access_mode="authenticated"))

        if len(attempts) == attempt_start:
            attempts.append(make_attempt("literature", title, doi, url, channel, template, "skipped", "no_candidate_url", access_mode="open"))

    for locator in direct_locators:
        locator_url = locator["url"]
        owner_spec = locator_owner_download_spec("literature", locator)
        if owner_spec is not None and not channel_selected(
            str(owner_spec.display_name),
            config,
        ):
            attempts.append(
                make_attempt(
                    "literature",
                    title,
                    doi,
                    locator_url,
                    "input_pdf_url",
                    locator_url,
                    "skipped",
                    "metadata_locator_owner_channel_disabled",
                    access_mode="skipped",
                )
            )
            continue
        if try_candidate_urls(
            "literature",
            title,
            doi,
            locator_url,
            "input_pdf_url",
            [locator_url],
            target_path,
            config,
            logger,
            attempts,
            "metadata",
            {"locator_source": locator["source"], "auth_state_scope": locator["auth_scope"]},
            paths,
        ):
            return successful_result(result, target_path, "input_pdf_url", attempts, "metadata")

        source_channel = locator["source"]
        scope = locator["auth_scope"].casefold()
        if source_channel not in {CNKI_SOURCE, WANFANG_SOURCE}:
            if scope == "cnki":
                source_channel = CNKI_SOURCE
            elif scope in {"wanfang", "wanfang_data"}:
                source_channel = WANFANG_SOURCE
        if source_channel not in {CNKI_SOURCE, WANFANG_SOURCE}:
            continue
        source_policy = dict(literature_channel_policy_map.get(source_channel, {}))
        source_policy["_download_record_type"] = "literature"
        source_policy["_locator_auth_scope"] = locator["auth_scope"]
        boundary_reason = last_failure_reason(attempts)
        if boundary_reason in {
            "access_denied",
            "html_instead_of_pdf",
            "manual_auth_required",
            "security_challenge_required",
            "subscription_required",
        } and (
            auth_enabled_for_channel(config, source_channel, source_policy)
            or auth_state_is_fresh(
                channel_auth_state_path(config, source_channel, source_policy, paths)
            )
        ):
            if try_candidate_urls(
                "literature",
                title,
                doi,
                locator_url,
                source_channel,
                [locator_url],
                target_path,
                config,
                logger,
                attempts,
                "authenticated",
                source_policy,
                paths,
            ):
                return successful_result(result, target_path, source_channel, attempts, "authenticated")

    # A canonical landing locator is a non-formal metadata handoff, not an
    # additional member of the frozen 35-channel order.  Consume it only after
    # every structurally applicable formal channel (and direct metadata PDF)
    # has failed.  The original locator ownership/auth scope is retained for a
    # single controlled authenticated retry.
    for locator in discovery_locators:
        locator_url = locator["url"]
        owner_spec = locator_owner_download_spec("literature", locator)
        if owner_spec is not None and not channel_selected(
            str(owner_spec.display_name),
            config,
        ):
            attempts.append(
                make_attempt(
                    "literature",
                    title,
                    doi,
                    locator_url,
                    "input_landing_url",
                    locator_url,
                    "skipped",
                    "metadata_locator_owner_channel_disabled",
                    access_mode="skipped",
                )
            )
            continue
        locator_policy: dict[str, Any] = {
            "locator_source": locator["source"],
            "auth_state_scope": locator["auth_scope"],
            "_current_record_resume_url": locator_url,
            "_download_record_type": "literature",
        }
        attempt_start = len(attempts)
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                locator_url,
                "input_landing_url",
                locator_url,
                "started",
                "metadata_discovery_attempt_started",
                access_mode="metadata",
                stage="metadata_discovery",
            )
        )
        landing_candidates = discover_from_page_or_direct_pdf(
            locator_url,
            config,
            logger,
            "input_landing_url",
            "metadata",
            locator_policy,
            paths,
        )
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                locator_url,
                "input_landing_url",
                locator_url,
                "success" if landing_candidates else "skipped",
                "metadata_discovery_candidates_found" if landing_candidates else "no_candidate_url",
                access_mode="metadata",
                stage="metadata_discovery",
            )
        )
        register_candidate_resolver(
            "input_landing_url",
            landing_candidates,
            "metadata_locator",
        )
        if try_candidate_urls(
            "literature",
            title,
            doi,
            locator_url,
            "input_landing_url",
            landing_candidates,
            target_path,
            config,
            logger,
            attempts,
            "metadata",
            locator_policy,
            paths,
        ):
            return successful_result(
                result,
                target_path,
                "input_landing_url",
                attempts,
                "metadata",
            )

        if owner_spec is None:
            continue
        source_channel = str(owner_spec.display_name)
        source_policy = dict(literature_channel_policy_map.get(source_channel, {}))
        source_policy.update(
            {
                "_auth_channel": source_channel,
                "_current_record_resume_url": locator_url,
                "_download_record_type": "literature",
                "_locator_auth_scope": locator["auth_scope"],
            }
        )
        boundary_reason = str(locator_policy.get("last_discovery_blocker") or "")
        if not boundary_reason:
            boundary_reason = next(
                (
                    attempt.reason_code
                    for attempt in reversed(attempts[attempt_start:])
                    if attempt.reason_code
                ),
                "",
            )
        if boundary_reason not in {
            "access_denied",
            "html_instead_of_pdf",
            "manual_auth_required",
            "security_challenge_required",
            "subscription_required",
        }:
            continue
        if not (
            auth_enabled_for_channel(config, source_channel, source_policy)
            or auth_state_is_fresh(
                channel_auth_state_path(
                    config,
                    source_channel,
                    source_policy,
                    paths,
                )
            )
        ):
            continue
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                locator_url,
                "input_landing_url",
                locator_url,
                "started",
                "authenticated_metadata_discovery_attempt_started",
                access_mode="authenticated",
                stage="authenticated_metadata_discovery",
            )
        )
        authenticated_candidates = discover_from_page_or_direct_pdf(
            locator_url,
            config,
            logger,
            source_channel,
            "authenticated",
            source_policy,
            paths,
        )
        attempts.append(
            make_attempt(
                "literature",
                title,
                doi,
                locator_url,
                "input_landing_url",
                locator_url,
                "success" if authenticated_candidates else "skipped",
                "authenticated_metadata_discovery_candidates_found" if authenticated_candidates else "no_candidate_url",
                access_mode="authenticated",
                stage="authenticated_metadata_discovery",
            )
        )
        register_candidate_resolver(
            "input_landing_url",
            authenticated_candidates,
            "metadata_locator",
        )
        if try_candidate_urls(
            "literature",
            title,
            doi,
            locator_url,
            "input_landing_url",
            authenticated_candidates,
            target_path,
            config,
            logger,
            attempts,
            "authenticated",
            source_policy,
            paths,
        ):
            return successful_result(
                result,
                target_path,
                "input_landing_url",
                attempts,
                "authenticated",
            )

    if direct_locators and not doi:
        result.status = "failed"
        result.failure_reason = "metadata_pdf_url_failed_without_doi"
        result.last_error = last_failure_reason(attempts)
        result.attempt_count = len(attempts)
        result.attempted_channels = [attempt.channel for attempt in attempts]
        return result

    result.status = "failed"
    result.failure_reason = last_failure_reason(attempts)
    result.last_error = result.failure_reason
    result.attempt_count = len(attempts)
    result.attempted_channels = [attempt.channel for attempt in attempts]
    return result


def process_patent_record(row: dict[str, str], config: DownloadConfig, paths: dict[str, Path], logger: logging.Logger) -> DownloadResult:
    ensure_patents_download_map_loaded()
    title = get_field(row, PATENT_TITLE_ALIASES) or "Untitled patent"
    url = normalize_url(get_field(row, PATENT_URL_ALIASES))
    publication_number = normalize_publication_number(
        get_field(row, PUBLICATION_NUMBER_ALIASES)
        or typed_identifier_value(row, "publication_number")
    )
    record_id = stable_record_id("patent", row)
    available_tokens = available_download_locator_tokens("patent", row)
    applicable_specs = tuple(
        spec
        for spec in get_download_adapters("patent")
        if download_channel_structurally_applicable(
            spec,
            row,
            available_tokens,
        )
    )
    identifier = publication_number or url or (record_id if applicable_specs else "")
    metadata_sources = row_metadata_sources(row)
    ATTEMPT_CONTEXT.value = {
        "run_id": CURRENT_RUN_ID,
        "invocation_id": CURRENT_INVOCATION_ID,
        "record_id": record_id,
        "metadata_sources": metadata_sources,
        "publication_number": publication_number,
        "candidate_resolvers": {},
        "candidate_metadata": {},
        "candidate_execution": {},
    }
    attempts: list[DownloadAttempt] = []
    result = DownloadResult(
        run_id=CURRENT_RUN_ID,
        record_id=record_id,
        record_type="patent",
        title=title,
        publication_number=publication_number,
        metadata_sources=metadata_sources,
        url=url,
        original_row=row,
        attempts=attempts,
    )

    if not identifier:
        attempts.append(make_attempt("patent", title, "", url, "input_validation", "", "failed", "missing_publication_number_or_url"))
        result.status = "failed"
        result.failure_reason = "missing_publication_number_or_url"
        result.last_error = "missing_publication_number_or_url"
        result.attempt_count = len(attempts)
        return result

    target_path = paths["patents_pdf"] / make_safe_pdf_filename("patent", "patent", record_id)
    if config.probe_channel_plan:
        attempts.extend(
            probe_channel_plan_attempts(
                "patent",
                title,
                "",
                url,
                patents_download_path_map,
                patents_channel_policy_map,
                config,
            )
        )
        return finish_probe_result(result, attempts)

    if target_path.exists() and is_valid_pdf(target_path) and not config.force:
        if CURRENT_RUN_RESUMED and str(row.get("_resume_record_state") or "") == "running":
            attempts.append(
                make_attempt(
                    "patent",
                    title,
                    "",
                    url,
                    "recovered_target_after_interrupt",
                    str(target_path),
                    "success",
                    "recovered_target_after_interrupt",
                    access_mode="existing",
                    stage="artifact_recovery",
                )
            )
            return successful_result(
                result,
                target_path,
                "recovered_target_after_interrupt",
                attempts,
                "existing",
            )
        result.status = "success"
        result.source_channel = "existing_file"
        result.pdf_path = relpath(target_path)
        result.file_size_bytes = target_path.stat().st_size
        result.sha256 = sha256_file(target_path)
        result.attempt_count = 0
        return result

    alias_record_id = (
        reuse_record_alias_artifact(
            "patent",
            row,
            paths["patents_pdf"],
            target_path,
        )
        if not config.force
        else ""
    )
    if alias_record_id:
        register_candidate_resolver("existing_alias", [alias_record_id], "existing_alias")
        attempts.append(
            make_attempt(
                "patent",
                title,
                "",
                url,
                "existing_alias",
                alias_record_id,
                "success",
                "existing_valid_alias_artifact",
                access_mode="existing",
            )
        )
        return successful_result(result, target_path, "existing_alias", attempts, "existing")

    if config.dry_run:
        existing_reason = "dry_run_not_downloaded"
        attempts.append(make_attempt("patent", title, "", url, "dry_run", "", "skipped", existing_reason))
        result.status = "dry_run"
        result.failure_reason = existing_reason
        result.last_error = existing_reason
        result.attempt_count = len(attempts)
        return result

    adapter_specs = {
        spec.display_name: spec for spec in get_download_adapters("patent")
    }
    for channel, template in patents_download_path_map.items():
        if not channel_selected(channel, config):
            continue
        spec = adapter_specs.get(channel)
        if spec is not None and not download_channel_structurally_applicable(
            spec,
            row,
            available_tokens,
        ):
            continue
        attempt_start = len(attempts)
        skipped_reason = skipped_download_channel_reason(channel)
        if skipped_reason:
            attempts.append(make_attempt("patent", title, "", url, channel, template, "skipped", skipped_reason, access_mode="skipped"))
            continue
        cooldown_reason = channel_cooldown_reason(channel)
        if cooldown_reason:
            attempts.append(make_attempt("patent", title, "", url, channel, template, "skipped", cooldown_reason, access_mode="skipped"))
            continue
        policy = dict(patents_channel_policy_map.get(channel, {}))
        policy["_download_record_type"] = "patent"
        missing_reason = missing_required_key_reason(policy)
        open_candidates: list[str] = []
        if missing_reason:
            attempts.append(make_attempt("patent", title, "", url, channel, template, "skipped", missing_api_substep_reason(policy), access_mode="api_substep", stage="api_substep"))
        attempts.append(
            make_attempt(
                "patent",
                title,
                "",
                url,
                channel,
                template,
                "started",
                "discovery_attempt_started",
                access_mode="open",
                stage="discovery",
            )
        )
        open_candidates = patent_channel_candidates(
            channel,
            template,
            row,
            title,
            url,
            publication_number,
            config,
            logger,
            "open",
            policy,
            paths,
        )
        attempts.append(
            make_attempt(
                "patent",
                title,
                "",
                url,
                channel,
                template,
                "success" if open_candidates else "skipped",
                "discovery_candidates_found" if open_candidates else "no_candidate_url",
                access_mode="open",
                stage="discovery",
            )
        )
        if try_candidate_urls("patent", title, "", url, channel, open_candidates, target_path, config, logger, attempts, "open", policy, paths):
            return successful_result(result, target_path, channel, attempts, "open")

        if should_try_open_web_discovery(channel, policy, missing_reason) and not parser_already_handles_patent_web_discovery(channel):
            attempts.append(
                make_attempt(
                    "patent",
                    title,
                    "",
                    url,
                    channel,
                    template,
                    "started",
                    "web_discovery_attempt_started",
                    access_mode="open",
                    stage="web_discovery",
                )
            )
            web_candidates = patent_web_channel_candidates(
                channel,
                template,
                row,
                title,
                url,
                publication_number,
                config,
                logger,
                "open",
                policy,
                paths,
            )
            attempts.append(
                make_attempt(
                    "patent",
                    title,
                    "",
                    url,
                    channel,
                    template,
                    "success" if web_candidates else "skipped",
                    "web_discovery_candidates_found" if web_candidates else "no_candidate_url",
                    access_mode="open",
                    stage="web_discovery",
                )
            )
            web_candidates = [candidate for candidate in web_candidates if candidate not in candidate_set(open_candidates)]
            if web_candidates and try_candidate_urls("patent", title, "", url, channel, web_candidates, target_path, config, logger, attempts, "open", policy, paths):
                return successful_result(result, target_path, channel, attempts, "open")

        if (
            should_try_authenticated_web_with_state(channel, policy, config, paths)
            and authenticated_web_relevant(channel, row, "", config)
            and explicit_auth_boundary_observed(channel, policy)
        ):
            attempts.append(
                make_attempt(
                    "patent",
                    title,
                    "",
                    url,
                    channel,
                    template,
                    "started",
                    "authenticated_discovery_attempt_started",
                    access_mode="authenticated",
                    stage="authenticated_discovery",
                )
            )
            auth_candidates = (
                patent_channel_candidates(
                    channel,
                    template,
                    row,
                    title,
                    url,
                    publication_number,
                    config,
                    logger,
                    "authenticated",
                    policy,
                    paths,
                )
                if channel in {CNKI_SOURCE, WANFANG_SOURCE, UYANIP_SOURCE}
                else patent_web_channel_candidates(
                    channel,
                    template,
                    row,
                    title,
                    url,
                    publication_number,
                    config,
                    logger,
                    "authenticated",
                    policy,
                    paths,
                )
            )
            attempts.append(
                make_attempt(
                    "patent",
                    title,
                    "",
                    url,
                    channel,
                    template,
                    "success" if auth_candidates else "skipped",
                    "authenticated_discovery_candidates_found" if auth_candidates else "no_candidate_url",
                    access_mode="authenticated",
                    stage="authenticated_discovery",
                )
            )
            if try_candidate_urls("patent", title, "", url, channel, auth_candidates, target_path, config, logger, attempts, "authenticated", policy, paths):
                return successful_result(result, target_path, channel, attempts, "authenticated")
        elif bool(policy.get("requires_auth")):
            blocker_reason = str(policy.get("last_discovery_blocker") or "")
            reason = (
                "wanfang_personal_account_required"
                if blocker_reason == "wanfang_personal_account_required"
                else "authenticated_web_not_relevant"
                if auth_enabled_for_channel(config, channel, policy) and channel_has_web_script(channel, policy)
                else "skipped_auth_required"
            )
            attempts.append(make_attempt("patent", title, "", url, channel, template, "skipped", reason, access_mode="authenticated"))

        if len(attempts) == attempt_start:
            attempts.append(make_attempt("patent", title, "", url, channel, template, "skipped", "no_candidate_url", access_mode="open"))

    result.status = "failed"
    result.failure_reason = last_failure_reason(attempts)
    result.last_error = result.failure_reason
    result.attempt_count = len(attempts)
    result.attempted_channels = [attempt.channel for attempt in attempts]
    return result


def successful_result(
    result: DownloadResult,
    target_path: Path,
    channel: str,
    attempts: list[DownloadAttempt],
    access_mode: str = "open",
) -> DownloadResult:
    successful_attempt = next(
        (attempt for attempt in reversed(attempts) if attempt.attempt_status == "success"),
        None,
    )
    result.status = "success"
    result.resolver_channel = successful_attempt.resolver_channel if successful_attempt else ""
    result.successful_planned_channel = (
        successful_attempt.planned_channel or successful_attempt.channel
        if successful_attempt
        else channel
    )
    result.successful_resolver_channel = (
        successful_attempt.resolver_channel if successful_attempt else ""
    )
    result.successful_delivery_source = (
        successful_attempt.delivery_source if successful_attempt else ""
    )
    result.source_channel = result.resolver_channel or channel
    result.pdf_path = relpath(target_path)
    result.file_size_bytes = target_path.stat().st_size
    result.sha256 = sha256_file(target_path)
    result.access_mode = access_mode
    result.attempt_count = len(attempts)
    result.attempted_channels = [attempt.channel for attempt in attempts]
    return result


def last_failure_reason(attempts: list[DownloadAttempt]) -> str:
    for attempt in reversed(attempts):
        if attempt.attempt_status in {"failed", "skipped"} and attempt.reason:
            return attempt.reason
    return "download_failed"


def result_identifier(record_type: str, row: dict[str, str]) -> tuple[str, bool]:
    readiness = str(row.get("retrieval_readiness") or "").strip().casefold()
    record_id = str(row.get("record_id") or "").strip()

    def typed_identifier() -> str:
        raw_identifiers: Any = row.get("identifiers") or []
        if isinstance(raw_identifiers, str):
            try:
                raw_identifiers = json.loads(raw_identifiers)
            except Exception:
                raw_identifiers = []
        if isinstance(raw_identifiers, Mapping):
            raw_identifiers = [
                {"identifier_type": kind, "value": value}
                for kind, value in raw_identifiers.items()
            ]
        for item in raw_identifiers if isinstance(raw_identifiers, list) else []:
            if not isinstance(item, Mapping):
                continue
            kind = str(
                item.get("identifier_type")
                or item.get("type")
                or item.get("kind")
                or "unknown"
            ).strip()
            value = str(item.get("normalized_value") or item.get("value") or "").strip()
            if value:
                return f"{kind}:{value}".casefold()
        return ""

    def observed_locator() -> str:
        entries = row_locator_entries(row)
        return f"locator:{entries[0]['url']}" if entries else ""

    if record_type == "literature":
        doi = normalize_doi(get_field(row, LITERATURE_DOI_ALIASES))
        if doi:
            return doi, True
        pdf_url = normalize_literature_pdf_url(
            get_field(row, LITERATURE_URL_ALIASES)
        )
        if pdf_url:
            return f"pdf_url:{pdf_url}", True
        typed = typed_identifier()
        if typed:
            return typed, True
        locator = observed_locator()
        if locator:
            return locator, True
        if record_id and structurally_applicable_download_specs(
            "literature",
            row,
        ):
            return record_id, True
        if record_id and readiness in {
            "direct_pdf",
            "identifier_resolvable",
            "landing_discoverable",
        }:
            return record_id, True
        return "", False
    url = normalize_url(get_field(row, PATENT_URL_ALIASES))
    pub = normalize_publication_number(
        get_field(row, PUBLICATION_NUMBER_ALIASES)
        or typed_identifier_value(row, "publication_number")
    )
    value = pub or url or typed_identifier() or observed_locator()
    if not value and record_id and structurally_applicable_download_specs(
        "patent",
        row,
    ):
        value = record_id
    if not value and record_id and readiness in {
        "direct_pdf",
        "identifier_resolvable",
        "landing_discoverable",
    }:
        value = record_id
    return value.casefold(), bool(value)


def worker_exception_result(record_type: str, row: dict[str, str], exc: Exception) -> DownloadResult:
    if record_type == "literature":
        title = get_field(row, LITERATURE_TITLE_ALIASES) or "Untitled literature"
        doi = normalize_doi(get_field(row, LITERATURE_DOI_ALIASES))
        url = normalize_url(get_field(row, LITERATURE_URL_ALIASES))
    else:
        title = get_field(row, PATENT_TITLE_ALIASES) or "Untitled patent"
        doi = ""
        url = normalize_url(get_field(row, PATENT_URL_ALIASES))
    record_id = stable_record_id(record_type, row)
    publication_number = (
        normalize_publication_number(
            get_field(row, PUBLICATION_NUMBER_ALIASES)
            or typed_identifier_value(row, "publication_number")
        )
        if record_type == "patent"
        else ""
    )
    metadata_sources = row_metadata_sources(row)
    ATTEMPT_CONTEXT.value = {
        "run_id": CURRENT_RUN_ID,
        "record_id": record_id,
        "metadata_sources": metadata_sources,
        "publication_number": publication_number,
    }
    reason = f"worker_exception:{exc.__class__.__name__}"
    attempt = make_attempt(record_type, title, doi, url, "worker_exception", "", "failed", reason)
    return DownloadResult(
        record_type=record_type,
        title=title,
        run_id=CURRENT_RUN_ID,
        record_id=record_id,
        doi=doi,
        publication_number=publication_number,
        metadata_sources=metadata_sources,
        url=url,
        status="failed",
        failure_reason="download_failed",
        attempted_channels=["worker_exception"],
        last_error=reason,
        original_row=row,
        attempts=[attempt],
        attempt_count=1,
    )


def not_downloadable_result(record_type: str, row: dict[str, Any]) -> DownloadResult:
    """Represent canonical metadata-only input as an explicit blocked record."""
    title_aliases = LITERATURE_TITLE_ALIASES if record_type == "literature" else PATENT_TITLE_ALIASES
    url_aliases = LITERATURE_URL_ALIASES if record_type == "literature" else PATENT_URL_ALIASES
    title = get_field(row, title_aliases) or (
        "Untitled literature" if record_type == "literature" else "Untitled patent"
    )
    doi = normalize_doi(get_field(row, LITERATURE_DOI_ALIASES)) if record_type == "literature" else ""
    url = normalize_url(get_field(row, url_aliases))
    publication_number = (
        normalize_publication_number(
            get_field(row, PUBLICATION_NUMBER_ALIASES)
            or typed_identifier_value(row, "publication_number")
        )
        if record_type == "patent"
        else ""
    )
    record_id = str(row.get("record_id") or stable_record_id(record_type, row))
    metadata_sources = row_metadata_sources(row)
    ATTEMPT_CONTEXT.value = {
        "run_id": CURRENT_RUN_ID,
        "record_id": record_id,
        "metadata_sources": metadata_sources,
        "publication_number": publication_number,
    }
    reason = "metadata_only_not_downloadable"
    attempt = make_attempt(
        record_type,
        title,
        doi,
        url,
        "input_readiness",
        "",
        "skipped",
        reason,
        access_mode="metadata",
    )
    return DownloadResult(
        record_type=record_type,
        title=title,
        run_id=CURRENT_RUN_ID,
        record_id=record_id,
        doi=doi,
        publication_number=publication_number,
        metadata_sources=metadata_sources,
        url=url,
        status="not_downloadable",
        failure_reason=reason,
        attempted_channels=["input_readiness"],
        last_error=reason,
        original_row=row,
        attempts=[attempt],
        attempt_count=1,
    )


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def prepare_record_input(
    record_type: str,
    csv_path: Path,
    config: DownloadConfig,
    paths: dict[str, Path],
    resolved_override: Any | None = None,
) -> PreparedRecordInput:
    v2_path = paths["literature_v2"] if record_type == "literature" else paths["patents_v2"]
    resolved = resolved_override or resolve_input_contract(
        config.input_contract,
        record_type,
        v2_path,
        csv_path,
        paths.get("legacy_search_state"),
    )
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    processed = 0
    total_records = 0
    duplicate_records = 0
    logical_input_payload: list[dict[str, str]] = []
    row_iterator = resolved.iter_rows()
    try:
        for row in merge_planner_rows(row_iterator):
            logical_input_payload.append(
                {
                    "record_id": str(
                        row.get("record_id")
                        or stable_record_id(record_type, row)
                    ),
                    "row_sha256": _canonical_digest(
                        sanitize_nested_for_output(row)
                    ),
                }
            )
            if config.doi_filters and record_type == "literature":
                if normalize_doi(get_field(row, LITERATURE_DOI_ALIASES)) not in config.doi_filters:
                    continue
            if config.publication_filters and record_type == "patent":
                publication = normalize_publication_number(
                    get_field(row, PUBLICATION_NUMBER_ALIASES)
                    or typed_identifier_value(row, "publication_number")
                )
                if publication not in config.publication_filters:
                    continue
            if config.limit is not None and processed >= config.limit:
                continue
            total_records += 1
            identifier, _valid = result_identifier(record_type, row)
            record_id = str(row.get("record_id") or stable_record_id(record_type, row))
            row["record_id"] = record_id
            row.setdefault("record_type", record_type)
            dedupe_key = record_id or identifier
            if dedupe_key and dedupe_key in seen:
                duplicate_records += 1
                continue
            if dedupe_key:
                seen.add(dedupe_key)
            rows.append(row)
            processed += 1
    finally:
        close = getattr(row_iterator, "close", None)
        if callable(close):
            close()
    plan_payload = [
        {
            "record_id": str(row.get("record_id") or ""),
            "row_sha256": _canonical_digest(sanitize_nested_for_output(row)),
        }
        for row in rows
    ]
    return PreparedRecordInput(
        record_type=record_type,
        rows=rows,
        resolved=resolved,
        total_records=total_records,
        duplicate_records=duplicate_records,
        plan_sha256=_canonical_digest(plan_payload),
        logical_input_sha256=_canonical_digest(logical_input_payload),
    )


def _credential_file_revision(path: Path | None, salt: bytes) -> dict[str, Any]:
    if path is None:
        return {"configured": False}
    try:
        resolved = path.expanduser().resolve()
    except Exception:
        return {"configured": True, "readable": False}
    result: dict[str, Any] = {
        "configured": True,
        "path_digest": hmac.new(salt, str(resolved).encode("utf-8"), hashlib.sha256).hexdigest(),
        "readable": resolved.is_file(),
    }
    if not resolved.is_file():
        return result
    try:
        stat = resolved.stat()
        content = resolved.read_bytes()
        result.update(
            {
                "size_bytes": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "content_hmac": hmac.new(salt, content, hashlib.sha256).hexdigest(),
            }
        )
    except OSError:
        result["readable"] = False
    return result


def credential_revision(config: DownloadConfig, salt: bytes) -> tuple[str, dict[str, Any]]:
    named_values: dict[str, str] = {
        "institution_account": config.account,
        "institution_password": config.password,
        "uyanip_account": config.uyanip_account,
        "uyanip_password": config.uyanip_password,
    }
    for name in API_CONFIG_KEYS:
        named_values[name] = env_value(name)
    aggregate = hmac.new(salt, digestmod=hashlib.sha256)
    configured_names: list[str] = []
    for name in sorted(named_values):
        value = str(named_values[name] or "")
        if not value:
            continue
        configured_names.append(name)
        aggregate.update(name.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(value.encode("utf-8"))
        aggregate.update(b"\0")
    file_revisions = {
        "runtime_config": _credential_file_revision(
            Path(config.runtime_config_path) if config.runtime_config_path else None,
            salt,
        ),
        "api_config": _credential_file_revision(get_api_config_path(), salt),
        "google_credentials": _credential_file_revision(
            Path(env_value("GOOGLE_APPLICATION_CREDENTIALS"))
            if env_value("GOOGLE_APPLICATION_CREDENTIALS")
            else None,
            salt,
        ),
    }
    aggregate.update(
        json.dumps(file_revisions, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    revision = aggregate.hexdigest()
    return revision, {
        "configured_key_names": configured_names,
        "credential_files": file_revisions,
        "aggregate_revision": revision,
    }


def build_download_run_fingerprint(
    prepared: Mapping[str, PreparedRecordInput],
    config: DownloadConfig,
    salt: bytes,
) -> tuple[str, dict[str, Any]]:
    input_evidence: dict[str, Any] = {}
    for record_type, item in sorted(prepared.items()):
        report = dict(item.resolved.migration_report)
        source = report.get("source") if isinstance(report.get("source"), Mapping) else {}
        handoff = report.get("handoff_manifest") if isinstance(report.get("handoff_manifest"), Mapping) else {}
        input_evidence[record_type] = {
            "requested_contract": item.resolved.requested_contract,
            "resolved_contract": item.resolved.resolved_contract,
            "source_sha256": (
                ""
                if item.resolved.resolved_contract == "legacy_sqlite"
                else str(source.get("sha256") or "")
            ),
            "source_size_bytes": (
                0
                if item.resolved.resolved_contract == "legacy_sqlite"
                else int(source.get("size_bytes") or 0)
            ),
            "logical_input_sha256": item.logical_input_sha256,
            "binding_status": str(handoff.get("binding_status") or ("standalone_unbound" if not handoff.get("present") else "legacy_unbound")),
            "handoff_generation_id": str(handoff.get("handoff_generation_id") or ""),
            "handoff_content_sha256": str(handoff.get("handoff_content_sha256") or ""),
            "manifest_sha256": str(handoff.get("manifest_sha256") or ""),
            "manifest_version": int(handoff.get("manifest_version") or 0),
            "record_plan_sha256": item.plan_sha256,
            "record_count": len(item.rows),
        }
    credential_digest, credential_evidence = credential_revision(config, salt)
    policy_environment_names = (
        "LAPS_API_TIMEOUT_SECONDS",
        "LAPS_DOWNLOAD_TIMEOUT_SECONDS",
        "LAPS_MAX_PDF_MIB",
        "LAPS_MAX_DISCOVERY_MIB",
        "LAPS_CHANNEL_RECOVERY_ATTEMPTS",
        "LAPS_PAGE_TIMEOUT_SECONDS",
        "LAPS_BROWSER_COOKIE_WARMUP_MS",
        "LAPS_BROWSER_NETWORK_IDLE_TIMEOUT_MS",
        "LAPS_BROWSER_TEXT_TIMEOUT_MS",
        "LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS",
        "LAPS_EXTERNAL_HANDOFF_TIMEOUT_SECONDS",
        "LAPS_EXTERNAL_CONTROL_BROWSER",
        "LAPS_SECURITY_CHALLENGE_HOOK_TIMEOUT_SECONDS",
        "LAPS_SECURITY_CHALLENGE_HOOK",
        "LAPS_SECURITY_CHALLENGE_HOOK_ALLOW_RAW_URL",
        "LAPS_SECURITY_CHALLENGE_COOLDOWN_SECONDS",
        "LAPS_SECURITY_CHALLENGE_DOMAIN_COOLDOWN_SECONDS",
        "LAPS_CHALLENGE_HOOK_COMMAND",
        "LAPS_HOOK_TOTAL_TIMEOUT_SECONDS",
        "LAPS_HOOK_TRY_CHROME",
        "LAPS_AUTH_CONTROL_HOOK_TIMEOUT_SECONDS",
        "LAPS_AUTH_CONTROL_VERIFY_SECONDS",
        "LAPS_AUTH_CONTROL_HOOK",
        "LAPS_AUTH_CONTROL_HOOK_ALLOW_CREDENTIALS",
        "LAPS_AUTH_CONTROL_HOOK_ALLOW_RAW_URL",
        "LAPS_AUTH_MANUAL_TIMEOUT_SECONDS",
        "LAPS_AUTH_FAILURE_COOLDOWN_SECONDS",
        "LAPS_AUTH_STATE_TTL_HOURS",
        "LAPS_VERIFICATION_MANUAL_TIMEOUT_SECONDS",
        "LAPS_VERIFICATION_AUTOMATION_LEVEL",
        "LAPS_AUTH_STATE_ATTESTATION_TTL_SECONDS",
        "LAPS_LOGIN_HOOK_COMMAND",
        "LAPS_UYANIP_LOGIN_TIMEOUT_SECONDS",
        "LAPS_CHROMIUM_CONTROL_TIMEOUT_SECONDS",
        "LAPS_CHROME_CONTROL_TIMEOUT_SECONDS",
        "LAPS_CODEX_EXTENSION_CONTROL_ENABLED",
        "LAPS_CODEX_EXTENSION_CONTROL_HOOK",
        "LAPS_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS",
        "LAPS_CODEX_CHROME_CONTROL_MODE",
        "LAPS_CODEX_CHROME_PREFLIGHT_STATE",
        "LAPS_CODEX_CHROME_SETUP_CONFIRM_TIMEOUT_SECONDS",
        "LAPS_CODEX_CHROME_SETUP_SCAN_TIMEOUT_SECONDS",
        "LAPS_CODEX_CHROME_CONNECT_SETTLE_SECONDS",
        "LAPS_CODEX_WINDOWS_CONTROL_PREAUTHORIZED",
        "LAPS_ORDINARY_CHROME_PREAUTHORIZED",
        "LAPS_CORE_ALLOW_UNAUTHENTICATED",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    )
    sensitive_policy_environment_names = frozenset(
        {
            "LAPS_EXTERNAL_CONTROL_BROWSER",
            "LAPS_SECURITY_CHALLENGE_HOOK",
            "LAPS_CHALLENGE_HOOK_COMMAND",
            "LAPS_AUTH_CONTROL_HOOK",
            "LAPS_LOGIN_HOOK_COMMAND",
            "LAPS_CODEX_EXTENSION_CONTROL_HOOK",
            "LAPS_CODEX_CHROME_PREFLIGHT_STATE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
        }
    )
    policy_environment: dict[str, Any] = {}
    for name in policy_environment_names:
        value = os.getenv(name, "")
        if name in sensitive_policy_environment_names and value:
            policy_environment[name] = hmac.new(
                salt, value.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        else:
            policy_environment[name] = value
    registry_payload = registry_snapshot()
    payload = {
        "fingerprint_schema_version": DOWNLOAD_FINGERPRINT_SCHEMA_VERSION,
        "planner_semantics_version": DOWNLOAD_PLANNER_SEMANTICS_VERSION,
        "canonical_schema_version": CANONICAL_SCHEMA_VERSION,
        "manifest_schema": HANDOFF_MANIFEST_SCHEMA,
        "manifest_version": HANDOFF_MANIFEST_VERSION,
        "registry_schema_version": REGISTRY_SCHEMA_VERSION,
        "registry_version": REGISTRY_VERSION,
        "registry_sha256": _canonical_digest(registry_payload),
        "inputs": input_evidence,
        "scope": {
            "record_types": sorted(prepared),
            "limit": config.limit,
            "doi_filters": list(config.doi_filters),
            "publication_filters": list(config.publication_filters),
            "channel_filters": list(config.channel_filters),
            "exact_channel_filters": list(config.exact_channel_filters),
            "disabled_channels": list(config.disabled_channels),
            "dry_run": config.dry_run,
            "probe_channel_plan": config.probe_channel_plan,
        },
        "policy": {
            "auth_mode": config.path,
            "auth_enabled": config.auth_enabled,
            "headless": config.headless,
            "credential_allowed_hosts": list(config.credential_allowed_hosts),
            "max_pdf_bytes": max_pdf_bytes(),
            "download_timeout_seconds": download_timeout_seconds(),
            "channel_recovery_attempts": channel_recovery_attempts(),
            "environment": policy_environment,
        },
        "credential_revision": credential_digest,
        "credential_evidence": credential_evidence,
    }
    return _canonical_digest(payload), payload


def process_records(
    record_type: str,
    prepared: PreparedRecordInput,
    config: DownloadConfig,
    paths: dict[str, Path],
    logger: logging.Logger,
) -> tuple[list[DownloadResult], RecordStats]:
    stats = RecordStats(record_type=record_type, started_at=utc_now())
    stats.total_records = prepared.total_records
    stats.duplicate_records = prepared.duplicate_records
    start = time.monotonic()
    results: list[DownloadResult] = []
    processor = process_literature_record if record_type == "literature" else process_patent_record
    resolved = prepared.resolved
    stats.input_contract = resolved.resolved_contract
    stats.input_path = str(resolved.source_path)
    try:
        with ThreadPoolExecutor(max_workers=config.thread_num) as executor:
            for chunk in iter_row_chunks(iter(prepared.rows)):
                futures = {}
                for row in chunk:
                    identifier, valid = result_identifier(record_type, row)
                    record_id = str(row.get("record_id") or stable_record_id(record_type, row))
                    structurally_downloadable = bool(
                        structurally_applicable_download_specs(record_type, row)
                    )
                    if (
                        str(row.get("retrieval_readiness") or "").casefold()
                        == "metadata_only"
                        and not structurally_downloadable
                    ):
                        stats.not_downloadable_records += 1
                        blocked_result = not_downloadable_result(record_type, row)
                        results.append(blocked_result)
                        append_result_attempts(paths, blocked_result)
                        update_stats_from_result(stats, blocked_result)
                        continue
                    if not valid:
                        stats.missing_identifier_records += 1
                    stats.valid_records += 1 if valid else 0
                    if ACTIVE_DOWNLOAD_LEDGER is not None:
                        if CURRENT_RUN_RESUMED:
                            row["_resume_record_state"] = (
                                ACTIVE_DOWNLOAD_LEDGER.resumable_record_state(
                                    CURRENT_RUN_ID,
                                    record_id,
                                )
                            )
                        ACTIVE_DOWNLOAD_LEDGER.mark_record_started(CURRENT_RUN_ID, record_id)
                    futures[executor.submit(processor, row, config, paths, logger)] = row
                for future in as_completed(futures):
                    try:
                        result = future.result()
                    except Exception as exc:
                        logger.error("Record failed with unexpected worker exception for %s: %s", record_type, exc.__class__.__name__)
                        result = worker_exception_result(record_type, futures[future], exc)
                    results.append(result)
                    append_result_attempts(paths, result)
                    update_stats_from_result(stats, result)
    finally:
        INPUT_CONTRACT_REPORTS[record_type] = dict(resolved.migration_report)
        if ACTIVE_DOWNLOAD_LEDGER is not None:
            ACTIVE_DOWNLOAD_LEDGER.record_migration(
                resolved.resolved_contract,
                resolved.source_path,
                resolved.migration_report,
            )
    stats.finished_at = utc_now()
    stats.elapsed_seconds = round(time.monotonic() - start, 3)
    return results, stats


def reconstruct_finalizing_results(
    ledger: DownloadStateLedger,
    run_id: str,
    prepared_inputs: Mapping[str, PreparedRecordInput],
) -> tuple[list[DownloadResult], list[DownloadResult], RecordStats, RecordStats]:
    """Rebuild materialized outputs from ledger state without network access."""

    attempt_rows = ledger.attempts_for_run(run_id)
    attempts_by_record: dict[str, list[DownloadAttempt]] = defaultdict(list)
    attempt_field_names = set(DownloadAttempt.__dataclass_fields__)
    for row in attempt_rows:
        if not isinstance(row, Mapping):
            continue
        values = {name: row.get(name) for name in attempt_field_names if name in row}
        values.setdefault("record_type", str(row.get("record_type") or "unknown"))
        values.setdefault("title", str(row.get("title") or ""))
        try:
            attempt = DownloadAttempt(**values)
        except TypeError:
            continue
        attempts_by_record[str(row.get("record_id") or "")].append(attempt)

    recovered: dict[str, list[DownloadResult]] = {"literature": [], "patent": []}
    for snapshot in ledger.run_record_snapshots(run_id):
        try:
            row = json.loads(str(snapshot.get("planner_row_json") or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            row = {}
        if not isinstance(row, dict):
            row = {}
        record_type = str(
            row.get("record_type") or snapshot.get("record_type") or ""
        )
        if record_type not in recovered:
            continue
        record_id = str(snapshot.get("record_id") or row.get("record_id") or "")
        title_aliases = (
            LITERATURE_TITLE_ALIASES
            if record_type == "literature"
            else PATENT_TITLE_ALIASES
        )
        url_aliases = (
            LITERATURE_URL_ALIASES
            if record_type == "literature"
            else PATENT_URL_ALIASES
        )
        title = get_field(row, title_aliases) or (
            "Untitled literature" if record_type == "literature" else "Untitled patent"
        )
        doi = (
            normalize_doi(get_field(row, LITERATURE_DOI_ALIASES))
            if record_type == "literature"
            else ""
        )
        publication_number = (
            normalize_publication_number(
                get_field(row, PUBLICATION_NUMBER_ALIASES)
                or typed_identifier_value(row, "publication_number")
            )
            if record_type == "patent"
            else ""
        )
        record_attempts = attempts_by_record.get(record_id, [])
        successful_attempts = [
            item for item in record_attempts if item.attempt_status == "success"
        ]
        terminal_attempt = successful_attempts[-1] if successful_attempts else (
            record_attempts[-1] if record_attempts else None
        )
        persisted_state = str(snapshot.get("state") or "failed")
        status = persisted_state
        failure_reason = str(snapshot.get("failure_reason") or "")
        artifact_path = ledger.valid_artifact_path(record_id, record_type)
        if status == "success" and artifact_path is None:
            status = "failed"
            failure_reason = "artifact_missing_or_invalid_during_finalization_recovery"
        elif status not in {"success", "failed", "dry_run", "not_downloadable"}:
            status = "failed"
            failure_reason = "interrupted_record_without_terminal_state"
        file_size = artifact_path.stat().st_size if artifact_path is not None else 0
        digest = sha256_file(artifact_path) if artifact_path is not None else ""
        attempted_channels = [
            item.planned_channel or item.channel
            for item in record_attempts
            if item.planned_channel or item.channel
        ]
        result = DownloadResult(
            record_type=record_type,
            title=title,
            run_id=run_id,
            record_id=record_id,
            doi=doi,
            publication_number=publication_number,
            metadata_sources=row_metadata_sources(row),
            url=normalize_url(get_field(row, url_aliases)),
            status=status,
            source_channel=(
                terminal_attempt.planned_channel or terminal_attempt.channel
                if terminal_attempt is not None and status == "success"
                else ""
            ),
            resolver_channel=(
                terminal_attempt.resolver_channel
                if terminal_attempt is not None and status == "success"
                else ""
            ),
            successful_planned_channel=(
                terminal_attempt.planned_channel or terminal_attempt.channel
                if terminal_attempt is not None and status == "success"
                else ""
            ),
            successful_resolver_channel=(
                terminal_attempt.resolver_channel
                if terminal_attempt is not None and status == "success"
                else ""
            ),
            successful_delivery_source=(
                terminal_attempt.delivery_source
                if terminal_attempt is not None and status == "success"
                else ""
            ),
            pdf_path=str(artifact_path or ""),
            file_size_bytes=file_size,
            sha256=digest,
            access_mode=(terminal_attempt.access_mode if terminal_attempt else "open"),
            attempt_count=len(record_attempts),
            failure_reason=failure_reason,
            attempted_channels=attempted_channels,
            last_error=failure_reason or (terminal_attempt.reason if terminal_attempt else ""),
            original_row=row,
            attempts=record_attempts,
        )
        recovered[record_type].append(result)

    def stats_for(record_type: str) -> RecordStats:
        prepared = prepared_inputs.get(record_type)
        stats = RecordStats(
            record_type=record_type,
            total_records=prepared.total_records if prepared else 0,
            duplicate_records=prepared.duplicate_records if prepared else 0,
            input_contract=(prepared.resolved.resolved_contract if prepared else ""),
            input_path=(str(prepared.resolved.source_path) if prepared else ""),
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        for result in recovered[record_type]:
            _identifier, valid = result_identifier(record_type, result.original_row)
            if valid:
                stats.valid_records += 1
            else:
                stats.missing_identifier_records += 1
            if result.status == "not_downloadable":
                stats.not_downloadable_records += 1
            update_stats_from_result(stats, result)
        return stats

    return (
        recovered["literature"],
        recovered["patent"],
        stats_for("literature"),
        stats_for("patent"),
    )


def update_stats_from_result(stats: RecordStats, result: DownloadResult) -> None:
    if result.status == "success":
        stats.success_count += 1
        if result.source_channel in {"existing_file", "existing_alias", "existing_ledger_artifact"}:
            stats.skipped_existing_files += 1
        if result.access_mode == "authenticated":
            stats.authenticated_success_count += 1
        else:
            stats.open_success_count += 1
        stats.per_channel_success_count[result.source_channel or "unknown"] += 1
    elif result.status == "dry_run":
        stats.dry_run_count += 1
    elif result.status == "not_downloadable":
        # Canonical metadata-only rows remain visible in the attempt ledger and
        # report, but are outside the submitted-download denominator.
        return
    else:
        stats.failure_count += 1
        channel = result.attempted_channels[-1] if result.attempted_channels else "unknown"
        stats.per_channel_failure_count[channel] += 1


def success_row(result: DownloadResult) -> dict[str, Any]:
    pdf_path = ""
    if result.pdf_path:
        candidate_path = Path(result.pdf_path)
        pdf_path = relpath(candidate_path) if candidate_path.is_absolute() else result.pdf_path.replace("\\", "/")
    return {
        "run_id": result.run_id,
        "record_id": result.record_id,
        "record_type": result.record_type,
        "title": result.title,
        "doi": result.doi,
        "publication_number": result.publication_number,
        "metadata_sources": "; ".join(result.metadata_sources),
        "url": sanitize_output_value("url", result.url),
        "source_channel": result.source_channel,
        "resolver_channel": result.resolver_channel,
        "successful_planned_channel": result.successful_planned_channel,
        "successful_resolver_channel": result.successful_resolver_channel,
        "successful_delivery_source": result.successful_delivery_source,
        "pdf_path": pdf_path,
        "file_size_bytes": result.file_size_bytes,
        "sha256": result.sha256,
        "access_mode": result.access_mode,
        "attempt_count": result.attempt_count,
        "created_at": utc_now(),
    }


def failure_row(result: DownloadResult, original_fields: list[str]) -> dict[str, Any]:
    row = {
        "run_id": result.run_id,
        "record_id": result.record_id,
        "record_type": result.record_type,
        "title": result.title,
        "doi": result.doi,
        "publication_number": result.publication_number,
        "metadata_sources": "; ".join(result.metadata_sources),
        "url": result.url,
        "failure_reason": result.failure_reason,
        "attempted_channels": "; ".join(result.attempted_channels),
        "last_error": result.last_error,
        "created_at": utc_now(),
    }
    for field_name in original_fields:
        row[field_name] = result.original_row.get(field_name, "")
    return {
        field_name: sanitize_csv_value(field_name, value)
        for field_name, value in row.items()
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8-sig", newline="") as handle:
            descriptor = -1
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        atomic_replace_file(temporary, path)
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        temporary.unlink(missing_ok=True)


def append_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        if needs_header:
            writer.writeheader()
        writer.writerows(rows)


def initialize_attempt_log(paths: dict[str, Path]) -> None:
    write_csv(paths["outputs"] / "download_attempts.csv", [], ATTEMPT_FIELDS)


def append_result_attempts(paths: dict[str, Path], result: DownloadResult) -> None:
    rows = [attempt.__dict__ for attempt in result.attempts]
    append_csv(paths["outputs"] / "download_attempts.csv", rows, ATTEMPT_FIELDS)
    if ACTIVE_DOWNLOAD_LEDGER is not None:
        ACTIVE_DOWNLOAD_LEDGER.upsert_record(result)
        ACTIVE_DOWNLOAD_LEDGER.mark_record_result(result)
        for attempt in result.attempts:
            ACTIVE_DOWNLOAD_LEDGER.append_attempt(attempt)
        if result.status == "success" and result.pdf_path:
            artifact_path = Path(result.pdf_path)
            if not artifact_path.is_absolute():
                artifact_path = ROOT_DIR / artifact_path
            if artifact_path.exists() and is_valid_pdf(artifact_path):
                ACTIVE_DOWNLOAD_LEDGER.add_artifact(result, artifact_path)


def auth_channel_filters(args: argparse.Namespace) -> tuple[tuple[str, ...], tuple[str, ...]]:
    fuzzy_filters: list[str] = []
    exact_filters: list[str] = []
    for value in getattr(args, "auth_channel", ()) or ():
        text = str(value).strip()
        if not text:
            continue
        if text.casefold().startswith("exact:"):
            exact = text.split(":", 1)[1].strip()
            if exact:
                exact_filters.append(exact.casefold())
            continue
        fuzzy_filters.append(text.casefold())
    for value in getattr(args, "exact_auth_channel", ()) or ():
        text = str(value).strip()
        if text:
            exact_filters.append(text.casefold())
    return tuple(fuzzy_filters), tuple(exact_filters)


def available_auth_check_channels() -> list[str]:
    available: list[str] = []
    for path_map, policy_map in (
        (literature_download_path_map, literature_channel_policy_map),
        (patents_download_path_map, patents_channel_policy_map),
    ):
        for channel in path_map:
            policy = policy_map.get(channel, {})
            if bool(policy.get("requires_auth")) and channel_has_web_script(channel, policy):
                available.append(channel)
    return sorted(available)


def auth_check_targets(args: argparse.Namespace) -> list[AuthCheckTarget]:
    fuzzy_filters, exact_filters = auth_channel_filters(args)
    targets: list[AuthCheckTarget] = []

    def append_targets(record_type: str, path_map: OrderedDict[str, str], policy_map: dict[str, dict[str, Any]]) -> None:
        for channel in path_map:
            policy = policy_map.get(channel, {})
            if not bool(policy.get("requires_auth")):
                continue
            if not channel_has_web_script(channel, policy):
                continue
            channel_key = channel.casefold()
            if exact_filters:
                if channel_key not in exact_filters:
                    continue
            elif fuzzy_filters and not any(filter_value in channel_key for filter_value in fuzzy_filters):
                continue
            targets.append(AuthCheckTarget(record_type, channel, policy))

    if not getattr(args, "patents_only", False):
        append_targets("literature", literature_download_path_map, literature_channel_policy_map)
    if not getattr(args, "literature_only", False):
        append_targets("patent", patents_download_path_map, patents_channel_policy_map)

    if (fuzzy_filters or exact_filters) and not targets:
        filter_name = "--exact-auth-channel" if exact_filters else "--auth-channel"
        raise ValueError(f"No authenticated channels matched {filter_name}. Available: {', '.join(available_auth_check_channels())}")
    return targets


def run_auth_checks(
    config: DownloadConfig,
    paths: dict[str, Path],
    logger: logging.Logger,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    targets = auth_check_targets(args)
    allow_state_reuse = not bool(getattr(args, "auth_no_state_reuse", False))
    projections: list[dict[str, Any]] = []
    groups: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    declarations: dict[str, tuple[str, str, str, str]] = {}

    for ordinal, target in enumerate(targets):
        state_path = channel_auth_state_path(
            config,
            target.channel,
            target.policy,
            paths,
        )
        auth_scope = source_auth_state_scope(target.channel, target.policy) or safe_slug(
            str(target.policy.get("auth_state_scope") or target.channel)
        )
        auth_mode = source_auth_mode(config, target.channel, target.policy)
        scope_key, principal_digest = auth_state_scope_identity(
            config,
            target.channel,
            target.policy,
            state_path,
        )
        service_host = expected_auth_state_service_host(
            target.channel,
            target.policy,
        )
        shared_scope = bool(source_auth_state_scope(target.channel, target.policy))
        declaration_key = (
            auth_scope
            if shared_scope
            else f"{auth_scope}:{target.channel}:{hashlib.sha256(str(state_path.resolve()).encode('utf-8')).hexdigest()}"
        )
        principal_class = (
            "institution"
            if auth_mode == "institution"
            else "site_personal"
            if auth_mode == "site_personal"
            else "personal"
        )
        declaration = (
            auth_mode,
            principal_class,
            service_host,
            str(state_path.resolve()),
        )
        previous = declarations.get(declaration_key)
        if previous is not None and previous != declaration:
            raise ValueError(
                f"auth_scope_configuration_conflict:{auth_scope}"
            )
        declarations[declaration_key] = declaration
        projection = {
            "ordinal": ordinal,
            "target": target,
            "state_path": state_path,
            "auth_scope": auth_scope,
            "auth_mode": auth_mode,
            "principal_digest": principal_digest,
            "principal_class": principal_class,
            "scope_key": scope_key,
            "service_host": service_host,
            "skipped_reason": skipped_download_channel_reason(target.channel),
        }
        projections.append(projection)
        groups.setdefault(scope_key, []).append(projection)

    def projected_row(
        projection: dict[str, Any],
        *,
        status: str,
        reason: str,
        state_reused: bool,
        elapsed_seconds: float,
        representative: dict[str, Any] | None,
        generation: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        reason_code, reason_category, retryable = reason_details(reason)
        target = projection["target"]
        is_projection = bool(
            representative is not None and projection is not representative
        )
        return {
            "record_type": target.record_type,
            "channel": target.channel,
            "status": status,
            "reason": reason,
            "state_reused": state_reused,
            "state_path": relpath(projection["state_path"]),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "created_at": utc_now(),
            "auth_scope": projection["auth_scope"],
            "auth_mode": projection["auth_mode"],
            "scope_key": projection["scope_key"],
            "generation_id": str((generation or {}).get("generation_id") or ""),
            "attestation_schema": (
                AUTH_STATE_ATTESTATION_SCHEMA if generation is not None else ""
            ),
            "attestation_status": (
                "bound_v2" if generation is not None else "missing_or_unconfirmed"
            ),
            "projected": is_projection,
            "projected_from_record_type": (
                representative["target"].record_type if is_projection else ""
            ),
            "projected_from_channel": (
                representative["target"].channel if is_projection else ""
            ),
            "reason_code": reason_code,
            "reason_category": reason_category,
            "retryable": retryable,
            "retry_at": "",
        }

    group_results: dict[str, dict[str, Any]] = {}
    try:
        sync_playwright = load_sync_playwright()
    except Exception as exc:
        reason = f"playwright_unavailable:{exc.__class__.__name__}"
        return [
            projected_row(
                projection,
                status="skipped" if projection["skipped_reason"] else "failure",
                reason=projection["skipped_reason"] or reason,
                state_reused=False,
                elapsed_seconds=0.0,
                representative=None,
                generation=None,
            )
            for projection in projections
        ]

    with sync_playwright() as playwright:
        for scope_key, members in groups.items():
            eligible = [member for member in members if not member["skipped_reason"]]
            if not eligible:
                continue
            representative = eligible[0]
            target = representative["target"]
            started = time.monotonic()
            browser = None
            context = None
            result = BrowserAuthResult(False, "unknown")
            try:
                logger.info("Checking authenticated login for %s channel: %s", target.record_type, target.channel)
                browser, context, result = open_authenticated_browser_context(
                    playwright,
                    config,
                    logger,
                    target.channel,
                    target.policy,
                    paths,
                    allow_state_reuse=allow_state_reuse,
                )
            except Exception as exc:
                result = BrowserAuthResult(False, f"{exc.__class__.__name__}: {exc}")
            finally:
                try:
                    if context is not None:
                        context.close()
                except Exception:
                    pass
                try:
                    if browser is not None:
                        browser.close()
                except Exception:
                    pass
            group_results[scope_key] = {
                "representative": representative,
                "status": "success" if result.ok else "failure",
                "reason": result.reason,
                "state_reused": result.state_reused,
                "elapsed_seconds": time.monotonic() - started,
                "generation": shared_auth_control_store().auth_generation(scope_key),
            }

    rows: list[dict[str, Any]] = []
    for projection in projections:
        if projection["skipped_reason"]:
            row = projected_row(
                projection,
                status="skipped",
                reason=projection["skipped_reason"],
                state_reused=False,
                elapsed_seconds=0.0,
                representative=None,
                generation=None,
            )
        else:
            result = group_results[projection["scope_key"]]
            row = projected_row(
                projection,
                status=result["status"],
                reason=result["reason"],
                state_reused=result["state_reused"],
                elapsed_seconds=result["elapsed_seconds"],
                representative=result["representative"],
                generation=result["generation"],
            )
        rows.append(row)
        write_auth_check_report(rows, paths)
    return rows


def write_auth_check_report(rows: list[dict[str, Any]], paths: dict[str, Path]) -> Path:
    report_path = paths["outputs"] / "auth_check_report.csv"
    sanitized_rows = [
        {
            **row,
            "reason": sanitize_text_for_output(row.get("reason", "")),
        }
        for row in rows
    ]
    write_csv(
        report_path,
        sanitized_rows,
        [
            "record_type",
            "channel",
            "status",
            "reason",
            "state_reused",
            "state_path",
            "elapsed_seconds",
            "created_at",
            "auth_scope",
            "auth_mode",
            "scope_key",
            "generation_id",
            "attestation_schema",
            "attestation_status",
            "projected",
            "projected_from_record_type",
            "projected_from_channel",
            "reason_code",
            "reason_category",
            "retryable",
            "retry_at",
        ],
    )
    return report_path


def print_auth_check_summary(rows: list[dict[str, Any]], report_path: Path) -> None:
    success_count = sum(1 for row in rows if row.get("status") == "success")
    skipped_count = sum(1 for row in rows if row.get("status") == "skipped")
    failure_count = len(rows) - success_count - skipped_count
    print(f"Auth channels checked: {len(rows)}")
    print(f"Auth success: {success_count}")
    print(f"Auth skipped: {skipped_count}")
    print(f"Auth failure: {failure_count}")
    print(f"Auth report: {report_path.resolve()}")


def stat_summary_row(stats: RecordStats, thread_num: int) -> dict[str, Any]:
    denominator = stats.success_count + stats.failure_count
    success_rate = (stats.success_count / denominator) if denominator else 0.0
    failure_rate = (stats.failure_count / denominator) if denominator else 0.0
    return {
        "record_type": stats.record_type,
        "total_records": stats.total_records,
        "valid_records": stats.valid_records,
        "duplicate_records": stats.duplicate_records,
        "missing_identifier_records": stats.missing_identifier_records,
        "not_downloadable_records": stats.not_downloadable_records,
        "input_contract": stats.input_contract,
        "input_path": stats.input_path,
        "skipped_existing_files": stats.skipped_existing_files,
        "success_count": stats.success_count,
        "failure_count": stats.failure_count,
        "success_rate": f"{success_rate:.4f}",
        "failure_rate": f"{failure_rate:.4f}",
        "open_success_count": stats.open_success_count,
        "authenticated_success_count": stats.authenticated_success_count,
        "per_channel_success_count": json.dumps(dict(stats.per_channel_success_count), ensure_ascii=False),
        "per_channel_failure_count": json.dumps(dict(stats.per_channel_failure_count), ensure_ascii=False),
        "started_at": stats.started_at,
        "finished_at": stats.finished_at,
        "elapsed_seconds": stats.elapsed_seconds,
        "thread_num": thread_num,
    }


def file_report(path: Path) -> dict[str, Any]:
    payload = {
        "path": relpath(path),
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() and path.is_file() else 0,
    }
    if path.is_file():
        payload["sha256"] = sha256_file(path)
    return payload


def result_status_counts(results: list[DownloadResult]) -> dict[str, int]:
    return dict(Counter(result.status for result in results))


def attempt_counters(attempts: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        "status": dict(Counter(str(attempt.get("attempt_status", "")) for attempt in attempts)),
        "reason": dict(Counter(str(attempt.get("reason", "")) for attempt in attempts if attempt.get("reason"))),
        "channel": dict(Counter(str(attempt.get("channel", "")) for attempt in attempts if attempt.get("channel"))),
        "access_mode": dict(Counter(str(attempt.get("access_mode", "")) for attempt in attempts if attempt.get("access_mode"))),
    }


def failure_reason_counts(results: list[DownloadResult]) -> dict[str, int]:
    return dict(
        Counter(
            sanitize_text_for_output(result.failure_reason)
            for result in results
            if result.status == "failed" and result.failure_reason
        )
    )


def workflow_completion_status(
    literature_stats: RecordStats,
    patent_stats: RecordStats,
    config: DownloadConfig,
) -> WorkflowStatus:
    del config
    return (
        WorkflowStatus.PARTIAL
        if literature_stats.failure_count or patent_stats.failure_count
        else WorkflowStatus.COMPLETE
    )


def write_results(
    literature_results: list[DownloadResult],
    patent_results: list[DownloadResult],
    literature_stats: RecordStats,
    patent_stats: RecordStats,
    config: DownloadConfig,
    paths: dict[str, Path],
) -> WorkflowStatus:
    workflow_status = workflow_completion_status(
        literature_stats, patent_stats, config
    )
    success_fields = [
        "run_id",
        "record_id",
        "record_type",
        "title",
        "doi",
        "publication_number",
        "metadata_sources",
        "url",
        "source_channel",
        "resolver_channel",
        "successful_planned_channel",
        "successful_resolver_channel",
        "successful_delivery_source",
        "pdf_path",
        "file_size_bytes",
        "sha256",
        "access_mode",
        "attempt_count",
        "created_at",
    ]
    failure_fields_base = ["run_id", "record_id", "record_type", "title", "doi", "publication_number", "metadata_sources", "url", "failure_reason", "attempted_channels", "last_error", "created_at"]
    summary_fields = list(stat_summary_row(literature_stats, config.thread_num).keys())

    internal_fields = {
        "metadata",
        "identifiers",
        "locators",
        "provenance",
        "locator_urls",
        "metadata_sources_json",
    }
    lit_original_fields = sorted(
        {
            key
            for result in literature_results
            for key, value in result.original_row.items()
            if key not in set(failure_fields_base)
            and not key.startswith("_")
            and key not in internal_fields
            and isinstance(value, (str, int, float, bool, type(None)))
        }
    )
    pat_original_fields = sorted(
        {
            key
            for result in patent_results
            for key, value in result.original_row.items()
            if key not in set(failure_fields_base)
            and not key.startswith("_")
            and key not in internal_fields
            and isinstance(value, (str, int, float, bool, type(None)))
        }
    )
    lit_success = [success_row(result) for result in literature_results if result.status == "success"]
    pat_success = [success_row(result) for result in patent_results if result.status == "success"]
    lit_failure = [failure_row(result, lit_original_fields) for result in literature_results if result.status == "failed"]
    pat_failure = [failure_row(result, pat_original_fields) for result in patent_results if result.status == "failed"]
    excluded_records = [
        {
            "record_id": result.record_id,
            "record_type": result.record_type,
            "retrieval_readiness": "metadata_only",
            "reason_code": sanitize_text_for_output(result.failure_reason),
        }
        for result in [*literature_results, *patent_results]
        if result.status == "not_downloadable"
    ]
    attempts = (
        ACTIVE_DOWNLOAD_LEDGER.attempts_for_run(CURRENT_RUN_ID)
        if ACTIVE_DOWNLOAD_LEDGER is not None
        else [
            attempt.__dict__
            for result in [*literature_results, *patent_results]
            for attempt in result.attempts
        ]
    )

    write_csv(paths["outputs"] / "literature_download_success_list.csv", lit_success, success_fields)
    write_csv(paths["outputs"] / "literature_download_failure_list.csv", lit_failure, failure_fields_base + lit_original_fields)
    write_csv(paths["outputs"] / "patents_download_success_list.csv", pat_success, success_fields)
    write_csv(paths["outputs"] / "patents_download_failure_list.csv", pat_failure, failure_fields_base + pat_original_fields)
    write_csv(paths["outputs"] / "download_attempts.csv", attempts, ATTEMPT_FIELDS)
    summary_rows = [stat_summary_row(literature_stats, config.thread_num), stat_summary_row(patent_stats, config.thread_num)]
    write_csv(paths["outputs"] / "download_summary.csv", summary_rows, summary_fields)

    output_file_names = [
        "literature_download_success_list.csv",
        "literature_download_failure_list.csv",
        "patents_download_success_list.csv",
        "patents_download_failure_list.csv",
        "download_attempts.csv",
        "download_summary.csv",
        "download_run_report.json",
        "download_state.sqlite3",
        "input_migration_report.v2.json",
        "download.log",
    ]
    migration_payload = {
        "schema_version": 2,
        "run_id": CURRENT_RUN_ID,
        "created_at": utc_now(),
        "non_destructive": True,
        "inputs": dict(INPUT_CONTRACT_REPORTS),
    }
    write_json_atomic(paths["migration_report"], migration_payload)
    report_path = paths["outputs"] / "download_run_report.json"
    report = {
        "run_id": CURRENT_RUN_ID,
        "invocation_id": CURRENT_INVOCATION_ID,
        "run_fingerprint": CURRENT_RUN_FINGERPRINT,
        "fingerprint_schema_version": DOWNLOAD_FINGERPRINT_SCHEMA_VERSION,
        "planner_semantics_version": DOWNLOAD_PLANNER_SEMANTICS_VERSION,
        "ledger_schema_version": DOWNLOAD_LEDGER_SCHEMA_VERSION,
        "run_recovery": (
            ACTIVE_DOWNLOAD_LEDGER.run_snapshot(CURRENT_RUN_ID)
            if ACTIVE_DOWNLOAD_LEDGER is not None
            else {}
        ),
        "status": workflow_status.value,
        "ok": workflow_status is WorkflowStatus.COMPLETE,
        "completion_scope": (
            "channel_plan_probe"
            if config.probe_channel_plan
            else "dry_run"
            if config.dry_run
            else "artifact_download"
        ),
        "artifact_completion_evaluated": not (config.dry_run or config.probe_channel_plan),
        "created_at": utc_now(),
        "config": sanitize_config(config),
        "runtime_config": {
            "path": str(paths["config"]),
            "exists": paths["config"].exists(),
            "env": list(RUNTIME_CONFIG_ENV_NAMES),
        },
        "paths": {key: relpath(value) for key, value in paths.items() if key in {"metadata_root", "pdf_root", "literature_csv", "patents_csv", "literature_v2", "patents_v2", "handoff_manifest_v2", "legacy_search_state", "literature_pdf", "patents_pdf", "outputs", "download_state", "migration_report", "download_auth_state"}},
        "input_files": {
            "literature_csv": file_report(paths["literature_csv"]),
            "patents_csv": file_report(paths["patents_csv"]),
            "literature_v2": file_report(paths["literature_v2"]),
            "patents_v2": file_report(paths["patents_v2"]),
            "handoff_manifest_v2": file_report(paths["handoff_manifest_v2"]),
            "legacy_search_state": file_report(paths["legacy_search_state"]),
        },
        "input_contracts": dict(INPUT_CONTRACT_REPORTS),
        "output_files": {name: file_report(paths["outputs"] / name) for name in output_file_names},
        "summary": summary_rows,
        "result_status_counts": {
            "literature": result_status_counts(literature_results),
            "patents": result_status_counts(patent_results),
        },
        "failure_reason_counts": {
            "literature": failure_reason_counts(literature_results),
            "patents": failure_reason_counts(patent_results),
        },
        "attempt_counters": attempt_counters(attempts),
        "dry_run_count": {
            "literature": literature_stats.dry_run_count,
            "patents": patent_stats.dry_run_count,
        },
        "excluded_records": excluded_records,
        "auth": {
            "enabled": config.auth_enabled,
            "path": config.path,
            "school_configured": bool(config.school.strip()),
            "state_dir": relpath(paths["download_auth_state"]),
            "stored_state_count": len(list(paths["download_auth_state"].glob("*.auth.json"))) if paths["download_auth_state"].exists() else 0,
        },
        "download_maps": {
            "literature": list(literature_download_path_map.keys()),
            "patents": list(patents_download_path_map.keys()),
        },
        "registry": {
            "registry_version": REGISTRY_VERSION,
            "snapshot": registry_snapshot(),
        },
        "channel_strategies": {
            "literature": channel_strategy_snapshot(literature_download_path_map, LITERATURE_CHANNEL_METHOD_TAGS),
            "patents": channel_strategy_snapshot(patents_download_path_map, PATENT_CHANNEL_METHOD_TAGS),
        },
        "known_skipped_channels": dict(KNOWN_SKIPPED_DOWNLOAD_CHANNELS),
        "active_channel_cooldowns": channel_cooldown_snapshot(),
        "active_domain_cooldowns": domain_cooldown_snapshot(),
        "external_control": {
            "external_control_timeout_seconds": external_control_timeout_seconds(),
            "chromium_control_timeout_seconds": chromium_control_timeout_seconds(),
            "chrome_control_timeout_seconds": chrome_control_timeout_seconds(),
            "hook_prefers_chrome": hook_prefers_chrome(),
            "local_chrome_available": bool(local_chrome_executable()),
            "local_chrome_path": local_chrome_executable(),
            "security_challenge_hook_configured": bool(os.getenv("LAPS_SECURITY_CHALLENGE_HOOK", "").strip() or os.getenv("LAPS_CHALLENGE_HOOK_COMMAND", "").strip()),
            "security_challenge_hook_timeout_seconds": challenge_hook_timeout_seconds(),
            "auth_control_hook_configured": bool(os.getenv("LAPS_AUTH_CONTROL_HOOK", "").strip() or os.getenv("LAPS_LOGIN_HOOK_COMMAND", "").strip()),
            "auth_control_hook_timeout_seconds": auth_control_hook_timeout_seconds(),
            "codex_extension_control_enabled": codex_extension_control_enabled(),
            "codex_extension_control_hook_configured": bool(os.getenv("LAPS_CODEX_EXTENSION_CONTROL_HOOK", "").strip()),
            "codex_extension_control_timeout_seconds": codex_extension_control_timeout_seconds(),
            "auth_control_verify_seconds": auth_control_verify_seconds(),
            "auth_manual_timeout_seconds": manual_auth_timeout_seconds(),
            "verification_manual_timeout_seconds": verification_manual_timeout_seconds(),
        },
        "environment": {
            "command_timeout_seconds": environment_command_timeout_seconds(),
            "lock_timeout_seconds": environment_lock_timeout_seconds(),
            "lock_path": relpath(environment_lock_path()),
            "python_packages": relpath(paths["python_packages"]),
            "playwright_browsers": relpath(paths["playwright_browsers"]),
            "legacy_playwright_browsers": relpath(paths["legacy_playwright_browsers"]),
        },
        "api_config": {
            "config_path": str(get_api_config_path() or ""),
            "configured_keys": sorted(key for key in API_CONFIG_VALUES if API_CONFIG_VALUES.get(key)),
        },
        "git_repository": git_repository_snapshot(),
    }
    write_json_atomic(report_path, report)
    report["output_files"]["download_run_report.json"] = file_report(report_path)
    write_json_atomic(report_path, report)
    return workflow_status


def download_channel_has_browser_path(method_tags: tuple[str, ...]) -> bool:
    return (
        "no_browser_fallback" not in method_tags
        and bool(DOWNLOAD_BROWSER_METHOD_TAGS.intersection(method_tags))
    )


def channel_inventory_snapshot() -> dict[str, Any]:
    ensure_literature_download_map_loaded()
    ensure_patents_download_map_loaded()

    def rows(
        record_type: str,
        channel_map: OrderedDict[str, str],
        parser_map: Mapping[str, Callable[..., list[str]]],
        tag_map: Mapping[str, tuple[str, ...]],
    ) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        specs = {
            spec.display_name: spec
            for spec in get_download_adapters(record_type)  # type: ignore[arg-type]
        }
        for order, (channel, template) in enumerate(channel_map.items(), start=1):
            parser = parser_map.get(channel)
            spec = specs.get(channel)
            method_tags = tag_map.get(channel, ())
            browser_path_declared = download_channel_has_browser_path(method_tags)
            output.append(
                {
                    "record_type": record_type,
                    "order": order,
                    "channel": channel,
                    "template": template,
                    "parser": getattr(parser, "__name__", "") if parser else "",
                    "actual_adapter": spec.actual_adapter if spec else "",
                    "fallback_resolver": spec.fallback_resolver if spec else "",
                    "required_locators": list(spec.required_locators) if spec else [],
                    "auth_scope": spec.auth_scope if spec else "unknown",
                    "config_keys": list(spec.config_keys) if spec else [],
                    "capabilities": list(spec.capabilities) if spec else [],
                    "default_enabled": bool(spec.default_enabled) if spec else True,
                    "method_tags": list(method_tags),
                    "browser_path_declared": browser_path_declared,
                    "browser_escalation_controller": (
                        COMMON_BROWSER_ESCALATION_CONTROLLER
                        if browser_path_declared
                        else ""
                    ),
                    "browser_escalation_policy": (
                        browser_escalation_policy_contract()
                        if browser_path_declared
                        else {}
                    ),
                    "control_authorization": (
                        control_authorization_contract()
                        if browser_path_declared
                        else {}
                    ),
                    "dedicated_parser_registered": bool(parser),
                }
            )
        return output

    literature_rows = rows("literature", literature_download_path_map, LITERATURE_CHANNEL_PARSERS, LITERATURE_CHANNEL_METHOD_TAGS)
    patent_rows = rows("patent", patents_download_path_map, PATENT_CHANNEL_PARSERS, PATENT_CHANNEL_METHOD_TAGS)
    all_rows = [*literature_rows, *patent_rows]
    legacy_metadata_shortcuts = {"metadata_" + "direct_pdf_url", "metadata_" + "full_text_url"}
    return {
        "created_at": utc_now(),
        "registry_version": REGISTRY_VERSION,
        "browser_escalation_policy": browser_escalation_policy_contract(),
        "control_authorization": control_authorization_contract(),
        "counts": {
            "literature_channels": len(literature_rows),
            "patent_channels": len(patent_rows),
        },
        "channels": {
            "literature": literature_rows,
            "patents": patent_rows,
        },
        "missing_parsers": {
            "literature": [row["channel"] for row in literature_rows if not row["parser"]],
            "patents": [row["channel"] for row in patent_rows if not row["parser"]],
        },
        "metadata_shortcut_channels_present": [
            row["channel"]
            for row in all_rows
            if row["channel"] in legacy_metadata_shortcuts
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download literature and patent PDFs from existing metadata CSV files.")
    parser.add_argument("--dry-run", action="store_true", help="Check environment, config, CSVs, and maps without downloading PDFs.")
    parser.add_argument("--probe-channel-plan", action="store_true", help="Emit selected per-channel attempts without calling APIs, browsers, web pages, or PDF downloads.")
    parser.add_argument("--literature-only", action="store_true", help="Only process literature metadata.")
    parser.add_argument("--patents-only", action="store_true", help="Only process patent metadata.")
    parser.add_argument("--batch-name", default="", help="Batch directory name under default metadata/pdf roots.")
    parser.add_argument("--metadata-root", default="", help="Exact metadata batch root. Contains literature_metadata_list and patents_metadata_list.")
    parser.add_argument("--pdf-root", default="", help="Exact PDF batch root. Contains literature_pdf, patents_pdf, and outputs.")
    parser.add_argument("--status", action="store_true", help="Print current download progress for the selected batch and exit.")
    parser.add_argument("--channel-inventory", action="store_true", help="Print channel order, parser coverage, and method tags as JSON without network access.")
    parser.add_argument("--prepare-runtime", action="store_true", help="Prepare local Python/Playwright runtime and exit before metadata or download work.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum records to process per record type.")
    parser.add_argument("--channel", action="append", default=[], help="Only try channels whose names contain this value. Can be repeated.")
    parser.add_argument("--exact-channel", action="append", default=[], help="Only try channels whose names exactly match this value. Can be repeated.")
    parser.add_argument("--disable-channel", action="append", default=[], help="Explicitly disable an exact channel name. Can be repeated; all channels are enabled by default.")
    parser.add_argument(
        "--input-contract",
        choices=("auto", "v2", "legacy"),
        default="auto",
        help="Select metadata input contract. auto prefers v2 JSONL and non-destructively falls back to legacy CSV.",
    )
    parser.add_argument("--doi", action="append", default=[], help="Only process literature records matching this DOI. Can be repeated.")
    parser.add_argument("--publication-number", action="append", default=[], help="Only process patent records matching this publication number. Can be repeated.")
    parser.add_argument("--patent-id", action="append", default=[], help="Alias for --publication-number. Can be repeated.")
    parser.add_argument("--force", action="store_true", help="Re-download even when a valid target PDF already exists.")
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Start a new logical run while still reusing validated artifacts and persistent cooldowns.",
    )
    parser.add_argument("--headful", action="store_true", help="Run browser in headful mode for debugging authenticated pages.")
    parser.add_argument("--auth-check", action="store_true", help="Check authenticated browser login flows and write auth_check_report.csv.")
    parser.add_argument("--auth-channel", action="append", default=[], help="Limit --auth-check to channels whose names contain this value. Use exact:<channel> for an exact match. Can be repeated.")
    parser.add_argument("--exact-auth-channel", action="append", default=[], help="Limit --auth-check to channels whose names exactly match this value. Can be repeated.")
    parser.add_argument("--auth-no-state-reuse", action="store_true", help="Force --auth-check to perform a fresh login instead of reusing storage_state.")
    parser.add_argument("--external-control-timeout-seconds", type=int, default=None, help="Default timeout for external control hooks when a hook-specific timeout is not set.")
    parser.add_argument("--security-challenge-hook-timeout-seconds", type=int, default=None, help="Timeout for security challenge external control hooks.")
    parser.add_argument("--auth-control-hook-timeout-seconds", type=int, default=None, help="Timeout for authentication external control hooks.")
    parser.add_argument("--auth-control-verify-seconds", type=int, default=None, help="Seconds to wait while verifying login after an authentication hook returns retry.")
    parser.add_argument("--auth-manual-timeout-seconds", type=int, default=None, help="Seconds to wait for manual visible-browser authentication when no auth hook is configured.")
    parser.add_argument("--verification-manual-timeout-seconds", type=int, default=None, help="Seconds to wait for external verification responses after a hook returns manual_pending.")
    parser.add_argument("--chromium-control-timeout-seconds", type=int, default=None, help="Default timeout for Codex hook handoff to bundled Chromium.")
    parser.add_argument("--chrome-control-timeout-seconds", type=int, default=None, help="Default timeout for hooks that delegate verification to local Chrome.")
    parser.add_argument("--codex-extension-control-timeout-seconds", type=int, default=None, help="Timeout for optional Codex Chrome Extension handoff after Playwright Chromium/Chrome fallback fails.")
    parser.add_argument("--env-command-timeout-seconds", type=int, default=None, help="Timeout for environment setup commands such as pip and Playwright install.")
    parser.add_argument("--env-lock-timeout-seconds", type=int, default=None, help="Timeout while waiting for another process to finish environment setup.")
    args = parser.parse_args(argv)
    if args.literature_only and args.patents_only:
        parser.error("--literature-only and --patents-only cannot be used together")
    if args.batch_name and (args.metadata_root or args.pdf_root):
        parser.error("--batch-name cannot be combined with --metadata-root or --pdf-root; pass exact roots or a batch name, not both")
    if bool(args.metadata_root) != bool(args.pdf_root):
        parser.error("--metadata-root and --pdf-root must be provided together")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    for attr in (
        "external_control_timeout_seconds",
        "security_challenge_hook_timeout_seconds",
        "auth_control_hook_timeout_seconds",
        "auth_control_verify_seconds",
        "verification_manual_timeout_seconds",
        "chromium_control_timeout_seconds",
        "chrome_control_timeout_seconds",
        "codex_extension_control_timeout_seconds",
        "env_command_timeout_seconds",
        "env_lock_timeout_seconds",
    ):
        if getattr(args, attr) is not None and getattr(args, attr) < 1:
            parser.error(f"--{attr.replace('_', '-')} must be positive")
    if args.auth_manual_timeout_seconds is not None and args.auth_manual_timeout_seconds < 10:
        parser.error("--auth-manual-timeout-seconds must be at least 10")
    if args.verification_manual_timeout_seconds is not None and args.verification_manual_timeout_seconds < 10:
        parser.error("--verification-manual-timeout-seconds must be at least 10")
    return args


def count_csv_rows(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    total = 0
    for chunk in iter_csv_chunks(path):
        total += len(chunk)
    return total


def count_literature_missing_doi_rows(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    total = 0
    for chunk in iter_csv_chunks(path):
        for row in chunk:
            if not normalize_doi(get_field(row, LITERATURE_DOI_ALIASES)):
                total += 1
    return total


def count_literature_missing_doi_and_pdf_url_rows(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    total = 0
    for chunk in iter_csv_chunks(path):
        for row in chunk:
            if not normalize_doi(
                get_field(row, LITERATURE_DOI_ALIASES)
            ) and not normalize_literature_pdf_url(
                get_field(row, LITERATURE_URL_ALIASES)
            ):
                total += 1
    return total


def count_pdf_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.glob("*.pdf") if item.is_file())


def latest_file_time(path: Path) -> str:
    if not path.exists():
        return ""
    newest = path if path.is_file() else max((item for item in path.rglob("*") if item.is_file()), key=lambda item: item.stat().st_mtime, default=None)
    if newest is None:
        return ""
    return datetime.fromtimestamp(newest.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")


def print_download_status(paths: dict[str, Path]) -> None:
    payload = {
        "metadata_root": str(paths["metadata_root"].resolve()),
        "pdf_root": str(paths["pdf_root"].resolve()),
        "literature_csv": str(paths["literature_csv"].resolve()),
        "patents_csv": str(paths["patents_csv"].resolve()),
        "literature_metadata_rows": count_csv_rows(paths["literature_csv"]),
        "literature_missing_doi_rows": count_literature_missing_doi_rows(paths["literature_csv"]),
        "literature_missing_doi_and_pdf_url_rows": count_literature_missing_doi_and_pdf_url_rows(
            paths["literature_csv"]
        ),
        "patent_metadata_rows": count_csv_rows(paths["patents_csv"]),
        "literature_v2": str(paths["literature_v2"].resolve()),
        "literature_v2_exists": paths["literature_v2"].exists(),
        "patents_v2": str(paths["patents_v2"].resolve()),
        "patents_v2_exists": paths["patents_v2"].exists(),
        "handoff_manifest_v2": str(paths["handoff_manifest_v2"].resolve()),
        "handoff_manifest_v2_exists": paths["handoff_manifest_v2"].exists(),
        "legacy_search_state": str(paths["legacy_search_state"].resolve()),
        "legacy_search_state_exists": paths["legacy_search_state"].exists(),
        "literature_pdf_count": count_pdf_files(paths["literature_pdf"]),
        "patent_pdf_count": count_pdf_files(paths["patents_pdf"]),
        "outputs": str(paths["outputs"].resolve()),
        "download_attempt_rows": count_csv_rows(paths["outputs"] / "download_attempts.csv"),
        "literature_success_rows": count_csv_rows(paths["outputs"] / "literature_download_success_list.csv"),
        "literature_failure_rows": count_csv_rows(paths["outputs"] / "literature_download_failure_list.csv"),
        "patent_success_rows": count_csv_rows(paths["outputs"] / "patents_download_success_list.csv"),
        "patent_failure_rows": count_csv_rows(paths["outputs"] / "patents_download_failure_list.csv"),
        "download_report": str((paths["outputs"] / "download_run_report.json").resolve()),
        "download_state": str(paths["download_state"].resolve()),
        "download_state_exists": paths["download_state"].exists(),
        "latest_output_update_utc": latest_file_time(paths["outputs"]),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def runtime_preparation_payload(
    paths: dict[str, Path],
    environment_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": True,
        "prepared_runtime": True,
        "venv": relpath(TOOLS_DIR / ".venv"),
        "playwright_browsers": relpath(paths["legacy_playwright_browsers"]),
        "legacy_python_packages": relpath(paths["python_packages"]),
        "legacy_playwright_browsers": relpath(paths["playwright_browsers"]),
        "playwright_importable": True,
        "chromium_installed": chromium_installed(paths["playwright_browsers"]) or chromium_installed(paths["legacy_playwright_browsers"]),
        "environment": {
            "command_timeout_seconds": environment_command_timeout_seconds(),
            "lock_timeout_seconds": environment_lock_timeout_seconds(),
            "lock_path": relpath(environment_lock_path()),
        },
        "environment_report": environment_report or {},
    }


def write_environment_bootstrap_failure_report(paths: dict[str, Path], config: DownloadConfig | None, exc: EnvironmentBootstrapError) -> None:
    paths["outputs"].mkdir(parents=True, exist_ok=True)
    report = {
        "status": WorkflowStatus.FAILED.value,
        "ok": False,
        "created_at": utc_now(),
        "failure_stage": "environment_bootstrap",
        "reason": sanitize_text_for_output(exc.reason),
        "message": sanitize_text_for_output(exc),
        "command": sanitize_text_for_output(" ".join(exc.command[:4])) if exc.command else "",
        "config": sanitize_config(config) if config is not None else {},
        "runtime_config": {
            "path": str(paths["config"]),
            "exists": paths["config"].exists(),
            "env": list(RUNTIME_CONFIG_ENV_NAMES),
        },
        "paths": {key: relpath(value) for key, value in paths.items() if key in {"metadata_root", "pdf_root", "outputs"}},
        "environment": {
            "command_timeout_seconds": environment_command_timeout_seconds(),
            "lock_timeout_seconds": environment_lock_timeout_seconds(),
            "lock_path": relpath(environment_lock_path()),
        },
        "git_repository": git_repository_snapshot(),
    }
    write_json_atomic(paths["outputs"] / "download_run_report.json", report)


def write_fatal_failure_report(
    paths: dict[str, Path],
    config: DownloadConfig | None,
    stage: str,
    exc: Exception,
) -> None:
    paths["outputs"].mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": CURRENT_RUN_ID,
        "status": WorkflowStatus.FAILED.value,
        "ok": False,
        "created_at": utc_now(),
        "failure_stage": stage,
        "reason_code": request_exception_reason(exc),
        "error_type": exc.__class__.__name__,
        "message": sanitize_text_for_output(exc)[:1000],
        "config": sanitize_config(config) if config is not None else {},
        "paths": {
            key: relpath(value)
            for key, value in paths.items()
            if key in {"metadata_root", "pdf_root", "outputs", "download_state"}
        },
        "registry_version": REGISTRY_VERSION,
    }
    write_json_atomic(paths["outputs"] / "download_run_report.json", payload)


def apply_environment_timeout_args(args: argparse.Namespace) -> None:
    arg_env_map = {
        "env_command_timeout_seconds": "LAPS_ENV_COMMAND_TIMEOUT_SECONDS",
        "env_lock_timeout_seconds": "LAPS_ENV_LOCK_TIMEOUT_SECONDS",
    }
    for attr, env_name in arg_env_map.items():
        value = getattr(args, attr, None)
        if value is not None:
            os.environ[env_name] = str(value)


def apply_external_control_timeout_args(args: argparse.Namespace) -> None:
    arg_env_map = {
        "external_control_timeout_seconds": "LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS",
        "security_challenge_hook_timeout_seconds": "LAPS_SECURITY_CHALLENGE_HOOK_TIMEOUT_SECONDS",
        "auth_control_hook_timeout_seconds": "LAPS_AUTH_CONTROL_HOOK_TIMEOUT_SECONDS",
        "auth_control_verify_seconds": "LAPS_AUTH_CONTROL_VERIFY_SECONDS",
        "auth_manual_timeout_seconds": "LAPS_AUTH_MANUAL_TIMEOUT_SECONDS",
        "verification_manual_timeout_seconds": "LAPS_VERIFICATION_MANUAL_TIMEOUT_SECONDS",
        "chromium_control_timeout_seconds": "LAPS_CHROMIUM_CONTROL_TIMEOUT_SECONDS",
        "chrome_control_timeout_seconds": "LAPS_CHROME_CONTROL_TIMEOUT_SECONDS",
        "codex_extension_control_timeout_seconds": "LAPS_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS",
    }
    for attr, env_name in arg_env_map.items():
        value = getattr(args, attr, None)
        if value is not None:
            os.environ[env_name] = str(value)


def print_run_summary(literature_stats: RecordStats, patent_stats: RecordStats, paths: dict[str, Path]) -> None:
    print(f"Literature processed: {literature_stats.total_records}")
    print(f"Literature valid input records: {literature_stats.valid_records}")
    print(f"Literature missing DOI/input id: {literature_stats.missing_identifier_records}")
    print(f"Literature success: {literature_stats.success_count}")
    print(f"Literature failure: {literature_stats.failure_count}")
    print(f"Patent processed: {patent_stats.total_records}")
    print(f"Patent valid input records: {patent_stats.valid_records}")
    print(f"Patent missing input id: {patent_stats.missing_identifier_records}")
    print(f"Patent success: {patent_stats.success_count}")
    print(f"Patent failure: {patent_stats.failure_count}")
    print(f"Outputs: {paths['outputs'].resolve()}")


def empty_stats(record_type: str) -> RecordStats:
    now = utc_now()
    return RecordStats(record_type=record_type, started_at=now, finished_at=now)


def main(argv: list[str] | None = None) -> int:
    global ACTIVE_DOWNLOAD_LEDGER, CURRENT_INVOCATION_ID, CURRENT_RUN_FINGERPRINT, CURRENT_RUN_ID, CURRENT_RUN_RESUMED
    args = parse_args(argv)
    apply_environment_timeout_args(args)
    apply_external_control_timeout_args(args)
    paths = discover_paths(args)
    if args.status:
        print_download_status(paths)
        return 0
    if args.channel_inventory:
        load_download_maps_from_search_script(paths["search_script"])
        print(json.dumps(channel_inventory_snapshot(), ensure_ascii=False, indent=2))
        return 0
    logger = setup_environment_logging()
    config: DownloadConfig | None = None
    stage = "environment_bootstrap"
    run_started = False
    try:
        environment_report = ensure_tools_environment(paths, logger)
        if args.prepare_runtime:
            print(
                json.dumps(
                    runtime_preparation_payload(paths, environment_report),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            logger.info("Runtime preparation finished")
            return 0

        ensure_output_directories(paths)
        logger = setup_logging(paths["outputs"])
        logger.info("Starting PDF download workflow")
        stage = "configuration"
        ensure_local_git_repository(logger)
        load_api_user_config_into_env(logger)
        config = load_config(paths["config"], args)
        logger.info("Runtime config loaded: %s", json.dumps(sanitize_config(config), ensure_ascii=False))
        load_download_maps_from_search_script(paths["search_script"])
        validate_channel_filters(config)
        logger.info("Literature channels: %s", len(literature_download_path_map))
        logger.info("Patent channels: %s", len(patents_download_path_map))

        if args.auth_check:
            rows = run_auth_checks(config, paths, logger, args)
            report_path = write_auth_check_report(rows, paths)
            print_auth_check_summary(rows, report_path)
            logger.info("Authenticated login check finished")
            return 0

        ACTIVE_DOWNLOAD_LEDGER = DownloadStateLedger(paths["download_state"])
        process_literature = not args.patents_only
        process_patents = not args.literature_only
        if config.probe_channel_plan:
            process_literature = probe_record_type_enabled("literature", args, config, logger)
            process_patents = probe_record_type_enabled("patent", args, config, logger)

        stage = "input_contract"
        prepared_inputs: dict[str, PreparedRecordInput] = {}
        try:
            selected_record_types = tuple(
                record_type
                for record_type, enabled in (
                    ("literature", process_literature),
                    ("patent", process_patents),
                )
                if enabled
            )
            resolved_bundle = resolve_input_bundle(
                config.input_contract,
                paths["literature_v2"],
                paths["patents_v2"],
                paths["literature_csv"],
                paths["patents_csv"],
                paths.get("legacy_search_state"),
                record_types=selected_record_types,
            )
            if process_literature:
                prepared_inputs["literature"] = prepare_record_input(
                    "literature",
                    paths["literature_csv"],
                    config,
                    paths,
                    resolved_bundle.contracts["literature"],
                )
            if process_patents:
                prepared_inputs["patent"] = prepare_record_input(
                    "patent",
                    paths["patents_csv"],
                    config,
                    paths,
                    resolved_bundle.contracts["patent"],
                )
        except Exception as exc:
            if ACTIVE_DOWNLOAD_LEDGER.has_unfinished_runs():
                raise RuntimeError("resume_input_unverifiable") from exc
            raise
        fingerprint, fingerprint_payload = build_download_run_fingerprint(
            prepared_inputs,
            config,
            ACTIVE_DOWNLOAD_LEDGER.fingerprint_salt(),
        )
        resume_policy = "force" if config.force else "no_resume" if config.no_resume else "auto"
        run_info = ACTIVE_DOWNLOAD_LEDGER.start_or_resume_run(
            fingerprint,
            fingerprint_payload,
            config,
            resume_policy=resume_policy,
            report_path=paths["outputs"] / "download_run_report.json",
        )
        CURRENT_RUN_ID = str(run_info["run_id"])
        CURRENT_INVOCATION_ID = str(run_info["invocation_id"])
        CURRENT_RUN_FINGERPRINT = fingerprint
        CURRENT_RUN_RESUMED = bool(run_info.get("resumed"))
        # From this point onward the process owns a persisted writer lease.  If
        # plan verification or persistence fails, the exception path must mark
        # this invocation interrupted and release that lease immediately.
        run_started = True
        ACTIVE_DOWNLOAD_LEDGER.store_run_plan(
            CURRENT_RUN_ID,
            {record_type: item.rows for record_type, item in prepared_inputs.items()},
        )
        if str(run_info.get("previous_lifecycle") or "") == "finalizing":
            stage = "finalization_recovery"
            report_path = paths["outputs"] / "download_run_report.json"
            evidence = ACTIVE_DOWNLOAD_LEDGER.finalization_report_evidence(
                CURRENT_RUN_ID,
                report_path,
            )
            if bool(evidence.get("complete")):
                recovered_status = WorkflowStatus(str(evidence.get("status") or "failed"))
                ACTIVE_DOWNLOAD_LEDGER.finish_run(
                    CURRENT_RUN_ID,
                    recovered_status.value,
                    report_path,
                )
                run_started = False
                logger.info(
                    "Recovered finalized report without network access: run_id=%s status=%s",
                    CURRENT_RUN_ID,
                    recovered_status.value,
                )
                return status_to_exit_code(recovered_status)
            logger.warning(
                "Finalizing run requires ledger rematerialization without network: %s",
                evidence.get("reason_code"),
            )
            for record_type, prepared in prepared_inputs.items():
                INPUT_CONTRACT_REPORTS[record_type] = dict(
                    prepared.resolved.migration_report
                )
            (
                literature_results,
                patent_results,
                literature_stats,
                patent_stats,
            ) = reconstruct_finalizing_results(
                ACTIVE_DOWNLOAD_LEDGER,
                CURRENT_RUN_ID,
                prepared_inputs,
            )
            for result in [*literature_results, *patent_results]:
                ACTIVE_DOWNLOAD_LEDGER.mark_record_result(result)
            recovered_status = workflow_completion_status(
                literature_stats,
                patent_stats,
                config,
            )
            ACTIVE_DOWNLOAD_LEDGER.begin_finalization(
                CURRENT_RUN_ID,
                recovered_status.value,
                report_path,
            )
            workflow_status = write_results(
                literature_results,
                patent_results,
                literature_stats,
                patent_stats,
                config,
                paths,
            )
            ACTIVE_DOWNLOAD_LEDGER.finish_run(
                CURRENT_RUN_ID,
                workflow_status.value,
                report_path,
            )
            run_started = False
            print_run_summary(literature_stats, patent_stats, paths)
            return status_to_exit_code(workflow_status)
        stage = "execution"

        if args.dry_run:
            logger.info("Dry run enabled; no PDF downloads will be attempted.")
        if config.probe_channel_plan:
            logger.info("Channel plan probe enabled; no APIs, browsers, web pages, or PDF downloads will be attempted.")

        initialize_attempt_log(paths)

        literature_results: list[DownloadResult] = []
        patent_results: list[DownloadResult] = []
        literature_stats = empty_stats("literature")
        patent_stats = empty_stats("patent")

        if process_literature:
            literature_results, literature_stats = process_records(
                "literature", prepared_inputs["literature"], config, paths, logger
            )
        if process_patents:
            patent_results, patent_stats = process_records(
                "patent", prepared_inputs["patent"], config, paths, logger
            )

        expected_status = workflow_completion_status(
            literature_stats,
            patent_stats,
            config,
        )
        stage = "finalization"
        ACTIVE_DOWNLOAD_LEDGER.begin_finalization(
            CURRENT_RUN_ID,
            expected_status.value,
            paths["outputs"] / "download_run_report.json",
        )
        workflow_status = write_results(literature_results, patent_results, literature_stats, patent_stats, config, paths)
        ACTIVE_DOWNLOAD_LEDGER.finish_run(
            CURRENT_RUN_ID,
            workflow_status.value,
            paths["outputs"] / "download_run_report.json",
        )
        run_started = False
        print_run_summary(literature_stats, patent_stats, paths)
        logger.info("PDF download workflow finished with status=%s", workflow_status.value)
        return status_to_exit_code(workflow_status)
    except EnvironmentBootstrapError as exc:
        logger.error("Environment bootstrap failed: %s", exc)
        write_environment_bootstrap_failure_report(paths, config, exc)
        if run_started and ACTIVE_DOWNLOAD_LEDGER is not None:
            ACTIVE_DOWNLOAD_LEDGER.interrupt_run(CURRENT_RUN_ID, "environment_bootstrap_failed")
        return 1
    except ValueError as exc:
        logger.error("PDF download workflow failed: %s", exc)
        write_fatal_failure_report(paths, config, stage, exc)
        if run_started and ACTIVE_DOWNLOAD_LEDGER is not None:
            ACTIVE_DOWNLOAD_LEDGER.interrupt_run(CURRENT_RUN_ID, f"value_error:{stage}")
        return 2 if stage == "configuration" else 1
    except Exception as exc:
        logger.exception("PDF download workflow failed: %s", exc)
        write_fatal_failure_report(paths, config, stage, exc)
        if run_started and ACTIVE_DOWNLOAD_LEDGER is not None:
            ACTIVE_DOWNLOAD_LEDGER.interrupt_run(CURRENT_RUN_ID, f"exception:{exc.__class__.__name__}")
        return 1
    finally:
        if ACTIVE_DOWNLOAD_LEDGER is not None:
            close_ledger = getattr(ACTIVE_DOWNLOAD_LEDGER, "close", None)
            if callable(close_ledger):
                close_ledger()
        ACTIVE_DOWNLOAD_LEDGER = None
        CURRENT_RUN_RESUMED = False


if __name__ == "__main__":
    raise SystemExit(main())
