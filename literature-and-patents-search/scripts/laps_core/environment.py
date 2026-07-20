"""Read-only environment inspection and bounded runtime preparation for LAPS.

The public ``check_environment`` function never creates or updates files.  The
separate ``prepare_environment`` function is the only entry point that writes
the managed runtime, and it writes only ``tools/.venv``,
``tools/ms-playwright`` and the short-lived bootstrap lock.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping, NoReturn, Sequence


ENVIRONMENT_REPORT_SCHEMA = "laps_environment_report_v1"
DEFAULT_ENV_COMMAND_TIMEOUT_SECONDS = 600
DEFAULT_ENV_LOCK_TIMEOUT_SECONDS = 900
ENV_BOOTSTRAP_LOCK_NAME = ".environment_bootstrap.lock"
MINIMUM_PYTHON_VERSION = (3, 10)
CDP_READONLY_PROBE_METHOD = "Page.getFrameTree"

FULL_CAPABILITY_REMINDER = (
    "若想开启 Skill 的全部能力，需要完成这两件事情：\n"
    "1. 在普通 Chrome 中安装、启用并连接 Codex Chrome 插件；\n"
    "2. 为当前任务开启 full CDP 访问权限。"
)

REQUIREMENT_IMPORTS: dict[str, tuple[str, ...]] = {
    "playwright": ("playwright.async_api", "playwright.sync_api"),
    "httpx": ("httpx",),
    "pandas": ("pandas",),
    "beautifulsoup4": ("bs4",),
    "lxml": ("lxml",),
    "python-dateutil": ("dateutil",),
    "tenacity": ("tenacity",),
    "tqdm": ("tqdm",),
    "feedparser": ("feedparser",),
    "xmltodict": ("xmltodict",),
    "pydantic": ("pydantic",),
    "orjson": ("orjson",),
    "pypdf": ("pypdf",),
    "google-cloud-bigquery": ("google.cloud.bigquery",),
    "zeep": ("zeep",),
}


@dataclass(frozen=True)
class EnvironmentPaths:
    """Resolved paths for one installed or staged skill."""

    skill_root: Path
    scripts_dir: Path
    tools_dir: Path
    venv_dir: Path
    playwright_dir: Path
    requirements_path: Path
    hook_dir: Path
    legacy_python_packages_dir: Path
    legacy_playwright_dir: Path
    lock_path: Path

    @classmethod
    def from_skill_root(cls, skill_root: str | os.PathLike[str] | None = None) -> "EnvironmentPaths":
        root = (
            Path(skill_root).expanduser().resolve()
            if skill_root is not None
            else Path(__file__).resolve().parents[2]
        )
        tools = root / "tools"
        return cls(
            skill_root=root,
            scripts_dir=root / "scripts",
            tools_dir=tools,
            venv_dir=tools / ".venv",
            playwright_dir=tools / "ms-playwright",
            requirements_path=tools / "requirements.txt",
            hook_dir=tools / "codex_hooks",
            legacy_python_packages_dir=tools / "python_packages",
            legacy_playwright_dir=tools / "playwright-browsers",
            lock_path=tools / ENV_BOOTSTRAP_LOCK_NAME,
        )

    def report_paths(self) -> dict[str, str]:
        return {
            "skill_root": str(self.skill_root),
            "tools": str(self.tools_dir),
            "venv": str(self.venv_dir),
            "playwright_browsers": str(self.playwright_dir),
            "requirements": str(self.requirements_path),
        }


class EnvironmentBootstrapError(RuntimeError):
    """A preparation failure with a stable machine-readable reason."""

    def __init__(self, reason: str, message: str, command: Sequence[str] | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.command = list(command or ())


def _env_seconds(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def environment_command_timeout_seconds(explicit: int | None = None) -> int:
    if explicit is not None:
        return max(1, int(explicit))
    return _env_seconds(
        "LAPS_ENV_COMMAND_TIMEOUT_SECONDS",
        DEFAULT_ENV_COMMAND_TIMEOUT_SECONDS,
    )


def environment_lock_timeout_seconds(explicit: int | None = None) -> int:
    if explicit is not None:
        return max(1, int(explicit))
    return _env_seconds(
        "LAPS_ENV_LOCK_TIMEOUT_SECONDS",
        DEFAULT_ENV_LOCK_TIMEOUT_SECONDS,
    )


def venv_python_path(venv_dir: str | os.PathLike[str]) -> Path:
    root = Path(venv_dir)
    if os.name == "nt":
        return root / "Scripts" / "python.exe"
    return root / "bin" / "python"


def running_in_tools_venv(skill_root: str | os.PathLike[str] | None = None) -> bool:
    expected = EnvironmentPaths.from_skill_root(skill_root).venv_dir
    try:
        executable = Path(sys.executable).resolve()
        prefix = Path(sys.prefix).resolve()
        return expected.resolve() in executable.parents or prefix == expected.resolve()
    except OSError:
        return False


def _chromium_executable(browser_dir: Path) -> Path | None:
    if not browser_dir.is_dir():
        return None
    executable_names = {
        "chrome.exe",
        "chrome",
        "chromium",
        "headless_shell.exe",
        "headless_shell",
    }
    try:
        candidates = (
            candidate
            for candidate in browser_dir.rglob("*")
            if candidate.is_file() and candidate.name.casefold() in executable_names
        )
        for candidate in candidates:
            if os.name == "nt" or os.access(candidate, os.X_OK):
                return candidate.resolve()
    except OSError:
        return None
    return None


def runtime_environment(
    skill_root: str | os.PathLike[str] | None = None,
    *,
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a child-process environment without mutating ``os.environ``.

    The managed browser location is preferred.  The two historical locations
    remain read-compatible, but preparation never writes to them.
    """

    paths = EnvironmentPaths.from_skill_root(skill_root)
    env = dict(os.environ if base is None else base)
    if _chromium_executable(paths.playwright_dir) is not None:
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(paths.playwright_dir)
    elif _chromium_executable(paths.legacy_playwright_dir) is not None:
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(paths.legacy_playwright_dir)
    else:
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(paths.playwright_dir)

    if paths.legacy_python_packages_dir.is_dir():
        existing = env.get("PYTHONPATH", "")
        entries = [entry for entry in existing.split(os.pathsep) if entry]
        legacy = str(paths.legacy_python_packages_dir)
        if legacy not in entries:
            entries.append(legacy)
        env["PYTHONPATH"] = os.pathsep.join(entries)
    return env


def _isolated_runtime_environment(paths: EnvironmentPaths) -> dict[str, str]:
    env = dict(os.environ)
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(paths.playwright_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env.pop("PYTHONPATH", None)
    return env


def _run_readonly(
    args: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 60,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        env=dict(env) if env is not None else None,
        text=True,
        capture_output=True,
        timeout=max(1, timeout_seconds),
        check=False,
    )


def _parse_requirements(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.is_file():
        return [], ["requirements_file_missing"]
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return [], ["requirements_file_unreadable"]
    parsed: list[dict[str, Any]] = []
    errors: list[str] = []
    pattern = re.compile(r"^([A-Za-z0-9_.-]+)\s*>=\s*([A-Za-z0-9_.+-]+)$")
    for line_number, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = pattern.fullmatch(line)
        if match is None:
            errors.append(f"unsupported_requirement_line:{line_number}")
            continue
        distribution = match.group(1).casefold()
        parsed.append(
            {
                "distribution": distribution,
                "minimum_version": match.group(2),
                "imports": list(REQUIREMENT_IMPORTS.get(distribution, (distribution.replace("-", "_"),))),
            }
        )
    if not parsed and not errors:
        errors.append("requirements_file_empty")
    return parsed, errors


def _version_key(value: str) -> tuple[int, ...]:
    numeric = [int(part) for part in re.findall(r"\d+", value)]
    return tuple(numeric or (0,))


def _version_at_least(installed: str, minimum: str) -> bool:
    actual = _version_key(installed)
    expected = _version_key(minimum)
    width = max(len(actual), len(expected))
    return actual + (0,) * (width - len(actual)) >= expected + (0,) * (width - len(expected))


_PYTHON_ENVIRONMENT_PROBE = r'''
import importlib
import importlib.metadata
import json
import sys

requirements = json.loads(sys.argv[1])
rows = []
for requirement in requirements:
    distribution = requirement["distribution"]
    try:
        version = importlib.metadata.version(distribution)
    except Exception as exc:
        version = ""
        version_error = exc.__class__.__name__
    else:
        version_error = ""
    imports = {}
    for module_name in requirement["imports"]:
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            imports[module_name] = {"ok": False, "error": exc.__class__.__name__}
        else:
            imports[module_name] = {"ok": True, "error": ""}
    rows.append({
        "distribution": distribution,
        "installed_version": version,
        "version_error": version_error,
        "imports": imports,
    })
print("LAPS_ENV_PROBE_JSON=" + json.dumps({
    "python_version": list(sys.version_info[:3]),
    "python_executable": sys.executable,
    "packages": rows,
}, sort_keys=True))
'''


def _probe_python_environment(
    python_executable: Path,
    requirements: list[dict[str, Any]],
    paths: EnvironmentPaths,
    timeout_seconds: int,
) -> dict[str, Any]:
    try:
        completed = _run_readonly(
            [
                str(python_executable),
                "-B",
                "-c",
                _PYTHON_ENVIRONMENT_PROBE,
                json.dumps(requirements, ensure_ascii=True),
            ],
            env=_isolated_runtime_environment(paths),
            timeout_seconds=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": exc.__class__.__name__, "packages": []}
    marker = "LAPS_ENV_PROBE_JSON="
    payload_line = next(
        (line[len(marker) :] for line in reversed(completed.stdout.splitlines()) if line.startswith(marker)),
        "",
    )
    if completed.returncode != 0 or not payload_line:
        return {
            "ok": False,
            "error": "python_environment_probe_failed",
            "returncode": completed.returncode,
            "packages": [],
        }
    try:
        payload = json.loads(payload_line)
    except json.JSONDecodeError:
        return {"ok": False, "error": "python_environment_probe_invalid_json", "packages": []}
    payload["ok"] = True
    return payload


def _probe_pip(
    python_executable: Path,
    paths: EnvironmentPaths,
    timeout_seconds: int,
) -> dict[str, Any]:
    try:
        completed = _run_readonly(
            [str(python_executable), "-B", "-m", "pip", "--version"],
            env=_isolated_runtime_environment(paths),
            timeout_seconds=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": exc.__class__.__name__}
    return {
        "ok": completed.returncode == 0,
        "version": completed.stdout.strip() if completed.returncode == 0 else "",
        "returncode": completed.returncode,
    }


def _probe_pip_check(
    python_executable: Path,
    paths: EnvironmentPaths,
    timeout_seconds: int,
) -> dict[str, Any]:
    try:
        completed = _run_readonly(
            [str(python_executable), "-B", "-m", "pip", "check"],
            env=_isolated_runtime_environment(paths),
            timeout_seconds=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": exc.__class__.__name__}
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "detail": (completed.stdout or completed.stderr).strip()[:1000],
    }


def _relative_to_root(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _probe_helpers(
    paths: EnvironmentPaths,
    python_executable: Path | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    helper_files = sorted((paths.scripts_dir / "laps_core").glob("*.py"))
    hook_path = paths.hook_dir / "codex_external_control_hook.py"
    if hook_path.is_file():
        helper_files.append(hook_path)
    syntax_errors: list[dict[str, str]] = []
    for helper in helper_files:
        try:
            source = helper.read_text(encoding="utf-8-sig")
            compile(source, str(helper), "exec", dont_inherit=True)
        except (OSError, UnicodeError, SyntaxError) as exc:
            syntax_errors.append(
                {
                    "path": _relative_to_root(helper, paths.skill_root),
                    "error": exc.__class__.__name__,
                }
            )
    if not helper_files:
        return {"ok": False, "syntax_errors": [], "load_error": "helper_files_missing"}
    if syntax_errors:
        return {"ok": False, "syntax_errors": syntax_errors, "load_error": ""}
    if python_executable is None or not python_executable.is_file():
        return {"ok": False, "syntax_errors": [], "load_error": "venv_python_unavailable"}
    if not hook_path.is_file():
        return {"ok": False, "syntax_errors": [], "load_error": "hook_file_missing"}
    probe = (
        "import runpy,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "import laps_core;"
        "runpy.run_path(sys.argv[2],run_name='laps_environment_hook_probe')"
    )
    try:
        completed = _run_readonly(
            [
                str(python_executable),
                "-B",
                "-c",
                probe,
                str(paths.scripts_dir),
                str(hook_path),
            ],
            env=_isolated_runtime_environment(paths),
            timeout_seconds=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "syntax_errors": [], "load_error": exc.__class__.__name__}
    return {
        "ok": completed.returncode == 0,
        "syntax_errors": [],
        "load_error": "" if completed.returncode == 0 else "helper_import_failed",
        "returncode": completed.returncode,
    }


def _probe_node(paths: EnvironmentPaths, timeout_seconds: int) -> dict[str, Any]:
    node = shutil.which("node")
    helper = paths.hook_dir / "codex_ordinary_chrome_credential_fill.mjs"
    if not node:
        return {"status": "unavailable", "executable": "", "helper_syntax": "not_checked"}
    if not helper.is_file():
        return {"status": "unavailable", "executable": node, "helper_syntax": "missing"}
    try:
        version = _run_readonly([node, "--version"], timeout_seconds=timeout_seconds)
        syntax = _run_readonly([node, "--check", str(helper)], timeout_seconds=timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "unavailable",
            "executable": node,
            "helper_syntax": exc.__class__.__name__,
        }
    ready = version.returncode == 0 and syntax.returncode == 0
    return {
        "status": "ready" if ready else "unavailable",
        "executable": node,
        "version": version.stdout.strip() if version.returncode == 0 else "",
        "helper_syntax": "ready" if syntax.returncode == 0 else "invalid",
    }


def _find_ordinary_chrome() -> Path | None:
    configured = (
        os.getenv("LAPS_CHROME_EXECUTABLE", "").strip()
        or os.getenv("CODEX_HOOK_CHROME_EXECUTABLE", "").strip()
    )
    candidates: list[Path] = [Path(configured).expanduser()] if configured else []
    for command in ("chrome", "chrome.exe", "google-chrome", "google-chrome-stable", "chromium"):
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
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).casefold()
        if key in seen:
            continue
        seen.add(key)
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def _ready(value: bool, **details: Any) -> dict[str, Any]:
    return {"status": "ready" if value else "blocked", **details}


def _issue(
    issues: list[dict[str, str]],
    severity: str,
    code: str,
    message: str,
    remediation: str,
) -> None:
    issues.append(
        {
            "severity": severity,
            "code": code,
            "message": message,
            "remediation": remediation,
        }
    )


def check_environment(
    skill_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Inspect the skill runtime without creating, deleting or updating files."""

    paths = EnvironmentPaths.from_skill_root(skill_root)
    issues: list[dict[str, str]] = []
    required: dict[str, dict[str, Any]] = {}
    probe_timeout = min(60, environment_command_timeout_seconds())

    host_version = tuple(sys.version_info[:3])
    host_supported = host_version >= MINIMUM_PYTHON_VERSION
    required["python"] = _ready(
        host_supported,
        executable=sys.executable,
        version=".".join(str(part) for part in host_version),
        minimum=".".join(str(part) for part in MINIMUM_PYTHON_VERSION),
    )
    if not host_supported:
        _issue(
            issues,
            "blocked",
            "python_version_unsupported",
            "Python 3.10 or newer is required.",
            "Install Python 3.10+ and rerun environment preparation.",
        )

    requirements, requirement_parse_errors = _parse_requirements(paths.requirements_path)
    requirements_file_ready = not requirement_parse_errors
    required["requirements_file"] = _ready(
        requirements_file_ready,
        path=str(paths.requirements_path),
        entries=len(requirements),
        errors=requirement_parse_errors,
    )
    if not requirements_file_ready:
        _issue(
            issues,
            "blocked",
            requirement_parse_errors[0],
            "The production requirements file is missing or invalid.",
            "Restore tools/requirements.txt before preparing the runtime.",
        )

    python_executable = venv_python_path(paths.venv_dir)
    venv_python_exists = python_executable.is_file()
    required["venv"] = _ready(
        paths.venv_dir.is_dir() and venv_python_exists,
        path=str(paths.venv_dir),
        python=str(python_executable),
    )
    if not venv_python_exists:
        _issue(
            issues,
            "blocked",
            "tools_venv_missing",
            "The managed tools/.venv Python environment is not ready.",
            "Run check_environment.py --prepare.",
        )

    python_probe: dict[str, Any] = {"ok": False, "packages": []}
    if venv_python_exists and requirements_file_ready:
        python_probe = _probe_python_environment(
            python_executable,
            requirements,
            paths,
            probe_timeout,
        )
    venv_python_supported = bool(
        python_probe.get("ok")
        and tuple(python_probe.get("python_version") or ()) >= MINIMUM_PYTHON_VERSION
    )
    required["venv_python"] = _ready(
        venv_python_supported,
        executable=str(python_executable),
        version=".".join(str(part) for part in (python_probe.get("python_version") or ())),
        error=str(python_probe.get("error") or ""),
    )
    if venv_python_exists and not venv_python_supported:
        _issue(
            issues,
            "blocked",
            "venv_python_unusable",
            "The managed virtual-environment Python could not be used or is older than 3.10.",
            "Recreate tools/.venv with Python 3.10+.",
        )

    pip_probe = (
        _probe_pip(python_executable, paths, probe_timeout)
        if venv_python_exists
        else {"ok": False, "error": "venv_python_unavailable"}
    )
    required["pip"] = _ready(
        bool(pip_probe.get("ok")),
        version=str(pip_probe.get("version") or ""),
        error=str(pip_probe.get("error") or ""),
    )
    if venv_python_exists and not pip_probe.get("ok"):
        _issue(
            issues,
            "blocked",
            "pip_unavailable",
            "pip is unavailable in tools/.venv.",
            "Run environment preparation to restore pip.",
        )

    probed_packages = {
        str(row.get("distribution") or "").casefold(): row
        for row in python_probe.get("packages") or ()
        if isinstance(row, dict)
    }
    requirement_items: list[dict[str, Any]] = []
    for requirement in requirements:
        distribution = requirement["distribution"]
        probe = probed_packages.get(distribution, {})
        installed_version = str(probe.get("installed_version") or "")
        imports = probe.get("imports") if isinstance(probe.get("imports"), dict) else {}
        imports_ready = bool(imports) and all(
            isinstance(value, dict) and value.get("ok") is True for value in imports.values()
        )
        version_ready = bool(installed_version) and _version_at_least(
            installed_version,
            requirement["minimum_version"],
        )
        if not installed_version:
            item_status = "missing"
        elif not version_ready:
            item_status = "outdated"
        elif not imports_ready:
            item_status = "import_failed"
        else:
            item_status = "ready"
        item = {
            **requirement,
            "installed_version": installed_version,
            "import_results": imports,
            "status": item_status,
        }
        requirement_items.append(item)
        if item_status != "ready":
            _issue(
                issues,
                "blocked",
                f"requirement_{item_status}:{distribution}",
                f"Required distribution {distribution} is {item_status.replace('_', ' ')}.",
                "Run check_environment.py --prepare.",
            )
    all_requirements_ready = bool(requirement_items) and all(
        item["status"] == "ready" for item in requirement_items
    )
    required["requirements"] = _ready(
        requirements_file_ready and all_requirements_ready,
        items=requirement_items,
    )

    pypdf_item = next(
        (item for item in requirement_items if item["distribution"] == "pypdf"),
        None,
    )
    pypdf_ready = bool(pypdf_item and pypdf_item["status"] == "ready")
    required["pypdf"] = _ready(
        pypdf_ready,
        installed_version=str((pypdf_item or {}).get("installed_version") or ""),
        minimum_version=str((pypdf_item or {}).get("minimum_version") or "5.0"),
    )
    if requirements_file_ready and not pypdf_ready:
        _issue(
            issues,
            "blocked",
            "pypdf_unavailable",
            "pypdf is required for authorized PDF validation and extraction.",
            "Run check_environment.py --prepare.",
        )

    playwright_item = next(
        (item for item in requirement_items if item["distribution"] == "playwright"),
        None,
    )
    playwright_imports = (playwright_item or {}).get("import_results") or {}
    playwright_api_ready = bool(
        playwright_item
        and playwright_item["status"] == "ready"
        and all(
            isinstance(playwright_imports.get(name), dict)
            and playwright_imports[name].get("ok") is True
            for name in REQUIREMENT_IMPORTS["playwright"]
        )
    )
    required["playwright_api"] = _ready(playwright_api_ready)
    if requirements_file_ready and not playwright_api_ready:
        _issue(
            issues,
            "blocked",
            "playwright_api_unavailable",
            "Both Playwright async and sync Python APIs must be importable.",
            "Run check_environment.py --prepare.",
        )

    pip_check = (
        _probe_pip_check(python_executable, paths, probe_timeout)
        if venv_python_exists and pip_probe.get("ok")
        else {"ok": False, "error": "pip_unavailable"}
    )
    required["pip_check"] = _ready(
        bool(pip_check.get("ok")),
        detail=str(pip_check.get("detail") or ""),
        error=str(pip_check.get("error") or ""),
    )
    if venv_python_exists and pip_probe.get("ok") and not pip_check.get("ok"):
        _issue(
            issues,
            "blocked",
            "pip_check_failed",
            "The managed environment contains incompatible package dependencies.",
            "Repair the requirements installation before running the skill.",
        )

    chromium = _chromium_executable(paths.playwright_dir)
    required["bundled_chromium"] = _ready(
        chromium is not None,
        path=str(chromium or paths.playwright_dir),
    )
    if chromium is None:
        _issue(
            issues,
            "blocked",
            "bundled_chromium_missing",
            "The bundled Playwright Chromium executable is missing.",
            "Run check_environment.py --prepare.",
        )

    helper_probe = _probe_helpers(
        paths,
        python_executable if venv_python_exists else None,
        probe_timeout,
    )
    required["python_helpers"] = _ready(
        bool(helper_probe.get("ok")),
        syntax_errors=helper_probe.get("syntax_errors") or [],
        load_error=str(helper_probe.get("load_error") or ""),
    )
    if not helper_probe.get("ok"):
        _issue(
            issues,
            "blocked",
            "python_helpers_unloadable",
            "One or more bundled Python helpers or the Codex hook cannot be loaded.",
            "Restore the published helper files and rerun the check.",
        )

    node = _probe_node(paths, probe_timeout)
    chrome = _find_ordinary_chrome()
    optional: dict[str, dict[str, Any]] = {
        "node": node,
        "ordinary_chrome": {
            "status": "ready" if chrome is not None else "unavailable",
            "executable": str(chrome or ""),
        },
        "chrome_plugin": {
            "status": "confirmation_required",
            "ready": False,
            "reason": "installation_enablement_and_current_task_connection_are_not_attested",
        },
        "full_cdp": {
            "status": "attestation_required",
            "ready": False,
            "probe_method": CDP_READONLY_PROBE_METHOD,
            "probe_succeeded": False,
            "reason": "standalone_environment_check_does_not_request_or_attest_cdp_access",
        },
    }
    if node.get("status") != "ready":
        _issue(
            issues,
            "degraded",
            "node_unavailable",
            "Node.js is unavailable, so the ordinary-Chrome credential helper cannot run.",
            "Install Node.js only if ordinary Chrome handoff is needed.",
        )
    if chrome is None:
        _issue(
            issues,
            "degraded",
            "ordinary_chrome_unavailable",
            "Ordinary Chrome was not found.",
            "Install Chrome only if the first two browser layers cannot complete the task.",
        )
    _issue(
        issues,
        "degraded",
        "chrome_plugin_confirmation_required",
        "The environment checker does not attest Chrome plugin installation or current-task connection.",
        "Confirm the plugin only when the workflow actually reaches the ordinary Chrome layer.",
    )
    _issue(
        issues,
        "degraded",
        "full_cdp_attestation_required",
        f"Full CDP access is unverified; readiness requires a successful read-only {CDP_READONLY_PROBE_METHOD} probe.",
        "Grant and attest full CDP only when the workflow actually reaches the ordinary Chrome layer.",
    )

    required_ready = all(item.get("status") == "ready" for item in required.values())
    status = "degraded" if required_ready else "blocked"
    legacy = {
        "python_packages": {
            "path": str(paths.legacy_python_packages_dir),
            "detected": paths.legacy_python_packages_dir.is_dir(),
            "mode": "read_compatibility_only",
        },
        "playwright_browsers": {
            "path": str(paths.legacy_playwright_dir),
            "detected": _chromium_executable(paths.legacy_playwright_dir) is not None,
            "mode": "read_compatibility_only",
        },
    }
    return {
        "schema": ENVIRONMENT_REPORT_SCHEMA,
        "status": status,
        "paths": paths.report_paths(),
        "required": required,
        "optional_full_capabilities": optional,
        "legacy_layout": legacy,
        "issues": issues,
        "full_capability_reminder": FULL_CAPABILITY_REMINDER,
    }


def required_environment_ready(report: Mapping[str, Any]) -> bool:
    required = report.get("required")
    return bool(
        isinstance(required, Mapping)
        and required
        and all(
            isinstance(value, Mapping) and value.get("status") == "ready"
            for value in required.values()
        )
    )


def environment_exit_code(report: Mapping[str, Any]) -> int:
    status = report.get("status")
    if status in {"ready", "degraded"}:
        return 0
    if status == "blocked":
        return 2
    return 1


def _process_is_running(pid: int) -> bool:
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


def _lock_owner_running(lock_path: Path) -> bool:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8-sig"))
        return _process_is_running(int(payload.get("pid") or 0))
    except Exception:
        return False


def _acquire_bootstrap_lock(paths: EnvironmentPaths, timeout_seconds: int) -> tuple[Path, str]:
    paths.tools_dir.mkdir(parents=True, exist_ok=True)
    lock_path = paths.lock_path
    token = f"{os.getpid()}-{time.time_ns()}"
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            descriptor = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "pid": os.getpid(),
                        "token": token,
                        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    },
                    handle,
                )
            return lock_path, token
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime if lock_path.exists() else 0.0
            except OSError:
                continue
            if age > timeout_seconds and not _lock_owner_running(lock_path):
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
            time.sleep(min(1.0, max(0.2, deadline - time.monotonic())))
        except OSError as exc:
            raise EnvironmentBootstrapError(
                "environment_bootstrap_lock_failed",
                f"Unable to create environment bootstrap lock {lock_path}: {exc}",
            ) from exc


def _release_bootstrap_lock(lock_path: Path, token: str) -> None:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8-sig")) if lock_path.exists() else {}
        if payload.get("token") == token:
            lock_path.unlink()
    except Exception:
        # A failed cleanup must not hide the original preparation result.
        return


def _process_group_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except Exception:
            pass
    else:
        try:
            import signal

            os.killpg(process.pid, signal.SIGTERM)
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


def _run_environment_command(
    args: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: int,
) -> None:
    command = list(args)
    command_preview = " ".join(command[:4])
    try:
        process = subprocess.Popen(
            command,
            env=dict(env),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **_process_group_kwargs(),
        )
    except OSError as exc:
        raise EnvironmentBootstrapError(
            "environment_bootstrap_failed",
            f"Environment command could not start: {command_preview}: {exc}",
            command,
        ) from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_tree(process)
        raise EnvironmentBootstrapError(
            "environment_bootstrap_timeout",
            f"Environment command timed out after {timeout_seconds} seconds: {command_preview}",
            command,
        ) from exc
    if process.returncode != 0:
        detail = (stderr or stdout or "").strip().splitlines()
        suffix = f": {detail[-1][:300]}" if detail else ""
        raise EnvironmentBootstrapError(
            "environment_bootstrap_failed",
            f"Environment command failed with exit code {process.returncode}: {command_preview}{suffix}",
            command,
        )


def prepare_environment(
    skill_root: str | os.PathLike[str] | None = None,
    *,
    command_timeout_seconds: int | None = None,
    lock_timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Prepare ``tools/.venv`` and ``tools/ms-playwright``, then re-check.

    Existing legacy runtime directories may be read by ``runtime_environment``
    but are never created or updated here.
    """

    paths = EnvironmentPaths.from_skill_root(skill_root)
    initial = check_environment(paths.skill_root)
    if required_environment_ready(initial):
        return initial
    if initial["required"]["python"]["status"] != "ready":
        return initial
    if initial["required"]["requirements_file"]["status"] != "ready":
        return initial

    command_timeout = environment_command_timeout_seconds(command_timeout_seconds)
    lock_timeout = environment_lock_timeout_seconds(lock_timeout_seconds)
    lock_path, token = _acquire_bootstrap_lock(paths, lock_timeout)
    try:
        env = _isolated_runtime_environment(paths)
        python_executable = venv_python_path(paths.venv_dir)
        created_venv = False
        if not python_executable.is_file():
            _run_environment_command(
                [sys.executable, "-m", "venv", str(paths.venv_dir)],
                env=env,
                timeout_seconds=command_timeout,
            )
            created_venv = True
        if not python_executable.is_file():
            raise EnvironmentBootstrapError(
                "environment_bootstrap_failed",
                f"Virtual environment creation did not produce a Python executable: {python_executable}",
            )

        pip_probe = _probe_pip(python_executable, paths, min(60, command_timeout))
        if not pip_probe.get("ok"):
            _run_environment_command(
                [str(python_executable), "-m", "ensurepip", "--upgrade"],
                env=env,
                timeout_seconds=command_timeout,
            )
            created_venv = True
        if created_venv:
            _run_environment_command(
                [str(python_executable), "-m", "pip", "install", "--upgrade", "pip"],
                env=env,
                timeout_seconds=command_timeout,
            )

        after_venv = check_environment(paths.skill_root)
        package_checks = (
            "pip",
            "requirements",
            "pypdf",
            "playwright_api",
            "pip_check",
        )
        if any(after_venv["required"][name]["status"] != "ready" for name in package_checks):
            _run_environment_command(
                [
                    str(python_executable),
                    "-m",
                    "pip",
                    "install",
                    "-r",
                    str(paths.requirements_path),
                ],
                env=env,
                timeout_seconds=command_timeout,
            )

        if _chromium_executable(paths.playwright_dir) is None:
            _run_environment_command(
                [str(python_executable), "-m", "playwright", "install", "chromium"],
                env=env,
                timeout_seconds=command_timeout,
            )
    finally:
        _release_bootstrap_lock(lock_path, token)
    return check_environment(paths.skill_root)


def restart_with_tools_python(
    script_path: str | os.PathLike[str],
    argv: Sequence[str],
    *,
    skill_root: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> NoReturn:
    """Restart one entry script in the managed virtual environment."""

    paths = EnvironmentPaths.from_skill_root(skill_root)
    python_executable = venv_python_path(paths.venv_dir)
    if not python_executable.is_file():
        raise EnvironmentBootstrapError(
            "environment_bootstrap_failed",
            f"Managed Python executable is missing: {python_executable}",
        )
    if running_in_tools_venv(paths.skill_root):
        raise EnvironmentBootstrapError(
            "environment_bootstrap_restart_loop",
            "Refusing to restart because the process is already running in tools/.venv.",
        )
    child_env = runtime_environment(paths.skill_root, base=env)
    args = [str(python_executable), str(Path(script_path).resolve()), *list(argv)]
    if os.name != "nt":
        os.execve(str(python_executable), args, child_env)
    raise SystemExit(subprocess.call(args, env=child_env))


def environment_error_report(
    error: BaseException,
    *,
    operation: str,
    skill_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    reason = getattr(error, "reason", "environment_check_failed")
    command = list(getattr(error, "command", ()) or ())
    return {
        "schema": ENVIRONMENT_REPORT_SCHEMA,
        "status": "blocked",
        "operation": operation,
        "paths": EnvironmentPaths.from_skill_root(skill_root).report_paths(),
        "error": {
            "code": str(reason),
            "message": str(error),
            "command": command,
        },
        "full_capability_reminder": FULL_CAPABILITY_REMINDER,
    }


def human_report_lines(report: Mapping[str, Any]) -> list[str]:
    lines = [f"Environment status: {report.get('status', 'unknown')}"]
    required = report.get("required")
    if isinstance(required, Mapping):
        for name, result in required.items():
            status = result.get("status", "unknown") if isinstance(result, Mapping) else "unknown"
            lines.append(f"  required/{name}: {status}")
    optional = report.get("optional_full_capabilities")
    if isinstance(optional, Mapping):
        for name, result in optional.items():
            status = result.get("status", "unknown") if isinstance(result, Mapping) else "unknown"
            lines.append(f"  optional/{name}: {status}")
    error = report.get("error")
    if isinstance(error, Mapping):
        lines.append(f"  error/{error.get('code', 'unknown')}: {error.get('message', '')}")
    lines.append("")
    lines.extend(FULL_CAPABILITY_REMINDER.splitlines())
    return lines


__all__ = [
    "CDP_READONLY_PROBE_METHOD",
    "DEFAULT_ENV_COMMAND_TIMEOUT_SECONDS",
    "DEFAULT_ENV_LOCK_TIMEOUT_SECONDS",
    "ENVIRONMENT_REPORT_SCHEMA",
    "EnvironmentBootstrapError",
    "EnvironmentPaths",
    "FULL_CAPABILITY_REMINDER",
    "check_environment",
    "environment_command_timeout_seconds",
    "environment_error_report",
    "environment_exit_code",
    "environment_lock_timeout_seconds",
    "human_report_lines",
    "prepare_environment",
    "required_environment_ready",
    "restart_with_tools_python",
    "running_in_tools_venv",
    "runtime_environment",
    "venv_python_path",
]
