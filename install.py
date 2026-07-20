#!/usr/bin/env python3
"""Install the bundled Codex skill without overwriting existing data."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SKILL_NAME = "literature-and-patents-search"
REMINDER = (
    "若想开启 Skill 的全部能力，需要完成这两件事情：\n"
    "1. 在普通 Chrome 中安装、启用并连接 Codex Chrome 插件；\n"
    "2. 为当前任务开启 full CDP 访问权限。"
)

BLOCKED_DIRECTORY_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "ms-playwright",
    "playwright-browsers",
    "python_packages",
    "run_logs",
    "auth_state",
    "events",
    "browser_profile",
    "browser_profiles",
}
BLOCKED_FILE_SUFFIXES = {
    ".pdf",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".log",
    ".csv",
    ".json",
    ".jsonl",
    ".pyc",
    ".pyo",
}
BLOCKED_FILE_NAMES = {
    "storage_state.json",
    "cookies.json",
    "cookie.json",
    "config.json",
    "literature_and_patents_search_scripts.json",
}
BLOCKED_NAME_FRAGMENTS = (
    "screenshot",
    "storage_state",
    "browser-profile",
    "cookie",
    "token",
)
REQUIRED_RELATIVE_PATHS = (
    Path("SKILL.md"),
    Path("agents") / "openai.yaml",
    Path("scripts") / "literature_and_patents_search_scripts.py",
    Path("scripts") / "literature_and_patents_download_scripts.py",
    Path("scripts") / "laps_core" / "__init__.py",
    Path("tools") / "check_environment.py",
    Path("tools") / "requirements.txt",
    Path("tools") / "codex_hooks" / "codex_external_control_hook.py",
    Path("tools") / "codex_hooks" / "codex_ordinary_chrome_credential_fill.mjs",
    Path("references") / "interface.md",
    Path("references") / "search-help.md",
    Path("references") / "search-limitations.md",
    Path("references") / "download-help.md",
    Path("references") / "download-usage.md",
    Path("references") / "download-limitations.md",
    Path("references") / "channels.md",
    Path("references") / "authentication.md",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install the literature-and-patents-search Codex skill safely."
    )
    parser.add_argument(
        "--target",
        type=Path,
        help=(
            "Codex skills root. Defaults to CODEX_HOME/skills, or "
            "~/.codex/skills when CODEX_HOME is unset."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and show the planned destination without writing files.",
    )
    return parser.parse_args(argv)


def default_skills_root() -> Path:
    codex_home = os.environ.get("CODEX_HOME", "").strip()
    if codex_home:
        return Path(codex_home).expanduser() / "skills"
    return Path.home() / ".codex" / "skills"


def validate_source(source: Path) -> list[str]:
    problems: list[str] = []
    for relative in REQUIRED_RELATIVE_PATHS:
        if not (source / relative).is_file():
            problems.append(f"missing required file: {relative.as_posix()}")

    for path in source.rglob("*"):
        relative = path.relative_to(source)
        lowered_parts = [part.lower() for part in relative.parts]
        if path.is_symlink():
            problems.append(f"symbolic link is not allowed: {relative.as_posix()}")
            continue
        if path.is_dir() and path.name.lower() in BLOCKED_DIRECTORY_NAMES:
            problems.append(f"runtime/test directory is not allowed: {relative.as_posix()}")
            continue
        if not path.is_file():
            continue
        lowered_name = path.name.lower()
        if any(part in BLOCKED_DIRECTORY_NAMES for part in lowered_parts[:-1]):
            problems.append(f"file under blocked directory: {relative.as_posix()}")
        elif lowered_name in BLOCKED_FILE_NAMES:
            problems.append(f"runtime/config file is not allowed: {relative.as_posix()}")
        elif path.suffix.lower() in BLOCKED_FILE_SUFFIXES:
            problems.append(f"runtime/output file is not allowed: {relative.as_posix()}")
        elif any(fragment in lowered_name for fragment in BLOCKED_NAME_FRAGMENTS):
            problems.append(f"sensitive/runtime filename is not allowed: {relative.as_posix()}")
    return sorted(set(problems))


def print_reminder() -> None:
    print()
    print(REMINDER)


def run_environment_check(destination: Path) -> int:
    checker = destination / "tools" / "check_environment.py"
    print(f"Running read-only environment check: {checker}")
    try:
        result = subprocess.run(
            [sys.executable, str(checker), "--check"],
            cwd=str(destination),
            check=False,
        )
    except OSError as exc:
        print(f"Warning: unable to start the environment check: {exc}", file=sys.stderr)
        return 1

    if result.returncode == 0:
        print("Environment check completed (ready or degraded).")
    elif result.returncode == 2:
        print(
            "Environment check found missing required components. "
            "Run tools/check_environment.py --prepare before normal search or download.",
            file=sys.stderr,
        )
    else:
        print(
            f"Warning: environment check failed with exit code {result.returncode}.",
            file=sys.stderr,
        )
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    package_root = Path(__file__).resolve().parent
    source = package_root / SKILL_NAME
    skills_root = (args.target or default_skills_root()).expanduser().resolve()
    destination = skills_root / SKILL_NAME

    problems = validate_source(source)
    if problems:
        print("Release source validation failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        print_reminder()
        return 1

    if destination.exists():
        print(f"Refusing to overwrite existing target: {destination}", file=sys.stderr)
        print_reminder()
        return 2

    print(f"Source:      {source}")
    print(f"Destination: {destination}")

    if args.dry_run:
        print("Dry run complete: no files were written.")
        print_reminder()
        return 0

    try:
        skills_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f".{SKILL_NAME}.install-", dir=skills_root
        ) as staging_parent_text:
            staging_parent = Path(staging_parent_text)
            staged_skill = staging_parent / SKILL_NAME
            shutil.copytree(source, staged_skill, copy_function=shutil.copy2)
            if destination.exists():
                raise FileExistsError(f"target appeared during installation: {destination}")
            staged_skill.rename(destination)
    except OSError as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        print_reminder()
        return 1

    print(f"Installed {SKILL_NAME} successfully.")
    check_code = run_environment_check(destination)
    if check_code != 0:
        print(
            "The Skill was installed, but its local runtime is not fully ready; "
            "the installer did not modify or download the environment.",
            file=sys.stderr,
        )
    print_reminder()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
