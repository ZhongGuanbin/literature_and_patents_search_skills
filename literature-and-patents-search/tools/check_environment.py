#!/usr/bin/env python3
"""Check or prepare the self-contained LAPS tools environment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
SKILL_ROOT = SCRIPT_PATH.parents[1]
SCRIPTS_DIR = SKILL_ROOT / "scripts"
sys.dont_write_bytecode = True
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from laps_core.environment import (  # noqa: E402
    check_environment,
    environment_error_report,
    environment_exit_code,
    human_report_lines,
    prepare_environment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect or prepare the dependencies stored under this skill's tools directory. "
            "--check is read-only; --prepare may create tools/.venv and tools/ms-playwright."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Inspect the environment without writing files.")
    mode.add_argument("--prepare", action="store_true", help="Prepare missing required dependencies, then re-check.")
    parser.add_argument("--json", action="store_true", help="Write the laps_environment_report_v1 JSON report.")
    return parser


def emit_report(report: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print("\n".join(human_report_lines(report)))


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    operation = "prepare" if args.prepare else "check"
    try:
        report = (
            prepare_environment(SKILL_ROOT)
            if args.prepare
            else check_environment(SKILL_ROOT)
        )
    except Exception as exc:
        report = environment_error_report(
            exc,
            operation=operation,
            skill_root=SKILL_ROOT,
        )
        emit_report(report, as_json=args.json)
        return 1
    emit_report(report, as_json=args.json)
    return environment_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
