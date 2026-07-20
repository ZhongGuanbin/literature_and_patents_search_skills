from __future__ import annotations

"""Shared workflow completion semantics and process exit-code mapping."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


EXIT_COMPLETE = 0
EXIT_FAILED = 1
EXIT_INVALID_USAGE = 2
EXIT_PARTIAL = 3


class WorkflowStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


def coerce_workflow_status(value: WorkflowStatus | str) -> WorkflowStatus:
    if isinstance(value, WorkflowStatus):
        return value
    try:
        return WorkflowStatus(str(value).strip().casefold())
    except ValueError as exc:
        raise ValueError(f"Unsupported workflow status: {value!r}") from exc


def status_to_exit_code(status: WorkflowStatus | str) -> int:
    normalized = coerce_workflow_status(status)
    return {
        WorkflowStatus.COMPLETE: EXIT_COMPLETE,
        WorkflowStatus.PARTIAL: EXIT_PARTIAL,
        WorkflowStatus.FAILED: EXIT_FAILED,
    }[normalized]


def exit_code_to_status(exit_code: int) -> WorkflowStatus:
    if exit_code == EXIT_COMPLETE:
        return WorkflowStatus.COMPLETE
    if exit_code == EXIT_PARTIAL:
        return WorkflowStatus.PARTIAL
    if exit_code == EXIT_FAILED:
        return WorkflowStatus.FAILED
    if exit_code == EXIT_INVALID_USAGE:
        raise ValueError("Exit code 2 represents invalid arguments/configuration, not a workflow result")
    raise ValueError(f"Unsupported workflow exit code: {exit_code}")


def workflow_ok(status: WorkflowStatus | str) -> bool:
    return coerce_workflow_status(status) is WorkflowStatus.COMPLETE


def aggregate_workflow_status(
    statuses: Iterable[WorkflowStatus | str],
    *,
    fatal: bool = False,
) -> WorkflowStatus:
    """Aggregate completed sub-workflows.

    A sub-workflow failure normally means the requested scope is partial; only
    a caller-confirmed contract/I/O/program failure (``fatal=True``) promotes
    the overall result to ``failed``.
    """

    values = tuple(coerce_workflow_status(item) for item in statuses)
    if fatal:
        return WorkflowStatus.FAILED
    if not values:
        return WorkflowStatus.COMPLETE
    if all(item is WorkflowStatus.COMPLETE for item in values):
        return WorkflowStatus.COMPLETE
    return WorkflowStatus.PARTIAL


def status_report(
    status: WorkflowStatus | str,
    **fields: Any,
) -> dict[str, Any]:
    normalized = coerce_workflow_status(status)
    return {
        "status": normalized.value,
        "ok": normalized is WorkflowStatus.COMPLETE,
        **fields,
    }


@dataclass(frozen=True, slots=True)
class WorkflowOutcome:
    status: WorkflowStatus
    reason_code: str = ""
    category: str = ""
    retryable: bool = False
    retry_at: str = ""

    @property
    def ok(self) -> bool:
        return self.status is WorkflowStatus.COMPLETE

    @property
    def exit_code(self) -> int:
        return status_to_exit_code(self.status)

    def to_dict(self, **fields: Any) -> dict[str, Any]:
        return status_report(
            self.status,
            reason_code=self.reason_code,
            category=self.category,
            retryable=self.retryable,
            retry_at=self.retry_at,
            **fields,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WorkflowOutcome":
        return cls(
            status=coerce_workflow_status(str(value.get("status", ""))),
            reason_code=str(value.get("reason_code") or ""),
            category=str(value.get("category") or ""),
            retryable=bool(value.get("retryable", False)),
            retry_at=str(value.get("retry_at") or ""),
        )


__all__ = [
    "EXIT_COMPLETE",
    "EXIT_FAILED",
    "EXIT_INVALID_USAGE",
    "EXIT_PARTIAL",
    "WorkflowStatus",
    "WorkflowOutcome",
    "coerce_workflow_status",
    "status_to_exit_code",
    "exit_code_to_status",
    "workflow_ok",
    "aggregate_workflow_status",
    "status_report",
]
