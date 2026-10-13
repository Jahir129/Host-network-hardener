from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class OutputManager:

    def __init__(self, report_root: str = "reports"):
        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        self.report_dir = (
            Path(report_root) / timestamp
        )

        self.report_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.json_path = (
            self.report_dir / "scan_data.json"
        )

        self.scan_data: dict[str, Any] = {
            "metadata": {
                "started_at": datetime.now().isoformat(),
                "pipeline": "host-network-hardener",
                "status": "running",
            }
        }

    # =========================================================
    # TERMINAL DASHBOARD
    # =========================================================

    def header(self):
        print()
        print("=" * 60)
        print("              HOST & NETWORK HARDENER")
        print("=" * 60)
        print()

    def target(self, value: str):
        print("Target")
        print(f"  {value}")
        print()

    def stage(
        self,
        number: str,
        name: str,
        status: str = "RUNNING",
        summary: str | None = None,
    ):
        if status == "OK":
            symbol = "✓"

        elif status == "FAILED":
            symbol = "✗"

        elif status == "SKIPPED":
            symbol = "-"

        else:
            symbol = "..."

        line = (
            f"  [{symbol}] "
            f"{number:<5} "
            f"{name:<30}"
        )

        if summary:
            line += summary

        print(line)

    def section(self, title: str):
        print()
        print("-" * 60)
        print(title)
        print("-" * 60)

    def summary(self, values: dict[str, Any]):
        print()
        print("-" * 60)
        print("SCAN SUMMARY")
        print("-" * 60)

        for key, value in values.items():
            print(
                f"{key:<20}: {value}"
            )

    # =========================================================
    # STRUCTURED EVIDENCE
    # =========================================================

    def store(
        self,
        key: str,
        value: Any,
    ):
        self.scan_data[key] = value

    def update(
        self,
        values: dict[str, Any],
    ):
        self.scan_data.update(values)

    # =========================================================
    # SERIALIZATION
    # =========================================================

    def _serialize(
        self,
        value: Any,
    ):
        if value is None:
            return None

        if isinstance(value, Enum):
            return value.value

        if is_dataclass(value):
            return {
                key: self._serialize(item)
                for key, item in asdict(value).items()
            }

        if hasattr(value, "model_dump"):
            return self._serialize(
                value.model_dump()
            )

        if hasattr(value, "dict"):
            return self._serialize(
                value.dict()
            )

        if isinstance(value, dict):
            return {
                str(key): self._serialize(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                self._serialize(item)
                for item in value
            ]

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, datetime):
            return value.isoformat()

        if isinstance(
            value,
            (str, int, float, bool),
        ):
            return value

        return str(value)

    # =========================================================
    # CHECKPOINT
    # =========================================================

    def checkpoint(
        self,
        stage: str | None = None,
    ):
        if stage:
            self.scan_data[
                "metadata"
            ]["last_completed_stage"] = stage

        serialized = self._serialize(
            self.scan_data
        )

        temporary_path = (
            self.report_dir
            / "scan_data.json.tmp"
        )

        with temporary_path.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                serialized,
                file,
                indent=2,
                ensure_ascii=False,
            )

        temporary_path.replace(
            self.json_path
        )

    # =========================================================
    # COMPLETION
    # =========================================================

    def complete(
        self,
        summary: dict[str, Any],
    ):
        self.scan_data[
            "metadata"
        ]["status"] = "complete"

        self.scan_data[
            "metadata"
        ]["completed_at"] = (
            datetime.now().isoformat()
        )

        self.checkpoint(
            "PIPELINE_COMPLETE"
        )

        print()

        print("=" * 60)
        print("                  PIPELINE COMPLETE")
        print("=" * 60)

        self.summary(
            summary
        )

        print()
        print(
            f"Evidence    : "
            f"{self.report_dir}"
        )

        print(
            f"JSON        : "
            f"{self.json_path}"
        )

        print("=" * 60)

    def fail(
        self,
        stage: str,
        error: Exception | str,
    ):
        self.scan_data[
            "metadata"
        ]["status"] = "failed"

        self.scan_data[
            "metadata"
        ]["failed_stage"] = stage

        self.scan_data[
            "metadata"
        ]["error"] = str(error)

        self.checkpoint()

        print()
        print("=" * 60)
        print("                    PIPELINE FAILED")
        print("=" * 60)
        print(f"Stage : {stage}")
        print(f"Error : {error}")
        print()
        print(
            f"Partial evidence preserved at:"
        )
        print(
            f"  {self.json_path}"
        )
        print("=" * 60)