from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ============================================================
# STEP 12 — REMEDIATION GUIDANCE
# ============================================================


class RemediationEvidence(BaseModel):
    source: str
    evidence_type: str
    value: str


class RemediationItem(BaseModel):
    category: str
    title: str

    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None

    severity: str = "informational"
    risk_score: int = 0

    priority: str = "routine"

    action: str
    rationale: str

    verification: list[str] = Field(
        default_factory=list
    )

    safety_note: str = (
        "Apply changes through the authorized "
        "system administration process and "
        "validate service availability afterward."
    )

    evidence: list[RemediationEvidence] = Field(
        default_factory=list
    )

    sources: list[str] = Field(
        default_factory=list
    )

    tags: list[str] = Field(
        default_factory=list
    )

    occurrence_count: int = 1


class RemediationSummary(BaseModel):
    total_items: int = 0

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    immediate_actions: int = 0
    planned_actions: int = 0
    routine_actions: int = 0


class RemediationGuidanceGenerator:
    """
    Converts Step 10 risk assessments into
    deterministic, actionable remediation guidance.

    Important design rule:

        Step 12 does NOT:
        - rescan the target
        - change risk scores
        - invent vulnerabilities
        - claim exploitability
        - modify previous findings

    It consumes the risk assessment produced by
    Step 10 and adds remediation guidance while
    preserving traceability to the original evidence.
    """

    PRIORITY_RULES = {
        "critical": "immediate",
        "high": "immediate",
        "medium": "planned",
        "low": "planned",
        "informational": "routine",
    }

    DEFAULT_ACTION = (
        "Review the finding and apply the minimum "
        "configuration change necessary to reduce "
        "the observed exposure."
    )

    DEFAULT_RATIONALE = (
        "The assessment identified a network-reachable "
        "condition within the authorized assessment scope. "
        "Reducing unnecessary exposure lowers the associated "
        "security risk."
    )

    DEFAULT_VERIFICATION = [
        "Re-run the relevant authorized assessment.",
        "Confirm that the original finding is no longer observed.",
        "Confirm that required service functionality remains available.",
    ]

    CATEGORY_GUIDANCE = {
        "INSECURE_PROTOCOL": {
            "action": (
                "Disable the insecure protocol or replace it "
                "with an encrypted and appropriately restricted "
                "alternative. Restrict the replacement service "
                "to authorized management or application networks."
            ),
            "rationale": (
                "The assessment observed an insecure protocol "
                "reachable from the scan vantage point. Such "
                "protocols may expose credentials, session data, "
                "or administrative traffic without adequate "
                "transport protection."
            ),
            "verification": [
                "Confirm the insecure protocol is disabled or no longer network reachable.",
                "Confirm the approved replacement service is reachable where required.",
                "Verify that administrative or application traffic uses the approved encrypted protocol.",
                "Re-run the authorized port and service assessment.",
            ],
        },

        "REMOTE_ADMINISTRATION_EXPOSURE": {
            "action": (
                "Restrict the remote administration service to "
                "authorized management networks, VPN access, "
                "or an approved bastion/jump-host path. Disable "
                "unused administration services."
            ),
            "rationale": (
                "A remote administration interface was observed "
                "as network reachable. Administrative interfaces "
                "should normally be limited to explicitly "
                "authorized management paths."
            ),
            "verification": [
                "Confirm the management service remains available from the authorized management path.",
                "Confirm the service is not reachable from unauthorized assessment networks.",
                "Confirm unused remote administration services are disabled.",
                "Re-run the authorized port scan from the relevant assessment vantage points.",
            ],
        },

        "DATABASE_EXPOSURE": {
            "action": (
                "Restrict the database listener to the required "
                "application or management networks. Disable "
                "unnecessary network listeners and apply host/network "
                "firewall controls appropriate to the deployment."
            ),
            "rationale": (
                "A database service was observed as network reachable. "
                "Database services generally require narrower network "
                "exposure than ordinary application services."
            ),
            "verification": [
                "Confirm the database is reachable from required application hosts.",
                "Confirm unauthorized network paths cannot reach the database listener.",
                "Confirm unnecessary database listeners are disabled.",
                "Re-run the authorized port scan against the affected host.",
            ],
        },

        "FILE_SHARING_EXPOSURE": {
            "action": (
                "Restrict file-sharing services to authorized clients "
                "and management networks. Disable unused file-sharing "
                "protocols and remove unnecessary network listeners."
            ),
            "rationale": (
                "A file-sharing service was observed as network reachable. "
                "Unnecessary file-sharing exposure can increase the amount "
                "of remotely accessible system or organizational data."
            ),
            "verification": [
                "Confirm required authorized clients can still access the share.",
                "Confirm unauthorized network paths cannot reach the file-sharing service.",
                "Confirm unused file-sharing protocols are disabled.",
                "Re-run the authorized port and service assessment.",
            ],
        },

        "INFRASTRUCTURE_EXPOSURE": {
            "action": (
                "Restrict infrastructure services such as DNS, RPC, "
                "SNMP, or related services to the networks and hosts "
                "that explicitly require them. Disable unnecessary "
                "listeners."
            ),
            "rationale": (
                "An infrastructure service was observed as network reachable. "
                "Infrastructure services often provide information or control "
                "that is not intended for general network access."
            ),
            "verification": [
                "Confirm required infrastructure clients continue to function.",
                "Confirm unauthorized network paths cannot reach the service.",
                "Confirm unnecessary infrastructure listeners are disabled.",
                "Re-run the relevant authorized port/service assessment.",
            ],
        },

        "WEB_EXPOSURE": {
            "action": (
                "Restrict administrative or unnecessary web services "
                "to their intended networks. Where sensitive traffic "
                "is handled, use approved HTTPS/TLS configuration and "
                "disable unnecessary HTTP or application listeners."
            ),
            "rationale": (
                "A web service was observed as network reachable. "
                "The appropriate remediation depends on whether the "
                "service is intended to be broadly reachable or is "
                "administrative/internal."
            ),
            "verification": [
                "Confirm the required web application remains reachable.",
                "Confirm administrative web interfaces are limited to authorized networks.",
                "Confirm sensitive traffic uses the approved TLS configuration where required.",
                "Re-run the authorized web/service assessment.",
            ],
        },

        "METADATA_LEAKAGE": {
            "action": (
                "Minimize unnecessary service banners, software version "
                "disclosures, internal hostnames, internal addressing, "
                "and other metadata exposed by network services."
            ),
            "rationale": (
                "The assessment observed metadata that can assist "
                "reconnaissance. Metadata disclosure is not by itself "
                "proof of a vulnerability, but unnecessary information "
                "should be minimized where operationally practical."
            ),
            "verification": [
                "Re-check service banners and HTTP response headers.",
                "Confirm unnecessary software/version information is no longer disclosed.",
                "Confirm internal hostnames or addressing are not unnecessarily exposed.",
                "Re-run the authorized service fingerprinting assessment.",
            ],
        },

        "MISCONFIGURATION": {
            "action": (
                "Review the affected service configuration and remove "
                "the observed insecure or unnecessary configuration. "
                "Apply the vendor-supported secure configuration while "
                "preserving required service functionality."
            ),
            "rationale": (
                "The analysis identified a configuration condition "
                "that increases exposure or weakens the intended "
                "security posture."
            ),
            "verification": [
                "Confirm the configuration change is active.",
                "Confirm the affected service remains operational.",
                "Confirm the original misconfiguration is no longer observed.",
                "Re-run the relevant authorized security analysis.",
            ],
        },
    }

    # --------------------------------------------------------
    # Helpers
    # --------------------------------------------------------

    @staticmethod
    def _get(
        obj: Any,
        field: str,
        default: Any = None,
    ) -> Any:

        if isinstance(obj, dict):
            return obj.get(
                field,
                default,
            )

        return getattr(
            obj,
            field,
            default,
        )

    @staticmethod
    def _normalize(
        value: Any,
    ) -> str:

        if value is None:
            return ""

        return str(value).strip()

    @staticmethod
    def _safe_int(
        value: Any,
        default: int = 0,
    ) -> int:

        try:
            return int(value)

        except (
            TypeError,
            ValueError,
        ):
            return default

    @staticmethod
    def _safe_list(
        value: Any,
    ) -> list:

        if value is None:
            return []

        if isinstance(value, list):
            return value

        if isinstance(value, tuple):
            return list(value)

        return [value]

    # --------------------------------------------------------
    # Priority
    # --------------------------------------------------------

    def _priority(
        self,
        severity: str,
    ) -> str:

        normalized = (
            severity
            or "informational"
        ).lower()

        return self.PRIORITY_RULES.get(
            normalized,
            "routine",
        )

    # --------------------------------------------------------
    # Category guidance
    # --------------------------------------------------------

    def _category_guidance(
        self,
        category: str,
    ) -> dict:

        normalized = (
            category
            or ""
        ).upper()

        guidance = self.CATEGORY_GUIDANCE.get(
            normalized
        )

        if guidance:
            return guidance

        return {
            "action": self.DEFAULT_ACTION,
            "rationale": self.DEFAULT_RATIONALE,
            "verification": list(
                self.DEFAULT_VERIFICATION
            ),
        }

    # --------------------------------------------------------
    # Location
    # --------------------------------------------------------

    def _location_text(
        self,
        assessment: Any,
    ) -> str:

        host = self._normalize(
            self._get(
                assessment,
                "host",
                "",
            )
        )

        port = self._get(
            assessment,
            "port",
            None,
        )

        protocol = self._normalize(
            self._get(
                assessment,
                "protocol",
                "",
            )
        )

        if port is None:
            return host

        if not protocol:
            protocol = "tcp"

        return (
            f"{host}:"
            f"{port}/"
            f"{protocol}"
        )

    # --------------------------------------------------------
    # Evidence conversion
    # --------------------------------------------------------

    def _convert_evidence(
        self,
        assessment: Any,
    ) -> list[RemediationEvidence]:

        result = []

        raw_evidence = self._safe_list(
            self._get(
                assessment,
                "evidence",
                [],
            )
        )

        for evidence in raw_evidence:

            source = self._normalize(
                self._get(
                    evidence,
                    "source",
                    "unknown",
                )
            )

            evidence_type = self._normalize(
                self._get(
                    evidence,
                    "evidence_type",
                    "observation",
                )
            )

            value = self._normalize(
                self._get(
                    evidence,
                    "value",
                    "",
                )
            )

            if not value:
                continue

            result.append(
                RemediationEvidence(
                    source=(
                        source
                        or "unknown"
                    ),
                    evidence_type=(
                        evidence_type
                        or "observation"
                    ),
                    value=value,
                )
            )

        return result

    # --------------------------------------------------------
    # Build one remediation item
    # --------------------------------------------------------

    def build_item(
        self,
        assessment: Any,
    ) -> RemediationItem:

        category = self._normalize(
            self._get(
                assessment,
                "category",
                "UNKNOWN",
            )
        )

        title = self._normalize(
            self._get(
                assessment,
                "title",
                "Security finding",
            )
        )

        host = self._normalize(
            self._get(
                assessment,
                "host",
                "",
            )
        )

        port = self._get(
            assessment,
            "port",
            None,
        )

        protocol = self._normalize(
            self._get(
                assessment,
                "protocol",
                "",
            )
        )

        severity = self._normalize(
            self._get(
                assessment,
                "severity",
                "informational",
            )
        ).lower()

        risk_score = self._safe_int(
            self._get(
                assessment,
                "risk_score",
                0,
            )
        )

        priority = self._priority(
            severity
        )

        guidance = self._category_guidance(
            category
        )

        evidence = self._convert_evidence(
            assessment
        )

        sources = [
            str(source)
            for source in self._safe_list(
                self._get(
                    assessment,
                    "sources",
                    [],
                )
            )
            if str(source).strip()
        ]

        tags = [
            str(tag)
            for tag in self._safe_list(
                self._get(
                    assessment,
                    "tags",
                    [],
                )
            )
            if str(tag).strip()
        ]

        occurrence_count = self._safe_int(
            self._get(
                assessment,
                "occurrence_count",
                1,
            ),
            default=1,
        )

        if occurrence_count < 1:
            occurrence_count = 1

        location = self._location_text(
            assessment
        )

        safety_note = (
            "Apply the change through the authorized "
            "administration process. Validate required "
            "service functionality after the change."
        )

        if priority == "immediate":
            safety_note = (
                "Prioritize this change according to the "
                "assessment severity, but validate service "
                "dependencies before disabling or restricting "
                "the affected service."
            )

        # Add location to rationale only as contextual
        # information. Do not claim Internet exposure.
        rationale = (
            f"{guidance['rationale']} "
            f"Affected location: {location}."
        )

        return RemediationItem(
            category=category,
            title=title,
            host=host,
            port=port,
            protocol=protocol or None,
            severity=severity or "informational",
            risk_score=max(
                0,
                min(
                    risk_score,
                    25,
                ),
            ),
            priority=priority,
            action=guidance["action"],
            rationale=rationale,
            verification=list(
                guidance["verification"]
            ),
            safety_note=safety_note,
            evidence=evidence,
            sources=sources,
            tags=tags,
            occurrence_count=occurrence_count,
        )

    # --------------------------------------------------------
    # Analyze all Step 10 assessments
    # --------------------------------------------------------

    def analyze(
        self,
        risk_assessments: list,
    ) -> list[RemediationItem]:

        remediation_items = []

        for assessment in (
            risk_assessments
            or []
        ):

            try:

                item = self.build_item(
                    assessment
                )

                remediation_items.append(
                    item
                )

            except Exception:
                # A malformed individual assessment should
                # not destroy the entire remediation phase.
                continue

        # Highest risk first.
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "informational": 4,
        }

        remediation_items.sort(
            key=lambda item: (
                severity_order.get(
                    item.severity.lower(),
                    5,
                ),
                -item.risk_score,
                item.host,
                item.port
                if item.port is not None
                else -1,
                item.title,
            )
        )

        return remediation_items

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    def summarize(
        self,
        remediation_items: list[
            RemediationItem
        ],
    ) -> dict:

        critical = 0
        high = 0
        medium = 0
        low = 0
        informational = 0

        immediate = 0
        planned = 0
        routine = 0

        for item in (
            remediation_items
            or []
        ):

            severity = (
                item.severity
                or "informational"
            ).lower()

            if severity == "critical":
                critical += 1

            elif severity == "high":
                high += 1

            elif severity == "medium":
                medium += 1

            elif severity == "low":
                low += 1

            else:
                informational += 1

            priority = (
                item.priority
                or "routine"
            ).lower()

            if priority == "immediate":
                immediate += 1

            elif priority == "planned":
                planned += 1

            else:
                routine += 1

        return {
            "total_items": len(
                remediation_items
                or []
            ),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "informational": informational,
            "immediate_actions": immediate,
            "planned_actions": planned,
            "routine_actions": routine,
        }