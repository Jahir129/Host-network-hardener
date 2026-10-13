from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
import html
import json

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


class ReportGenerator:
    """
    Step 11 — Report Generation

    Converts the collected pipeline evidence and Step 10
    risk assessments into human-readable security reports.

    This module does NOT:
      - scan hosts
      - perform network connections
      - calculate new risk scores
      - create remediation recommendations

    It only presents the results already produced by previous
    pipeline stages.
    """

    def __init__(self, report_dir):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    # =========================================================
    # GENERIC HELPERS
    # =========================================================

    @staticmethod
    def _value(obj: Any, field: str, default=None):
        """
        Safely retrieve a field from either a Pydantic model
        or a normal dictionary.
        """

        if isinstance(obj, dict):
            return obj.get(field, default)

        return getattr(
            obj,
            field,
            default,
        )

    @classmethod
    def _serialize(cls, value: Any):
        """
        Convert Pydantic models, dictionaries, lists, sets,
        Paths and other common objects into JSON-safe data.
        """

        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, dict):
            return {
                str(key): cls._serialize(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                cls._serialize(item)
                for item in value
            ]

        if hasattr(value, "model_dump"):
            return cls._serialize(
                value.model_dump()
            )

        if hasattr(value, "dict"):
            return cls._serialize(
                value.dict()
            )

        if hasattr(value, "value"):
            return cls._serialize(
                value.value
            )

        # Preserve structured attributes from dataclass /
        # normal Python result objects instead of reducing them
        # to strings such as <core.discovery.DiscoveryResult ...>.
        if hasattr(value, "__dict__"):
            return cls._serialize(
                vars(value)
            )

        return str(value)

    @staticmethod
    def _escape(value: Any) -> str:
        return html.escape(
            str(value)
            if value is not None
            else ""
        )

    @staticmethod
    def _location(item) -> str:
        host = (
            ReportGenerator._value(
                item,
                "host",
                "unknown",
            )
            or "unknown"
        )

        port = ReportGenerator._value(
            item,
            "port",
            None,
        )

        protocol = ReportGenerator._value(
            item,
            "protocol",
            None,
        )

        if port is None:
            return str(host)

        protocol = protocol or "tcp"

        return (
            f"{host}:{port}/{protocol}"
        )

    @staticmethod
    def _safe_list(value):
        if value is None:
            return []

        if isinstance(value, list):
            return value

        if isinstance(value, tuple):
            return list(value)

        return [value]

    @classmethod
    def _attack_specific_remediation(cls, service, method):
        """
        Return short remediation guidance specifically tied to the
        Step 13 attack method being described.

        This is presentation guidance only. It does not replace the
        broader Step 12 remediation actions and does not assert that
        the described attack was successfully performed.
        """

        service_text = str(service or "").strip().lower()
        method_text = str(method or "").strip().lower()
        context = f"{service_text} {method_text}"

        if service_text == "ssh":
            if any(token in context for token in ("legacy", "algorithm", "cipher", "mac", "kex", "key exchange")):
                return [
                    "Upgrade the SSH server to a supported, security-maintained release.",
                    "Disable obsolete key-exchange, host-key, cipher, and MAC algorithms associated with this exposure.",
                    "Restrict SSH access to authorized management networks or a controlled bastion host.",
                    "Review SSH configuration and authentication logs for unsupported algorithms or repeated access attempts.",
                    "Verify that only approved algorithms are advertised and that the legacy option is no longer negotiable.",
                ]
            return [
                "Restrict SSH access to authorized management networks or a controlled bastion host.",
                "Require strong authentication and remove unused or unnecessary SSH accounts.",
                "Apply current SSH server security updates and disable unnecessary authentication methods.",
                "Monitor authentication failures and unusual source addresses for the SSH service.",
                "Verify access controls and authentication policy from an authorized management vantage point.",
            ]

        if service_text in {"telnet", "telnetd"} or "telnet" in context:
            return [
                "Disable Telnet where it is not required and replace it with SSH or another encrypted management service.",
                "Restrict any remaining Telnet access to explicitly authorized management networks.",
                "Remove unused accounts and require strong authentication on the replacement service.",
                "Monitor authentication attempts and unexpected Telnet connections.",
                "Verify that Telnet is no longer reachable from unauthorized network segments.",
            ]

        if service_text in {"ftp", "ftpd"} or "ftp" in context:
            return [
                "Disable FTP if it is not required; otherwise replace it with SFTP or another encrypted transfer service.",
                "Restrict file-transfer access to authorized client networks and required accounts only.",
                "Disable anonymous or unnecessary accounts and enforce strong authentication.",
                "Apply current FTP server security updates and review file/directory permissions.",
                "Verify that only the intended users and networks can reach the service and access permitted data.",
            ]

        if any(token in service_text for token in ("smb", "microsoft-ds", "netbios")) or "smb" in context:
            return [
                "Disable legacy SMB protocols and insecure protocol options that are not required.",
                "Restrict SMB access to authorized hosts and management or application networks.",
                "Review share permissions, remove unnecessary shares, and enforce least privilege.",
                "Require strong authentication and appropriate SMB security controls such as signing where supported.",
                "Verify that unauthorized hosts cannot enumerate or access the exposed shares.",
            ]

        if "nfs" in service_text or "nfs" in context:
            return [
                "Restrict NFS exports to explicitly authorized hosts or networks.",
                "Remove unnecessary exports and apply least-privilege export and filesystem permissions.",
                "Review root access and export options for unnecessary trust relationships.",
                "Monitor NFS access and unexpected mount or export activity.",
                "Verify that only intended clients can discover and mount the required exports.",
            ]

        if any(token in service_text for token in ("mysql", "mariadb", "postgres", "postgresql", "database")) or any(token in context for token in ("database", "mysql", "postgres")):
            return [
                "Restrict database connectivity to authorized application and management networks only.",
                "Disable unnecessary network listeners and remove unused database accounts.",
                "Require strong authentication and least-privilege database permissions.",
                "Apply supported database security updates and monitor authentication and access logs.",
                "Verify that unauthorized hosts cannot establish database sessions or enumerate the service.",
            ]

        if any(token in service_text for token in ("http", "https", "apache", "nginx", "tomcat", "ajp", "web")) or any(token in context for token in ("web", "http", "application")):
            return [
                "Restrict the web service to the networks and users that require access.",
                "Upgrade the web/application server and exposed components to supported security-maintained releases.",
                "Disable unnecessary applications, management interfaces, modules, and default endpoints.",
                "Review access logs and application security monitoring for suspicious requests or repeated probing.",
                "Verify that only intended endpoints are reachable and that unnecessary service metadata is minimized.",
            ]

        if any(token in service_text for token in ("vnc", "x11", "remote desktop")) or any(token in context for token in ("remote desktop", "graphical")):
            return [
                "Disable the remote graphical service if it is not required.",
                "Restrict access to authorized management networks or a controlled jump host.",
                "Require strong authentication and use encrypted transport where supported.",
                "Apply current service security updates and monitor authentication and connection logs.",
                "Verify that unauthorized network segments cannot establish graphical management sessions.",
            ]

        return [
            "Disable the exposed service if it is not required for the intended system function.",
            "Restrict network access to authorized hosts, users, or management networks only.",
            "Apply current security updates and remove unnecessary configuration or service features.",
            "Enable appropriate authentication, least-privilege access, and monitoring for the service.",
            "Verify from an authorized vantage point that the attack preconditions are no longer present.",
        ]

    @classmethod
    def _finding_sources(cls, data):
        """
        Return all finding collections that may contain
        descriptions, evidence, and recommendations.

        Step 11 only presents information already generated
        by previous pipeline stages.
        """

        collections = [
            data.get("security_analysis", []),
            data.get("database_analysis", []),
            data.get("metadata_analysis", []),
            data.get("misconfiguration_analysis", []),
            data.get("management_analysis", []),
        ]

        findings = []

        for collection in collections:
            findings.extend(
                cls._safe_list(collection)
            )

        return findings

    @classmethod
    def _match_finding_for_assessment(
        cls,
        assessment,
        findings,
    ):
        """
        Match a Step 10 risk assessment back to the
        underlying Step 9 finding so the report can show
        the original description, evidence, and recommendation.
        """

        assessment_host = str(
            cls._value(
                assessment,
                "host",
                "",
            )
        )

        assessment_port = cls._value(
            assessment,
            "port",
            None,
        )

        assessment_protocol = str(
            cls._value(
                assessment,
                "protocol",
                "tcp",
            )
            or "tcp"
        ).lower()

        assessment_title = str(
            cls._value(
                assessment,
                "title",
                "",
            )
        ).strip().lower()

        candidates = []

        for finding in findings:

            host = str(
                cls._value(
                    finding,
                    "host",
                    "",
                )
            )

            port = cls._value(
                finding,
                "port",
                None,
            )

            protocol = str(
                cls._value(
                    finding,
                    "protocol",
                    "tcp",
                )
                or "tcp"
            ).lower()

            if host != assessment_host:
                continue

            if port != assessment_port:
                continue

            if protocol != assessment_protocol:
                continue

            candidates.append(finding)

        if not candidates:
            return None

        # Prefer an exact title match.
        for finding in candidates:

            title = str(
                cls._value(
                    finding,
                    "title",
                    "",
                )
            ).strip().lower()

            if title == assessment_title:
                return finding

        # Same location is still useful if titles differ
        # slightly between analysis stages.
        return candidates[0]

    @classmethod
    def _recommendation_for_assessment(
        cls,
        assessment,
        findings,
    ):
        finding = cls._match_finding_for_assessment(
            assessment,
            findings,
        )

        if finding is None:
            return {
                "finding": None,
                "description": "",
                "recommendation": "",
                "evidence": [],
            }

        evidence = cls._safe_list(
            cls._value(
                finding,
                "evidence",
                [],
            )
        )

        return {
            "finding": finding,
            "description": cls._value(
                finding,
                "description",
                "",
            ),
            "recommendation": cls._value(
                finding,
                "recommendation",
                "",
            ),
            "evidence": evidence,
        }

    # =========================================================
    # DATA PREPARATION
    # =========================================================

    def build_report_data(
        self,
        *,
        target,
        scope,
        dns,
        target_expansion,
        discovery,
        port_scan,
        service_enumeration,
        fingerprinting,
        os_fingerprinting,
        tls_analysis,
        ssh_analysis,
        management_analysis,
        security_analysis,
        database_analysis,
        metadata_analysis,
        misconfiguration_analysis,
        correlated_findings,
        correlation_summary,
        risk_analysis,
        risk_summary,
        remediation_guidance=None,
        remediation_summary=None,
        exploitation_analysis=None,
        exploitation_summary=None,
    ):
        """
        Build one normalized report structure.

        This deliberately mirrors the pipeline architecture
        instead of inventing a second data model.
        """

        target_value = self._value(
            target,
            "normalized_value",
            None,
        )

        if target_value is None:
            target_value = self._value(
                target,
                "normalized",
                target,
            )

        target_type = self._value(
            target,
            "target_type",
            None,
        )

        if hasattr(target_type, "value"):
            target_type = target_type.value

        report = {
            "report": {
                "title": "Host & Network Hardener Security Report",
                "generated_at": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "generator": "Host & Network Hardener",
                "pipeline_stage": "11",
            },

            "target": {
                "value": target_value,
                "type": target_type,
            },

            "scope": scope,

            "dns": dns,

            "target_expansion": target_expansion,

            "discovery": discovery,

            "port_scan": port_scan,

            "service_enumeration": service_enumeration,

            "fingerprinting": fingerprinting,

            "os_fingerprinting": os_fingerprinting,

            "tls_analysis": tls_analysis,

            "ssh_analysis": ssh_analysis,

            "management_analysis": management_analysis,

            "security_analysis": security_analysis,

            "database_analysis": database_analysis,

            "metadata_analysis": metadata_analysis,

            "misconfiguration_analysis":
                misconfiguration_analysis,

            "correlated_findings":
                correlated_findings,

            "correlation_summary":
                correlation_summary,

            "risk_analysis":
                risk_analysis,

            "risk_summary":
                risk_summary,

            "remediation_guidance":
                remediation_guidance or [],

            "remediation_summary":
                remediation_summary or {},

            # Step 13 evidence is presented without changing
            # any earlier scan, risk, or remediation results.
            "exploitation_analysis":
                exploitation_analysis or [],

            "exploitation_summary":
                exploitation_summary or {},
        }

        return self._serialize(report)

    # =========================================================
    # SUMMARY CALCULATIONS
    # =========================================================

    def _summary(self, data):
        discovery = data.get(
            "discovery",
            {},
        )

        port_scan = data.get(
            "port_scan",
            {},
        )

        services = data.get(
            "service_enumeration",
            [],
        )

        management = data.get(
            "management_analysis",
            [],
        )

        security = data.get(
            "security_analysis",
            [],
        )

        databases = data.get(
            "database_analysis",
            [],
        )

        metadata = data.get(
            "metadata_analysis",
            [],
        )

        misconfigurations = data.get(
            "misconfiguration_analysis",
            [],
        )

        correlated = data.get(
            "correlated_findings",
            [],
        )

        risk = data.get(
            "risk_summary",
            {},
        )

        live_hosts = discovery.get(
            "live_hosts",
            []
        ) if isinstance(
            discovery,
            dict,
        ) else []

        port_results = port_scan.get(
            "results",
            []
        ) if isinstance(
            port_scan,
            dict,
        ) else []

        open_ports = [
            result
            for result in port_results
            if str(
                self._value(
                    result,
                    "state",
                    "",
                )
            ).lower()
            == "open"
        ]

        open_tcp = [
            result
            for result in open_ports
            if str(
                self._value(
                    result,
                    "protocol",
                    "",
                )
            ).lower()
            == "tcp"
        ]

        open_udp = [
            result
            for result in open_ports
            if str(
                self._value(
                    result,
                    "protocol",
                    "",
                )
            ).lower()
            == "udp"
        ]

        tls_results = data.get(
            "tls_analysis",
            [],
        )

        tls_endpoints = sum(
            1
            for result in tls_results
            if self._value(
                result,
                "tls_detected",
                False,
            )
        )

        remediation = self._safe_list(
            data.get(
                "remediation_guidance",
                [],
            )
        )

        exploitation = self._safe_list(
            data.get(
                "exploitation_analysis",
                [],
            )
        )

        attack_methods = sum(
            len(
                self._safe_list(
                    self._value(assessment, "attack_methods", [])
                )
            )
            for assessment in exploitation
        )

        return {
            "live_hosts": len(live_hosts),
            "open_ports": len(open_ports),
            "open_tcp": len(open_tcp),
            "open_udp": len(open_udp),
            "services": len(services),
            "management_interfaces":
                len(management),
            "security_observations":
                len(security),
            "database_observations":
                len(databases),
            "metadata_observations":
                len(metadata),
            "misconfiguration_observations":
                len(misconfigurations),
            "correlated_findings":
                len(correlated),
            "tls_endpoints":
                tls_endpoints,
            "ssh_endpoints":
                len(
                    data.get(
                        "ssh_analysis",
                        [],
                    )
                ),
            "remediation_actions":
                len(remediation),
            "exploitation_assessments":
                len(exploitation),
            "exploitation_attack_methods":
                attack_methods,
            "exploitation_services_assessed":
                len(exploitation),
            "risk": risk,
        }

    # =========================================================
    # MARKDOWN REPORT
    # =========================================================

    def generate_markdown(
        self,
        data,
        output_name="security_report.md",
    ):
        summary = self._summary(data)

        target = data.get(
            "target",
            {},
        )

        report = data.get(
            "report",
            {},
        )

        risk_summary = data.get(
            "risk_summary",
            {},
        )

        risk_analysis = self._safe_list(
            data.get(
                "risk_analysis",
                [],
            )
        )

        correlated = self._safe_list(
            data.get(
                "correlated_findings",
                [],
            )
        )

        port_scan = data.get(
            "port_scan",
            {},
        )

        port_results = self._safe_list(
            port_scan.get(
                "results",
                [],
            )
            if isinstance(
                port_scan,
                dict,
            )
            else []
        )

        services = self._safe_list(
            data.get(
                "service_enumeration",
                [],
            )
        )

        os_results = self._safe_list(
            data.get(
                "os_fingerprinting",
                [],
            )
        )

        management = self._safe_list(
            data.get(
                "management_analysis",
                [],
            )
        )

        lines = []

        lines.append(
            "# Host & Network Hardener Security Report"
        )
        lines.append("")

        lines.append(
            f"Generated: {report.get('generated_at', 'unknown')}"
        )
        lines.append("")

        # -----------------------------------------------------
        # Executive Summary
        # -----------------------------------------------------

        lines.append(
            "## Executive Summary"
        )
        lines.append("")

        lines.append(
            f"- **Target:** {target.get('value', 'unknown')}"
        )
        lines.append(
            f"- **Live hosts:** {summary['live_hosts']}"
        )
        lines.append(
            f"- **Open ports:** {summary['open_ports']}"
        )
        lines.append(
            f"- **Identified services:** {summary['services']}"
        )
        lines.append(
            f"- **Correlated findings:** "
            f"{summary['correlated_findings']}"
        )
        lines.append(
            f"- **Risk assessments:** "
            f"{risk_summary.get('total_assessed', 0)}"
        )
        lines.append(
            f"- **Highest risk score:** "
            f"{risk_summary.get('highest_risk_score', 0)}/25"
        )
        lines.append("")

        lines.append(
            "### Risk Distribution"
        )
        lines.append("")

        lines.append(
            f"| Severity | Count |"
        )
        lines.append(
            f"|---|---:|"
        )

        for severity in (
            "critical",
            "high",
            "medium",
            "low",
            "informational",
        ):
            lines.append(
                f"| {severity.title()} | "
                f"{risk_summary.get(severity, 0)} |"
            )

        lines.append("")

        # -----------------------------------------------------
        # Target / Scope
        # -----------------------------------------------------

        lines.append(
            "## Target and Scope"
        )
        lines.append("")

        lines.append(
            f"- Target: `{target.get('value', 'unknown')}`"
        )
        lines.append(
            f"- Type: `{target.get('type', 'unknown')}`"
        )

        scope = data.get(
            "scope",
            {},
        )

        if isinstance(scope, dict):
            lines.append(
                f"- Authorized: "
                f"`{scope.get('authorized', 'unknown')}`"
            )

        lines.append("")

        # -----------------------------------------------------
        # Discovery
        # -----------------------------------------------------

        lines.append(
            "## Discovery"
        )
        lines.append("")

        lines.append(
            f"- Live hosts: **{summary['live_hosts']}**"
        )
        lines.append(
            f"- Open TCP ports: **{summary['open_tcp']}**"
        )
        lines.append(
            f"- Open UDP ports: **{summary['open_udp']}**"
        )
        lines.append("")

        # -----------------------------------------------------
        # Ports
        # -----------------------------------------------------

        lines.append(
            "## Open Ports"
        )
        lines.append("")

        if not port_results:
            lines.append(
                "No port results were recorded."
            )
        else:
            lines.append(
                "| Host | Port | Protocol | State | Engine |"
            )
            lines.append(
                "|---|---:|---|---|---|"
            )

            for result in port_results:
                state = self._value(
                    result,
                    "state",
                    "",
                )

                if str(state).lower() != "open":
                    continue

                lines.append(
                    f"| {self._value(result, 'host', '')} "
                    f"| {self._value(result, 'port', '')} "
                    f"| {self._value(result, 'protocol', '')} "
                    f"| {state} "
                    f"| {self._value(result, 'engine', '')} |"
                )

        lines.append("")

        # -----------------------------------------------------
        # Services
        # -----------------------------------------------------

        lines.append(
            "## Service Enumeration"
        )
        lines.append("")

        if not services:
            lines.append(
                "No service enumeration results were recorded."
            )
        else:
            lines.append(
                "| Location | Service | Product | Version | Confidence |"
            )
            lines.append(
                "|---|---|---|---|---|"
            )

            for service in services:
                lines.append(
                    f"| {self._location(service)} "
                    f"| {self._value(service, 'service', '')} "
                    f"| {self._value(service, 'product', '')} "
                    f"| {self._value(service, 'version', '')} "
                    f"| {self._value(service, 'confidence', '')} |"
                )

        lines.append("")

        # -----------------------------------------------------
        # OS
        # -----------------------------------------------------

        lines.append(
            "## Operating System / Platform"
        )
        lines.append("")

        if not os_results:
            lines.append(
                "No OS fingerprinting result was recorded."
            )
        else:
            for result in os_results:
                lines.append(
                    f"- Host: "
                    f"`{self._value(result, 'host', 'unknown')}`"
                )
                lines.append(
                    f"- OS Family: "
                    f"`{self._value(result, 'os_family', 'unknown')}`"
                )
                lines.append(
                    f"- OS Name: "
                    f"`{self._value(result, 'os_name', 'unknown')}`"
                )
                lines.append(
                    f"- Distribution Hint: "
                    f"`{self._value(result, 'distribution_hint', 'unknown')}`"
                )
                lines.append(
                    f"- Kernel Generation: "
                    f"`{self._value(result, 'kernel_generation', 'unknown')}`"
                )
                lines.append(
                    f"- Confidence: "
                    f"`{self._value(result, 'confidence', 'unknown')}`"
                )
                lines.append("")

        # -----------------------------------------------------
        # Security Analysis
        # -----------------------------------------------------

        lines.append(
            "## Security Analysis"
        )
        lines.append("")

        analysis_sections = [
            (
                "Network Security Observations",
                data.get(
                    "security_analysis",
                    [],
                ),
            ),
            (
                "Database Exposure",
                data.get(
                    "database_analysis",
                    [],
                ),
            ),
            (
                "Metadata Leakage",
                data.get(
                    "metadata_analysis",
                    [],
                ),
            ),
            (
                "Misconfiguration Analysis",
                data.get(
                    "misconfiguration_analysis",
                    [],
                ),
            ),
        ]

        for title, findings in analysis_sections:

            findings = self._safe_list(
                findings
            )

            lines.append(
                f"### {title}"
            )
            lines.append("")

            if not findings:
                lines.append(
                    "No observations recorded."
                )
                lines.append("")
                continue

            lines.append(
                "| Category | Location | Title | Confidence |"
            )
            lines.append(
                "|---|---|---|---|"
            )

            for finding in findings:
                lines.append(
                    f"| {self._value(finding, 'category', '')} "
                    f"| {self._location(finding)} "
                    f"| {self._value(finding, 'title', '')} "
                    f"| {self._value(finding, 'confidence', '')} |"
                )

            lines.append("")

        # -----------------------------------------------------
        # Management
        # -----------------------------------------------------

        lines.append(
            "## Management Interfaces"
        )
        lines.append("")

        if not management:
            lines.append(
                "No management interfaces were identified."
            )
        else:
            lines.append(
                "| Location | Category | Title | Service | Confidence |"
            )
            lines.append(
                "|---|---|---|---|---|"
            )

            for item in management:
                lines.append(
                    f"| {self._location(item)} "
                    f"| {self._value(item, 'category', '')} "
                    f"| {self._value(item, 'title', '')} "
                    f"| {self._value(item, 'service', '')} "
                    f"| {self._value(item, 'confidence', '')} |"
                )

        lines.append("")

        # -----------------------------------------------------
        # Correlation
        # -----------------------------------------------------

        lines.append(
            "## Correlated Findings"
        )
        lines.append("")

        if not correlated:
            lines.append(
                "No correlated findings were produced."
            )
        else:
            lines.append(
                "| Category | Location | Title | Confidence | Occurrences |"
            )
            lines.append(
                "|---|---|---|---|---:|"
            )

            for finding in correlated:
                lines.append(
                    f"| {self._value(finding, 'category', '')} "
                    f"| {self._location(finding)} "
                    f"| {self._value(finding, 'title', '')} "
                    f"| {self._value(finding, 'confidence', '')} "
                    f"| {self._value(finding, 'occurrence_count', 1)} |"
                )

        lines.append("")

        # -----------------------------------------------------
        # Risk Assessment
        # -----------------------------------------------------

        lines.append(
            "## Risk Assessment"
        )
        lines.append("")

        if not risk_analysis:
            lines.append(
                "No risk assessments were produced."
            )
        else:
            lines.append(
                "| Severity | Risk | Location | Finding | Impact | Likelihood | Confidence |"
            )
            lines.append(
                "|---|---:|---|---|---:|---:|---|"
            )

            for assessment in risk_analysis:
                lines.append(
                    f"| {self._value(assessment, 'severity', '').title()} "
                    f"| {self._value(assessment, 'risk_score', '')}/25 "
                    f"| {self._location(assessment)} "
                    f"| {self._value(assessment, 'title', '')} "
                    f"| {self._value(assessment, 'impact_score', '')} "
                    f"| {self._value(assessment, 'likelihood_score', '')} "
                    f"| {self._value(assessment, 'confidence', '')} |"
                )

        lines.append("")

        # -----------------------------------------------------
        # Step 13 — Service Exposure & Exploitation Methods
        # -----------------------------------------------------

        exploitation = self._safe_list(
            data.get("exploitation_analysis", [])
        )

        lines.append("## Service Exposure & Exploitation Methods")
        lines.append("")
        lines.append(
            "Step 13 is an analysis-only assessment of exposed services. "
            "It presents potential attack methods, prerequisites, potential impact, "
            "detection indicators, defensive controls, verification guidance, and "
            "related remediation already produced by the pipeline. It does not execute "
            "exploits or perform additional scanning."
        )
        lines.append("")

        attack_method_count = sum(
            len(self._safe_list(self._value(item, "attack_methods", [])))
            for item in exploitation
        )
        lines.append(f"- **Assessments Generated:** {len(exploitation)}")
        lines.append(f"- **Attack Methods Mapped:** {attack_method_count}")
        lines.append("")

        for index, assessment in enumerate(exploitation, start=1):
            service = self._value(assessment, "service", "unknown")
            host = self._value(assessment, "host", "")
            port = self._value(assessment, "port", None)
            protocol = self._value(assessment, "protocol", "tcp")
            location = host
            if port is not None:
                location = f"{host}:{port}/{protocol or 'tcp'}"

            lines.append(f"### {index}. {service}")
            lines.append("")
            lines.append(f"- **Location:** `{location}`")

            exposure = self._value(assessment, "exposure", "")
            if exposure:
                lines.append(f"- **Exposure:** {exposure}")
                lines.append("")

            methods = self._safe_list(self._value(assessment, "attack_methods", []))
            if methods:
                lines.append("#### Attack Methods")
                lines.append("")
                for method_index, method in enumerate(methods, start=1):
                    method_name = self._value(method, "method", "Attack method")
                    lines.append(f"**{method_index}. {method_name}**")
                    lines.append("")
                    for label, field in (
                        ("Description", "description"),
                        ("Preconditions", "preconditions"),
                        ("Potential Impact", "potential_impact"),
                        ("Detection / Indicators", "detection_indicators"),
                        ("Defensive Controls", "defensive_controls"),
                        ("Verification", "verification"),
                    ):
                        values = self._safe_list(self._value(method, field, []))
                        if not values:
                            scalar = self._value(method, field, None)
                            if scalar not in (None, ""):
                                values = [scalar]
                        if values:
                            lines.append(f"- **{label}:**")
                            lines.extend(f"  - {value}" for value in values)
                            lines.append("")
                    attack_remediation = self._attack_specific_remediation(
                        service,
                        method_name,
                    )
                    lines.append("- **Attack-Specific Remediation:**")
                    lines.extend(
                        f"  - {value}"
                        for value in attack_remediation
                    )
                    lines.append("")
            else:
                lines.append("No attack methods were recorded for this assessment.")
                lines.append("")

            related = self._safe_list(self._value(assessment, "related_remediation", []))
            if not related:
                for item in self._safe_list(data.get("remediation_guidance", [])):
                    if (
                        str(self._value(item, "host", "")) == str(host)
                        and str(self._value(item, "port", "")) == str(port)
                    ):
                        related.append(item)

            lines.append("#### Related Remediation")
            lines.append("")
            if related:
                for rem_index, item in enumerate(related, start=1):
                    priority = self._value(item, "priority", "")
                    action = self._value(item, "recommendation", self._value(item, "action", ""))
                    verify = self._value(item, "verify", "")
                    prefix = f"[{priority}] " if priority else ""
                    lines.append(f"**{rem_index}. {prefix}{action}**")
                    if verify:
                        lines.append(f"- **Verify:** {verify}")
                    lines.append("")
            else:
                lines.append("No directly linked remediation action was recorded.")
                lines.append("")

            lines.append("---")
            lines.append("")

        # -----------------------------------------------------
        # Coverage
        # -----------------------------------------------------

        lines.append(
            "## Analysis Coverage"
        )
        lines.append("")

        lines.append(
            f"- TLS endpoints detected: "
            f"**{summary['tls_endpoints']}**"
        )
        lines.append(
            f"- SSH endpoints analyzed: "
            f"**{summary['ssh_endpoints']}**"
        )
        lines.append(
            f"- Management interfaces: "
            f"**{summary['management_interfaces']}**"
        )
        lines.append("")

        # -----------------------------------------------------
        # Methodology
        # -----------------------------------------------------

        lines.append(
            "## Methodology"
        )
        lines.append("")

        lines.append(
            "This report presents evidence collected by the "
            "Host & Network Hardener pipeline and the risk "
            "assessments generated in Step 10."
        )
        lines.append("")

        lines.append(
            "Step 11 does not perform additional network "
            "scanning or vulnerability exploitation."
        )
        lines.append("")

        lines.append(
            "Network exposure statements describe reachability "
            "from the scan vantage point and should not be "
            "interpreted as proof of Internet exposure."
        )
        lines.append("")

        lines.append(
            "Version information alone is not treated as proof "
            "of a vulnerability. Exploitability is reported "
            "according to the vulnerability intelligence "
            "available to the Step 10 risk engine."
        )
        lines.append("")

        # -----------------------------------------------------
        # Limitations
        # -----------------------------------------------------

        lines.append(
            "## Limitations"
        )
        lines.append("")

        lines.append(
            "- The report reflects only the targets authorized "
            "by the configured scope."
        )
        lines.append(
            "- Results depend on the scan profile and network "
            "visibility available during the assessment."
        )
        lines.append(
            "- UDP service identification may be less complete "
            "than TCP service identification."
        )
        lines.append(
            "- TLS analysis is only performed for endpoints "
            "identified as TLS candidates."
        )
        lines.append(
            "- Step 10 currently treats exploitability as "
            "unknown when no vulnerability intelligence is "
            "available."
        )
        lines.append("")

        # -----------------------------------------------------
        # Evidence
        # -----------------------------------------------------

        lines.append(
            "## Evidence"
        )
        lines.append("")

        lines.append(
            "The complete machine-readable evidence remains "
            "available in `scan_data.json`."
        )
        lines.append("")

        content = "\n".join(lines)

        path = (
            self.report_dir
            / output_name
        )

        path.write_text(
            content,
            encoding="utf-8",
        )

        return path

        # =========================================================
    # HTML REPORT
    # =========================================================

    def generate_html(
        self,
        data,
        output_name="security_report.html",
    ):
        summary = self._summary(data)

        target = data.get(
            "target",
            {},
        )

        report = data.get(
            "report",
            {},
        )

        risk_summary = data.get(
            "risk_summary",
            {},
        )

        risk_analysis = self._safe_list(
            data.get(
                "risk_analysis",
                [],
            )
        )

        correlated = self._safe_list(
            data.get(
                "correlated_findings",
                [],
            )
        )

        services = self._safe_list(
            data.get(
                "service_enumeration",
                [],
            )
        )

        management = self._safe_list(
            data.get(
                "management_analysis",
                [],
            )
        )

        security = self._safe_list(
            data.get(
                "security_analysis",
                [],
            )
        )

        databases = self._safe_list(
            data.get(
                "database_analysis",
                [],
            )
        )

        metadata = self._safe_list(
            data.get(
                "metadata_analysis",
                [],
            )
        )

        misconfigurations = self._safe_list(
            data.get(
                "misconfiguration_analysis",
                [],
            )
        )

        port_scan = data.get(
            "port_scan",
            {},
        )

        port_results = self._safe_list(
            port_scan.get(
                "results",
                [],
            )
            if isinstance(
                port_scan,
                dict,
            )
            else []
        )

        os_results = self._safe_list(
            data.get(
                "os_fingerprinting",
                [],
            )
        )

        # -----------------------------------------------------
        # Helpers
        # -----------------------------------------------------

        def td(value):
            return (
                "<td>"
                + self._escape(value)
                + "</td>"
            )

        def severity_class(severity):
            return (
                str(severity)
                .lower()
                .replace(
                    " ",
                    "-",
                )
            )

        html_parts = []

        html_parts.append(
            """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1">
<title>Host & Network Hardener Security Report</title>

<style>
body {
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Arial,
        sans-serif;
    margin: 0;
    background: #f5f7fa;
    color: #20242a;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px;
}

header {
    background: #18212b;
    color: white;
    padding: 32px;
    border-radius: 10px;
    margin-bottom: 24px;
}

header h1 {
    margin: 0 0 10px 0;
}

header p {
    margin: 4px 0;
}

section {
    background: white;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow:
        0 1px 3px rgba(0,0,0,0.08);
}

h2 {
    margin-top: 0;
}

h3 {
    margin-top: 28px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(180px, 1fr)
        );
    gap: 14px;
}

.card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 18px;
}

.card .label {
    font-size: 13px;
    color: #64748b;
}

.card .value {
    font-size: 26px;
    font-weight: 700;
    margin-top: 5px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}

th,
td {
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}

th {
    background: #f8fafc;
}

.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}

.badge.critical {
    background: #fee2e2;
    color: #991b1b;
}

.badge.high {
    background: #ffedd5;
    color: #9a3412;
}

.badge.medium {
    background: #fef3c7;
    color: #92400e;
}

.badge.low {
    background: #dcfce7;
    color: #166534;
}

.badge.informational {
    background: #e0f2fe;
    color: #075985;
}

.small {
    color: #64748b;
    font-size: 13px;
}

pre {
    background: #111827;
    color: #e5e7eb;
    padding: 16px;
    overflow-x: auto;
    border-radius: 8px;
}

@media (max-width: 700px) {
    .container {
        padding: 14px;
    }

    section {
        padding: 16px;
        overflow-x: auto;
    }
}
</style>
</head>
<body>
<div class="container">
"""
        )

        # -----------------------------------------------------
        # Header
        # -----------------------------------------------------

        html_parts.append(
            "<header>"
        )

        html_parts.append(
            "<h1>"
            "Host & Network Hardener"
            "</h1>"
        )

        html_parts.append(
            "<p>Security Assessment Report</p>"
        )

        html_parts.append(
            "<p class=\"small\">"
            + self._escape(
                report.get(
                    "generated_at",
                    "unknown",
                )
            )
            + "</p>"
        )

        html_parts.append(
            "</header>"
        )

        # -----------------------------------------------------
        # Executive Summary
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Executive Summary</h2>"
        )

        html_parts.append(
            "<p>"
            "This report presents the security observations "
            "and risk assessments produced by the "
            "Host & Network Hardener pipeline."
            "</p>"
        )

        html_parts.append(
            "<div class=\"grid\">"
        )

        cards = [
            (
                "Target",
                target.get(
                    "value",
                    "unknown",
                ),
            ),
            (
                "Live Hosts",
                summary["live_hosts"],
            ),
            (
                "Open Ports",
                summary["open_ports"],
            ),
            (
                "Services",
                summary["services"],
            ),
            (
                "Correlated Findings",
                summary["correlated_findings"],
            ),
            (
                "Highest Risk",
                f"{risk_summary.get('highest_risk_score', 0)}/25",
            ),
        ]

        for label, value in cards:
            html_parts.append(
                "<div class=\"card\">"
                "<div class=\"label\">"
                + self._escape(label)
                + "</div>"
                "<div class=\"value\">"
                + self._escape(value)
                + "</div>"
                "</div>"
            )

        html_parts.append(
            "</div>"
        )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # Risk Distribution
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Risk Distribution</h2>"
        )

        html_parts.append(
            "<table>"
            "<thead>"
            "<tr>"
            "<th>Severity</th>"
            "<th>Count</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
        )

        for severity in (
            "critical",
            "high",
            "medium",
            "low",
            "informational",
        ):

            count = risk_summary.get(
                severity,
                0,
            )

            html_parts.append(
                "<tr>"
                + td(severity.title())
                + td(count)
                + "</tr>"
            )

        html_parts.append(
            "</tbody></table>"
        )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # Risk Findings
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Risk Assessment</h2>"
        )

        if not risk_analysis:

            html_parts.append(
                "<p>No risk assessments were produced.</p>"
            )

        else:

            html_parts.append(
                "<table>"
                "<thead>"
                "<tr>"
                "<th>Severity</th>"
                "<th>Risk</th>"
                "<th>Location</th>"
                "<th>Finding</th>"
                "<th>Impact</th>"
                "<th>Likelihood</th>"
                "<th>Confidence</th>"
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for assessment in risk_analysis:

                severity = self._value(
                    assessment,
                    "severity",
                    "unknown",
                )

                badge = (
                    "<span class=\"badge "
                    + severity_class(severity)
                    + "\">"
                    + self._escape(severity)
                    + "</span>"
                )

                html_parts.append(
                    "<tr>"
                    "<td>"
                    + badge
                    + "</td>"
                    + td(
                        str(
                            self._value(
                                assessment,
                                "risk_score",
                                "",
                            )
                        )
                        + "/25"
                    )
                    + td(
                        self._location(
                            assessment
                        )
                    )
                    + td(
                        self._value(
                            assessment,
                            "title",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            assessment,
                            "impact_score",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            assessment,
                            "likelihood_score",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            assessment,
                            "confidence",
                            "",
                        )
                    )
                    + "</tr>"
                )

            html_parts.append(
                "</tbody></table>"
            )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # Ports
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Open Ports</h2>"
        )

        html_parts.append(
            "<table>"
            "<thead>"
            "<tr>"
            "<th>Host</th>"
            "<th>Port</th>"
            "<th>Protocol</th>"
            "<th>Engine</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
        )

        for result in port_results:

            if str(
                self._value(
                    result,
                    "state",
                    "",
                )
            ).lower() != "open":
                continue

            html_parts.append(
                "<tr>"
                + td(
                    self._value(
                        result,
                        "host",
                        "",
                    )
                )
                + td(
                    self._value(
                        result,
                        "port",
                        "",
                    )
                )
                + td(
                    self._value(
                        result,
                        "protocol",
                        "",
                    )
                )
                + td(
                    self._value(
                        result,
                        "engine",
                        "",
                    )
                )
                + "</tr>"
            )

        html_parts.append(
            "</tbody></table>"
        )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # Services
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Service Enumeration</h2>"
        )

        html_parts.append(
            "<table>"
            "<thead>"
            "<tr>"
            "<th>Location</th>"
            "<th>Service</th>"
            "<th>Product</th>"
            "<th>Version</th>"
            "<th>Confidence</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
        )

        for service in services:

            html_parts.append(
                "<tr>"
                + td(
                    self._location(
                        service
                    )
                )
                + td(
                    self._value(
                        service,
                        "service",
                        "",
                    )
                )
                + td(
                    self._value(
                        service,
                        "product",
                        "",
                    )
                )
                + td(
                    self._value(
                        service,
                        "version",
                        "",
                    )
                )
                + td(
                    self._value(
                        service,
                        "confidence",
                        "",
                    )
                )
                + "</tr>"
            )

        html_parts.append(
            "</tbody></table>"
        )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # OS
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Operating System / Platform</h2>"
        )

        if not os_results:

            html_parts.append(
                "<p>No OS fingerprinting result was recorded.</p>"
            )

        else:

            html_parts.append(
                "<table>"
                "<thead>"
                "<tr>"
                "<th>Host</th>"
                "<th>OS Family</th>"
                "<th>OS Name</th>"
                "<th>Distribution Hint</th>"
                "<th>Kernel</th>"
                "<th>Confidence</th>"
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for result in os_results:

                html_parts.append(
                    "<tr>"
                    + td(
                        self._value(
                            result,
                            "host",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            result,
                            "os_family",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            result,
                            "os_name",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            result,
                            "distribution_hint",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            result,
                            "kernel_generation",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            result,
                            "confidence",
                            "",
                        )
                    )
                    + "</tr>"
                )

            html_parts.append(
                "</tbody></table>"
            )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # Security Findings
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Security Analysis</h2>"
        )

        security_sections = [
            (
                "Network Security",
                security,
            ),
            (
                "Database Exposure",
                databases,
            ),
            (
                "Metadata Leakage",
                metadata,
            ),
            (
                "Misconfiguration",
                misconfigurations,
            ),
            (
                "Management Interfaces",
                management,
            ),
        ]

        for title, findings in security_sections:

            html_parts.append(
                "<h3>"
                + self._escape(title)
                + "</h3>"
            )

            if not findings:

                html_parts.append(
                    "<p class=\"small\">"
                    "No observations recorded."
                    "</p>"
                )

                continue

            html_parts.append(
                "<table>"
                "<thead>"
                "<tr>"
                "<th>Category</th>"
                "<th>Location</th>"
                "<th>Title</th>"
                "<th>Confidence</th>"
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for finding in findings:

                html_parts.append(
                    "<tr>"
                    + td(
                        self._value(
                            finding,
                            "category",
                            "",
                        )
                    )
                    + td(
                        self._location(
                            finding
                        )
                    )
                    + td(
                        self._value(
                            finding,
                            "title",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            finding,
                            "confidence",
                            "",
                        )
                    )
                    + "</tr>"
                )

            html_parts.append(
                "</tbody></table>"
            )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # Correlation
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Correlated Findings</h2>"
        )

        if not correlated:

            html_parts.append(
                "<p>No correlated findings were produced.</p>"
            )

        else:

            html_parts.append(
                "<table>"
                "<thead>"
                "<tr>"
                "<th>Category</th>"
                "<th>Location</th>"
                "<th>Title</th>"
                "<th>Confidence</th>"
                "<th>Occurrences</th>"
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for finding in correlated:

                html_parts.append(
                    "<tr>"
                    + td(
                        self._value(
                            finding,
                            "category",
                            "",
                        )
                    )
                    + td(
                        self._location(
                            finding
                        )
                    )
                    + td(
                        self._value(
                            finding,
                            "title",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            finding,
                            "confidence",
                            "",
                        )
                    )
                    + td(
                        self._value(
                            finding,
                            "occurrence_count",
                            1,
                        )
                    )
                    + "</tr>"
                )

            html_parts.append(
                "</tbody></table>"
            )

        html_parts.append(
            "</section>"
        )

        # -----------------------------------------------------
        # Step 13 — Service Exposure & Exploitation Methods
        # -----------------------------------------------------

        exploitation = self._safe_list(
            data.get("exploitation_analysis", [])
        )

        html_parts.append("<section>")
        html_parts.append("<h2>Service Exposure &amp; Exploitation Methods</h2>")
        html_parts.append(
            "<p>Step 13 is an analysis-only assessment of exposed services. "
            "It presents potential attack methods, prerequisites, potential impact, "
            "detection indicators, defensive controls, verification guidance, and "
            "related remediation already produced by the pipeline. It does not execute "
            "exploits or perform additional scanning.</p>"
        )
        attack_method_count = sum(
            len(self._safe_list(self._value(item, "attack_methods", [])))
            for item in exploitation
        )
        html_parts.append(
            f"<p><strong>Assessments Generated:</strong> {len(exploitation)} &nbsp; "
            f"<strong>Attack Methods Mapped:</strong> {attack_method_count}</p>"
        )

        for index, assessment in enumerate(exploitation, start=1):
            service = self._value(assessment, "service", "unknown")
            host = self._value(assessment, "host", "")
            port = self._value(assessment, "port", None)
            protocol = self._value(assessment, "protocol", "tcp")
            location = host
            if port is not None:
                location = f"{host}:{port}/{protocol or 'tcp'}"

            html_parts.append(f"<h3>{index}. {html.escape(str(service))}</h3>")
            html_parts.append(
                "<p><strong>Location:</strong> " + html.escape(str(location)) + "</p>"
            )
            exposure = self._value(assessment, "exposure", "")
            if exposure:
                html_parts.append(
                    "<p><strong>Exposure:</strong> " + html.escape(str(exposure)) + "</p>"
                )

            methods = self._safe_list(self._value(assessment, "attack_methods", []))
            if methods:
                html_parts.append("<h4>Attack Methods</h4>")
                for method_index, method in enumerate(methods, start=1):
                    method_name = self._value(method, "method", "Attack method")
                    html_parts.append(
                        f"<h5>{method_index}. {html.escape(str(method_name))}</h5>"
                    )
                    for label, field in (
                        ("Description", "description"),
                        ("Preconditions", "preconditions"),
                        ("Potential Impact", "potential_impact"),
                        ("Detection / Indicators", "detection_indicators"),
                        ("Defensive Controls", "defensive_controls"),
                        ("Verification", "verification"),
                    ):
                        values = self._safe_list(self._value(method, field, []))
                        if not values:
                            scalar = self._value(method, field, None)
                            if scalar not in (None, ""):
                                values = [scalar]
                        if values:
                            html_parts.append("<p><strong>" + label + ":</strong></p><ul>")
                            html_parts.extend(
                                "<li>" + html.escape(str(value)) + "</li>"
                                for value in values
                            )
                            html_parts.append("</ul>")
                    attack_remediation = self._attack_specific_remediation(
                        service,
                        method_name,
                    )
                    html_parts.append("<p><strong>Attack-Specific Remediation:</strong></p><ul>")
                    html_parts.extend(
                        "<li>" + html.escape(str(value)) + "</li>"
                        for value in attack_remediation
                    )
                    html_parts.append("</ul>")
            else:
                html_parts.append("<p>No attack methods were recorded for this assessment.</p>")

            related = self._safe_list(self._value(assessment, "related_remediation", []))
            if not related:
                for item in self._safe_list(data.get("remediation_guidance", [])):
                    if (
                        str(self._value(item, "host", "")) == str(host)
                        and str(self._value(item, "port", "")) == str(port)
                    ):
                        related.append(item)

            html_parts.append("<h4>Related Remediation</h4>")
            if related:
                html_parts.append("<ol>")
                for item in related:
                    priority = self._value(item, "priority", "")
                    action = self._value(item, "recommendation", self._value(item, "action", ""))
                    verify = self._value(item, "verify", "")
                    prefix = f"[{priority}] " if priority else ""
                    html_parts.append("<li><strong>" + html.escape(prefix + str(action)) + "</strong>")
                    if verify:
                        html_parts.append(
                            "<br><span class=\"small\"><strong>Verify:</strong> "
                            + html.escape(str(verify))
                            + "</span>"
                        )
                    html_parts.append("</li>")
                html_parts.append("</ol>")
            else:
                html_parts.append("<p>No directly linked remediation action was recorded.</p>")
            html_parts.append("<hr>")

        if not exploitation:
            html_parts.append("<p>No Step 13 service exposure assessments were recorded.</p>")
        html_parts.append("</section>")

        # -----------------------------------------------------
        # Coverage / limitations
        # -----------------------------------------------------

        html_parts.append(
            "<section>"
        )

        html_parts.append(
            "<h2>Analysis Coverage</h2>"
        )

        coverage = [
            (
                "TLS endpoints",
                summary["tls_endpoints"],
            ),
            (
                "SSH endpoints",
                summary["ssh_endpoints"],
            ),
            (
                "Management interfaces",
                summary["management_interfaces"],
            ),
            (
                "Security observations",
                summary["security_observations"],
            ),
            (
                "Database observations",
                summary["database_observations"],
            ),
            (
                "Metadata observations",
                summary["metadata_observations"],
            ),
            (
                "Misconfiguration observations",
                summary["misconfiguration_observations"],
            ),
        ]

        html_parts.append(
            "<table>"
            "<thead>"
            "<tr>"
            "<th>Area</th>"
            "<th>Count</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
        )

        for label, value in coverage:

            html_parts.append(
                "<tr>"
                + td(label)
                + td(value)
                + "</tr>"
            )

        html_parts.append(
            "</tbody></table>"
        )

        html_parts.append(
            "<h3>Methodology Notes</h3>"
        )

        html_parts.append(
            "<ul>"
            "<li>"
            "This report presents evidence already collected "
            "by the scanning and analysis pipeline."
            "</li>"
            "<li>"
            "Step 11 does not perform additional network "
            "scanning or vulnerability exploitation."
            "</li>"
            "<li>"
            "Network exposure refers to reachability from "
            "the scan vantage point."
            "</li>"
            "<li>"
            "Version information alone is not treated as "
            "proof of a vulnerability."
            "</li>"
            "</ul>"
        )

        html_parts.append(
            "</section>"
        )

        html_parts.append(
            "</div>"
            "</body>"
            "</html>"
        )

        content = "".join(
            html_parts
        )

        path = (
            self.report_dir
            / output_name
        )

        path.write_text(
            content,
            encoding="utf-8",
        )

        return path
    # =========================================================
    # PDF REPORT
    # =========================================================

    def generate_pdf(
        self,
        data,
        output_name="security_report.pdf",
    ):
        """
        Generate the operator-facing PDF security report.

        Presentation only:
          - uses the evidence and risk values already produced
            by previous pipeline stages
          - does not scan, rescan, exploit, recalculate risk,
            or create new remediation logic
          - keeps detailed machine-readable evidence in a clearly
            separated appendix instead of displaying raw JSON
            throughout the main report
        """

        summary = self._summary(data)

        target = data.get("target", {})
        report = data.get("report", {})
        scope = data.get("scope", {})
        target_expansion = data.get("target_expansion", {})
        dns = data.get("dns", {})
        discovery = data.get("discovery", {})
        port_scan = data.get("port_scan", {})
        services = self._safe_list(data.get("service_enumeration", []))
        fingerprint_results = self._safe_list(data.get("fingerprinting", []))
        os_results = self._safe_list(data.get("os_fingerprinting", []))
        tls_results = self._safe_list(data.get("tls_analysis", []))
        ssh_results = self._safe_list(data.get("ssh_analysis", []))
        management_results = self._safe_list(data.get("management_analysis", []))
        security_results = self._safe_list(data.get("security_analysis", []))
        database_results = self._safe_list(data.get("database_analysis", []))
        metadata_results = self._safe_list(data.get("metadata_analysis", []))
        misconfiguration_results = self._safe_list(data.get("misconfiguration_analysis", []))
        correlated_results = self._safe_list(data.get("correlated_findings", []))
        risk_analysis = self._safe_list(data.get("risk_analysis", []))
        risk_summary = data.get("risk_summary", {})
        remediation_guidance = self._safe_list(data.get("remediation_guidance", []))
        remediation_summary = data.get("remediation_summary", {})
        exploitation_results = self._safe_list(data.get("exploitation_analysis", []))
        exploitation_summary = data.get("exploitation_summary", {})

        port_results = self._safe_list(
            port_scan.get("results", [])
            if isinstance(port_scan, dict)
            else []
        )

        finding_sources = self._finding_sources(data)

        path = self.report_dir / output_name

        document = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            rightMargin=14 * mm,
            leftMargin=14 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title="Host & Network Hardener Security Assessment Report",
            author="Host & Network Hardener",
            subject="Automated Host and Network Security Assessment",
        )

        styles = getSampleStyleSheet()

        # -----------------------------------------------------
        # Styles
        # -----------------------------------------------------

        title_style = ParagraphStyle(
            "HNHTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=28,
            alignment=TA_CENTER,
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "HNHSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#4b5563"),
            spaceAfter=12,
        )

        cover_meta_style = ParagraphStyle(
            "HNHCoverMeta",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#374151"),
            spaceAfter=4,
        )

        section_style = ParagraphStyle(
            "HNHSection",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            spaceBefore=10,
            spaceAfter=8,
            keepWithNext=True,
            textColor=colors.HexColor("#111827"),
        )

        subsection_style = ParagraphStyle(
            "HNHSubsection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            spaceBefore=8,
            spaceAfter=5,
            keepWithNext=True,
            textColor=colors.HexColor("#1f2937"),
        )

        body_style = ParagraphStyle(
            "HNHBody",
            parent=styles["BodyText"],
            fontSize=8.7,
            leading=12.2,
            spaceAfter=5,
            textColor=colors.HexColor("#1f2937"),
        )

        small_style = ParagraphStyle(
            "HNHSmall",
            parent=body_style,
            fontSize=7.3,
            leading=9.5,
            spaceAfter=2,
        )

        tiny_style = ParagraphStyle(
            "HNHTiny",
            parent=body_style,
            fontSize=6.5,
            leading=8,
            spaceAfter=1,
        )

        table_header_style = ParagraphStyle(
            "HNHTableHeader",
            parent=small_style,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )

        table_cell_style = ParagraphStyle(
            "HNHTableCell",
            parent=small_style,
            textColor=colors.HexColor("#111827"),
        )

        table_cell_center_style = ParagraphStyle(
            "HNHTableCellCenter",
            parent=table_cell_style,
            alignment=TA_CENTER,
        )

        finding_title_style = ParagraphStyle(
            "HNHFindingTitle",
            parent=body_style,
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            spaceAfter=3,
        )

        finding_label_style = ParagraphStyle(
            "HNHFindingLabel",
            parent=small_style,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#374151"),
        )

        score_style = ParagraphStyle(
            "HNHScore",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=20,
            alignment=TA_CENTER,
            spaceAfter=2,
        )

        appendix_style = ParagraphStyle(
            "HNHAppendix",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=5.8,
            leading=7.2,
            leftIndent=3,
            rightIndent=3,
            spaceAfter=5,
        )

        note_style = ParagraphStyle(
            "HNHNote",
            parent=body_style,
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#4b5563"),
        )

        # -----------------------------------------------------
        # Flowable helpers
        # -----------------------------------------------------

        def clean_text(value):
            if value is None:
                return ""
            text_value = str(value)
            if " object at 0x" in text_value and text_value.startswith("<"):
                return "Structured object representation omitted; see structured fields above."
            return text_value

        def p(value, style=body_style):
            text_value = clean_text(value)
            return Paragraph(
                html.escape(text_value).replace("\n", "<br/>"),
                style,
            )

        def header_cell(value):
            return p(value, table_header_style)

        def cell(value, center=False):
            return p(
                value,
                table_cell_center_style if center else table_cell_style,
            )

        def make_table(rows, widths, header=True, repeat=True):
            if not rows:
                return None

            table = Table(
                rows,
                colWidths=widths,
                repeatRows=1 if header and repeat else 0,
                hAlign="LEFT",
            )

            commands = [
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d5db")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]

            if header:
                commands.extend([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ])

            table.setStyle(TableStyle(commands))
            return table

        def add_section(story, title):
            story.append(Spacer(1, 4))
            story.append(p(title, section_style))

        def add_subsection(story, title):
            story.append(p(title, subsection_style))

        def display_value(value, default="Not recorded"):
            if value is None or value == "":
                return default
            if isinstance(value, (dict, list, tuple, set)):
                return ", ".join(
                    clean_text(item)
                    for item in self._safe_list(value)
                ) if isinstance(value, (list, tuple, set)) else "Structured data"
            return clean_text(value)

        def yes_no(value):
            if value is True:
                return "Yes"
            if value is False:
                return "No"
            return "Not recorded"

        def severity_text(value):
            value = clean_text(value).strip()
            if not value:
                return "Informational"
            return value.title()

        def severity_background(value):
            normalized = clean_text(value).lower()
            if normalized == "critical":
                return colors.HexColor("#7f1d1d")
            if normalized == "high":
                return colors.HexColor("#b91c1c")
            if normalized == "medium":
                return colors.HexColor("#b45309")
            if normalized == "low":
                return colors.HexColor("#2563eb")
            return colors.HexColor("#6b7280")

        def badge(value):
            text_value = severity_text(value)
            table = Table([[p(text_value, ParagraphStyle(
                "Badge",
                parent=small_style,
                fontName="Helvetica-Bold",
                fontSize=7,
                leading=9,
                alignment=TA_CENTER,
                textColor=colors.white,
            ))]], colWidths=[25 * mm])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), severity_background(value)),
                ("BOX", (0, 0), (-1, -1), 0.4, severity_background(value)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            return table

        def add_key_value_table(story, pairs, widths=(43 * mm, 132 * mm)):
            rows = []
            for key, value in pairs:
                rows.append([
                    p(key, finding_label_style),
                    p(display_value(value), table_cell_style),
                ])
            table = make_table(rows, widths, header=False, repeat=False)
            if table:
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                ]))
                story.append(table)
                story.append(Spacer(1, 6))

        def add_empty(story, message="No observations recorded."):
            story.append(p(message, note_style))
            story.append(Spacer(1, 3))

        def finding_card(story, finding, assessment=None, index=None):
            title = self._value(finding, "title", "Security finding")
            category = self._value(finding, "category", "")
            host = self._value(finding, "host", "")
            port = self._value(finding, "port", None)
            protocol = self._value(finding, "protocol", None)
            confidence = self._value(finding, "confidence", "")
            description = self._value(finding, "description", "")
            recommendation = self._value(finding, "recommendation", "")
            evidence = self._safe_list(self._value(finding, "evidence", []))

            if assessment is not None:
                severity = self._value(assessment, "severity", "Informational")
                score = self._value(assessment, "risk_score", None)
                impact = self._value(assessment, "impact", None)
                likelihood = self._value(assessment, "likelihood", None)
                assessment_confidence = self._value(assessment, "confidence", confidence)
            else:
                severity = "Informational"
                score = None
                impact = None
                likelihood = None
                assessment_confidence = confidence

            location = host or "unknown"
            if port is not None:
                location = f"{location}:{port}/{protocol or 'tcp'}"

            title_prefix = f"{index}. " if index is not None else ""

            card_rows = [[
                badge(severity),
                p(title_prefix + clean_text(title), finding_title_style),
            ]]
            card = Table(card_rows, colWidths=[30 * mm, 145 * mm])
            card.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f9fafb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(card)
            story.append(Spacer(1, 4))

            details = [
                [p("Location", finding_label_style), p(location, table_cell_style)],
                [p("Category", finding_label_style), p(category or "Not recorded", table_cell_style)],
                [p("Confidence", finding_label_style), p(assessment_confidence or "Not recorded", table_cell_style)],
            ]

            if score is not None:
                details.extend([
                    [p("Risk Score", finding_label_style), p(f"{score}/25", table_cell_style)],
                    [p("Impact", finding_label_style), p(display_value(impact), table_cell_style)],
                    [p("Likelihood", finding_label_style), p(display_value(likelihood), table_cell_style)],
                ])

            detail_table = make_table(
                details,
                [35 * mm, 140 * mm],
                header=False,
                repeat=False,
            )
            if detail_table:
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                ]))
                story.append(detail_table)

            if description:
                story.append(Spacer(1, 4))
                story.append(p("Description", finding_label_style))
                story.append(p(description, body_style))

            if evidence:
                evidence_rows = [[header_cell("Evidence Type"), header_cell("Source"), header_cell("Value")]]
                for item in evidence:
                    evidence_rows.append([
                        cell(self._value(item, "evidence_type", "evidence")),
                        cell(self._value(item, "source", "unknown")),
                        cell(self._value(item, "value", "")),
                    ])
                evidence_table = make_table(
                    evidence_rows,
                    [43 * mm, 38 * mm, 94 * mm],
                )
                if evidence_table:
                    story.append(Spacer(1, 4))
                    story.append(p("Evidence", finding_label_style))
                    story.append(evidence_table)

            if recommendation:
                story.append(Spacer(1, 4))
                story.append(p("Recommendation", finding_label_style))
                story.append(p(recommendation, body_style))

            story.append(Spacer(1, 8))

        def exploitation_card(story, assessment, index, remediation_guidance):
            service = self._value(assessment, "service", "unknown")
            host = self._value(assessment, "host", "")
            port = self._value(assessment, "port", None)
            protocol = self._value(assessment, "protocol", "tcp")
            location = host
            if port is not None:
                location = f"{host}:{port}/{protocol or 'tcp'}"

            title_table = Table([[
                p(f"{index}. {str(service).upper()}", finding_title_style),
                p(location, small_style),
            ]], colWidths=[55 * mm, 120 * mm])
            title_table.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f3f4f6")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(title_table)
            story.append(Spacer(1, 5))

            exposure = self._value(assessment, "exposure", "")
            if exposure:
                story.append(p("Exposure", finding_label_style))
                story.append(p(exposure, body_style))

            methods = self._safe_list(self._value(assessment, "attack_methods", []))
            if methods:
                story.append(p("Attack Methods", finding_label_style))
                for method_index, method in enumerate(methods, start=1):
                    method_name = self._value(method, "method", "Attack method")
                    story.append(p(f"{method_index}. {method_name}", finding_title_style))
                    for label, field in (
                        ("Description", "description"),
                        ("Preconditions", "preconditions"),
                        ("Potential Impact", "potential_impact"),
                        ("Detection / Indicators", "detection_indicators"),
                        ("Defensive Controls", "defensive_controls"),
                        ("Verification", "verification"),
                    ):
                        values = self._safe_list(self._value(method, field, []))
                        if not values:
                            scalar = self._value(method, field, None)
                            if scalar not in (None, ""):
                                values = [scalar]
                        if values:
                            story.append(p(label, finding_label_style))
                            for value in values:
                                story.append(p(f"• {value}", body_style))

                    attack_remediation = self._attack_specific_remediation(
                        service,
                        method_name,
                    )
                    story.append(p("Attack-Specific Remediation", finding_label_style))
                    for value in attack_remediation:
                        story.append(p(f"• {value}", body_style))
                    story.append(Spacer(1, 3))
            else:
                add_empty(story, "No attack methods were recorded for this assessment.")

            related = self._safe_list(self._value(assessment, "related_remediation", []))
            if not related:
                for item in self._safe_list(remediation_guidance):
                    if (
                        str(self._value(item, "host", "")) == str(host)
                        and str(self._value(item, "port", "")) == str(port)
                    ):
                        related.append(item)

            story.append(p("Related Remediation", finding_label_style))
            if related:
                rows = [[header_cell("Priority"), header_cell("Action"), header_cell("Verification")]]
                for item in related:
                    rows.append([
                        cell(self._value(item, "priority", ""), center=True),
                        cell(self._value(item, "recommendation", self._value(item, "action", ""))),
                        cell(self._value(item, "verify", "")),
                    ])
                table = make_table(rows, [28 * mm, 92 * mm, 55 * mm])
                if table:
                    story.append(table)
            else:
                add_empty(story, "No directly linked remediation action was recorded.")
            story.append(Spacer(1, 10))

        def compact_analysis_table(story, findings, include_category=False):
            if not findings:
                add_empty(story)
                return

            rows = [[
                header_cell("Location"),
                header_cell("Finding"),
                header_cell("Confidence"),
            ]]
            if include_category:
                rows[0].insert(0, header_cell("Category"))

            for item in findings:
                location = self._location(item)
                title = self._value(item, "title", "")
                if not title:
                    title = self._value(item, "service", "Observation")
                row = [
                    cell(location),
                    cell(title),
                    cell(self._value(item, "confidence", ""), center=True),
                ]
                if include_category:
                    row.insert(0, cell(self._value(item, "category", "")))
                rows.append(row)

            widths = [55 * mm, 88 * mm, 32 * mm]
            if include_category:
                widths = [40 * mm, 47 * mm, 73 * mm, 15 * mm]
            table = make_table(rows, widths)
            if table:
                story.append(table)
                story.append(Spacer(1, 7))

        # -----------------------------------------------------
        # Page header/footer
        # -----------------------------------------------------

        def draw_page(canvas, doc):
            canvas.saveState()
            width, height = A4

            if doc.page > 1:
                canvas.setStrokeColor(colors.HexColor("#d1d5db"))
                canvas.setLineWidth(0.4)
                canvas.line(14 * mm, height - 11 * mm, width - 14 * mm, height - 11 * mm)
                canvas.setFont("Helvetica-Bold", 7)
                canvas.setFillColor(colors.HexColor("#374151"))
                canvas.drawString(14 * mm, height - 8 * mm, "HOST & NETWORK HARDENER")
                canvas.setFont("Helvetica", 7)
                canvas.setFillColor(colors.HexColor("#6b7280"))
                canvas.drawRightString(width - 14 * mm, height - 8 * mm, "Security Assessment Report")

            canvas.setStrokeColor(colors.HexColor("#d1d5db"))
            canvas.line(14 * mm, 12 * mm, width - 14 * mm, 12 * mm)
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.HexColor("#6b7280"))
            canvas.drawString(14 * mm, 7 * mm, "Host & Network Hardener — Step 11")
            canvas.drawRightString(width - 14 * mm, 7 * mm, f"Page {doc.page}")
            canvas.restoreState()

        story = []

        # =====================================================
        # COVER / EXECUTIVE SUMMARY
        # =====================================================

        story.append(Spacer(1, 22 * mm))
        story.append(p("HOST & NETWORK HARDENER", title_style))
        story.append(p("Detailed Security Assessment Report", subtitle_style))
        story.append(Spacer(1, 4 * mm))

        cover_target = display_value(target.get("value", "unknown"))
        generated_at = display_value(report.get("generated_at", "unknown"))

        cover_table = Table([
            [p("Target", finding_label_style), p(cover_target, body_style)],
            [p("Target Type", finding_label_style), p(display_value(target.get("type")), body_style)],
            [p("Generated", finding_label_style), p(generated_at, body_style)],
            [p("Pipeline Stage", finding_label_style), p("Step 11 — Report Generation", body_style)],
        ], colWidths=[45 * mm, 130 * mm])
        cover_table.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#9ca3af")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(cover_table)
        story.append(Spacer(1, 10 * mm))

        # Risk overview cards.
        risk_counts = []
        for severity in ("critical", "high", "medium", "low", "informational"):
            value = risk_summary.get(severity, 0) if isinstance(risk_summary, dict) else 0
            risk_counts.append((severity.title(), value))

        card_rows = []
        for severity, value in risk_counts:
            card_rows.append([
                p(severity, ParagraphStyle(
                    f"RiskLabel{severity}",
                    parent=small_style,
                    fontName="Helvetica-Bold",
                    alignment=TA_CENTER,
                    textColor=colors.white,
                )),
                p(str(value), score_style),
            ])

        risk_cards = Table(card_rows, colWidths=[28 * mm, 15 * mm])
        risk_cards.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 0), (0, 0), severity_background("critical")),
            ("BACKGROUND", (0, 1), (0, 1), severity_background("high")),
            ("BACKGROUND", (0, 2), (0, 2), severity_background("medium")),
            ("BACKGROUND", (0, 3), (0, 3), severity_background("low")),
            ("BACKGROUND", (0, 4), (0, 4), severity_background("informational")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        # A wider summary table is more useful than a single dense JSON block.
        summary_table = Table([
            [p("LIVE HOSTS", table_header_style), p("OPEN PORTS", table_header_style), p("SERVICES", table_header_style), p("FINDINGS", table_header_style)],
            [p(str(summary["live_hosts"]), score_style), p(str(summary["open_ports"]), score_style), p(str(summary["services"]), score_style), p(str(summary["correlated_findings"]), score_style)],
        ], colWidths=[43.75 * mm] * 4)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d5db")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 7 * mm))

        story.append(p(
            "This report presents the results produced by the Host & Network Hardener pipeline. "
            "Risk values shown in this document are the assessments generated by Step 10; "
            "Step 11 only formats and presents those values.",
            note_style,
        ))

        story.append(PageBreak())

        # =====================================================
        # 1. TARGET AND SCOPE
        # =====================================================

        add_section(story, "1. Target and Scope")
        add_key_value_table(story, [
            ("Target", target.get("value")),
            ("Target Type", target.get("type")),
            ("Scope Authorized", scope.get("authorized") if isinstance(scope, dict) else None),
            ("Configured Scope", scope.get("configured_scope") if isinstance(scope, dict) else None),
            ("Allowed Targets", target_expansion.get("allowed") if isinstance(target_expansion, dict) else None),
            ("Blocked Targets", target_expansion.get("blocked") if isinstance(target_expansion, dict) else None),
        ])

        add_subsection(story, "DNS / Infrastructure Resolution")
        if isinstance(dns, dict):
            add_key_value_table(story, [
                ("Status", dns.get("status")),
                ("Resolution", dns.get("resolution")),
                ("Reason", dns.get("reason")),
            ])
        else:
            add_empty(story)

        # =====================================================
        # 2. HOST DISCOVERY
        # =====================================================

        add_section(story, "2. Host Discovery")
        live_hosts = discovery.get("live_hosts", []) if isinstance(discovery, dict) else []
        authorized_targets = discovery.get("authorized_targets", []) if isinstance(discovery, dict) else []
        if live_hosts:
            rows = [[header_cell("Host"), header_cell("Status"), header_cell("Evidence")]]
            discovery_results = (
                self._safe_list(discovery.get("results", []))
                if isinstance(discovery, dict)
                else []
            )

            for item in self._safe_list(live_hosts):
                host = item if isinstance(item, str) else self._value(item, "host", "")
                status = self._value(item, "status", "alive") if not isinstance(item, str) else "alive"
                evidence = self._value(item, "evidence", "") if not isinstance(item, str) else ""

                # live_hosts normally contains only the host string.
                # The detailed discovery evidence is stored in results[].
                if not evidence and isinstance(item, str):
                    for result in discovery_results:
                        result_host = self._value(result, "host", "")
                        if str(result_host) != str(host):
                            continue

                        result_status = self._value(result, "status", None)
                        if result_status:
                            status = result_status

                        evidence_value = self._value(result, "evidence", None)
                        if evidence_value:
                            evidence_items = self._safe_list(evidence_value)
                            formatted = []
                            for evidence_item in evidence_items:
                                if isinstance(evidence_item, dict):
                                    source = evidence_item.get("source") or evidence_item.get("method")
                                    value = evidence_item.get("value") or evidence_item.get("description")
                                    if source and value:
                                        formatted.append(f"{source}: {value}")
                                    elif value:
                                        formatted.append(str(value))
                                    elif source:
                                        formatted.append(str(source))
                                else:
                                    formatted.append(str(evidence_item))
                            evidence = "; ".join(formatted)

                        if not evidence:
                            for field in ("method", "probe", "reason", "discovery_method", "alive_method"):
                                value = self._value(result, field, None)
                                if value:
                                    evidence = str(value)
                                    break
                        break

                rows.append([cell(host), cell(status, center=True), cell(evidence or "Not recorded")])
            table = make_table(rows, [55 * mm, 30 * mm, 80 * mm])
            if table:
                story.append(table)
        else:
            add_empty(story)

        story.append(Spacer(1, 4))
        story.append(p(
            f"Authorized targets: {display_value(authorized_targets)}",
            note_style,
        ))

        # =====================================================
        # 3. PORT SCAN
        # =====================================================

        add_section(story, "3. Port Scan")
        open_results = [
            result for result in port_results
            if str(self._value(result, "state", "")).lower() == "open"
        ]

        add_key_value_table(story, [
            ("Total Scan Results", len(port_results)),
            ("Open Ports", len(open_results)),
            ("Open TCP", summary["open_tcp"]),
            ("Open UDP", summary["open_udp"]),
        ])

        if open_results:
            rows = [[
                header_cell("Host"),
                header_cell("Port"),
                header_cell("Protocol"),
                header_cell("State"),
                header_cell("Engine"),
                header_cell("Method"),
            ]]
            for result in open_results:
                rows.append([
                    cell(self._value(result, "host", "")),
                    cell(self._value(result, "port", ""), center=True),
                    cell(self._value(result, "protocol", ""), center=True),
                    cell(self._value(result, "state", ""), center=True),
                    cell(self._value(result, "engine", "")),
                    cell(self._value(result, "method", "")),
                ])
            table = make_table(rows, [42 * mm, 17 * mm, 21 * mm, 20 * mm, 37 * mm, 38 * mm])
            if table:
                story.append(table)
        else:
            add_empty(story)

        story.append(p(
            "Only open ports are shown in the main report. Complete closed/filtered scan results are retained in the evidence appendix.",
            note_style,
        ))

        # =====================================================
        # 4. SERVICE ENUMERATION
        # =====================================================

        add_section(story, "4. Service Enumeration and Fingerprinting")
        if services:
            rows = [[
                header_cell("Location"),
                header_cell("Service"),
                header_cell("Product / Version"),
                header_cell("Confidence"),
            ]]
            for service in services:
                product = display_value(self._value(service, "product"), "")
                version = self._value(service, "version", None)
                if version:
                    product = f"{product} {version}".strip()
                rows.append([
                    cell(self._location(service)),
                    cell(self._value(service, "service", "unknown")),
                    cell(product or "Not identified"),
                    cell(self._value(service, "confidence", ""), center=True),
                ])
            table = make_table(rows, [47 * mm, 32 * mm, 70 * mm, 26 * mm])
            if table:
                story.append(table)
        else:
            add_empty(story)

        add_subsection(story, "Fingerprinting Summary")
        if fingerprint_results:
            compact_analysis_table(story, fingerprint_results, include_category=False)
        else:
            add_empty(story)

        # =====================================================
        # 5. OPERATING SYSTEM
        # =====================================================

        add_section(story, "5. Operating System / Platform Fingerprinting")
        if os_results:
            rows = [[
                header_cell("Host"),
                header_cell("OS Family"),
                header_cell("OS Name"),
                header_cell("Generation"),
                header_cell("Confidence"),
            ]]
            for result in os_results:
                rows.append([
                    cell(self._value(result, "host", "")),
                    cell(self._value(result, "os_family", "")),
                    cell(self._value(result, "os_name", "")),
                    cell(self._value(result, "kernel_generation", ""), center=True),
                    cell(self._value(result, "confidence", ""), center=True),
                ])
            table = make_table(rows, [38 * mm, 30 * mm, 54 * mm, 25 * mm, 28 * mm])
            if table:
                story.append(table)
        else:
            add_empty(story)

        # =====================================================
        # 6. TLS / SSH / MANAGEMENT
        # =====================================================

        add_section(story, "6. TLS, SSH and Management Analysis")

        add_subsection(story, "TLS / SSL")
        if tls_results:
            compact_analysis_table(story, tls_results)
        else:
            add_empty(story)

        add_subsection(story, "SSH")
        if ssh_results:
            compact_analysis_table(story, ssh_results)
        else:
            add_empty(story)

        add_subsection(story, "Management Interfaces")
        if management_results:
            rows = [[
                header_cell("Location"),
                header_cell("Service"),
                header_cell("Interface Type"),
                header_cell("Capability"),
                header_cell("Confirmed"),
                header_cell("Confidence"),
            ]]
            for item in management_results:
                rows.append([
                    cell(self._location(item)),
                    cell(self._value(item, "service", "")),
                    cell(self._value(item, "interface_type", "")),
                    cell(self._value(item, "capability", "")),
                    cell(yes_no(self._value(item, "management_confirmed", None)), center=True),
                    cell(self._value(item, "confidence", ""), center=True),
                ])
            table = make_table(rows, [36 * mm, 28 * mm, 32 * mm, 42 * mm, 19 * mm, 18 * mm])
            if table:
                story.append(table)
        else:
            add_empty(story)

        # =====================================================
        # 7. SECURITY OBSERVATIONS
        # =====================================================

        add_section(story, "7. Security Analysis")
        add_subsection(story, "Network Exposure")
        if security_results:
            compact_analysis_table(story, security_results, include_category=True)
        else:
            add_empty(story)

        add_subsection(story, "Database Exposure")
        if database_results:
            compact_analysis_table(story, database_results, include_category=True)
        else:
            add_empty(story)

        add_subsection(story, "Metadata Leakage")
        if metadata_results:
            compact_analysis_table(story, metadata_results, include_category=True)
        else:
            add_empty(story)

        add_subsection(story, "Misconfiguration Analysis")
        if misconfiguration_results:
            compact_analysis_table(story, misconfiguration_results, include_category=True)
        else:
            add_empty(story)

        # =====================================================
        # 8. CORRELATION
        # =====================================================

        add_section(story, "8. Correlated Findings")
        if isinstance(data.get("correlation_summary"), dict):
            cs = data.get("correlation_summary", {})
            add_key_value_table(story, [
                ("Total Findings", cs.get("total_findings")),
                ("Categories", cs.get("categories")),
                ("Confidence", cs.get("confidence")),
                ("Sources", cs.get("sources")),
            ])

        if correlated_results:
            rows = [[
                header_cell("Category"),
                header_cell("Location"),
                header_cell("Finding"),
                header_cell("Confidence"),
            ]]
            for item in correlated_results:
                rows.append([
                    cell(self._value(item, "category", "")),
                    cell(self._location(item)),
                    cell(self._value(item, "title", "")),
                    cell(self._value(item, "confidence", ""), center=True),
                ])
            table = make_table(rows, [42 * mm, 45 * mm, 70 * mm, 18 * mm])
            if table:
                story.append(table)
        else:
            add_empty(story)

        # =====================================================
        # 9. RISK ASSESSMENT
        # =====================================================

        story.append(PageBreak())
        add_section(story, "9. Risk Assessment")
        story.append(p(
            "Risk scores and severity values shown below are the assessments generated by Step 10. "
            "Step 11 does not recalculate or modify these values.",
            note_style,
        ))

        # Risk distribution.
        rows = [[
            header_cell("Severity"),
            header_cell("Count"),
        ]]
        for severity in ("critical", "high", "medium", "low", "informational"):
            count = risk_summary.get(severity, 0) if isinstance(risk_summary, dict) else 0
            rows.append([
                cell(severity.title()),
                cell(count, center=True),
            ])
        table = make_table(rows, [90 * mm, 85 * mm])
        if table:
            story.append(table)
            story.append(Spacer(1, 7))

        if risk_analysis:
            rows = [[
                header_cell("Severity"),
                header_cell("Risk"),
                header_cell("Location"),
                header_cell("Finding"),
                header_cell("Impact"),
                header_cell("Likelihood"),
                header_cell("Confidence"),
            ]]

            for assessment in risk_analysis:
                severity = self._value(assessment, "severity", "Informational")
                score = self._value(assessment, "risk_score", 0)
                location = self._location(assessment)
                title = self._value(assessment, "title", "Risk assessment")
                impact = self._value(assessment, "impact", "")
                likelihood = self._value(assessment, "likelihood", "")
                confidence = self._value(assessment, "confidence", "")
                rows.append([
                    cell(severity_text(severity), center=True),
                    cell(f"{score}/25", center=True),
                    cell(location),
                    cell(title),
                    cell(impact, center=True),
                    cell(likelihood, center=True),
                    cell(confidence, center=True),
                ])

            table = make_table(rows, [24 * mm, 18 * mm, 39 * mm, 42 * mm, 16 * mm, 18 * mm, 18 * mm])
            if table:
                story.append(table)
        else:
            add_empty(story)

        # =====================================================
        # 10. DETAILED FINDINGS
        # =====================================================

        add_section(story, "10. Detailed Security Findings")

        # Prefer Step 10 assessments so the detailed cards are tied
        # directly to the displayed risk values.
        if risk_analysis:
            for index, assessment in enumerate(risk_analysis, start=1):
                match = self._match_finding_for_assessment(
                    assessment,
                    finding_sources,
                )
                if match is None:
                    match = {
                        "host": self._value(assessment, "host", ""),
                        "port": self._value(assessment, "port", None),
                        "protocol": self._value(assessment, "protocol", "tcp"),
                        "title": self._value(assessment, "title", "Risk assessment"),
                        "category": self._value(assessment, "category", ""),
                        "confidence": self._value(assessment, "confidence", ""),
                        "description": "No matching Step 9 finding was recorded.",
                        "recommendation": "Review the corresponding Step 10 risk assessment and underlying evidence.",
                        "evidence": [],
                    }
                finding_card(story, match, assessment=assessment, index=index)
        elif correlated_results:
            for index, finding in enumerate(correlated_results, start=1):
                finding_card(story, finding, index=index)
        else:
            add_empty(story)

        # =====================================================
        # 11. REMEDIATION
        # =====================================================

        add_section(story, "11. Remediation Guidance")
        if remediation_summary:
            if isinstance(remediation_summary, dict):
                add_key_value_table(story, [
                    ("Summary", remediation_summary.get("summary")),
                    ("Total Actions", remediation_summary.get("total_actions")),
                    ("Priority Actions", remediation_summary.get("priority_actions")),
                ])

        if remediation_guidance:
            rows = [[
                header_cell("Priority"),
                header_cell("Action"),
                header_cell("Source"),
            ]]
            for item in remediation_guidance:
                if isinstance(item, dict):
                    rows.append([
                        cell(item.get("priority", ""), center=True),
                        cell(item.get("recommendation", item.get("action", ""))),
                        cell(item.get("source", item.get("category", ""))),
                    ])
                else:
                    rows.append([
                        cell(""),
                        cell(item),
                        cell(""),
                    ])
            table = make_table(rows, [25 * mm, 112 * mm, 38 * mm])
            if table:
                story.append(table)
        else:
            # Recommendations embedded in findings are still presented
            # in the detailed findings section above.
            add_empty(story, "No separate remediation guidance was recorded.")

        # =====================================================
        # 12. SERVICE EXPOSURE & EXPLOITATION METHODS
        # =====================================================

        story.append(PageBreak())
        add_section(story, "12. Service Exposure & Exploitation Methods")
        story.append(p(
            "Step 13 is an analysis-only assessment of exposed services. The following "
            "entries preserve the complete service-by-service evidence produced by the "
            "exploitation analysis, including attack methods, preconditions, potential impact, "
            "detection indicators, defensive controls, verification guidance, and related "
            "remediation. The report generator does not execute exploits or perform additional scanning.",
            note_style,
        ))

        attack_method_count = sum(
            len(self._safe_list(self._value(item, "attack_methods", [])))
            for item in exploitation_results
        )
        services_assessed = (
            exploitation_summary.get("services_assessed", len(exploitation_results))
            if isinstance(exploitation_summary, dict)
            else len(exploitation_results)
        )
        add_key_value_table(story, [
            ("Assessments Generated", len(exploitation_results)),
            ("Attack Methods Mapped", attack_method_count),
            ("Services Assessed", services_assessed),
        ])

        if exploitation_results:
            for index, assessment in enumerate(exploitation_results, start=1):
                exploitation_card(story, assessment, index, remediation_guidance)
        else:
            add_empty(story, "No Step 13 service exposure assessments were recorded.")

        # =====================================================
        # 13. ANALYSIS COVERAGE
        # =====================================================

        add_section(story, "13. Analysis Coverage")

        # Keep the final section visually complete.  The Markdown and
        # HTML reports already render these coverage metrics; the PDF
        # previously ended with only the section heading, which left
        # an empty/unstructured area at the end of the document.
        coverage_rows = [
            [p("Analysis Area", table_header_style), p("Count", table_header_style)],
            [p("TLS endpoints", table_cell_style), p(str(summary["tls_endpoints"]), table_cell_style)],
            [p("SSH endpoints", table_cell_style), p(str(summary["ssh_endpoints"]), table_cell_style)],
            [p("Management interfaces", table_cell_style), p(str(summary["management_interfaces"]), table_cell_style)],
            [p("Security observations", table_cell_style), p(str(summary["security_observations"]), table_cell_style)],
            [p("Database observations", table_cell_style), p(str(summary["database_observations"]), table_cell_style)],
            [p("Metadata observations", table_cell_style), p(str(summary["metadata_observations"]), table_cell_style)],
            [p("Misconfiguration observations", table_cell_style), p(str(summary["misconfiguration_observations"]), table_cell_style)],
            [p("Correlated findings", table_cell_style), p(str(summary["correlated_findings"]), table_cell_style)],
            [p("Remediation actions", table_cell_style), p(str(summary["remediation_actions"]), table_cell_style)],
            [p("Step 13 assessments", table_cell_style), p(str(summary["exploitation_assessments"]), table_cell_style)],
            [p("Step 13 attack methods", table_cell_style), p(str(summary["exploitation_attack_methods"]), table_cell_style)],
            [p("Step 13 services assessed", table_cell_style), p(str(summary["exploitation_services_assessed"]), table_cell_style)],
        ]

        coverage_table = Table(
            coverage_rows,
            colWidths=[115 * mm, 55 * mm],
            repeatRows=1,
            hAlign="LEFT",
        )
        coverage_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(coverage_table)
        story.append(Spacer(1, 8))
        story.append(p(
            "Coverage counts summarize the evidence and analysis stages represented in this report. "
            "They do not imply that an attack was executed or that a vulnerability was confirmed "
            "solely from service/version identification.",
            note_style,
        ))

        document.build(
            story,
            onFirstPage=draw_page,
            onLaterPages=draw_page,
        )

        return str(path)

    def save_report_data(
        self,
        data,
        output_name="report_data.json",
    ):
        """
        Save the complete normalized report data.

        JSON remains the machine-readable source of truth.
        The PDF is the human-readable presentation of the
        same normalized data.
        """

        path = (
            self.report_dir
            / output_name
        )

        path.write_text(
            json.dumps(
                self._serialize(data),
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )

        return path

    # =========================================================
    # GENERATE ALL REPORT FORMATS
    # =========================================================

    def generate(
        self,
        *,
        target,
        scope,
        dns,
        target_expansion,
        discovery,
        port_scan,
        service_enumeration,
        fingerprinting,
        os_fingerprinting,
        tls_analysis,
        ssh_analysis,
        management_analysis,
        security_analysis,
        database_analysis,
        metadata_analysis,
        misconfiguration_analysis,
        correlated_findings,
        correlation_summary,
        risk_analysis,
        risk_summary,
        remediation_guidance=None,
        remediation_summary=None,
        exploitation_analysis=None,
        exploitation_summary=None,
    ):
        """
        Generate all report formats from the same normalized
        pipeline data.

        Important:
        remediation_guidance and remediation_summary are
        optional so the report generator remains compatible
        with callers that do not yet provide Step 12 data.
        """

        data = self.build_report_data(
            target=target,
            scope=scope,
            dns=dns,
            target_expansion=target_expansion,
            discovery=discovery,
            port_scan=port_scan,
            service_enumeration=service_enumeration,
            fingerprinting=fingerprinting,
            os_fingerprinting=os_fingerprinting,
            tls_analysis=tls_analysis,
            ssh_analysis=ssh_analysis,
            management_analysis=management_analysis,
            security_analysis=security_analysis,
            database_analysis=database_analysis,
            metadata_analysis=metadata_analysis,
            misconfiguration_analysis=misconfiguration_analysis,
            correlated_findings=correlated_findings,
            correlation_summary=correlation_summary,
            risk_analysis=risk_analysis,
            risk_summary=risk_summary,
            remediation_guidance=remediation_guidance,
            remediation_summary=remediation_summary,
            exploitation_analysis=exploitation_analysis,
            exploitation_summary=exploitation_summary,
        )

        # -----------------------------------------------------
        # Machine-readable report
        # -----------------------------------------------------

        report_data_path = self.save_report_data(
            data
        )

        # -----------------------------------------------------
        # Markdown report
        # -----------------------------------------------------

        markdown_path = self.generate_markdown(
            data
        )

        # -----------------------------------------------------
        # HTML report
        # -----------------------------------------------------

        html_path = self.generate_html(
            data
        )

        # -----------------------------------------------------
        # Detailed human-readable PDF
        # -----------------------------------------------------

        pdf_path = self.generate_pdf(
            data
        )

        return {
            "report_data": report_data_path,
            "markdown": markdown_path,
            "html": html_path,
            "pdf": pdf_path,
        }