from __future__ import annotations

import warnings

# Suppress Scapy's internal cryptography deprecation warning.
# This warning comes from Scapy's TLS crypto implementation and does
# not indicate that the scanned target is using deprecated DH.

try:
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings(
        "ignore",
        category=CryptographyDeprecationWarning,
    )

except ImportError:
    pass


from core.target import (
    parse_target,
    is_in_scope,
    expand_and_validate_targets,
)

from core.dns import resolve_domain
from core.discovery import discover_host
from core.config import load_scope, load_allowed_domains
from core.port_scanner import PortScanner
from core.service_enum import ServiceEnumerator
from core.os_fingerprint import OSFingerprinter
from core.security_analysis import SecurityAnalyzer
from core.tls_analyzer import TLSAnalyzer
from core.ssh_analyzer import SSHAnalyzer
from core.management_analyzer import ManagementAnalyzer
from core.risk_analysis import RiskAnalyzer
from core.report_generation import ReportGenerator

from core.remediation_guidance import (
    RemediationGuidanceGenerator,
)

from core.exploitation_analysis import (
    ExploitationAnalyzer,
)

from core.correlation_analysis import (
    DatabaseExposureAnalyzer,
    MetadataLeakageAnalyzer,
    MisconfigurationAnalyzer,
    FindingCorrelator,
)

from core.output import OutputManager


ALLOWED_SCOPE = load_scope()
ALLOWED_DOMAINS = load_allowed_domains()


def main():

    output = OutputManager()

    output.header()

    # ============================================================
    # TARGET INPUT
    # ============================================================

    raw_input = input(
        "Enter target (IP / Range / CIDR / Domain): "
    ).strip()

    if not raw_input:
        print("[!] Target cannot be empty.")
        return

    # ============================================================
    # STEP 1 — TARGET VALIDATION
    # ============================================================

    try:

        target = parse_target(
            raw_input
        )

    except ValueError as error:

        print(
            f"[!] Invalid target: {error}"
        )

        return

    output.target(
        target.normalized_value
    )

    output.store(
        "target",
        target,
    )

    output.checkpoint(
        "TARGET_VALIDATION"
    )

    output.stage(
        "1",
        "Target Validation",
        "OK",
        target.normalized_value,
    )

    # ============================================================
    # STEP 2A — DNS RESOLUTION
    #
    # Domain targets must be resolved BEFORE scope validation.
    #
    # IP / CIDR / range targets skip DNS.
    # ============================================================

    if target.target_type.value == "domain":

        try:

            dns_result = resolve_domain(
                target
            )

        except Exception as error:

            output.fail(
                "DNS_RESOLUTION",
                error,
            )

            return

        output.store(
            "dns",
            dns_result,
        )

        output.checkpoint(
            "DNS_RESOLUTION"
        )

        output.stage(
            "2A",
            "DNS Resolution",
            "OK",
            (
                f"{len(dns_result.a_records)} "
                f"A record(s)"
            ),
        )

    else:

        dns_result = {
            "applicable": False,
            "reason": "IP/network target",
        }

        output.store(
            "dns",
            dns_result,
        )

        output.checkpoint(
            "DNS_RESOLUTION"
        )

        output.stage(
            "2A",
            "DNS Resolution",
            "SKIPPED",
            "IP target",
        )

    # ============================================================
    # STEP 2 — SCOPE VALIDATION
    #
    # For IP/CIDR/range:
    #     validate the original target.
    #
    # For domain:
    #     DNS has already resolved the domain, so the explicitly
    #     authorized domain is checked against allowed_domains.
    # ============================================================

    try:

        in_scope = is_in_scope(
            target,
            ALLOWED_SCOPE,
            ALLOWED_DOMAINS,
        )

    except Exception as error:

        output.fail(
            "SCOPE_VALIDATION",
            error,
        )

        return

    if not in_scope:

        output.store(
            "scope",
            {
                "authorized": False,
                "reason": (
                    "Target or resolved address(es) "
                    "are outside configured scope."
                ),
            },
        )

        output.checkpoint(
            "SCOPE_VALIDATION"
        )

        output.stage(
            "2",
            "Scope Validation",
            "FAILED",
            "blocked",
        )

        return

    output.store(
        "scope",
        {
            "authorized": True,
            "configured_scope": ALLOWED_SCOPE,
        },
    )

    output.checkpoint(
        "SCOPE_VALIDATION"
    )

    output.stage(
        "2",
        "Scope Validation",
        "OK",
        "authorized",
    )

    # ============================================================
    # STEP 2B — TARGET EXPANSION
    # ============================================================

    try:

        scope_report = (
            expand_and_validate_targets(
                [raw_input],
                ALLOWED_SCOPE,
                ALLOWED_DOMAINS,
            )
        )

    except Exception as error:

        output.fail(
            "TARGET_EXPANSION",
            error,
        )

        return

    allowed_targets = (
        scope_report["allowed"]
    )

    blocked_targets = (
        scope_report["blocked"]
    )

    output.store(
        "target_expansion",
        {
            "allowed": allowed_targets,
            "blocked": blocked_targets,
        },
    )

    output.checkpoint(
        "TARGET_EXPANSION"
    )

    output.stage(
        "2B",
        "Target Expansion",
        "OK",
        (
            f"{len(allowed_targets)} "
            f"authorized IP(s)"
        ),
    )

    if not allowed_targets:

        output.fail(
            "TARGET_EXPANSION",
            "No authorized targets available.",
        )

        return

    # ============================================================
    # STEP 3 — HOST DISCOVERY
    # ============================================================

    live_hosts = []

    discovery_results = []

    for ip in allowed_targets:

        try:

            result = discover_host(
                ip
            )

            discovery_results.append(
                result
            )

            if (
                result.status.value
                == "alive"
            ):

                live_hosts.append(
                    ip
                )

        except Exception as error:

            discovery_results.append(
                {
                    "host": ip,
                    "error": str(error),
                }
            )

    output.store(
        "discovery",
        {
            "authorized_targets":
                allowed_targets,
            "live_hosts":
                live_hosts,
            "results":
                discovery_results,
        },
    )

    output.checkpoint(
        "HOST_DISCOVERY"
    )

    output.stage(
        "3",
        "Host Discovery",
        "OK",
        f"{len(live_hosts)} live host(s)",
    )

    if not live_hosts:

        output.stage(
            "4",
            "Port Scanning",
            "SKIPPED",
            "no live hosts",
        )

        output.complete(
            {
                "Hosts": 0,
                "Open Ports": 0,
                "TCP": 0,
                "UDP": 0,
                "Services": 0,
                "Status": "No live hosts",
            }
        )

        return

    # ============================================================
    # STEP 4 — PORT SCANNING
    # ============================================================

    print()

    print(
        "Select scan profile:"
    )

    print()

    print(
        "1. Normal Scan"
    )

    print(
        "   Nmap TCP top 1000 + UDP top 50"
    )

    print()

    print(
        "2. Quick Scan"
    )

    print(
        "   RustScan TCP + Nmap verification + UDP top 50"
    )

    print()

    print(
        "3. Full Scan"
    )

    print(
        "   Masscan TCP + Nmap verification + full UDP"
    )

    print()

    profile_choice = input(
        "Select scan profile [1-3]: "
    ).strip()

    profile_map = {
        "1": "normal",
        "2": "quick",
        "3": "full",
    }

    profile = profile_map.get(
        profile_choice
    )

    if profile is None:

        print(
            "[!] Invalid scan profile."
        )

        return

    print()

    print(
        f"Selected profile: "
        f"{profile.upper()}"
    )

    try:

        scanner = PortScanner(
            profile=profile,
            max_rate=100,
            nmap_timeout=300,
            rustscan_timeout_ms=1500,
        )

    except Exception as error:

        output.fail(
            "PORT_SCANNER_INITIALIZATION",
            error,
        )

        return

    try:

        port_results = (
            scanner.scan_hosts(
                live_hosts
            )
        )

    except Exception as error:

        output.fail(
            "PORT_SCANNING",
            error,
        )

        return

    output.store(
        "port_scan",
        {
            "profile": profile,
            "results": port_results,
        },
    )

    output.checkpoint(
        "PORT_SCANNING"
    )

    open_ports = [
        result
        for result in port_results
        if result.state.lower()
        == "open"
    ]

    open_tcp = [
        result
        for result in open_ports
        if result.protocol.lower()
        == "tcp"
    ]

    open_udp = [
        result
        for result in open_ports
        if result.protocol.lower()
        == "udp"
    ]

    output.stage(
        "4",
        "Port Scanning",
        "OK",
        f"{len(open_ports)} open ports",
    )

    # ============================================================
    # STEP 5 — SERVICE ENUMERATION
    # ============================================================

    try:

        service_enumerator = (
            ServiceEnumerator()
        )

        service_results = (
            service_enumerator.enumerate_ports(
                port_results
            )
        )

    except Exception as error:

        output.fail(
            "SERVICE_ENUMERATION",
            error,
        )

        return

    output.store(
        "service_enumeration",
        service_results,
    )

    output.checkpoint(
        "SERVICE_ENUMERATION"
    )

    output.stage(
        "5",
        "Service Enumeration",
        "OK",
        f"{len(service_results)} service endpoint(s)",
    )

    # ============================================================
    # STEP 6 — SERVICE FINGERPRINTING
    # ============================================================

    output.store(
        "fingerprinting",
        {
            "status": "completed",
            "results": service_results,
        },
    )

    output.checkpoint(
        "FINGERPRINTING"
    )

    output.stage(
        "6",
        "Fingerprinting",
        "OK",
        "completed",
    )

    # ============================================================
    # STEP 7 — OS / PLATFORM FINGERPRINTING
    # ============================================================

    try:

        os_fingerprinter = (
            OSFingerprinter()
        )

        os_results = (
            os_fingerprinter.fingerprint_hosts(
                hosts=live_hosts,
                service_results=service_results,
            )
        )

    except Exception as error:

        output.fail(
            "OS_FINGERPRINTING",
            error,
        )

        return

    output.store(
        "os_fingerprinting",
        os_results,
    )

    output.checkpoint(
        "OS_FINGERPRINTING"
    )

    os_summary = "unknown"

    if os_results:

        first_os = os_results[0]

        os_summary = (
            first_os.os_name
            or first_os.os_family
            or "unknown"
        )

        if first_os.distribution_hint:

            os_summary += (
                " / "
                + first_os.distribution_hint
            )

    output.stage(
        "7",
        "OS Fingerprinting",
        "OK",
        os_summary,
    )

    # ============================================================
    # STEP 9B — TLS / SSL ANALYSIS
    # ============================================================

    try:

        tls_analyzer = TLSAnalyzer()

        tls_results = (
            tls_analyzer.analyze_ports(
                port_results=port_results,
                service_results=service_results,
            )
        )

    except Exception as error:

        output.fail(
            "9B_TLS_ANALYSIS",
            error,
        )

        return

    output.store(
        "tls_analysis",
        tls_results,
    )

    output.checkpoint(
        "9B_TLS_ANALYSIS"
    )

    tls_detected = sum(
        1
        for result in tls_results
        if result.tls_detected
    )

    output.stage(
        "9B",
        "TLS/SSL Analysis",
        "OK",
        f"{tls_detected} TLS endpoint(s)",
    )

    # ============================================================
    # STEP 9C — SSH SECURITY ANALYSIS
    # ============================================================

    try:

        ssh_analyzer = SSHAnalyzer()

        ssh_results = (
            ssh_analyzer.analyze_ports(
                port_results
            )
        )

    except Exception as error:

        output.fail(
            "9C_SSH_ANALYSIS",
            error,
        )

        return

    output.store(
        "ssh_analysis",
        ssh_results,
    )

    output.checkpoint(
        "9C_SSH_ANALYSIS"
    )

    output.stage(
        "9C",
        "SSH Security Analysis",
        "OK",
        f"{len(ssh_results)} SSH endpoint(s)",
    )

    # ============================================================
    # STEP 9D — MANAGEMENT INTERFACE ANALYSIS
    # ============================================================

    try:

        management_analyzer = (
            ManagementAnalyzer()
        )

        management_results = (
            management_analyzer.analyze(
                service_results
            )
        )

    except Exception as error:

        output.fail(
            "9D_MANAGEMENT_ANALYSIS",
            error,
        )

        return

    output.store(
        "management_analysis",
        management_results,
    )

    output.checkpoint(
        "9D_MANAGEMENT_ANALYSIS"
    )

    output.stage(
        "9D",
        "Management Analysis",
        "OK",
        (
            f"{len(management_results)} "
            f"interface(s)"
        ),
    )

    # ============================================================
    # STEP 9A — NETWORK / SECURITY ANALYSIS
    # ============================================================

    try:

        security_analyzer = (
            SecurityAnalyzer()
        )

        security_findings = (
            security_analyzer.analyze(
                port_results=port_results,
                service_results=service_results,
                tls_results=tls_results,
            )
        )

    except Exception as error:

        output.fail(
            "9A_SECURITY_ANALYSIS",
            error,
        )

        return

    output.store(
        "security_analysis",
        security_findings,
    )

    output.checkpoint(
        "9A_SECURITY_ANALYSIS"
    )

    output.stage(
        "9A",
        "Network Security Analysis",
        "OK",
        (
            f"{len(security_findings)} "
            f"observation(s)"
        ),
    )

    # ============================================================
    # STEP 9E — DATABASE EXPOSURE ANALYSIS
    # ============================================================

    try:

        database_analyzer = (
            DatabaseExposureAnalyzer()
        )

        database_findings = (
            database_analyzer.analyze(
                port_results=port_results,
                service_results=service_results,
            )
        )

    except Exception as error:

        output.fail(
            "9E_DATABASE_ANALYSIS",
            error,
        )

        return

    output.store(
        "database_exposure_analysis",
        database_findings,
    )

    output.checkpoint(
        "9E_DATABASE_ANALYSIS"
    )

    output.stage(
        "9E",
        "Database Exposure Analysis",
        "OK",
        (
            f"{len(database_findings)} "
            f"observation(s)"
        ),
    )

    # ============================================================
    # STEP 9F — METADATA LEAKAGE ANALYSIS
    # ============================================================

    try:

        metadata_analyzer = (
            MetadataLeakageAnalyzer()
        )

        metadata_findings = (
            metadata_analyzer.analyze(
                service_results=service_results,
                os_results=os_results,
            )
        )

    except Exception as error:

        output.fail(
            "9F_METADATA_ANALYSIS",
            error,
        )

        return

    output.store(
        "metadata_leakage_analysis",
        metadata_findings,
    )

    output.checkpoint(
        "9F_METADATA_ANALYSIS"
    )

    output.stage(
        "9F",
        "Metadata Leakage Analysis",
        "OK",
        (
            f"{len(metadata_findings)} "
            f"observation(s)"
        ),
    )

    # ============================================================
    # STEP 9G — MISCONFIGURATION ANALYSIS
    # ============================================================

    try:

        misconfiguration_analyzer = (
            MisconfigurationAnalyzer()
        )

        misconfiguration_findings = (
            misconfiguration_analyzer.analyze(
                service_results=service_results,
                ssh_results=ssh_results,
                management_results=management_results,
                tls_results=tls_results,
            )
        )

    except Exception as error:

        output.fail(
            "9G_MISCONFIGURATION_ANALYSIS",
            error,
        )

        return

    output.store(
        "misconfiguration_analysis",
        misconfiguration_findings,
    )

    output.checkpoint(
        "9G_MISCONFIGURATION_ANALYSIS"
    )

    output.stage(
        "9G",
        "Misconfiguration Analysis",
        "OK",
        (
            f"{len(misconfiguration_findings)} "
            f"observation(s)"
        ),
    )

    # ============================================================
    # STEP 9H — COMBINE + DEDUPLICATE FINDINGS
    # ============================================================

    try:

        correlator = FindingCorrelator(
            existing_findings=security_findings
        )

        correlated_findings = (
            correlator.combine(
                [
                    *database_findings,
                    *metadata_findings,
                    *misconfiguration_findings,
                ]
            )
        )

        correlation_summary = (
            correlator.summarize(
                correlated_findings
            )
        )

    except Exception as error:

        output.fail(
            "9H_CORRELATION",
            error,
        )

        return

    output.store(
        "correlated_findings",
        correlated_findings,
    )

    output.store(
        "correlation_summary",
        correlation_summary,
    )

    output.checkpoint(
        "9H_CORRELATION"
    )

    output.stage(
        "9H",
        "Combine + Deduplicate Findings",
        "OK",
        (
            f"{len(correlated_findings)} "
            f"unique finding(s)"
        ),
    )

    # ============================================================
    # STEP 10 — CORRELATION & RISK SCORING
    # ============================================================

    try:

        risk_analyzer = RiskAnalyzer()

        risk_assessments = (
            risk_analyzer.analyze(
                correlated_findings
            )
        )

        risk_summary = (
            risk_analyzer.summarize(
                risk_assessments
            )
        )

    except Exception as error:

        output.fail(
            "10_RISK_ANALYSIS",
            error,
        )

        return

    output.store(
        "risk_analysis",
        risk_assessments,
    )

    output.store(
        "risk_summary",
        risk_summary,
    )

    output.checkpoint(
        "10_RISK_ANALYSIS"
    )

    output.stage(
        "10",
        "Correlation & Risk Scoring",
        "OK",
        f"{len(risk_assessments)} findings assessed",
    )

    # --------------------------------------------------------
    # STEP 10 — RISK ASSESSMENT DISPLAY
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("                 RISK ASSESSMENT")
    print("=" * 60)
    print()

    print("Risk Overview")

    print(
        f"  Findings Assessed       : "
        f"{risk_summary['total_assessed']}"
    )

    print(
        f"  Critical                : "
        f"{risk_summary['critical']}"
    )

    print(
        f"  High                    : "
        f"{risk_summary['high']}"
    )

    print(
        f"  Medium                  : "
        f"{risk_summary['medium']}"
    )

    print(
        f"  Low                     : "
        f"{risk_summary['low']}"
    )

    print(
        f"  Informational           : "
        f"{risk_summary['informational']}"
    )

    print()

    print(
        f"  Highest Risk            : "
        f"{risk_summary['highest_risk_score']} / 25"
    )

    print(
        f"  Average Risk            : "
        f"{risk_summary['average_risk_score']} / 25"
    )

    # --------------------------------------------------------
    # Risk distribution
    # --------------------------------------------------------

    print()
    print("Risk Distribution")

    distribution = [
        ("Critical", risk_summary["critical"]),
        ("High", risk_summary["high"]),
        ("Medium", risk_summary["medium"]),
        ("Low", risk_summary["low"]),
        ("Informational", risk_summary["informational"]),
    ]

    max_count = max(
        (
            count
            for _, count in distribution
        ),
        default=0,
    )

    for label, count in distribution:

        if max_count > 0:

            bar_length = round(
                (count / max_count) * 20
            )

        else:

            bar_length = 0

        bar = "█" * bar_length

        print(
            f"  {label:<14} "
            f"[{bar:<20}] "
            f"{count}"
        )

    # --------------------------------------------------------
    # Top risk findings
    # --------------------------------------------------------

    print()
    print("Top Risk Findings")

    if not risk_assessments:

        print(
            "  No risk findings available."
        )

    else:

        for index, assessment in enumerate(
            risk_assessments[:5],
            start=1,
        ):

            location = assessment.host

            if assessment.port is not None:

                protocol = (
                    assessment.protocol
                    or "tcp"
                )

                location = (
                    f"{location}:"
                    f"{assessment.port}/"
                    f"{protocol}"
                )

            print(
                f"  {index}. "
                f"{assessment.severity.upper():<13} "
                f"{assessment.title}"
            )

            print(
                f"     {location}"
                f" | Risk {assessment.risk_score}/25"
            )

    # ============================================================
    # STEP 12 — REMEDIATION GUIDANCE
    #
    # Step 12 consumes Step 10 output only.
    # It does not rescan, rescore, or modify findings.
    # ============================================================

    try:

        remediation_generator = (
            RemediationGuidanceGenerator()
        )

        remediation_items = (
            remediation_generator.analyze(
                risk_assessments
            )
        )

        remediation_summary = (
            remediation_generator.summarize(
                remediation_items
            )
        )

    except Exception as error:

        output.fail(
            "12_REMEDIATION_GUIDANCE",
            error,
        )

        return

    output.store(
        "remediation_guidance",
        remediation_items,
    )

    output.store(
        "remediation_summary",
        remediation_summary,
    )

    output.checkpoint(
        "12_REMEDIATION_GUIDANCE"
    )

    output.stage(
        "12",
        "Remediation Guidance",
        "OK",
        (
            f"{len(remediation_items)} "
            f"action(s) generated"
        ),
    )

    # ============================================================
    # STEP 13 — SERVICE EXPOSURE & EXPLOITATION METHODS
    #
    # Step 13 is analysis-only. It consumes evidence already
    # collected by the pipeline and describes potential attack
    # methods, prerequisites, impact, detection indicators,
    # defensive controls, and verification guidance.
    #
    # It does NOT:
    #   - execute exploits
    #   - authenticate to services
    #   - generate payloads
    #   - perform additional network scanning
    #   - modify risk scores
    #   - modify remediation guidance
    # ============================================================

    try:

        exploitation_analyzer = (
            ExploitationAnalyzer()
        )

        exploitation_assessments = (
            exploitation_analyzer.analyze(
                service_results=service_results,
                port_results=port_results,
                ssh_results=ssh_results,
                security_findings=security_findings,
                correlated_findings=correlated_findings,
                risk_assessments=risk_assessments,
                remediation_items=remediation_items,
            )
        )

        exploitation_summary = (
            exploitation_analyzer.summarize(
                exploitation_assessments
            )
        )

    except Exception as error:

        output.fail(
            "13_EXPLOITATION_ANALYSIS",
            error,
        )

        return

    output.store(
        "exploitation_analysis",
        exploitation_assessments,
    )

    output.store(
        "exploitation_summary",
        exploitation_summary,
    )

    output.checkpoint(
        "13_EXPLOITATION_ANALYSIS"
    )

    output.stage(
        "13",
        "Service Exposure & Exploitation Methods",
        "OK",
        (
            f"{len(exploitation_assessments)} "
            f"service exposure assessment(s) generated"
        ),
    )

    # --------------------------------------------------------
    # STEP 13 — EXPOSURE / EXPLOITATION DISPLAY
    # --------------------------------------------------------

    # Step 13 keeps the terminal output intentionally compact.
    # The complete service exposure assessments remain stored in
    # evidence and are available to the final reports.

    print()
    print("=" * 60)
    print("       SERVICE EXPOSURE & EXPLOITATION METHODS")
    print("=" * 60)
    print()

    total_assessments = len(
        exploitation_assessments
    )

    services_assessed = len(
        exploitation_assessments
    )

    # Calculate this directly from the generated assessments so
    # the terminal reflects the actual Step 13 evidence even if
    # the analyzer summary does not expose the aggregate count.
    attack_methods_mapped = sum(
        len(assessment.attack_methods or [])
        for assessment in exploitation_assessments
    )

    print("Exposure Analysis Overview")

    print(
        f"  Assessments Generated   : "
        f"{total_assessments}"
    )

    print(
        f"  Attack Methods Mapped   : "
        f"{attack_methods_mapped}"
    )

    print(
        f"  Services Assessed       : "
        f"{services_assessed}"
    )

    print()

    if not exploitation_assessments:

        print(
            "  No service exposure assessments generated."
        )

    else:

        print("Preview")

        # Only a small preview is shown in the terminal.
        # Full Step 13 evidence is retained for report generation.
        preview_count = min(
            2,
            len(exploitation_assessments),
        )

        for index, assessment in enumerate(
            exploitation_assessments[:preview_count],
            start=1,
        ):

            location = assessment.host

            if assessment.port is not None:

                protocol = (
                    assessment.protocol
                    or "tcp"
                )

                location = (
                    f"{location}:"
                    f"{assessment.port}/"
                    f"{protocol}"
                )

            methods = (
                assessment.attack_methods
                or []
            )

            primary_risk = (
                "Service exposure and potential "
                "unauthorized access"
            )

            if methods:

                first_method = methods[0]

                method_name = getattr(
                    first_method,
                    "method",
                    None,
                )

                if method_name:
                    primary_risk = str(
                        method_name
                    )

            controls = []

            for method in methods:

                for control in (
                    getattr(
                        method,
                        "defensive_controls",
                        None,
                    )
                    or []
                ):

                    control_text = str(
                        control
                    ).strip()

                    if (
                        control_text
                        and control_text
                        not in controls
                    ):
                        controls.append(
                            control_text
                        )

            if controls:

                controls_summary = "; ".join(
                    controls[:2]
                )

            else:

                controls_summary = (
                    "See detailed defensive controls "
                    "in the report."
                )

            print()

            print(
                f"  {index}. "
                f"{str(assessment.service or 'unknown').upper()}"
            )

            print(
                f"     Location     : {location}"
            )

            print(
                f"     Methods      : {len(methods)}"
            )

            print(
                f"     Primary Risk : {primary_risk}"
            )

            print(
                f"     Controls     : {controls_summary}"
            )

        remaining = (
            len(exploitation_assessments)
            - preview_count
        )

        if remaining > 0:

            print()

            print(
                f"  ... {remaining} additional "
                f"service assessment(s) stored in evidence."
            )

    print()

    # ============================================================
    # STEP 11 — FINAL REPORT GENERATION
    #
    # The report is generated after Steps 12 and 13 so the final
    # evidence set can include remediation and exploitation analysis.
    #
    # It does not:
    #   - scan hosts
    #   - perform network connections
    #   - calculate new risk scores
    #   - create remediation recommendations
    # ============================================================

    try:

        report_generator = ReportGenerator(
            output.report_dir
        )

        report_paths = report_generator.generate(
            target=target,
            scope={
                "authorized": True,
                "configured_scope": ALLOWED_SCOPE,
            },
            dns=dns_result,
            target_expansion={
                "allowed": allowed_targets,
                "blocked": blocked_targets,
            },
            discovery={
                "authorized_targets": allowed_targets,
                "live_hosts": live_hosts,
                "results": discovery_results,
            },
            port_scan={
                "profile": profile,
                "results": port_results,
            },
            service_enumeration=service_results,
            fingerprinting={
                "status": "completed",
                "results": service_results,
            },
            os_fingerprinting=os_results,
            tls_analysis=tls_results,
            ssh_analysis=ssh_results,
            management_analysis=management_results,
            security_analysis=security_findings,
            database_analysis=database_findings,
            metadata_analysis=metadata_findings,
            misconfiguration_analysis=misconfiguration_findings,
            correlated_findings=correlated_findings,
            correlation_summary=correlation_summary,
            risk_analysis=risk_assessments,
            risk_summary=risk_summary,
            remediation_guidance=remediation_items,
            remediation_summary=remediation_summary,
            exploitation_analysis=exploitation_assessments,
            exploitation_summary=exploitation_summary,
        )

    except Exception as error:

        output.fail(
            "11_REPORT_GENERATION",
            error,
        )

        return

    output.store(
        "report_generation",
        report_paths,
    )

    output.checkpoint(
        "11_REPORT_GENERATION"
    )

    output.stage(
        "11",
        "Report Generation",
        "OK",
        "JSON, Markdown, HTML, and PDF reports generated",
    )

    print()
    print("=" * 60)
    print("                  REPORT GENERATION")
    print("=" * 60)
    print()

    print(
        f"  Report Data (JSON)      : "
        f"{report_paths['report_data']}"
    )

    print(
        f"  Markdown Report         : "
        f"{report_paths['markdown']}"
    )

    print(
        f"  HTML Report             : "
        f"{report_paths['html']}"
    )

    print(
        f"  PDF Report              : "
        f"{report_paths['pdf']}"
    )

    print()


    # --------------------------------------------------------
    # STEP 12 — REMEDIATION DISPLAY
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("                 REMEDIATION GUIDANCE")
    print("=" * 60)
    print()

    print("Remediation Overview")

    print(
        f"  Actions Generated       : "
        f"{remediation_summary['total_items']}"
    )

    print(
        f"  Immediate Actions       : "
        f"{remediation_summary['immediate_actions']}"
    )

    print(
        f"  Planned Actions         : "
        f"{remediation_summary['planned_actions']}"
    )

    print(
        f"  Routine Actions         : "
        f"{remediation_summary['routine_actions']}"
    )

    print()

    if not remediation_items:

        print(
            "  No remediation guidance generated."
        )

    else:

        print(
            "Priority Remediation Actions"
        )

        for index, item in enumerate(
            remediation_items[:10],
            start=1,
        ):

            location = item.host

            if item.port is not None:

                protocol = (
                    item.protocol
                    or "tcp"
                )

                location = (
                    f"{location}:"
                    f"{item.port}/"
                    f"{protocol}"
                )

            print()

            print(
                f"  {index}. "
                f"[{item.priority.upper()}] "
                f"{item.severity.upper()} "
                f"Risk {item.risk_score}/25"
            )

            print(
                f"     {item.title}"
            )

            print(
                f"     Location : "
                f"{location}"
            )

            print(
                f"     Action   : "
                f"{item.action}"
            )

            if item.verification:

                print(
                    f"     Verify   : "
                    f"{item.verification[0]}"
                )

        if len(remediation_items) > 10:

            print()

            print(
                f"  ... {len(remediation_items) - 10} "
                f"additional remediation action(s) "
                f"stored in evidence."
            )

    # ============================================================
    # STEP 9H — FINDING CORRELATION SUMMARY
    # ============================================================

    print()
    print("=" * 60)
    print("                  FINDING CORRELATION")
    print("=" * 60)
    print()

    print(
        f"  Unique Findings            : "
        f"{len(correlated_findings)}"
    )

    categories = (
        correlation_summary.get(
            "categories",
            {},
        )
    )

    for category, count in categories.items():

        print(
            f"  {category:<28}: "
            f"{count}"
        )

    # ============================================================
    # PIPELINE COMPLETE
    # ============================================================

    print()
    print("=" * 60)
    print("                  SECURITY POSTURE SUMMARY")
    print("=" * 60)
    print()

    # ------------------------------------------------------------
    # Target
    # ------------------------------------------------------------

    print("Target")

    print(
        f"  {target.normalized_value}"
    )

    # ------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------

    print()
    print("Discovery")

    print(
        f"  Hosts Discovered         : "
        f"{len(live_hosts)}"
    )

    print(
        f"  Open Ports               : "
        f"{len(open_ports)}"
    )

    print(
        f"    TCP                    : "
        f"{len(open_tcp)}"
    )

    print(
        f"    UDP                    : "
        f"{len(open_udp)}"
    )

    # ------------------------------------------------------------
    # Services
    # ------------------------------------------------------------

    print()
    print("Services")

    print(
        f"  Identified Services      : "
        f"{len(service_results)}"
    )

    print(
        f"  Management Interfaces    : "
        f"{len(management_results)}"
    )

    # ------------------------------------------------------------
    # Platform
    # ------------------------------------------------------------

    print()
    print("Platform")

    print(
        f"  Operating System         : "
        f"{os_summary}"
    )

    # ------------------------------------------------------------
    # Security Analysis
    # ------------------------------------------------------------

    print()
    print("Security Analysis")

    print(
        f"  Security Observations    : "
        f"{len(security_findings)}"
    )

    print(
        f"  Database Exposures       : "
        f"{len(database_findings)}"
    )

    print(
        f"  Metadata Findings        : "
        f"{len(metadata_findings)}"
    )

    print(
        f"  Misconfigurations        : "
        f"{len(misconfiguration_findings)}"
    )

    print(
        f"  Correlated Findings      : "
        f"{len(correlated_findings)}"
    )

    # ------------------------------------------------------------
    # Risk Assessment
    # ------------------------------------------------------------

    print()
    print("Risk Assessment")

    print(
        f"  Critical                 : "
        f"{risk_summary['critical']}"
    )

    print(
        f"  High                     : "
        f"{risk_summary['high']}"
    )

    print(
        f"  Medium                   : "
        f"{risk_summary['medium']}"
    )

    print(
        f"  Low                      : "
        f"{risk_summary['low']}"
    )

    print(
        f"  Informational            : "
        f"{risk_summary['informational']}"
    )

    print()

    print(
        f"  Highest Risk             : "
        f"{risk_summary['highest_risk_score']} / 25"
    )

    print(
        f"  Average Risk             : "
        f"{risk_summary['average_risk_score']} / 25"
    )

    # ------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------

    print()
    print("Remediation")

    print(
        f"  Actions Generated        : "
        f"{remediation_summary['total_items']}"
    )

    print(
        f"  Immediate Actions        : "
        f"{remediation_summary['immediate_actions']}"
    )

    print(
        f"  Planned Actions          : "
        f"{remediation_summary['planned_actions']}"
    )

    print(
        f"  Routine Actions          : "
        f"{remediation_summary['routine_actions']}"
    )

    # ------------------------------------------------------------
    # Service Exposure & Exploitation Analysis
    # ------------------------------------------------------------

    print()
    print("Service Exposure & Exploitation Analysis")

    print(
        f"  Assessments Generated   : "
        f"{len(exploitation_assessments)}"
    )

    print(
        f"  Attack Methods Mapped   : "
        f"{exploitation_summary.get('attack_methods', 0)}"
    )

    # ------------------------------------------------------------
    # Analysis Coverage
    # ------------------------------------------------------------

    print()
    print("Analysis Coverage")

    print(
        f"  TLS Endpoints            : "
        f"{tls_detected}"
    )

    print(
        f"  SSH Endpoints            : "
        f"{len(ssh_results)}"
    )

    # ------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------

    print()
    print("Artifacts")

    print(
        f"  Evidence Directory       : "
        f"{output.report_dir}"
    )

    print(
        f"  JSON Evidence            : "
        f"{output.json_path}"
    )

    print("=" * 60)

    # ------------------------------------------------------------
    # Final machine-readable completion summary
    # ------------------------------------------------------------

    output.complete(
        {
            "Hosts":
                len(live_hosts),

            "Open Ports":
                len(open_ports),

            "TCP":
                len(open_tcp),

            "UDP":
                len(open_udp),

            "Services":
                len(service_results),

            "OS":
                os_summary,

            "TLS Endpoints":
                tls_detected,

            "SSH Endpoints":
                len(ssh_results),

            "Management":
                len(management_results),

            "9A Security Observations":
                len(security_findings),

            "9E Database Observations":
                len(database_findings),

            "9F Metadata Observations":
                len(metadata_findings),

            "9G Misconfiguration Observations":
                len(misconfiguration_findings),

            "9H Unique Findings":
                len(correlated_findings),

            "10 Risk Assessments":
                len(risk_assessments),

            "10 Highest Risk":
                risk_summary[
                    "highest_risk_score"
                ],

            "12 Remediation Actions":
                len(remediation_items),

            "12 Immediate Actions":
                remediation_summary[
                    "immediate_actions"
                ],

            "13 Exploitation Assessments":
                len(exploitation_assessments),
        }
    )


if __name__ == "__main__":
    main()