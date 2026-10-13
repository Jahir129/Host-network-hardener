from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from pydantic import BaseModel, Field


# ============================================================
# EVIDENCE
# ============================================================

class CorrelationEvidence(BaseModel):
    source: str
    evidence_type: str
    value: str


# ============================================================
# CORRELATED FINDING
# ============================================================

class CorrelationFinding(BaseModel):
    category: str
    title: str

    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None

    confidence: str = "unknown"

    description: str
    recommendation: Optional[str] = None

    evidence: list[CorrelationEvidence] = Field(
        default_factory=list
    )

    tags: list[str] = Field(
        default_factory=list
    )

    # Filled by 9H
    sources: list[str] = Field(
        default_factory=list
    )

    occurrence_count: int = 1


# ============================================================
# HELPERS
# ============================================================

def _value(obj: Any, name: str, default=None):
    """
    Safely read an attribute from Pydantic models,
    dataclasses, dictionaries, or generic objects.
    """

    if obj is None:
        return default

    if isinstance(obj, dict):
        return obj.get(name, default)

    return getattr(obj, name, default)


def _lower(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip().lower()


def _confidence_rank(value: str) -> int:
    return {
        "unknown": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
    }.get(_lower(value), 0)


def _max_confidence(values: Iterable[str]) -> str:
    values = list(values)

    if not values:
        return "unknown"

    return max(
        values,
        key=_confidence_rank,
    )


def _location(
    host: str,
    port: Optional[int],
    protocol: Optional[str],
) -> str:

    value = host

    if port is not None:
        value += f":{port}"

        if protocol:
            value += f"/{protocol}"

    return value


def _make_evidence(
    source: str,
    evidence_type: str,
    value: Any,
) -> CorrelationEvidence:

    return CorrelationEvidence(
        source=source,
        evidence_type=evidence_type,
        value=str(value),
    )


def _service_text(result: Any) -> str:

    values = [
        _value(result, "service"),
        _value(result, "product"),
        _value(result, "version"),
        _value(result, "extra_info"),
        _value(result, "banner"),
    ]

    return " ".join(
        str(value)
        for value in values
        if value
    )


def _service_name(result: Any) -> str:
    return _lower(
        _value(result, "service")
    )


def _is_open(result: Any) -> bool:
    return (
        _lower(
            _value(result, "state")
        )
        == "open"
    )


# ============================================================
# 9E — DATABASE EXPOSURE ANALYSIS
# ============================================================

class DatabaseExposureAnalyzer:

    DATABASE_SERVICES = {
        "mysql",
        "mariadb",
        "postgresql",
        "postgres",
        "mssql",
        "ms-sql-s",
        "oracle",
        "oracle-tns",
        "redis",
        "mongodb",
        "mongod",
        "couchdb",
        "cassandra",
        "memcached",
        "db2",
        "sql",
    }

    DATABASE_PORTS = {
        1433,
        1521,
        2483,
        2484,
        3306,
        5432,
        5984,
        6379,
        9042,
        11211,
        27017,
        28017,
    }

    def analyze(
        self,
        port_results: list[Any],
        service_results: list[Any],
    ) -> list[CorrelationFinding]:

        findings: list[CorrelationFinding] = []

        service_by_location = {
            (
                _value(result, "host"),
                _value(result, "port"),
                _lower(
                    _value(
                        result,
                        "protocol",
                        "tcp",
                    )
                ),
            ): result
            for result in service_results
        }

        for port_result in port_results:

            if not _is_open(port_result):
                continue

            protocol = _lower(
                _value(
                    port_result,
                    "protocol",
                    "tcp",
                )
            )

            host = str(
                _value(port_result, "host")
            )

            port = _value(
                port_result,
                "port",
            )

            service_result = service_by_location.get(
                (
                    host,
                    port,
                    protocol,
                )
            )

            service = _service_name(
                service_result
            )

            is_database = (
                service in self.DATABASE_SERVICES
                or port in self.DATABASE_PORTS
            )

            if not is_database:
                continue

            evidence = [
                _make_evidence(
                    "port_scanner",
                    "open_port",
                    _location(
                        host,
                        port,
                        protocol,
                    ),
                ),
                _make_evidence(
                    "database_analyzer",
                    "database_service",
                    service or f"port-{port}",
                ),
            ]

            if service_result is not None:

                product = _value(
                    service_result,
                    "product",
                )

                version = _value(
                    service_result,
                    "version",
                )

                banner = _value(
                    service_result,
                    "banner",
                )

                confidence = _value(
                    service_result,
                    "confidence",
                    "unknown",
                )

                if product:
                    evidence.append(
                        _make_evidence(
                            "service_enum",
                            "product",
                            product,
                        )
                    )

                if version:
                    evidence.append(
                        _make_evidence(
                            "service_enum",
                            "version",
                            version,
                        )
                    )

                if banner:
                    evidence.append(
                        _make_evidence(
                            "banner_grabber",
                            "banner",
                            banner,
                        )
                    )

            else:
                confidence = "medium"

            findings.append(
                CorrelationFinding(
                    category="DATABASE_EXPOSURE",
                    title="Database service exposed",
                    host=host,
                    port=port,
                    protocol=protocol,
                    confidence=confidence,
                    description=(
                        "A database service is reachable "
                        "from the scan vantage point."
                    ),
                    recommendation=(
                        "Restrict database services to "
                        "authorized application or management "
                        "networks and disable unnecessary "
                        "network exposure."
                    ),
                    evidence=evidence,
                    tags=[
                        "exposure",
                        "database",
                    ],
                    sources=[
                        "9E_database_analysis"
                    ],
                )
            )

        return findings


# ============================================================
# 9F — METADATA LEAKAGE ANALYSIS
# ============================================================

class MetadataLeakageAnalyzer:

    # Headers / banners that commonly disclose
    # implementation information.
    METADATA_PATTERNS = {
        "server": "server_header",
        "x-powered-by": "technology_header",
        "x-aspnet-version": "technology_header",
        "x-generator": "technology_header",
        "x-runtime": "technology_header",
        "x-drupal": "technology_header",
        "apache": "server_software",
        "nginx": "server_software",
        "iis": "server_software",
        "tomcat": "application_server",
        "php": "runtime",
        "openssh": "remote_service_version",
        "vsftpd": "ftp_service_version",
        "proftpd": "ftp_service_version",
        "samba": "file_service_version",
        "postgresql": "database_version",
        "mysql": "database_version",
        "mariadb": "database_version",
    }

    INTERNAL_IP_RE = re.compile(
        r"\b("
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r")\b"
    )

    INTERNAL_HOST_RE = re.compile(
        r"\b(?:"
        r"localhost"
        r"|[a-zA-Z0-9_-]+\.local"
        r"|[a-zA-Z0-9_-]+\.internal"
        r"|[a-zA-Z0-9_-]+\.lan"
        r")\b",
        re.IGNORECASE,
    )

    def _metadata_matches(
        self,
        text: str,
    ) -> list[tuple[str, str]]:

        matches: list[tuple[str, str]] = []

        lowered = text.lower()

        for pattern, metadata_type in (
            self.METADATA_PATTERNS.items()
        ):
            if pattern in lowered:
                matches.append(
                    (
                        metadata_type,
                        pattern,
                    )
                )

        return matches

    def analyze(
        self,
        service_results: list[Any],
        os_results: Optional[list[Any]] = None,
    ) -> list[CorrelationFinding]:

        findings: list[CorrelationFinding] = []

        for result in service_results:

            host = str(
                _value(result, "host")
            )

            port = _value(
                result,
                "port",
            )

            protocol = _lower(
                _value(
                    result,
                    "protocol",
                    "tcp",
                )
            )

            confidence = _value(
                result,
                "confidence",
                "unknown",
            )

            service = _value(
                result,
                "service",
            )

            product = _value(
                result,
                "product",
            )

            version = _value(
                result,
                "version",
            )

            banner = _value(
                result,
                "banner",
            )

            pieces = [
                value
                for value in (
                    service,
                    product,
                    version,
                    banner,
                )
                if value
            ]

            if not pieces:
                continue

            text = "\n".join(
                str(value)
                for value in pieces
            )

            matches = self._metadata_matches(
                text
            )

            internal_ips = (
                self.INTERNAL_IP_RE.findall(
                    text
                )
            )

            internal_hosts = (
                self.INTERNAL_HOST_RE.findall(
                    text
                )
            )

            # ----------------------------------------------------
            # Technology/version metadata
            # ----------------------------------------------------

            if matches:

                metadata_types = sorted(
                    {
                        metadata_type
                        for metadata_type, _ in matches
                    }
                )

                matched_tokens = sorted(
                    {
                        token
                        for _, token in matches
                    }
                )

                evidence = [
                    _make_evidence(
                        "service_enum",
                        "metadata_type",
                        ", ".join(
                            metadata_types
                        ),
                    ),
                    _make_evidence(
                        "service_enum",
                        "disclosed_tokens",
                        ", ".join(
                            matched_tokens
                        ),
                    ),
                ]

                if product:
                    evidence.append(
                        _make_evidence(
                            "service_enum",
                            "product",
                            product,
                        )
                    )

                if version:
                    evidence.append(
                        _make_evidence(
                            "service_enum",
                            "version",
                            version,
                        )
                    )

                if banner:
                    evidence.append(
                        _make_evidence(
                            "banner_grabber",
                            "banner",
                            banner,
                        )
                    )

                findings.append(
                    CorrelationFinding(
                        category="METADATA_LEAKAGE",
                        title=(
                            "Service metadata disclosed"
                        ),
                        host=host,
                        port=port,
                        protocol=protocol,
                        confidence=confidence,
                        description=(
                            "The service response or "
                            "fingerprint discloses implementation "
                            "details such as software, product, "
                            "runtime, or version information."
                        ),
                        recommendation=(
                            "Minimize unnecessary software and "
                            "version disclosure in service banners "
                            "and HTTP response headers where practical."
                        ),
                        evidence=evidence,
                        tags=[
                            "metadata",
                            "information_disclosure",
                        ],
                        sources=[
                            "9F_metadata_analysis"
                        ],
                    )
                )

            # ----------------------------------------------------
            # Internal network information
            # ----------------------------------------------------

            if internal_ips or internal_hosts:

                evidence = []

                if internal_ips:
                    evidence.append(
                        _make_evidence(
                            "metadata_analyzer",
                            "internal_ip",
                            ", ".join(
                                sorted(
                                    set(
                                        internal_ips
                                    )
                                )
                            ),
                        )
                    )

                if internal_hosts:
                    evidence.append(
                        _make_evidence(
                            "metadata_analyzer",
                            "internal_hostname",
                            ", ".join(
                                sorted(
                                    set(
                                        internal_hosts
                                    )
                                )
                            ),
                        )
                    )

                evidence.append(
                    _make_evidence(
                        "banner_grabber",
                        "metadata_source",
                        text[:4096],
                    )
                )

                findings.append(
                    CorrelationFinding(
                        category="METADATA_LEAKAGE",
                        title=(
                            "Internal network metadata disclosed"
                        ),
                        host=host,
                        port=port,
                        protocol=protocol,
                        confidence=confidence,
                        description=(
                            "Service evidence contains an "
                            "internal address or hostname that "
                            "may disclose network topology."
                        ),
                        recommendation=(
                            "Review service responses and banners "
                            "for unnecessary internal addresses "
                            "or hostnames and remove unnecessary "
                            "topology information."
                        ),
                        evidence=evidence,
                        tags=[
                            "metadata",
                            "information_disclosure",
                            "internal_network",
                        ],
                        sources=[
                            "9F_metadata_analysis"
                        ],
                    )
                )

        # --------------------------------------------------------
        # OS metadata
        # --------------------------------------------------------

        if os_results:

            for result in os_results:

                host = str(
                    _value(result, "host")
                )

                distribution = _value(
                    result,
                    "distribution_hint",
                )

                kernel = _value(
                    result,
                    "kernel_generation",
                )

                if not distribution and not kernel:
                    continue

                evidence = []

                if distribution:
                    evidence.append(
                        _make_evidence(
                            "os_fingerprint",
                            "distribution_hint",
                            distribution,
                        )
                    )

                if kernel:
                    evidence.append(
                        _make_evidence(
                            "os_fingerprint",
                            "kernel_generation",
                            kernel,
                        )
                    )

                findings.append(
                    CorrelationFinding(
                        category="METADATA_LEAKAGE",
                        title="Platform metadata disclosed",
                        host=host,
                        confidence=_value(
                            result,
                            "confidence",
                            "unknown",
                        ),
                        description=(
                            "Fingerprinting evidence identifies "
                            "platform information that may assist "
                            "service or vulnerability profiling."
                        ),
                        recommendation=(
                            "Treat detailed platform disclosure "
                            "as useful reconnaissance information "
                            "and minimize unnecessary disclosure "
                            "where practical."
                        ),
                        evidence=evidence,
                        tags=[
                            "metadata",
                            "platform",
                        ],
                        sources=[
                            "9F_metadata_analysis"
                        ],
                    )
                )

        return findings


# ============================================================
# 9G — MISCONFIGURATION ANALYSIS
# ============================================================

class MisconfigurationAnalyzer:

    INSECURE_SERVICES = {
        "telnet",
        "ftp",
        "rlogin",
        "rsh",
        "rexec",
        "login",
        "shell",
    }

    LEGACY_SSH_PATTERNS = (
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "ssh-dss",
        "ssh-rsa",
        "3des-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1-96",
    )

    def analyze(
        self,
        service_results: list[Any],
        ssh_results: Optional[list[Any]] = None,
        management_results: Optional[list[Any]] = None,
        tls_results: Optional[list[Any]] = None,
    ) -> list[CorrelationFinding]:

        findings: list[CorrelationFinding] = []

        # --------------------------------------------------------
        # Cleartext / legacy services
        # --------------------------------------------------------

        for result in service_results:

            service = _service_name(result)

            if service not in self.INSECURE_SERVICES:
                continue

            host = str(
                _value(result, "host")
            )

            port = _value(
                result,
                "port",
            )

            protocol = _lower(
                _value(
                    result,
                    "protocol",
                    "tcp",
                )
            )

            evidence = [
                _make_evidence(
                    "service_enum",
                    "service",
                    service,
                )
            ]

            product = _value(
                result,
                "product",
            )

            version = _value(
                result,
                "version",
            )

            if product:
                evidence.append(
                    _make_evidence(
                        "service_enum",
                        "product",
                        product,
                    )
                )

            if version:
                evidence.append(
                    _make_evidence(
                        "service_enum",
                        "version",
                        version,
                    )
                )

            findings.append(
                CorrelationFinding(
                    category="MISCONFIGURATION",
                    title=(
                        "Legacy or cleartext protocol exposed"
                    ),
                    host=host,
                    port=port,
                    protocol=protocol,
                    confidence=_value(
                        result,
                        "confidence",
                        "unknown",
                    ),
                    description=(
                        "A legacy or cleartext protocol "
                        "is reachable from the scan vantage point."
                    ),
                    recommendation=(
                        "Disable the service when unnecessary "
                        "or replace it with a modern encrypted "
                        "alternative."
                    ),
                    evidence=evidence,
                    tags=[
                        "misconfiguration",
                        "legacy_protocol",
                    ],
                    sources=[
                        "9G_misconfiguration_analysis"
                    ],
                )
            )

        # --------------------------------------------------------
        # SSH legacy algorithms
        # --------------------------------------------------------

        if ssh_results:

            for result in ssh_results:

                host = str(
                    _value(result, "host")
                )

                port = _value(
                    result,
                    "port",
                )

                protocol = _lower(
                    _value(
                        result,
                        "protocol",
                        "tcp",
                    )
                )

                algorithm_groups = {
                    "kex": _value(
                        result,
                        "key_exchange_algorithms",
                        [],
                    ),
                    "host_key": _value(
                        result,
                        "host_key_algorithms",
                        [],
                    ),
                    "cipher": _value(
                        result,
                        "ciphers",
                        [],
                    ),
                    "mac": _value(
                        result,
                        "macs",
                        [],
                    ),
                }

                legacy: list[str] = []

                for algorithms in algorithm_groups.values():

                    for algorithm in algorithms or []:

                        lowered = _lower(
                            algorithm
                        )

                        if any(
                            pattern in lowered
                            for pattern in self.LEGACY_SSH_PATTERNS
                        ):
                            legacy.append(
                                str(algorithm)
                            )

                # Prefer the analyzer's own legacy list
                # when available.
                for algorithm in (
                    _value(
                        result,
                        "legacy_algorithms",
                        [],
                    )
                    or []
                ):
                    if algorithm not in legacy:
                        legacy.append(
                            str(algorithm)
                        )

                if not legacy:
                    continue

                findings.append(
                    CorrelationFinding(
                        category="MISCONFIGURATION",
                        title=(
                            "Legacy SSH algorithms enabled"
                        ),
                        host=host,
                        port=port,
                        protocol=protocol,
                        confidence=_value(
                            result,
                            "confidence",
                            "high",
                        ),
                        description=(
                            "SSH negotiation exposes one or "
                            "more legacy algorithms that should "
                            "be reviewed for continued necessity."
                        ),
                        recommendation=(
                            "Disable legacy SSH key-exchange, "
                            "host-key, cipher, or MAC algorithms "
                            "and retain modern algorithms supported "
                            "by the required clients."
                        ),
                        evidence=[
                            _make_evidence(
                                "ssh_analyzer",
                                "legacy_algorithm",
                                algorithm,
                            )
                            for algorithm in sorted(
                                set(legacy)
                            )
                        ],
                        tags=[
                            "misconfiguration",
                            "ssh",
                            "legacy_algorithm",
                        ],
                        sources=[
                            "9G_misconfiguration_analysis"
                        ],
                    )
                )

        # --------------------------------------------------------
        # HTTP management interface without confirmed TLS
        # --------------------------------------------------------

        if management_results:

            for management in management_results:

                service = _lower(
                    _value(
                        management,
                        "service",
                    )
                )

                if service not in {
                    "http",
                    "http-proxy",
                }:
                    continue

                host = str(
                    _value(
                        management,
                        "host",
                    )
                )

                port = _value(
                    management,
                    "port",
                )

                protocol = _lower(
                    _value(
                        management,
                        "protocol",
                        "tcp",
                    )
                )

                findings.append(
                    CorrelationFinding(
                        category="MISCONFIGURATION",
                        title=(
                            "Management interface uses HTTP"
                        ),
                        host=host,
                        port=port,
                        protocol=protocol,
                        confidence=_value(
                            management,
                            "confidence",
                            "medium",
                        ),
                        description=(
                            "A management-oriented interface "
                            "was identified using HTTP rather than "
                            "an explicitly identified HTTPS endpoint."
                        ),
                        recommendation=(
                            "Prefer encrypted management transport "
                            "and restrict administrative interfaces "
                            "to authorized management networks."
                        ),
                        evidence=[
                            _make_evidence(
                                "management_analyzer",
                                "management_service",
                                service,
                            )
                        ],
                        tags=[
                            "misconfiguration",
                            "management",
                            "cleartext_transport",
                        ],
                        sources=[
                            "9G_misconfiguration_analysis"
                        ],
                    )
                )

        return findings


# ============================================================
# 9H — COMBINE + DEDUPLICATE
# ============================================================

class FindingCorrelator:

    def __init__(
        self,
        existing_findings: Optional[
            list[Any]
        ] = None,
    ):
        self.existing_findings = (
            existing_findings or []
        )

    @staticmethod
    def _convert_existing(
        finding: Any,
    ) -> CorrelationFinding:

        evidence = []

        for item in (
            _value(
                finding,
                "evidence",
                [],
            )
            or []
        ):

            evidence.append(
                CorrelationEvidence(
                    source=str(
                        _value(
                            item,
                            "source",
                            "unknown",
                        )
                    ),
                    evidence_type=str(
                        _value(
                            item,
                            "evidence_type",
                            "unknown",
                        )
                    ),
                    value=str(
                        _value(
                            item,
                            "value",
                            "",
                        )
                    ),
                )
            )

        return CorrelationFinding(
            category=str(
                _value(
                    finding,
                    "category",
                    "UNKNOWN",
                )
            ),
            title=str(
                _value(
                    finding,
                    "title",
                    "Unnamed finding",
                )
            ),
            host=str(
                _value(
                    finding,
                    "host",
                    "",
                )
            ),
            port=_value(
                finding,
                "port",
            ),
            protocol=_value(
                finding,
                "protocol",
            ),
            confidence=str(
                _value(
                    finding,
                    "confidence",
                    "unknown",
                )
            ),
            description=str(
                _value(
                    finding,
                    "description",
                    "",
                )
            ),
            recommendation=_value(
                finding,
                "recommendation",
            ),
            evidence=evidence,
            tags=list(
                _value(
                    finding,
                    "tags",
                    [],
                )
                or []
            ),
            sources=[
                "9A_security_analysis"
            ],
        )

    @staticmethod
    def _dedup_key(
        finding: CorrelationFinding,
    ) -> tuple:

        return (
            _lower(finding.category),
            _lower(finding.title),
            _lower(finding.host),
            finding.port,
            _lower(finding.protocol),
        )

    def combine(
        self,
        additional_findings: list[
            CorrelationFinding
        ],
    ) -> list[CorrelationFinding]:

        all_findings = [
            self._convert_existing(
                finding
            )
            for finding in self.existing_findings
        ]

        all_findings.extend(
            additional_findings
        )

        combined: dict[
            tuple,
            CorrelationFinding
        ] = {}

        for finding in all_findings:

            key = self._dedup_key(
                finding
            )

            if key not in combined:

                combined[key] = finding
                continue

            existing = combined[key]

            # ----------------------------------------------------
            # Merge evidence
            # ----------------------------------------------------

            evidence_keys = {
                (
                    item.source,
                    item.evidence_type,
                    item.value,
                )
                for item in existing.evidence
            }

            for item in finding.evidence:

                evidence_key = (
                    item.source,
                    item.evidence_type,
                    item.value,
                )

                if evidence_key not in evidence_keys:

                    existing.evidence.append(
                        item
                    )

                    evidence_keys.add(
                        evidence_key
                    )

            # ----------------------------------------------------
            # Merge sources
            # ----------------------------------------------------

            for source in finding.sources:

                if source not in existing.sources:

                    existing.sources.append(
                        source
                    )

            # ----------------------------------------------------
            # Merge tags
            # ----------------------------------------------------

            for tag in finding.tags:

                if tag not in existing.tags:

                    existing.tags.append(
                        tag
                    )

            # ----------------------------------------------------
            # Keep strongest confidence
            # ----------------------------------------------------

            existing.confidence = (
                _max_confidence(
                    [
                        existing.confidence,
                        finding.confidence,
                    ]
                )
            )

            existing.occurrence_count += (
                finding.occurrence_count
            )

        return list(
            combined.values()
        )

    def summarize(
        self,
        findings: list[CorrelationFinding],
    ) -> dict[str, Any]:

        categories: dict[str, int] = {}

        confidence: dict[str, int] = {}

        source_counts: dict[str, int] = {}

        for finding in findings:

            categories[
                finding.category
            ] = (
                categories.get(
                    finding.category,
                    0,
                )
                + 1
            )

            confidence[
                finding.confidence
            ] = (
                confidence.get(
                    finding.confidence,
                    0,
                )
                + 1
            )

            for source in finding.sources:

                source_counts[source] = (
                    source_counts.get(
                        source,
                        0,
                    )
                    + 1
                )

        return {
            "total_findings": len(findings),
            "categories": categories,
            "confidence": confidence,
            "sources": source_counts,
        }