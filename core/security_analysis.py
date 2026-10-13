from typing import Optional

from pydantic import BaseModel, Field

from core.tls_analyzer import TLSResult


# =========================================================
# SECURITY EVIDENCE
# =========================================================

class SecurityEvidence(BaseModel):
    source: str
    evidence_type: str
    value: str


# =========================================================
# SECURITY FINDING
# =========================================================

class SecurityFinding(BaseModel):
    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None

    category: str
    title: str
    description: str

    confidence: str = "unknown"

    evidence: list[SecurityEvidence] = Field(
        default_factory=list
    )

    recommendation: Optional[str] = None

    tags: list[str] = Field(
        default_factory=list
    )


# =========================================================
# SECURITY ANALYZER
# =========================================================

class SecurityAnalyzer:

    # =====================================================
    # SERVICE GROUPS
    # =====================================================

    SERVICE_GROUPS = {
        "remote_administration": {
            "ssh",
            "telnet",
            "rdp",
            "vnc",
            "winrm",
            "wsman",
            "ms-wbt-server",
            "rlogin",
            "rexec",
            "rsh",
            "login",
            "shell",
        },

        "database": {
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
        },

        "file_sharing": {
            "ftp",
            "netbios-ssn",
            "microsoft-ds",
            "microsoft-ds?",
            "smb",
            "nfs",
        },

        "infrastructure": {
            "domain",
            "dns",
            "rpcbind",
            "snmp",
            "ntp",
            "kerberos",
            "kerberos-sec",
            "kpasswd5",
            "ldap",
            "ldapssl",
            "globalcatldap",
            "globalcatldapssl",
            "msrpc",
            "ncacn_http",
            "http-rpc-epmap",
        },

        "web": {
            "http",
            "https",
            "http-proxy",
        },
    }

    # =====================================================
    # INSECURE SERVICES
    # =====================================================

    INSECURE_SERVICES = {
        "telnet",
        "ftp",
        "rlogin",
        "rsh",
        "rexec",
        "login",
        "shell",
    }

    INSECURE_PORTS = {
        21: "ftp",
        23: "telnet",
        512: "rexec",
        513: "login",
        514: "shell",
    }

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(
        self,
        port_results,
        service_results,
        tls_results: Optional[list[TLSResult]] = None,
    ) -> list[SecurityFinding]:

        findings: list[SecurityFinding] = []

        service_map = self._build_service_map(
            service_results
        )

        # -------------------------------------------------
        # STEP 9A
        # -------------------------------------------------

        findings.extend(
            self._analyze_exposure(
                port_results=port_results,
                service_results=service_results,
                service_map=service_map,
            )
        )

        findings.extend(
            self._analyze_insecure_protocol(
                port_results=port_results,
                service_results=service_results,
                service_map=service_map,
            )
        )

        # -------------------------------------------------
        # STEP 9B
        # -------------------------------------------------

        if tls_results:

            findings.extend(
                self._analyze_tls_results(
                    tls_results
                )
            )

        return findings

    # =====================================================
    # SERVICE MAP
    # =====================================================

    def _build_service_map(
        self,
        service_results,
    ) -> dict:

        service_map = {}

        for service_result in service_results:

            key = (
                service_result.host,
                service_result.port,
                service_result.protocol.lower(),
            )

            service_map[key] = service_result

        return service_map

    # =====================================================
    # NORMALIZE SERVICE NAME
    # =====================================================

    def _normalize_service_name(
        self,
        service_name: Optional[str],
    ) -> Optional[str]:

        if not service_name:
            return None

        value = service_name.strip().lower().rstrip("?")

        if not value:
            return None

        return value

    # =====================================================
    # SERVICE HELPERS
    # =====================================================

    def _get_service_name(
        self,
        service_result,
    ) -> Optional[str]:

        if not service_result:
            return None

        return self._normalize_service_name(
            service_result.service
        )

    def _get_product(
        self,
        service_result,
    ) -> Optional[str]:

        if not service_result:
            return None

        return service_result.product

    def _get_version(
        self,
        service_result,
    ) -> Optional[str]:

        if not service_result:
            return None

        return service_result.version

    def _get_banner(
        self,
        service_result,
    ) -> Optional[str]:

        if not service_result:
            return None

        return service_result.banner

    # =====================================================
    # SERVICE CATEGORY
    # =====================================================

    def _get_service_category(
        self,
        service_name: Optional[str],
        port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> Optional[str]:

        normalized = self._normalize_service_name(
            service_name
        )

        proto = str(protocol or "tcp").lower()

        # Port-specific context is used for exposure classification only.
        # It is not proof that a particular protocol is enabled.
        if proto == "tcp" and port in {5985, 5986}:
            return "remote_administration"

        if port in {53, 88, 123, 135, 389, 464, 593, 636, 3268, 3269}:
            return "infrastructure"

        if proto == "tcp" and port in {139, 445}:
            return "file_sharing"

        if not normalized:
            return None

        for category, services in self.SERVICE_GROUPS.items():
            if normalized in services:
                return category

        return None

    # =====================================================
    # SERVICE CONFIDENCE
    # =====================================================

    def _service_confidence(
        self,
        service_result,
    ) -> str:

        if not service_result:
            return "unknown"

        confidence = (
            service_result.confidence or "unknown"
        ).lower()

        if confidence == "high":
            return "high"

        if confidence == "medium":
            return "medium"

        if confidence == "low":
            return "low"

        return "unknown"

    # =====================================================
    # STEP 9A
    # NETWORK / SERVICE EXPOSURE
    # =====================================================

    def _analyze_exposure(
        self,
        port_results,
        service_results,
        service_map,
    ) -> list[SecurityFinding]:

        findings: list[SecurityFinding] = []

        for port_result in port_results:

            if port_result.state.lower() != "open":
                continue

            protocol = port_result.protocol.lower()

            key = (
                port_result.host,
                port_result.port,
                protocol,
            )

            service_result = service_map.get(key)

            service_name = self._get_service_name(
                service_result
            )

            category = self._get_service_category(
                service_name,
                port=port_result.port,
                protocol=protocol,
            )

            if not category:
                continue

            display_service = (
                service_name
                if service_name
                else "unknown service"
            )

            evidence = [
                SecurityEvidence(
                    source="port_scanner",
                    evidence_type="open_port",
                    value=(
                        f"{port_result.host}:"
                        f"{port_result.port}/"
                        f"{protocol} is open"
                    ),
                ),
                SecurityEvidence(
                    source="security_analyzer",
                    evidence_type="service_classification",
                    value=(
                        f"{display_service} classified as "
                        f"{category}"
                    ),
                ),
            ]

            if service_result:

                if service_result.product:

                    evidence.append(
                        SecurityEvidence(
                            source="service_enumerator",
                            evidence_type="product",
                            value=service_result.product,
                        )
                    )

                if service_result.version:

                    evidence.append(
                        SecurityEvidence(
                            source="service_enumerator",
                            evidence_type="version",
                            value=service_result.version,
                        )
                    )

                if service_result.banner:

                    evidence.append(
                        SecurityEvidence(
                            source="banner_grabber",
                            evidence_type="banner",
                            value=service_result.banner,
                        )
                    )

            descriptions = {
                "remote_administration": (
                    "A remote administration service is "
                    "reachable from the scan vantage point."
                ),

                "database": (
                    "A database service is reachable from "
                    "the scan vantage point."
                ),

                "file_sharing": (
                    "A file-sharing service is reachable "
                    "from the scan vantage point."
                ),

                "infrastructure": (
                    "An infrastructure service is reachable "
                    "from the scan vantage point."
                ),

                "web": (
                    "A web service is reachable from the "
                    "scan vantage point."
                ),
            }

            recommendations = {
                "remote_administration": (
                    "Restrict remote administration services "
                    "to authorized management networks and "
                    "disable services that are not required."
                ),

                "database": (
                    "Restrict database services to authorized "
                    "application or management networks and "
                    "avoid unnecessary network exposure."
                ),

                "file_sharing": (
                    "Restrict file-sharing services to "
                    "authorized networks and disable unused "
                    "sharing protocols."
                ),

                "infrastructure": (
                    "Restrict infrastructure services to "
                    "networks that require them and disable "
                    "unnecessary exposure."
                ),

                "web": (
                    "Confirm that the web service is intended "
                    "to be reachable from this network segment "
                    "and restrict access where appropriate."
                ),
            }

            titles = {
                "remote_administration":
                    "Remote administration service exposed",

                "database":
                    "Database service exposed",

                "file_sharing":
                    "File-sharing service exposed",

                "infrastructure":
                    "Infrastructure service exposed",

                "web":
                    "Web service exposed",
            }

            # Refine common Windows/AD endpoint descriptions without
            # claiming that an open port alone confirms a vulnerability.
            if (
                port_result.port in {5985, 5986}
                and protocol == "tcp"
                and service_name in {"http", "https", "http-proxy", "unknown service", None}
            ):
                descriptions["remote_administration"] = (
                    "An HTTP(S) endpoint is reachable on a port commonly used "
                    "for Windows Remote Management (WinRM). Confirm the intended "
                    "service and restrict it to authorized management hosts. "
                    "Port and banner evidence alone do not prove WinRM is enabled "
                    "or that a vulnerability exists."
                )
                recommendations["remote_administration"] = (
                    "Verify whether WinRM is intentionally enabled. Restrict "
                    "access to approved management networks, require appropriate "
                    "authentication and transport protection, and disable the "
                    "listener if it is not needed."
                )
                titles["remote_administration"] = (
                    "Potential Windows remote-management endpoint exposed"
                )

            findings.append(
                SecurityFinding(
                    host=port_result.host,
                    port=port_result.port,
                    protocol=protocol,
                    category=(
                        f"{category.upper()}_EXPOSURE"
                    ),
                    title=titles[category],
                    description=descriptions[category],
                    confidence=self._service_confidence(
                        service_result
                    ),
                    evidence=evidence,
                    recommendation=recommendations[
                        category
                    ],
                    tags=[
                        "exposure",
                        category,
                    ],
                )
            )

        return findings

    # =====================================================
    # STEP 9A
    # INSECURE PROTOCOL ANALYSIS
    # =====================================================

    def _analyze_insecure_protocol(
        self,
        port_results,
        service_results,
        service_map,
    ) -> list[SecurityFinding]:

        findings: list[SecurityFinding] = []

        for port_result in port_results:

            if port_result.state.lower() != "open":
                continue

            protocol = port_result.protocol.lower()

            key = (
                port_result.host,
                port_result.port,
                protocol,
            )

            service_result = service_map.get(key)

            service_name = self._get_service_name(
                service_result
            )

            insecure_service = (
                service_name
                if service_name in self.INSECURE_SERVICES
                else None
            )

            port_fallback = (
                self.INSECURE_PORTS.get(port_result.port)
                if protocol == "tcp"
                else None
            )

            detected_service = (
                insecure_service
                or port_fallback
            )

            if not detected_service:
                continue

            evidence = [
                SecurityEvidence(
                    source="port_scanner",
                    evidence_type="open_port",
                    value=(
                        f"{port_result.host}:"
                        f"{port_result.port}/"
                        f"{protocol} is open"
                    ),
                ),
                SecurityEvidence(
                    source="security_analyzer",
                    evidence_type="insecure_protocol",
                    value=detected_service,
                ),
            ]

            if service_result:

                if service_result.product:

                    evidence.append(
                        SecurityEvidence(
                            source="service_enumerator",
                            evidence_type="product",
                            value=service_result.product,
                        )
                    )

                if service_result.version:

                    evidence.append(
                        SecurityEvidence(
                            source="service_enumerator",
                            evidence_type="version",
                            value=service_result.version,
                        )
                    )

                if service_result.banner:

                    evidence.append(
                        SecurityEvidence(
                            source="banner_grabber",
                            evidence_type="banner",
                            value=service_result.banner,
                        )
                    )

            recommendations = {
                "ftp": (
                    "Use encrypted file-transfer mechanisms "
                    "or require an appropriately secured "
                    "FTP/TLS configuration."
                ),

                "telnet": (
                    "Replace Telnet with SSH or another "
                    "encrypted remote administration protocol."
                ),

                "rlogin": (
                    "Disable rlogin and use an encrypted "
                    "remote administration protocol."
                ),

                "rsh": (
                    "Disable rsh and use an encrypted "
                    "remote administration protocol."
                ),

                "rexec": (
                    "Disable rexec and use an encrypted "
                    "remote administration protocol."
                ),

                "login": (
                    "Disable legacy plaintext remote-login "
                    "services and use a secure alternative."
                ),

                "shell": (
                    "Disable legacy plaintext remote-shell "
                    "services and use a secure alternative."
                ),
            }

            findings.append(
                SecurityFinding(
                    host=port_result.host,
                    port=port_result.port,
                    protocol=protocol,
                    category="INSECURE_PROTOCOL",
                    title=(
                        f"Insecure or legacy protocol exposed: "
                        f"{detected_service.upper()}"
                    ),
                    description=(
                        f"The service identified as "
                        f"{detected_service} is reachable "
                        f"from the scan vantage point. "
                        f"The protocol does not provide the "
                        f"same transport protection expected "
                        f"from modern encrypted alternatives."
                    ),
                    confidence=self._service_confidence(
                        service_result
                    ),
                    evidence=evidence,
                    recommendation=recommendations.get(
                        detected_service,
                        (
                            "Replace the legacy protocol with "
                            "a secure encrypted alternative."
                        ),
                    ),
                    tags=[
                        "insecure-protocol",
                        detected_service,
                    ],
                )
            )

        return findings

    # =====================================================
    # STEP 9B
    # TLS / SSL ANALYSIS
    # =====================================================

    def _analyze_tls_results(
        self,
        tls_results: list[TLSResult],
    ) -> list[SecurityFinding]:

        findings: list[SecurityFinding] = []

        for tls_result in tls_results:

            # -------------------------------------------------
            # EXPIRED CERTIFICATE
            # -------------------------------------------------

            if tls_result.certificate_expired:

                evidence = [
                    SecurityEvidence(
                        source=evidence_item.source,
                        evidence_type=evidence_item.evidence_type,
                        value=evidence_item.value,
                    )
                    for evidence_item
                    in tls_result.evidence
                ]

                findings.append(
                    SecurityFinding(
                        host=tls_result.host,
                        port=tls_result.port,
                        protocol=tls_result.protocol,
                        category="TLS_SECURITY",
                        title="TLS certificate is expired",
                        description=(
                            "The TLS endpoint presented a "
                            "certificate whose validity period "
                            "has expired."
                        ),
                        confidence="high",
                        evidence=evidence,
                        recommendation=(
                            "Replace the expired certificate "
                            "with a currently valid certificate "
                            "and verify the certificate renewal "
                            "process."
                        ),
                        tags=[
                            "tls",
                            "ssl",
                            "certificate",
                            "expired",
                        ],
                    )
                )

            # -------------------------------------------------
            # NOT-YET-VALID CERTIFICATE
            # -------------------------------------------------

            if tls_result.certificate_not_yet_valid:

                evidence = [
                    SecurityEvidence(
                        source=evidence_item.source,
                        evidence_type=evidence_item.evidence_type,
                        value=evidence_item.value,
                    )
                    for evidence_item
                    in tls_result.evidence
                ]

                findings.append(
                    SecurityFinding(
                        host=tls_result.host,
                        port=tls_result.port,
                        protocol=tls_result.protocol,
                        category="TLS_SECURITY",
                        title=(
                            "TLS certificate is not yet valid"
                        ),
                        description=(
                            "The TLS endpoint presented a "
                            "certificate whose validity period "
                            "has not started."
                        ),
                        confidence="high",
                        evidence=evidence,
                        recommendation=(
                            "Install a certificate whose "
                            "validity period is currently "
                            "active and verify system time "
                            "and certificate deployment."
                        ),
                        tags=[
                            "tls",
                            "ssl",
                            "certificate",
                            "validity",
                        ],
                    )
                )

            # -------------------------------------------------
            # LEGACY TLS PROTOCOL
            # -------------------------------------------------

            if (
                "TLS_LEGACY_PROTOCOL"
                in tls_result.findings
            ):

                evidence = [
                    SecurityEvidence(
                        source=evidence_item.source,
                        evidence_type=evidence_item.evidence_type,
                        value=evidence_item.value,
                    )
                    for evidence_item
                    in tls_result.evidence
                    if evidence_item.evidence_type
                    in {
                        "tls_version",
                        "protocol_security",
                        "tls_handshake",
                    }
                ]

                findings.append(
                    SecurityFinding(
                        host=tls_result.host,
                        port=tls_result.port,
                        protocol=tls_result.protocol,
                        category="TLS_SECURITY",
                        title=(
                            "Legacy TLS protocol negotiated"
                        ),
                        description=(
                            f"The endpoint negotiated "
                            f"{tls_result.tls_version}, "
                            f"which is a legacy TLS protocol "
                            f"version."
                        ),
                        confidence="high",
                        evidence=evidence,
                        recommendation=(
                            "Disable legacy TLS protocol "
                            "versions and require modern "
                            "TLS configurations."
                        ),
                        tags=[
                            "tls",
                            "ssl",
                            "legacy-protocol",
                        ],
                    )
                )

        return findings

    # =====================================================
    # PRINT FINDINGS
    # =====================================================

    def print_findings(
        self,
        findings: list[SecurityFinding],
    ) -> None:

        if not findings:

            print(
                "No security findings detected."
            )

            return

        print(
            f"\nSecurity findings: {len(findings)}"
        )

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            print(
                f"\n[{index}] "
                f"{finding.category}"
            )

            print(
                f"  Host        : "
                f"{finding.host}"
            )

            if finding.port is not None:

                print(
                    f"  Port        : "
                    f"{finding.port}/"
                    f"{finding.protocol or 'unknown'}"
                )

            print(
                f"  Title       : "
                f"{finding.title}"
            )

            print(
                f"  Description : "
                f"{finding.description}"
            )

            print(
                f"  Confidence  : "
                f"{finding.confidence}"
            )

            if finding.recommendation:

                print(
                    "  Recommendation:"
                )

                print(
                    f"    {finding.recommendation}"
                )

            if finding.tags:

                print(
                    f"  Tags        : "
                    f"{', '.join(finding.tags)}"
                )

            if finding.evidence:

                print(
                    "  Evidence:"
                )

                for evidence in finding.evidence:

                    print(
                        f"    [{evidence.source}] "
                        f"{evidence.evidence_type}: "
                        f"{evidence.value}"
                    )