from typing import List, Optional
from pydantic import BaseModel, Field

from core.service_enum import ServiceResult


class ManagementEvidence(BaseModel):
    source: str
    evidence_type: str
    value: str


class ManagementResult(BaseModel):
    host: str
    port: int
    protocol: str

    interface_type: str
    capability: str

    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None

    transport: str = "unknown"
    authentication: str = "unknown"

    management_confirmed: bool = False

    confidence: str = "unknown"

    evidence: List[ManagementEvidence] = Field(default_factory=list)

    related_analysis: List[str] = Field(default_factory=list)


class ManagementAnalyzer:

    # ---------------------------------------------------------
    # Primary service classifications
    # ---------------------------------------------------------

    REMOTE_SHELL = {
        "ssh",
        "telnet",
        "rsh",
        "shell",
    }

    REMOTE_LOGIN = {
        "rlogin",
        "login",
    }

    REMOTE_COMMAND = {
        "rexec",
        "exec",
    }

    REMOTE_DESKTOP = {
        "vnc",
        "rdp",
    }

    REMOTE_DISPLAY = {
        "x11",
        "x11-server",
    }

    REMOTE_APPLICATION = {
        "java-rmi",
        "rmi",
        "sun-rmi",
    }

    APPLICATION_CONNECTOR = {
        "ajp",
        "ajp13",
    }

    WEB_APPLICATIONS = {
        "tomcat",
    }

    # ---------------------------------------------------------
    # Normalization
    # ---------------------------------------------------------

    def _normalize(self, value: Optional[str]) -> str:
        if not value:
            return ""

        return value.strip().lower()

    def _values(self, result: ServiceResult) -> set[str]:
        values = {
            self._normalize(result.service),
            self._normalize(result.product),
            self._normalize(result.version),
            self._normalize(result.banner),
            self._normalize(result.extra_info),
        }

        return {value for value in values if value}

    def _contains(
        self,
        values: set[str],
        keywords: set[str],
    ) -> Optional[str]:

        for value in values:
            for keyword in keywords:
                if keyword in value:
                    return keyword

        return None

    # ---------------------------------------------------------
    # Transport interpretation
    # ---------------------------------------------------------

    def _transport_for_service(
        self,
        service: str,
    ) -> str:

        service = self._normalize(service)

        if service in {
            "ssh",
            "https",
            "tls",
        }:
            return "encrypted"

        if service in {
            "telnet",
            "rlogin",
            "rsh",
            "rexec",
            "login",
            "shell",
            "exec",
        }:
            return "plaintext"

        if service in {
            "vnc",
            "rdp",
            "x11",
            "x11-server",
        }:
            return "unknown"

        return "unknown"

    # ---------------------------------------------------------
    # Authentication interpretation
    # ---------------------------------------------------------

    def _authentication_for_service(
        self,
        service: str,
    ) -> str:

        service = self._normalize(service)

        if service in {
            "ssh",
            "telnet",
            "rlogin",
            "rexec",
            "rsh",
            "login",
            "shell",
            "exec",
            "vnc",
            "rdp",
        }:
            return "expected"

        if service in {
            "java-rmi",
            "rmi",
            "sun-rmi",
            "x11",
            "x11-server",
        }:
            return "unknown"

        return "unknown"

    # ---------------------------------------------------------
    # Evidence construction
    # ---------------------------------------------------------

    def _build_evidence(
        self,
        result: ServiceResult,
        matched_keyword: str,
        evidence_source: str = "management_analyzer",
    ) -> List[ManagementEvidence]:

        evidence = [
            ManagementEvidence(
                source="service_enum",
                evidence_type="service",
                value=result.service or "unknown",
            )
        ]

        if result.product:
            evidence.append(
                ManagementEvidence(
                    source="service_enum",
                    evidence_type="product",
                    value=result.product,
                )
            )

        if result.version:
            evidence.append(
                ManagementEvidence(
                    source="service_enum",
                    evidence_type="version",
                    value=result.version,
                )
            )

        if result.banner:
            evidence.append(
                ManagementEvidence(
                    source="service_enum",
                    evidence_type="banner",
                    value=result.banner,
                )
            )

        evidence.append(
            ManagementEvidence(
                source=evidence_source,
                evidence_type="classification",
                value=matched_keyword,
            )
        )

        return evidence

    # ---------------------------------------------------------
    # Result builder
    # ---------------------------------------------------------

    def _create_result(
        self,
        result: ServiceResult,
        interface_type: str,
        capability: str,
        matched_keyword: str,
        management_confirmed: bool,
        related_analysis: Optional[List[str]] = None,
    ) -> ManagementResult:

        service = self._normalize(result.service)

        return ManagementResult(
            host=result.host,
            port=result.port,
            protocol=result.protocol,

            interface_type=interface_type,
            capability=capability,

            service=result.service,
            product=result.product,
            version=result.version,

            transport=self._transport_for_service(service),
            authentication=self._authentication_for_service(service),

            management_confirmed=management_confirmed,

            confidence=result.confidence or "unknown",

            evidence=self._build_evidence(
                result,
                matched_keyword,
            ),

            related_analysis=related_analysis or [],
        )

    # ---------------------------------------------------------
    # Main analysis
    # ---------------------------------------------------------

    def analyze(
        self,
        service_results: List[ServiceResult],
    ) -> List[ManagementResult]:

        results: List[ManagementResult] = []

        for result in service_results:

            if result.state.lower() != "open":
                continue

            values = self._values(result)

            service = self._normalize(result.service)

            # -------------------------------------------------
            # SSH
            # -------------------------------------------------

            if service == "ssh":

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="REMOTE_SHELL",
                        capability="interactive_shell",
                        matched_keyword="ssh",
                        management_confirmed=True,
                        related_analysis=[
                            "9C_SSH_SECURITY_ANALYSIS",
                        ],
                    )
                )

                continue

            # -------------------------------------------------
            # Telnet
            # -------------------------------------------------

            if service == "telnet":

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="REMOTE_SHELL",
                        capability="interactive_shell",
                        matched_keyword="telnet",
                        management_confirmed=True,
                    )
                )

                continue

            # -------------------------------------------------
            # Remote login
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.REMOTE_LOGIN,
            )

            if matched:

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="REMOTE_LOGIN",
                        capability="remote_login",
                        matched_keyword=matched,
                        management_confirmed=True,
                    )
                )

                continue

            # -------------------------------------------------
            # Remote command execution
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.REMOTE_COMMAND,
            )

            if matched:

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="REMOTE_COMMAND_EXECUTION",
                        capability="remote_command_execution",
                        matched_keyword=matched,
                        management_confirmed=True,
                    )
                )

                continue

            # -------------------------------------------------
            # Remote shell
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.REMOTE_SHELL,
            )

            if matched:

                # A bindshell is different from a normal
                # authenticated remote shell.

                if "bindshell" in values or "root shell" in values:

                    results.append(
                        self._create_result(
                            result=result,
                            interface_type="UNAUTHENTICATED_REMOTE_SHELL",
                            capability="remote_shell",
                            matched_keyword="bindshell",
                            management_confirmed=True,
                        )
                    )

                else:

                    results.append(
                        self._create_result(
                            result=result,
                            interface_type="REMOTE_SHELL",
                            capability="remote_shell",
                            matched_keyword=matched,
                            management_confirmed=True,
                        )
                    )

                continue

            # -------------------------------------------------
            # VNC / RDP
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.REMOTE_DESKTOP,
            )

            if matched:

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="REMOTE_DESKTOP",
                        capability="interactive_desktop",
                        matched_keyword=matched,
                        management_confirmed=True,
                    )
                )

                continue

            # -------------------------------------------------
            # X11
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.REMOTE_DISPLAY,
            )

            if matched:

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="REMOTE_DISPLAY",
                        capability="remote_display",
                        matched_keyword=matched,
                        management_confirmed=True,
                    )
                )

                continue

            # -------------------------------------------------
            # Java RMI
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.REMOTE_APPLICATION,
            )

            if matched:

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="REMOTE_APPLICATION",
                        capability="remote_application_communication",
                        matched_keyword=matched,
                        management_confirmed=False,
                    )
                )

                continue

            # -------------------------------------------------
            # AJP
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.APPLICATION_CONNECTOR,
            )

            if matched:

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="APPLICATION_CONNECTOR",
                        capability="application_server_connector",
                        matched_keyword=matched,
                        management_confirmed=False,
                    )
                )

                continue

            # -------------------------------------------------
            # Tomcat / web application
            # -------------------------------------------------

            matched = self._contains(
                values,
                self.WEB_APPLICATIONS,
            )

            if matched:

                results.append(
                    self._create_result(
                        result=result,
                        interface_type="WEB_APPLICATION",
                        capability="web_application",
                        matched_keyword=matched,
                        management_confirmed=False,
                    )
                )

                continue

        return results