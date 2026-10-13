import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, Field


class TLSEvidence(BaseModel):
    source: str
    evidence_type: str
    value: str


class TLSResult(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"

    tls_detected: bool = False

    tls_version: Optional[str] = None
    cipher: Optional[str] = None

    certificate_present: bool = False
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_not_before: Optional[str] = None
    certificate_not_after: Optional[str] = None
    certificate_sans: list[str] = Field(default_factory=list)

    certificate_expired: bool = False
    certificate_not_yet_valid: bool = False

    handshake_error: Optional[str] = None
    certificate_parse_error: Optional[str] = None

    sni_used: Optional[str] = None

    findings: list[str] = Field(default_factory=list)
    evidence: list[TLSEvidence] = Field(default_factory=list)


class TLSAnalyzer:
    """
    Safe TLS/SSL analyzer.

    The analyzer:
      - performs a TLS handshake
      - collects negotiated TLS information
      - retrieves the peer certificate
      - parses certificate metadata
      - checks certificate validity dates
      - records structured evidence

    It does not:
      - authenticate
      - send application credentials
      - modify server state
      - exploit TLS vulnerabilities
      - brute-force ciphers
    """

    # ---------------------------------------------------------
    # Direct TLS candidates
    # ---------------------------------------------------------

    DIRECT_TLS_PORTS = {
        443,
        4443,
        465,
        636,
        853,
        990,
        993,
        995,
        8443,
    }

    # Service names that strongly indicate a direct TLS service.
    #
    # IMPORTANT:
    # Do not put generic services such as "irc" here.
    # A service name being associated with a port does not mean
    # that the service is speaking TLS directly.
    TLS_SERVICE_NAMES = {
        "https",
        "ssl/http",
        "tls",
        "imaps",
        "pop3s",
        "smtps",
        "ftps",
        "ldaps",
        "nntps",
    }

    # These protocols commonly support STARTTLS or explicit TLS,
    # but are deliberately NOT treated as direct TLS endpoints
    # in this baseline.
    STARTTLS_PORTS = {
        25,   # SMTP
        110,  # POP3
        143,  # IMAP
        587,  # SMTP submission
        21,   # FTP explicit TLS
    }

    # Known plain-text/non-direct-TLS service names.
    #
    # This is an additional guard so that a service fingerprint
    # cannot accidentally cause an unnecessary TLS handshake.
    NON_TLS_SERVICE_NAMES = {
        "irc",
        "ftp",
        "telnet",
        "ssh",
        "smtp",
        "pop3",
        "imap",
        "http",
        "domain",
        "dns",
        "rpcbind",
        "netbios-ssn",
        "microsoft-ds",
        "mysql",
        "postgresql",
        "postgres",
        "vnc",
        "x11",
    }

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    # ---------------------------------------------------------
    # Candidate detection
    # ---------------------------------------------------------

    def is_tls_candidate(
        self,
        port: int,
        service_name: Optional[str] = None,
    ) -> bool:
        """
        Decide whether a port should receive a direct TLS handshake.

        Port number is treated as a candidate indicator, not proof
        that TLS is actually running.

        Service names are used as supporting evidence.

        STARTTLS protocols are deliberately excluded from this
        direct-TLS baseline.
        """

        # Explicitly exclude STARTTLS ports from direct TLS testing.
        if port in self.STARTTLS_PORTS:
            return False

        # If service identification says this is a known plain-text
        # service, do not send a direct TLS handshake.
        if service_name:
            normalized = service_name.strip().lower()

            if normalized in self.NON_TLS_SERVICE_NAMES:
                return False

        # Standard direct-TLS ports.
        if port in self.DIRECT_TLS_PORTS:
            return True

        if service_name:
            normalized = service_name.strip().lower()

            # Strong TLS service-name match.
            if normalized in self.TLS_SERVICE_NAMES:
                return True

            # Examples:
            # https-alt
            # https-proxy
            #
            # Only use this for names containing "https".
            if "https" in normalized:
                return True

            # Explicit TLS variants such as:
            # imaps
            # pop3s
            # smtps
            # ftps
            # ldaps
            # nntps
            if normalized.endswith("s") and normalized in {
                "imaps",
                "pop3s",
                "smtps",
                "ftps",
                "ldaps",
                "nntps",
            }:
                return True

        return False

    # ---------------------------------------------------------
    # SNI handling
    # ---------------------------------------------------------

    def _normalize_server_name(
        self,
        server_name: Optional[str],
    ) -> Optional[str]:
        """
        SNI should normally be a DNS hostname.

        Do not send an IP literal as SNI.
        """

        if not server_name:
            return None

        server_name = server_name.strip()

        if not server_name:
            return None

        try:
            ipaddress.ip_address(server_name)
            return None
        except ValueError:
            pass

        return server_name

    # ---------------------------------------------------------
    # Certificate helpers
    # ---------------------------------------------------------

    def _format_datetime(
        self,
        value: datetime,
    ) -> str:
        """
        Normalize certificate datetime into UTC ISO format.
        """

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        value = value.astimezone(timezone.utc)

        return value.isoformat()

    def _get_certificate_datetime(
        self,
        certificate,
        attribute_name: str,
        utc_attribute_name: str,
    ) -> datetime:
        """
        Support both newer and older cryptography versions.
        """

        utc_value = getattr(
            certificate,
            utc_attribute_name,
            None,
        )

        if utc_value is not None:
            return utc_value

        value = getattr(
            certificate,
            attribute_name,
        )

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value

    def _parse_certificate(
        self,
        certificate_der: bytes,
    ) -> dict:
        """
        Parse a DER certificate using cryptography.
        """

        certificate = x509.load_der_x509_certificate(
            certificate_der,
            default_backend(),
        )

        subject = certificate.subject.rfc4514_string()
        issuer = certificate.issuer.rfc4514_string()

        not_before = self._get_certificate_datetime(
            certificate,
            "not_valid_before",
            "not_valid_before_utc",
        )

        not_after = self._get_certificate_datetime(
            certificate,
            "not_valid_after",
            "not_valid_after_utc",
        )

        sans: list[str] = []

        try:
            san_extension = (
                certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
            )

            san_value = san_extension.value

            for dns_name in san_value.get_values_for_type(
                x509.DNSName
            ):
                sans.append(
                    f"DNS:{dns_name}"
                )

            for ip_address_value in san_value.get_values_for_type(
                x509.IPAddress
            ):
                sans.append(
                    f"IP:{ip_address_value}"
                )

        except x509.ExtensionNotFound:
            pass

        now = datetime.now(timezone.utc)

        certificate_expired = now > not_after
        certificate_not_yet_valid = now < not_before

        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": self._format_datetime(
                not_before
            ),
            "not_after": self._format_datetime(
                not_after
            ),
            "sans": sans,
            "expired": certificate_expired,
            "not_yet_valid": certificate_not_yet_valid,
        }

    # ---------------------------------------------------------
    # TLS endpoint analysis
    # ---------------------------------------------------------

    def analyze_endpoint(
        self,
        host: str,
        port: int,
        server_name: Optional[str] = None,
    ) -> TLSResult:

        result = TLSResult(
            host=host,
            port=port,
            protocol="tcp",
        )

        normalized_server_name = (
            self._normalize_server_name(
                server_name
            )
        )

        result.sni_used = normalized_server_name

        if normalized_server_name:
            result.evidence.append(
                TLSEvidence(
                    source="tls_analyzer",
                    evidence_type="sni",
                    value=normalized_server_name,
                )
            )

        raw_socket = None
        tls_socket = None

        try:
            # -------------------------------------------------
            # TCP connection
            # -------------------------------------------------

            raw_socket = socket.create_connection(
                (host, port),
                timeout=self.timeout,
            )

            result.evidence.append(
                TLSEvidence(
                    source="tls_analyzer",
                    evidence_type="tcp_connection",
                    value="TCP connection established",
                )
            )

            # -------------------------------------------------
            # TLS context
            # -------------------------------------------------

            context = ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            )

            # We are inspecting the peer certificate rather
            # than performing trust validation.
            #
            # This allows inspection of self-signed or otherwise
            # untrusted certificates without treating the endpoint
            # as unavailable.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            tls_socket = context.wrap_socket(
                raw_socket,
                server_hostname=normalized_server_name,
            )

            # -------------------------------------------------
            # Handshake succeeded
            # -------------------------------------------------

            result.tls_detected = True

            result.evidence.append(
                TLSEvidence(
                    source="tls_analyzer",
                    evidence_type="tls_handshake",
                    value="TLS handshake successful",
                )
            )

            # -------------------------------------------------
            # Negotiated TLS version
            # -------------------------------------------------

            result.tls_version = tls_socket.version()

            if result.tls_version:
                result.evidence.append(
                    TLSEvidence(
                        source="tls_analyzer",
                        evidence_type="tls_version",
                        value=result.tls_version,
                    )
                )

            # -------------------------------------------------
            # Negotiated cipher
            # -------------------------------------------------

            cipher_info = tls_socket.cipher()

            if cipher_info:
                cipher_name = cipher_info[0]

                result.cipher = cipher_name

                result.evidence.append(
                    TLSEvidence(
                        source="tls_analyzer",
                        evidence_type="cipher",
                        value=str(cipher_info),
                    )
                )

            # -------------------------------------------------
            # Peer certificate
            # -------------------------------------------------

            certificate_der = tls_socket.getpeercert(
                binary_form=True
            )

            if certificate_der:
                result.certificate_present = True

                result.evidence.append(
                    TLSEvidence(
                        source="tls_analyzer",
                        evidence_type="certificate",
                        value="Peer certificate received",
                    )
                )

                try:
                    certificate_data = (
                        self._parse_certificate(
                            certificate_der
                        )
                    )

                    result.certificate_subject = (
                        certificate_data["subject"]
                    )

                    result.certificate_issuer = (
                        certificate_data["issuer"]
                    )

                    result.certificate_not_before = (
                        certificate_data["not_before"]
                    )

                    result.certificate_not_after = (
                        certificate_data["not_after"]
                    )

                    result.certificate_sans = (
                        certificate_data["sans"]
                    )

                    result.certificate_expired = (
                        certificate_data["expired"]
                    )

                    result.certificate_not_yet_valid = (
                        certificate_data["not_yet_valid"]
                    )

                    result.evidence.extend(
                        [
                            TLSEvidence(
                                source="certificate",
                                evidence_type="subject",
                                value=(
                                    result.certificate_subject
                                    or ""
                                ),
                            ),
                            TLSEvidence(
                                source="certificate",
                                evidence_type="issuer",
                                value=(
                                    result.certificate_issuer
                                    or ""
                                ),
                            ),
                            TLSEvidence(
                                source="certificate",
                                evidence_type="not_before",
                                value=(
                                    result.certificate_not_before
                                    or ""
                                ),
                            ),
                            TLSEvidence(
                                source="certificate",
                                evidence_type="not_after",
                                value=(
                                    result.certificate_not_after
                                    or ""
                                ),
                            ),
                        ]
                    )

                    if result.certificate_sans:
                        result.evidence.append(
                            TLSEvidence(
                                source="certificate",
                                evidence_type=(
                                    "subject_alternative_names"
                                ),
                                value=", ".join(
                                    result.certificate_sans
                                ),
                            )
                        )

                    # -------------------------------------------------
                    # Certificate validity observations
                    # -------------------------------------------------

                    if result.certificate_expired:
                        result.findings.append(
                            "TLS_CERTIFICATE_EXPIRED"
                        )

                        result.evidence.append(
                            TLSEvidence(
                                source="tls_analyzer",
                                evidence_type=(
                                    "certificate_validity"
                                ),
                                value=(
                                    "Certificate is expired"
                                ),
                            )
                        )

                    if result.certificate_not_yet_valid:
                        result.findings.append(
                            "TLS_CERTIFICATE_NOT_YET_VALID"
                        )

                        result.evidence.append(
                            TLSEvidence(
                                source="tls_analyzer",
                                evidence_type=(
                                    "certificate_validity"
                                ),
                                value=(
                                    "Certificate is not yet valid"
                                ),
                            )
                        )

                except Exception as error:
                    result.certificate_parse_error = (
                        str(error)
                    )

                    result.evidence.append(
                        TLSEvidence(
                            source="tls_analyzer",
                            evidence_type=(
                                "certificate_parse_error"
                            ),
                            value=str(error),
                        )
                    )

            else:
                result.evidence.append(
                    TLSEvidence(
                        source="tls_analyzer",
                        evidence_type="certificate",
                        value=(
                            "No peer certificate returned"
                        ),
                    )
                )

            # -------------------------------------------------
            # Legacy protocol detection
            # -------------------------------------------------

            if result.tls_version in {
                "TLSv1",
                "TLSv1.0",
                "TLSv1.1",
            }:

                result.findings.append(
                    "TLS_LEGACY_PROTOCOL"
                )

                result.evidence.append(
                    TLSEvidence(
                        source="tls_analyzer",
                        evidence_type=(
                            "protocol_security"
                        ),
                        value=(
                            "Legacy TLS version negotiated: "
                            f"{result.tls_version}"
                        ),
                    )
                )

        except ssl.SSLError as error:
            result.handshake_error = str(error)

            result.evidence.append(
                TLSEvidence(
                    source="tls_analyzer",
                    evidence_type="tls_handshake_error",
                    value=str(error),
                )
            )

        except (
            socket.timeout,
            ConnectionRefusedError,
            OSError,
        ) as error:

            result.handshake_error = str(error)

            result.evidence.append(
                TLSEvidence(
                    source="tls_analyzer",
                    evidence_type="connection_error",
                    value=str(error),
                )
            )

        except Exception as error:
            result.handshake_error = str(error)

            result.evidence.append(
                TLSEvidence(
                    source="tls_analyzer",
                    evidence_type="unexpected_error",
                    value=str(error),
                )
            )

        finally:

            if tls_socket is not None:
                try:
                    tls_socket.close()
                except OSError:
                    pass

            elif raw_socket is not None:
                try:
                    raw_socket.close()
                except OSError:
                    pass

        return result

    # ---------------------------------------------------------
    # Multi-port analysis
    # ---------------------------------------------------------

    def analyze_ports(
        self,
        port_results,
        service_results,
        server_name: Optional[str] = None,
    ) -> list[TLSResult]:

        service_map = {}

        for service_result in service_results:

            key = (
                service_result.host,
                service_result.port,
                service_result.protocol.lower(),
            )

            service_map[key] = service_result

        candidates = {}

        for port_result in port_results:

            # Only analyze open ports.
            if port_result.state.lower() != "open":
                continue

            # TLS baseline currently covers TCP only.
            if port_result.protocol.lower() != "tcp":
                continue

            key = (
                port_result.host,
                port_result.port,
                port_result.protocol.lower(),
            )

            service_result = service_map.get(key)

            service_name = None

            if service_result:
                service_name = service_result.service

            if self.is_tls_candidate(
                port=port_result.port,
                service_name=service_name,
            ):
                candidates[key] = (
                    port_result.host,
                    port_result.port,
                )

        results: list[TLSResult] = []

        for host, port in candidates.values():

            tls_result = self.analyze_endpoint(
                host=host,
                port=port,
                server_name=server_name,
            )

            results.append(tls_result)

        return results

    # ---------------------------------------------------------
    # Display helper
    # ---------------------------------------------------------

    def print_results(
        self,
        results: list[TLSResult],
    ) -> None:

        if not results:
            print(
                "No direct TLS candidates detected."
            )
            return

        for result in results:

            print(
                f"\n{result.host}:{result.port}"
            )

            print(
                "  TLS Detected : "
                f"{result.tls_detected}"
            )

            print(
                "  TLS Version  : "
                f"{result.tls_version or 'unknown'}"
            )

            print(
                "  Cipher       : "
                f"{result.cipher or 'unknown'}"
            )

            print(
                "  Certificate  : "
                f"{result.certificate_present}"
            )

            if result.certificate_subject:
                print(
                    "  Subject      : "
                    f"{result.certificate_subject}"
                )

            if result.certificate_issuer:
                print(
                    "  Issuer       : "
                    f"{result.certificate_issuer}"
                )

            if result.certificate_not_before:
                print(
                    "  Not Before   : "
                    f"{result.certificate_not_before}"
                )

            if result.certificate_not_after:
                print(
                    "  Not After    : "
                    f"{result.certificate_not_after}"
                )

            if result.certificate_sans:
                print(
                    "  SANs         : "
                    f"{', '.join(result.certificate_sans)}"
                )

            print(
                "  Expired      : "
                f"{result.certificate_expired}"
            )

            print(
                "  Not Yet Valid: "
                f"{result.certificate_not_yet_valid}"
            )

            if result.sni_used:
                print(
                    "  SNI          : "
                    f"{result.sni_used}"
                )

            if result.findings:
                print("  Findings:")

                for finding in result.findings:
                    print(
                        f"    - {finding}"
                    )

            if result.handshake_error:
                print(
                    "  Handshake Error: "
                    f"{result.handshake_error}"
                )

            print("  Evidence:")

            for evidence in result.evidence:
                print(
                    f"    [{evidence.source}] "
                    f"{evidence.evidence_type}: "
                    f"{evidence.value}"
                )