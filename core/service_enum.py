from __future__ import annotations

import re

import shutil

import socket

import subprocess

import xml.etree.ElementTree as ET

from typing import Optional

from pydantic import BaseModel


# =========================================================
# CONSERVATIVE PORT-BASED SERVICE HINTS
# =========================================================
#
# These are NOT service fingerprints. They are only low-confidence
# hints used to preserve confirmed-open endpoints when Nmap service
# enumeration does not return a service record.
#
# The tuple key deliberately includes protocol so that, for example,
# 53/tcp and 53/udp remain distinct endpoints.
# =========================================================

PORT_SERVICE_HINTS: dict[tuple[str, int], str] = {
    # DNS
    ("tcp", 53): "domain",
    ("udp", 53): "domain",

    # NTP
    ("udp", 123): "ntp",

    # Kerberos / password change
    ("tcp", 88): "kerberos-sec",
    ("udp", 88): "kerberos-sec",
    ("tcp", 464): "kpasswd5",
    ("udp", 464): "kpasswd5",

    # Windows RPC / NetBIOS / SMB
    ("tcp", 135): "msrpc",
    ("tcp", 139): "netbios-ssn",
    ("udp", 137): "netbios-ns",
    ("udp", 138): "netbios-dgm",
    ("tcp", 445): "microsoft-ds",

    # LDAP / Active Directory
    ("tcp", 389): "ldap",
    ("udp", 389): "ldap",
    ("tcp", 636): "ldaps",
    ("tcp", 3268): "globalcatldap",
    ("tcp", 3269): "globalcatldapssl",

    # RPC over HTTP / WinRM
    ("tcp", 593): "ncacn_http",
    ("tcp", 5985): "http",
    ("tcp", 5986): "https",
}



# =========================================================

# EVIDENCE

# =========================================================

class ServiceEvidence(BaseModel):

    source: str

    evidence_type: str

    value: str



# =========================================================

# FINGERPRINT

# =========================================================

class ServiceFingerprint(BaseModel):

    service: Optional[str] = None

    product: Optional[str] = None

    version: Optional[str] = None

    platform_hint: Optional[str] = None

    confidence: str = "unknown"

    conflicts: list[str] = []



# =========================================================

# SERVICE RESULT

# =========================================================

class ServiceResult(BaseModel):

    host: str

    port: int

    protocol: str = "tcp"

    state: str = "unknown"

    service: Optional[str] = None

    product: Optional[str] = None

    version: Optional[str] = None

    banner: Optional[str] = None

    extra_info: Optional[str] = None

    method: str = "nmap-service"

    confidence: str = "unknown"

    fingerprint: Optional[

        ServiceFingerprint

    ] = None

    evidence: list[

        ServiceEvidence

    ] = []



# =========================================================

# ENUMERATOR

# =========================================================

class ServiceEnumerator:

    def __init__(

        self,

        timeout: int = 60,

        banner_timeout: float = 3.0,

    ):

        self.timeout = timeout

        self.banner_timeout = banner_timeout

        self.nmap_path = shutil.which(

            "nmap"

        )

        if not self.nmap_path:

            raise RuntimeError(

                "Nmap was not found."

            )

    # =====================================================

    # CONFIDENCE

    # =====================================================

    @staticmethod

    def _confidence(

        value: Optional[str],

    ) -> str:

        if not value:

            return "unknown"

        try:

            accuracy = int(value)

        except (ValueError, TypeError):

            return "unknown"

        if accuracy >= 90:

            return "high"

        if accuracy >= 60:

            return "medium"

        if accuracy > 0:

            return "low"

        return "unknown"

    # =====================================================

    # COMMAND

    # =====================================================

    def _build_command(

        self,

        host: str,

        ports: list[int],

    ) -> list[str]:

        port_string = ",".join(

            str(port)

            for port in sorted(set(ports))

        )

        return [

            self.nmap_path,

            "-sV",

            "-Pn",

            "-n",

            "-T3",

            "--version-light",

            "--host-timeout",

            f"{self.timeout}s",

            "--max-retries",

            "2",

            "-p",

            port_string,

            "-oX",

            "-",

            host,

        ]

    # =====================================================

    # XML PARSER

    # =====================================================

    def _parse_xml(

        self,

        xml_output: str,

        host: str,

    ) -> list[ServiceResult]:

        root = ET.fromstring(

            xml_output

        )

        results: list[ServiceResult] = []

        for host_node in root.findall(

            "host"

        ):

            ports_node = (

                host_node.find("ports")

            )

            if ports_node is None:

                continue

            for port_node in ports_node.findall(

                "port"

            ):

                protocol = (

                    port_node.get(

                        "protocol",

                        "tcp",

                    )

                )

                port_id = (

                    port_node.get(

                        "portid"

                    )

                )

                if port_id is None:

                    continue

                state_node = (

                    port_node.find("state")

                )

                if state_node is None:

                    continue

                state = state_node.get(

                    "state",

                    "unknown",

                )

                if state != "open":

                    continue

                service_node = (

                    port_node.find("service")

                )

                # -------------------------------------------------

                # No service identification

                # -------------------------------------------------

                if service_node is None:

                    result = ServiceResult(

                        host=host,

                        port=int(port_id),

                        protocol=protocol,

                        state=state,

                    )

                    result.evidence.append(

                        ServiceEvidence(

                            source="service_enum",

                            evidence_type="service",

                            value="unknown",

                        )

                    )

                    results.append(

                        result

                    )

                    continue

                # -------------------------------------------------

                # Service information

                # -------------------------------------------------

                service = (

                    service_node.get(

                        "name"

                    )

                )

                product = (

                    service_node.get(

                        "product"

                    )

                )

                version = (

                    service_node.get(

                        "version"

                    )

                )

                extra_info = (

                    service_node.get(

                        "extrainfo"

                    )

                )

                accuracy = (

                    service_node.get(

                        "conf"

                    )

                )

                confidence = (

                    self._confidence(

                        accuracy

                    )

                )

                result = ServiceResult(

                    host=host,

                    port=int(port_id),

                    protocol=protocol,

                    state=state,

                    service=service,

                    product=product,

                    version=version,

                    extra_info=extra_info,

                    method="nmap-service",

                    confidence=confidence,

                )

                # -------------------------------------------------

                # Evidence

                # -------------------------------------------------

                result.evidence.append(

                    ServiceEvidence(

                        source="service_enum",

                        evidence_type="service",

                        value=(

                            service

                            or "unknown"

                        ),

                    )

                )

                if product:

                    result.evidence.append(

                        ServiceEvidence(

                            source="service_enum",

                            evidence_type="product",

                            value=product,

                        )

                    )

                if version:

                    result.evidence.append(

                        ServiceEvidence(

                            source="service_enum",

                            evidence_type="version",

                            value=version,

                        )

                    )

                if extra_info:

                    result.evidence.append(

                        ServiceEvidence(

                            source="service_enum",

                            evidence_type="extra_info",

                            value=extra_info,

                        )

                    )

                if accuracy:

                    result.evidence.append(

                        ServiceEvidence(

                            source="service_enum",

                            evidence_type="nmap_confidence",

                            value=accuracy,

                        )

                    )

                # -------------------------------------------------

                # Fingerprint

                # -------------------------------------------------

                platform_hint = (

                    self._platform_hint(

                        product,

                        version,

                        extra_info,

                    )

                )

                result.fingerprint = (

                    ServiceFingerprint(

                        service=service,

                        product=product,

                        version=version,

                        platform_hint=platform_hint,

                        confidence=confidence,

                    )

                )

                if platform_hint:

                    result.evidence.append(

                        ServiceEvidence(

                            source="service_enum",

                            evidence_type="platform_hint",

                            value=platform_hint,

                        )

                    )

                results.append(

                    result

                )

        return results

    # =====================================================

    # PLATFORM HINT

    # =====================================================

    @staticmethod

    def _platform_hint(

        product: Optional[str],

        version: Optional[str],

        extra_info: Optional[str],

    ) -> Optional[str]:

        text = " ".join(

            value

            for value in (

                product,

                version,

                extra_info,

            )

            if value

        ).lower()

        hints = [

            "ubuntu",

            "debian",

            "centos",

            "red hat",

            "rhel",

            "fedora",

            "suse",

            "windows",

            "freebsd",

            "openbsd",

            "solaris",

        ]

        for hint in hints:

            if hint in text:

                return hint

        return None

    # =====================================================

    # BANNER HELPERS

    # =====================================================

    @staticmethod

    def _clean_banner(

        data: bytes,

    ) -> Optional[str]:

        if not data:

            return None

        text = data.decode(

            "utf-8",

            errors="replace",

        )

        # Remove control characters while

        # preserving useful printable content.

        text = re.sub(

            r"[**\x00**-**\x08\x0b\x0c\x0e**-**\x1f\x7f**]",

            "",

            text,

        )

        text = text.strip()

        if not text:

            return None

        # Keep banners bounded.

        return text[:4096]

    # =====================================================

    # SAFE BANNER GRAB

    # =====================================================

    def _grab_banner(

        self,

        host: str,

        port: int,

        service: Optional[str],

    ) -> Optional[str]:

        """

        Perform a minimal TCP banner observation.

        This intentionally does NOT authenticate, exploit,

        brute-force, or execute commands.

        Some protocols send a banner immediately after the

        TCP connection. Others require an application request,

        so absence of a banner is not treated as evidence

        that the service is absent.

        """

        sock = socket.socket(

            socket.AF_INET,

            socket.SOCK_STREAM,

        )

        try:

            sock.settimeout(

                self.banner_timeout

            )

            sock.connect(

                (host, port)

            )

            # -------------------------------------------------

            # Passive banner observation

            # -------------------------------------------------

            try:

                data = sock.recv(

                    4096

                )

                banner = (

                    self._clean_banner(

                        data

                    )

                )

                if banner:

                    return banner

            except socket.timeout:

                pass

            # -------------------------------------------------

            # Minimal protocol-specific probes

            # -------------------------------------------------

            service_name = (

                service or ""

            ).lower()

            # HTTP

            if service_name in {

                "http",

                "https",

                "http-proxy",

            }:

                request = (

                    b"HEAD / HTTP/1.0\r\n"

                    b"Host: localhost\r\n"

                    b"Connection: close\r\n"

                    b"\r\n"

                )

                sock.sendall(

                    request

                )

                data = sock.recv(

                    4096

                )

                return self._clean_banner(

                    data

                )

            # FTP / SMTP / POP3 / IMAP

            #

            # These normally send a banner

            # immediately, so we do not need

            # to transmit anything.

            if service_name in {

                "ftp",

                "smtp",

                "pop3",

                "imap",

                "imap4",

            }:

                return None

            return None

        except (

            socket.timeout,

            ConnectionRefusedError,

            ConnectionResetError,

            BrokenPipeError,

            OSError,

        ):

            return None

        finally:

            try:

                sock.close()

            except OSError:

                pass

    # =====================================================

    # ADD BANNER

    # =====================================================

    def _add_banner(

        self,

        result: ServiceResult,

    ):

        try:

            banner = self._grab_banner(

                result.host,

                result.port,

                result.service,

            )

        except Exception as error:

            result.evidence.append(

                ServiceEvidence(

                    source="banner_grabber",

                    evidence_type="error",

                    value=str(error),

                )

            )

            return

        if not banner:

            return

        result.banner = banner

        result.evidence.append(

            ServiceEvidence(

                source="banner_grabber",

                evidence_type="banner",

                value=banner,

            )

        )

    # =====================================================

    # ONE HOST

    # =====================================================

    def enumerate_host(

        self,

        host: str,

        ports: list[int],

    ) -> list[ServiceResult]:

        if not ports:

            return []

        command = self._build_command(

            host,

            ports,

        )

        try:

            process = subprocess.run(

                command,

                capture_output=True,

                text=True,

                timeout=self.timeout + 10,

            )

        except subprocess.TimeoutExpired as error:

            raise RuntimeError(

                f"Service enumeration timed out "

                f"for {host} "

                f"after {self.timeout + 10}s"

            ) from error

        if process.returncode != 0:

            stderr = (

                process.stderr.strip()

            )

            raise RuntimeError(

                "Nmap service enumeration failed"

                + (

                    f": {stderr}"

                    if stderr

                    else ""

                )

            )

        try:

            results = self._parse_xml(

                process.stdout,

                host,

            )

        except ET.ParseError as error:

            raise RuntimeError(

                "Unable to parse Nmap service "

                "enumeration XML"

            ) from error

        # -------------------------------------------------

        # Banner collection

        #

        # Supplemental evidence only.

        # Missing banner != missing service.

        # -------------------------------------------------

        for result in results:

            self._add_banner(

                result

            )

        return results

    # =====================================================

    # MULTI-HOST

    # =====================================================

    def enumerate_ports(
        self,
        port_results,
    ) -> list[ServiceResult]:
        """
        Enumerate confirmed-open TCP services while preserving every
        confirmed-open endpoint for downstream analysis.

        UDP endpoints are not subjected to a second UDP scan here.
        The port scanner already established confirmed UDP reachability.
        Known UDP services receive low-confidence port-based hints so
        the pipeline does not silently discard UDP exposure.
        """

        open_results = [
            result
            for result in port_results
            if str(getattr(result, "state", "")).lower() == "open"
        ]

        tcp_ports_by_host: dict[str, list[int]] = {}

        for result in open_results:
            protocol = str(
                getattr(result, "protocol", "tcp")
                or "tcp"
            ).lower()

            if protocol != "tcp":
                continue

            host = str(
                getattr(result, "host", "")
                or ""
            )

            if host:
                tcp_ports_by_host.setdefault(
                    host,
                    [],
                ).append(int(result.port))

        all_results: list[ServiceResult] = []

        # TCP service fingerprinting remains the existing Nmap path.
        for host, ports in tcp_ports_by_host.items():
            results = self.enumerate_host(
                host,
                sorted(set(ports)),
            )
            all_results.extend(results)

        # Preserve every confirmed-open endpoint that Nmap service
        # enumeration did not return. This prevents analysis loss while
        # keeping the distinction between fingerprinted and inferred data.
        existing = {
            (
                result.host,
                int(result.port),
                str(result.protocol).lower(),
            )
            for result in all_results
        }

        for port_result in open_results:
            host = str(
                getattr(port_result, "host", "")
                or ""
            )
            port = int(port_result.port)
            protocol = str(
                getattr(port_result, "protocol", "tcp")
                or "tcp"
            ).lower()

            key = (host, port, protocol)
            if key in existing:
                continue

            service_hint = PORT_SERVICE_HINTS.get(
                (protocol, port)
            )

            evidence = [
                ServiceEvidence(
                    source="port_scanner",
                    evidence_type="open_port",
                    value=(
                        f"{host}:{port}/{protocol} is confirmed open"
                    ),
                )
            ]

            if service_hint:
                evidence.append(
                    ServiceEvidence(
                        source="service_enum",
                        evidence_type="port_based_inference",
                        value=(
                            f"Port {port}/{protocol} commonly maps to "
                            f"{service_hint}; low-confidence service hint."
                        ),
                    )
                )

            result = ServiceResult(
                host=host,
                port=port,
                protocol=protocol,
                state="open",
                service=service_hint,
                method=(
                    "port-inference"
                    if service_hint
                    else "port-presence"
                ),
                confidence=(
                    "low"
                    if service_hint
                    else "unknown"
                ),
                evidence=evidence,
            )

            if service_hint:
                result.fingerprint = ServiceFingerprint(
                    service=service_hint,
                    confidence="low",
                )

            all_results.append(result)
            existing.add(key)

        return sorted(
            all_results,
            key=lambda item: (
                item.host,
                str(item.protocol).lower(),
                int(item.port),
            ),
        )
