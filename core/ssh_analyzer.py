from typing import Optional
import re
import socket

import nmap
from pydantic import BaseModel, Field


class SSHEvidence(BaseModel):
    source: str
    evidence_type: str
    value: str


class SSHResult(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"

    ssh_detected: bool = False
    protocol_version: Optional[str] = None
    banner: Optional[str] = None

    software: Optional[str] = None
    version: Optional[str] = None

    key_exchange_algorithms: list[str] = Field(default_factory=list)
    host_key_algorithms: list[str] = Field(default_factory=list)
    ciphers: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    compression_algorithms: list[str] = Field(default_factory=list)

    legacy_algorithms: list[str] = Field(default_factory=list)

    handshake_error: Optional[str] = None
    enumeration_error: Optional[str] = None

    evidence: list[SSHEvidence] = Field(default_factory=list)


class SSHAnalyzer:
    """
    Safe SSH security analysis.

    This analyzer performs only pre-authentication inspection.
    It does not attempt authentication or execute commands.
    """

    SSH_PORTS = {
        22,
        2222,
        2200,
    }

    # These are observations we want to surface for later analysis.
    # They are not severity decisions.
    LEGACY_PATTERNS = (
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
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
        "rijndael-cbc",
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1",
        "hmac-sha1-96",
    )

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.nm = nmap.PortScanner()

    # =========================================================
    # SSH BANNER
    # =========================================================

    def grab_banner(
        self,
        host: str,
        port: int,
    ) -> tuple[Optional[str], Optional[str]]:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(self.timeout)

        try:
            sock.connect((host, port))

            data = b""

            while b"\n" not in data and len(data) < 4096:
                chunk = sock.recv(512)

                if not chunk:
                    break

                data += chunk

            if not data:
                return None, None

            text = data.decode(
                "utf-8",
                errors="replace",
            )

            for line in text.splitlines():
                line = line.strip()

                if line.startswith("SSH-"):
                    return line, None

            return None, None

        except socket.timeout as exc:
            return None, str(exc)

        except (
            ConnectionRefusedError,
            OSError,
        ) as exc:
            return None, str(exc)

        finally:
            sock.close()

    # =========================================================
    # BANNER PARSING
    # =========================================================

    def parse_banner(
        self,
        banner: str,
    ) -> tuple[
        Optional[str],
        Optional[str],
        Optional[str],
    ]:

        if not banner:
            return None, None, None

        match = re.match(
            r"^SSH-(?P<protocol>[^-]+)-(?P<software>[^ \r\n]+)",
            banner,
        )

        if not match:
            return None, None, None

        protocol_version = match.group("protocol")
        software_field = match.group("software")

        software = software_field
        version = None

        # Example:
        # OpenSSH_4.7p1
        openssh_match = re.match(
            r"^(OpenSSH)_(.+)$",
            software_field,
            re.IGNORECASE,
        )

        if openssh_match:
            software = openssh_match.group(1)
            version = openssh_match.group(2)

        else:
            generic_match = re.match(
                r"^([A-Za-z0-9._+-]+?)[_-]"
                r"([0-9][A-Za-z0-9._+-]*)$",
                software_field,
            )

            if generic_match:
                software = generic_match.group(1)
                version = generic_match.group(2)

        return (
            protocol_version,
            software,
            version,
        )

    # =========================================================
    # NMAP SSH ENUMERATION
    # =========================================================

    def enumerate_algorithms(
        self,
        host: str,
        port: int,
    ) -> tuple[
        dict[str, list[str]],
        Optional[str],
    ]:

        results = {
            "key_exchange_algorithms": [],
            "host_key_algorithms": [],
            "ciphers": [],
            "macs": [],
            "compression_algorithms": [],
        }

        try:
            arguments = (
                f"-Pn -p {port} "
                "--script ssh2-enum-algos "
                "-T3"
            )

            self.nm.scan(
                hosts=host,
                arguments=arguments,
            )

            if host not in self.nm.all_hosts():
                return results, "Nmap returned no host data"

            host_data = self.nm[host]

            if "tcp" not in host_data:
                return results, "Nmap returned no TCP data"

            if port not in host_data["tcp"]:
                return results, "Nmap returned no SSH port data"

            port_data = host_data["tcp"][port]

            script_data = port_data.get(
                "script",
                {},
            )

            raw_output = script_data.get(
                "ssh2-enum-algos"
            )

            if not raw_output:
                return (
                    results,
                    "Nmap ssh2-enum-algos returned no output",
                )

            self._parse_nmap_algorithm_output(
                raw_output,
                results,
            )

            total_algorithms = sum(
                len(values)
                for values in results.values()
            )

            if total_algorithms == 0:
                return (
                    results,
                    "Nmap returned SSH enumeration output "
                    "but no algorithms were parsed",
                )

            return results, None

        except nmap.PortScannerError as exc:
            return results, f"Nmap error: {exc}"

        except (
            KeyError,
            ValueError,
            OSError,
        ) as exc:
            return results, f"Enumeration error: {exc}"

    # =========================================================
    # NMAP OUTPUT PARSER
    # =========================================================

    def _parse_nmap_algorithm_output(
        self,
        output: str,
        results: dict[str, list[str]],
    ) -> None:

        current_category: Optional[str] = None

        category_map = {
            "kex_algorithms": "key_exchange_algorithms",
            "server_host_key_algorithms": "host_key_algorithms",
            "encryption_algorithms": "ciphers",
            "mac_algorithms": "macs",
            "compression_algorithms": "compression_algorithms",
        }

        for raw_line in output.splitlines():

            line = raw_line.strip()

            if not line:
                continue

            # -------------------------------------------------
            # Section headers
            #
            # Examples:
            #
            # kex_algorithms: (4)
            # server_host_key_algorithms: (2)
            # encryption_algorithms: (13)
            # -------------------------------------------------

            section_match = re.match(
                r"^([a-zA-Z0-9_]+):\s*(?:\(\d+\))?$",
                line,
            )

            if section_match:

                section_name = (
                    section_match.group(1).lower()
                )

                current_category = category_map.get(
                    section_name
                )

                continue

            if current_category is None:
                continue

            # -------------------------------------------------
            # Ignore Nmap metadata
            # -------------------------------------------------

            if ":" in line:
                continue

            # -------------------------------------------------
            # Normalize algorithm line
            # -------------------------------------------------

            algorithm = line.lstrip(
                "-• "
            ).strip()

            if not algorithm:
                continue

            # Nmap algorithm names are generally represented
            # as a single token.
            #
            # Ignore obvious formatting artifacts.
            if not re.match(
                r"^[A-Za-z0-9@._+:-]+$",
                algorithm,
            ):
                continue

            if algorithm not in results[current_category]:
                results[current_category].append(
                    algorithm
                )

    # =========================================================
    # LEGACY ALGORITHM DETECTION
    # =========================================================

    def find_legacy_algorithms(
        self,
        algorithms: dict[str, list[str]],
    ) -> list[str]:

        found = []

        all_algorithms = []

        for values in algorithms.values():
            all_algorithms.extend(values)

        for algorithm in all_algorithms:

            normalized = algorithm.lower()

            for pattern in self.LEGACY_PATTERNS:

                if pattern in normalized:

                    if algorithm not in found:
                        found.append(algorithm)

                    break

        return found

    # =========================================================
    # FULL SSH ENDPOINT ANALYSIS
    # =========================================================

    def analyze_port(
        self,
        host: str,
        port: int,
    ) -> Optional[SSHResult]:

        result = SSHResult(
            host=host,
            port=port,
        )

        # -----------------------------------------------------
        # Banner
        # -----------------------------------------------------

        banner, banner_error = self.grab_banner(
            host,
            port,
        )

        if banner:

            result.banner = banner
            result.ssh_detected = True

            result.evidence.append(
                SSHEvidence(
                    source="ssh_analyzer",
                    evidence_type="banner",
                    value=banner,
                )
            )

            (
                result.protocol_version,
                result.software,
                result.version,
            ) = self.parse_banner(banner)

            if result.protocol_version:

                result.evidence.append(
                    SSHEvidence(
                        source="ssh_analyzer",
                        evidence_type="protocol_version",
                        value=result.protocol_version,
                    )
                )

            if result.software:

                result.evidence.append(
                    SSHEvidence(
                        source="ssh_analyzer",
                        evidence_type="software",
                        value=result.software,
                    )
                )

            if result.version:

                result.evidence.append(
                    SSHEvidence(
                        source="ssh_analyzer",
                        evidence_type="version",
                        value=result.version,
                    )
                )

        elif banner_error:

            result.handshake_error = banner_error

            result.evidence.append(
                SSHEvidence(
                    source="ssh_analyzer",
                    evidence_type="banner_error",
                    value=banner_error,
                )
            )

        # -----------------------------------------------------
        # Algorithm enumeration
        # -----------------------------------------------------

        (
            algorithms,
            enumeration_error,
        ) = self.enumerate_algorithms(
            host,
            port,
        )

        result.enumeration_error = enumeration_error

        # -----------------------------------------------------
        # Store algorithm lists
        # -----------------------------------------------------

        result.key_exchange_algorithms = algorithms[
            "key_exchange_algorithms"
        ]

        result.host_key_algorithms = algorithms[
            "host_key_algorithms"
        ]

        result.ciphers = algorithms[
            "ciphers"
        ]

        result.macs = algorithms[
            "macs"
        ]

        result.compression_algorithms = algorithms[
            "compression_algorithms"
        ]

        # -----------------------------------------------------
        # Evidence
        # -----------------------------------------------------

        for algorithm in result.key_exchange_algorithms:

            result.evidence.append(
                SSHEvidence(
                    source="nmap",
                    evidence_type="kex_algorithm",
                    value=algorithm,
                )
            )

        for algorithm in result.host_key_algorithms:

            result.evidence.append(
                SSHEvidence(
                    source="nmap",
                    evidence_type="host_key_algorithm",
                    value=algorithm,
                )
            )

        for algorithm in result.ciphers:

            result.evidence.append(
                SSHEvidence(
                    source="nmap",
                    evidence_type="cipher",
                    value=algorithm,
                )
            )

        for algorithm in result.macs:

            result.evidence.append(
                SSHEvidence(
                    source="nmap",
                    evidence_type="mac",
                    value=algorithm,
                )
            )

        for algorithm in result.compression_algorithms:

            result.evidence.append(
                SSHEvidence(
                    source="nmap",
                    evidence_type="compression_algorithm",
                    value=algorithm,
                )
            )

        # -----------------------------------------------------
        # Enumeration error evidence
        # -----------------------------------------------------

        if result.enumeration_error:

            result.evidence.append(
                SSHEvidence(
                    source="ssh_analyzer",
                    evidence_type="enumeration_error",
                    value=result.enumeration_error,
                )
            )

        # -----------------------------------------------------
        # Legacy algorithms
        # -----------------------------------------------------

        result.legacy_algorithms = (
            self.find_legacy_algorithms(
                algorithms
            )
        )

        for algorithm in result.legacy_algorithms:

            result.evidence.append(
                SSHEvidence(
                    source="ssh_analyzer",
                    evidence_type="legacy_algorithm",
                    value=algorithm,
                )
            )

        return result

    # =========================================================
    # MULTIPLE ENDPOINTS
    # =========================================================

    def analyze_ports(
        self,
        port_results,
    ) -> list[SSHResult]:

        results: list[SSHResult] = []

        seen = set()

        for port_result in port_results:

            if port_result.state != "open":
                continue

            if port_result.protocol.lower() != "tcp":
                continue

            service = getattr(
                port_result,
                "service",
                None,
            )

            port = port_result.port
            host = port_result.host

            is_ssh = (
                port in self.SSH_PORTS
                or (
                    service
                    and "ssh" in service.lower()
                )
            )

            if not is_ssh:
                continue

            key = (
                host,
                port,
            )

            if key in seen:
                continue

            seen.add(key)

            result = self.analyze_port(
                host,
                port,
            )

            if result:
                results.append(result)

        return results