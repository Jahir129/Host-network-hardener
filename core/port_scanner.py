import os
import pwd
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from pydantic import BaseModel


class PortResult(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    state: str
    method: str
    engine: str
    reason: Optional[str] = None

    # Evidence provenance
    discovered_by: Optional[str] = None
    verified_by: Optional[str] = None


class PortScanner:
    """
    Agent-level port scanning interface.

    User-facing profiles:

        quick:
            RustScan TCP 1-65535
                ->
            Nmap TCP verification
                +
            Nmap UDP top 50

        normal:
            Nmap TCP top 1000
                +
            Nmap UDP top 50

        full:
            Masscan TCP 1-65535
                ->
            Nmap TCP verification
                +
            Nmap UDP 1-65535

    The user never chooses TCP/UDP or a scanning engine directly.
    """

    VALID_PROFILES = {
        "quick",
        "normal",
        "full",
    }

    # Profile-specific port coverage.
    QUICK_UDP = "top:50"
    NORMAL_TCP = "top:1000"
    NORMAL_UDP = "top:50"
    FULL_TCP = "1-65535"
    FULL_UDP = "1-65535"

    def __init__(
        self,
        profile="normal",
        max_rate=100,
        nmap_timeout=300,
        rustscan_timeout_ms=1500,
    ):
        if profile not in self.VALID_PROFILES:
            raise ValueError(
                f"Unsupported scan profile: {profile}. "
                f"Choose from: {sorted(self.VALID_PROFILES)}"
            )

        self.profile = profile
        self.max_rate = max_rate
        self.nmap_timeout = nmap_timeout
        self.rustscan_timeout_ms = rustscan_timeout_ms

        self.nmap_path = self._find_tool("nmap")

        if self.nmap_path is None:
            raise RuntimeError(
                "Nmap was not found. "
                "Install it with: sudo apt install nmap"
            )

        self.rustscan_path = self._find_tool("rustscan")
        self.masscan_path = self._find_tool("masscan")

    # =========================================================
    # TOOL DISCOVERY
    # =========================================================

    @staticmethod
    def _find_tool(tool):
        """
        Find an executable.

        When running through sudo, also check the original user's
        home directory. This is useful for RustScan installed under
        ~/.cargo/bin.
        """

        path = shutil.which(tool)

        if path:
            return path

        possible_homes = []

        sudo_user = os.environ.get("SUDO_USER")

        if sudo_user:
            try:
                sudo_home = pwd.getpwnam(sudo_user).pw_dir
                possible_homes.append(sudo_home)
            except KeyError:
                pass

        possible_homes.append(os.path.expanduser("~"))

        possible_paths = []

        for home in possible_homes:
            possible_paths.extend(
                [
                    os.path.join(home, ".cargo", "bin", tool),
                    os.path.join(home, ".local", "bin", tool),
                ]
            )

        possible_paths.extend(
            [
                f"/usr/local/bin/{tool}",
                f"/usr/bin/{tool}",
                f"/bin/{tool}",
            ]
        )

        checked = set()

        for candidate in possible_paths:
            if candidate in checked:
                continue

            checked.add(candidate)

            if os.path.isfile(candidate) and os.access(
                candidate,
                os.X_OK,
            ):
                return candidate

        return None

    # =========================================================
    # PROFILE INFORMATION
    # =========================================================

    def print_profile(self):
        print("\n" + "=" * 60)
        print("PORT SCAN PROFILE")
        print("=" * 60)

        if self.profile == "quick":
            print("Profile : QUICK")
            print("TCP     : RustScan 1-65535")
            print("Verify  : Nmap TCP candidates")
            print("UDP     : Nmap top 50")

        elif self.profile == "normal":
            print("Profile : NORMAL")
            print("TCP     : Nmap top 1000")
            print("UDP     : Nmap top 50")

        elif self.profile == "full":
            print("Profile : FULL")
            print("TCP     : Masscan 1-65535")
            print("Verify  : Nmap TCP candidates")
            print("UDP     : Nmap 1-65535")

        print("=" * 60)

    # =========================================================
    # NMAP COMMAND BUILDING
    # =========================================================

    def _build_nmap_command(
        self,
        host,
        method,
        port_spec,
    ):
        """
        Build a single-protocol Nmap command.

        We intentionally run TCP and UDP separately.

        This gives us:
        - simpler XML parsing
        - independent timing
        - clearer Wireshark observations
        - better error handling
        """

        if method == "syn":
            scan_flag = "-sS"

        elif method == "connect":
            scan_flag = "-sT"

        elif method == "udp":
            scan_flag = "-sU"

        else:
            raise ValueError(
                f"Unsupported Nmap method: {method}"
            )

        command = [
            self.nmap_path,
            scan_flag,
            "-n",
            "-Pn",
            "-T3",
            "--reason",
            "--max-rate",
            str(self.max_rate),
            "--max-retries",
            "1",
            "--host-timeout",
            f"{self.nmap_timeout}s",
        ]

        if port_spec.startswith("top:"):
            top_ports = port_spec.split(":", 1)[1]

            command.extend(
                [
                    "--top-ports",
                    top_ports,
                ]
            )

        else:
            command.extend(
                [
                    "-p",
                    port_spec,
                ]
            )

        command.extend(
            [
                "-oX",
                "-",
                host,
            ]
        )

        return command

    # =========================================================
    # NMAP XML PARSER
    # =========================================================

    def _parse_nmap_xml(
        self,
        xml_output,
        host,
        method,
        discovered_by="nmap",
        verified_by="nmap",
    ):
        results = []

        if not xml_output.strip():
            return results

        root = ET.fromstring(xml_output)

        for host_node in root.findall("host"):

            ports_node = host_node.find("ports")

            if ports_node is None:
                continue

            for port_node in ports_node.findall("port"):

                protocol = port_node.get(
                    "protocol",
                    "tcp",
                )

                port_id = port_node.get("portid")

                state_node = port_node.find("state")

                if port_id is None or state_node is None:
                    continue

                state = state_node.get(
                    "state",
                    "unknown",
                )

                reason = state_node.get("reason")

                results.append(
                    PortResult(
                        host=host,
                        port=int(port_id),
                        protocol=protocol,
                        state=state,
                        method=method,
                        engine="nmap",
                        reason=reason,
                        discovered_by=discovered_by,
                        verified_by=verified_by,
                    )
                )

        return results

    # =========================================================
    # NMAP SCANNING
    # =========================================================

    def scan_nmap(
        self,
        host,
        method,
        port_spec,
        discovered_by="nmap",
        verified_by="nmap",
    ):
        command = self._build_nmap_command(
            host,
            method,
            port_spec,
        )

        print("\n" + "-" * 60)
        print(f"Scanning host : {host}")
        print("Engine        : NMAP")
        print(f"Method        : {method.upper()}")
        print(f"Ports         : {port_spec}")

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.nmap_timeout + 30,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Nmap {method} scan timed out while scanning {host}"
            ) from exc

        if process.returncode != 0:
            error = process.stderr.strip()

            raise RuntimeError(
                f"Nmap {method} scan failed: {error}"
            )

        results = self._parse_nmap_xml(
            process.stdout,
            host,
            method,
            discovered_by=discovered_by,
            verified_by=verified_by,
        )

        open_results = [
            result
            for result in results
            if result.state == "open"
        ]

        print(
            f"Nmap results : {len(results)}"
        )

        print(
            f"Open ports   : {len(open_results)}"
        )

        return results

    # =========================================================
    # TCP METHOD
    # =========================================================

    @staticmethod
    def _tcp_method():
        """
        Prefer SYN when running as root.

        Otherwise use TCP Connect.
        """

        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return "syn"

        return "connect"

    # =========================================================
    # RUSTSCAN
    # =========================================================

    def _build_rustscan_command(self, host):
        if self.rustscan_path is None:
            raise RuntimeError(
                "RustScan was not found."
            )

        return [
            self.rustscan_path,
            "-a",
            host,
            "--range",
            "1-65535",
            "--ulimit",
            "5000",
            "--batch-size",
            "1000",
            "--timeout",
            str(self.rustscan_timeout_ms),
        ]

    def _parse_rustscan_output(
        self,
        output,
        host,
    ):
        results = []

        patterns = [
            re.compile(
                rf"Open {re.escape(host)}:(\d+)"
            ),
            re.compile(
                rf"{re.escape(host)} -> (\d+)"
            ),
        ]

        found_ports = set()

        for pattern in patterns:

            for match in pattern.finditer(output):

                port = int(match.group(1))

                if port in found_ports:
                    continue

                found_ports.add(port)

                results.append(
                    PortResult(
                        host=host,
                        port=port,
                        protocol="tcp",
                        state="open",
                        method="tcp",
                        engine="rustscan",
                        reason="rustscan-open",
                        discovered_by="rustscan",
                        verified_by=None,
                    )
                )

        return results

    def scan_rustscan(self, host):

        if self.rustscan_path is None:
            raise RuntimeError(
                "RustScan was not found. "
                "Install RustScan or choose Normal Scan."
            )

        command = self._build_rustscan_command(host)

        print("\n" + "-" * 60)
        print(f"Scanning host : {host}")
        print("Engine        : RUSTSCAN")
        print("Protocol      : TCP")
        print("Ports         : 1-65535")
        print(
            f"Timeout       : "
            f"{self.rustscan_timeout_ms} ms"
        )

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"RustScan timed out while scanning {host}"
            ) from exc

        if process.returncode != 0:
            error = process.stderr.strip()

            raise RuntimeError(
                f"RustScan failed: {error}"
            )

        results = self._parse_rustscan_output(
            process.stdout,
            host,
        )

        print(
            f"RustScan candidates: {len(results)}"
        )

        return results

    # =========================================================
    # MASSCAN
    # =========================================================

    def _build_masscan_command(self, host):

        if self.masscan_path is None:
            raise RuntimeError(
                "Masscan was not found. "
                "Install Masscan or choose another profile."
            )

        return [
            self.masscan_path,
            host,
            "-p",
            "1-65535",
            "--rate",
            str(self.max_rate),
            "--wait",
            "2",
        ]

    def _parse_masscan_output(
        self,
        output,
        host,
    ):
        results = []

        pattern = re.compile(
            r"Discovered open port (\d+)/tcp"
        )

        found_ports = set()

        for match in pattern.finditer(output):

            port = int(match.group(1))

            if port in found_ports:
                continue

            found_ports.add(port)

            results.append(
                PortResult(
                    host=host,
                    port=port,
                    protocol="tcp",
                    state="open",
                    method="tcp",
                    engine="masscan",
                    reason="masscan-open",
                    discovered_by="masscan",
                    verified_by=None,
                )
            )

        return results

    def scan_masscan(self, host):

        if self.masscan_path is None:
            raise RuntimeError(
                "Masscan was not found. "
                "Install Masscan or choose another profile."
            )

        command = self._build_masscan_command(host)

        print("\n" + "-" * 60)
        print(f"Scanning host : {host}")
        print("Engine        : MASSCAN")
        print("Protocol      : TCP")
        print("Ports         : 1-65535")
        print(
            f"Rate          : "
            f"{self.max_rate} packets/sec"
        )

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=900,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Masscan timed out while scanning {host}"
            ) from exc

        if process.returncode != 0:
            error = process.stderr.strip()

            raise RuntimeError(
                f"Masscan failed: {error}"
            )

        results = self._parse_masscan_output(
            process.stdout,
            host,
        )

        print(
            f"Masscan candidates: {len(results)}"
        )

        return results

    # =========================================================
    # NMAP TCP VERIFICATION
    # =========================================================

    def verify_with_nmap(
        self,
        host,
        candidate_results,
    ):
        """
        Verify TCP candidates from RustScan or Masscan.

        Only discovered candidate ports are passed to Nmap.
        """

        tcp_ports = sorted(
            {
                result.port
                for result in candidate_results
                if result.protocol == "tcp"
            }
        )

        if not tcp_ports:
            print(
                "\nNo TCP candidates found."
            )

            return []

        port_string = ",".join(
            str(port)
            for port in tcp_ports
        )

        discovery_engine = (
            candidate_results[0].engine
        )

        tcp_method = self._tcp_method()

        print("\n" + "=" * 60)
        print("              NMAP TCP VERIFICATION")
        print("=" * 60)

        print(
            f"Discovery engine : "
            f"{discovery_engine.upper()}"
        )

        print(
            f"Candidate ports  : "
            f"{port_string}"
        )

        print(
            f"Verification     : "
            f"Nmap {tcp_method.upper()}"
        )

        return self.scan_nmap(
            host,
            tcp_method,
            port_string,
            discovered_by=discovery_engine,
            verified_by="nmap",
        )

    # =========================================================
    # PROFILE: QUICK
    # =========================================================

    def scan_quick(self, host):

        print("\n" + "=" * 60)
        print("                  QUICK SCAN")
        print("=" * 60)

        # -----------------------------------------
        # TCP: RustScan discovery
        # -----------------------------------------

        candidates = self.scan_rustscan(host)

        print("\nRustScan candidates:")

        if candidates:

            for result in sorted(
                candidates,
                key=lambda item: item.port,
            ):
                print(
                    f"  {result.port}/tcp open"
                )

        else:
            print(
                "  No TCP candidates found."
            )

        # -----------------------------------------
        # TCP: Nmap verification
        # -----------------------------------------

        tcp_results = self.verify_with_nmap(
            host,
            candidates,
        )

        # -----------------------------------------
        # UDP: common ports only
        # -----------------------------------------

        udp_results = self.scan_nmap(
            host,
            "udp",
            self.QUICK_UDP,
        )

        return tcp_results + udp_results

    # =========================================================
    # PROFILE: NORMAL
    # =========================================================

    def scan_normal(self, host):

        print("\n" + "=" * 60)
        print("                 NORMAL SCAN")
        print("=" * 60)

        # -----------------------------------------
        # TCP
        # -----------------------------------------

        tcp_results = self.scan_nmap(
            host,
            self._tcp_method(),
            self.NORMAL_TCP,
        )

        # -----------------------------------------
        # UDP
        # -----------------------------------------

        udp_results = self.scan_nmap(
            host,
            "udp",
            self.NORMAL_UDP,
        )

        return tcp_results + udp_results

    # =========================================================
    # PROFILE: FULL
    # =========================================================

    def scan_full(self, host):

        print("\n" + "=" * 60)
        print("                   FULL SCAN")
        print("=" * 60)

        # -----------------------------------------
        # TCP: Masscan discovery
        # -----------------------------------------

        candidates = self.scan_masscan(host)

        print("\nMasscan candidates:")

        if candidates:

            for result in sorted(
                candidates,
                key=lambda item: item.port,
            ):
                print(
                    f"  {result.port}/tcp open"
                )

        else:
            print(
                "  No TCP candidates found."
            )

        # -----------------------------------------
        # TCP: Nmap verification
        # -----------------------------------------

        tcp_results = self.verify_with_nmap(
            host,
            candidates,
        )

        # -----------------------------------------
        # UDP: full range
        # -----------------------------------------

        udp_results = self.scan_nmap(
            host,
            "udp",
            self.FULL_UDP,
        )

        return tcp_results + udp_results

    # =========================================================
    # HIGH-LEVEL DISPATCH
    # =========================================================

    def scan_host(self, host):

        if self.profile == "quick":
            return self.scan_quick(host)

        if self.profile == "normal":
            return self.scan_normal(host)

        if self.profile == "full":
            return self.scan_full(host)

        raise ValueError(
            f"Unsupported profile: {self.profile}"
        )

    def scan_hosts(self, hosts):

        all_results = []

        for host in hosts:

            results = self.scan_host(host)

            all_results.extend(results)

        return self.unique_ports(
            all_results
        )

    # =========================================================
    # RESULT HELPERS
    # =========================================================

    @staticmethod
    def open_ports(results):

        return [
            result
            for result in results
            if result.state == "open"
        ]

    @staticmethod
    def unique_ports(results):

        unique = {}

        for result in results:

            key = (
                result.host,
                result.protocol,
                result.port,
            )

            unique[key] = result

        return list(
            unique.values()
        )

    @staticmethod
    def print_summary(results):

        results = sorted(
            results,
            key=lambda result: (
                result.host,
                result.protocol,
                result.port,
            ),
        )

        print("\n" + "=" * 75)
        print("                 PORT SCAN RESULTS")
        print("=" * 75)

        if not results:
            print("\nNo port results found.")
            return

        for result in results:

            print(
                f"{result.host:<16} "
                f"{result.port:>5}/"
                f"{result.protocol:<3} "
                f"{result.state:<12} "
                f"engine={result.engine:<8} "
                f"method={result.method:<7} "
                f"discovered_by="
                f"{result.discovered_by or '-':<9} "
                f"verified_by="
                f"{result.verified_by or '-'}"
            )

        open_results = PortScanner.open_ports(
            results
        )

        tcp_open = [
            result
            for result in open_results
            if result.protocol == "tcp"
        ]

        udp_open = [
            result
            for result in open_results
            if result.protocol == "udp"
        ]

        print("\n" + "-" * 75)

        print(
            f"Total results : "
            f"{len(results)}"
        )

        print(
            f"Open ports    : "
            f"{len(open_results)}"
        )

        print(
            f"Open TCP      : "
            f"{len(tcp_open)}"
        )

        print(
            f"Open UDP      : "
            f"{len(udp_open)}"
        )

        print("=" * 75)


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    scanner = PortScanner(
        profile="normal",
        max_rate=100,
        nmap_timeout=300,
    )

    scanner.print_profile()

    target = "192.168.56.129"

    results = scanner.scan_host(
        target
    )

    scanner.print_summary(
        results
    )