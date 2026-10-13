import platform
import socket
import subprocess
import time
from enum import Enum
from typing import Optional

from core.rate_limit import RateLimiter


# ==========================================
# ENUMS
# ==========================================

class DiscoveryStatus(str, Enum):
    ALIVE = "alive"
    DOWN = "down"
    UNKNOWN = "unknown"


class DiscoveryMethod(str, Enum):
    ICMP = "icmp"
    ARP = "arp"
    TCP = "tcp"


class TCPMethod(str, Enum):
    SYN = "syn"
    CONNECT = "connect"


# ==========================================
# EVIDENCE MODEL
# ==========================================

class DiscoveryEvidence:

    def __init__(
        self,
        method: DiscoveryMethod,
        status: DiscoveryStatus,
        response_time_ms: Optional[float] = None,
        mac_address: Optional[str] = None,
        port: Optional[int] = None,
        tcp_method: Optional[TCPMethod] = None,
    ):
        self.method = method
        self.status = status
        self.response_time_ms = response_time_ms
        self.mac_address = mac_address
        self.port = port
        self.tcp_method = tcp_method


# ==========================================
# DISCOVERY RESULT
# ==========================================

class DiscoveryResult:

    def __init__(
        self,
        target: str,
        status: DiscoveryStatus,
        evidence: list[DiscoveryEvidence],
    ):
        self.target = target
        self.status = status
        self.evidence = evidence


# ==========================================
# ICMP DISCOVERY
# ==========================================

def icmp_discovery(
    target: str,
    timeout: float = 1.0,
) -> DiscoveryEvidence:

    start = time.monotonic()

    try:

        result = subprocess.run(
            [
                "ping",
                "-c",
                "1",
                "-W",
                str(int(timeout)),
                target,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        elapsed = (
            time.monotonic() - start
        ) * 1000

        if result.returncode == 0:

            return DiscoveryEvidence(
                method=DiscoveryMethod.ICMP,
                status=DiscoveryStatus.ALIVE,
                response_time_ms=round(
                    elapsed,
                    2,
                ),
            )

        return DiscoveryEvidence(
            method=DiscoveryMethod.ICMP,
            status=DiscoveryStatus.DOWN,
        )

    except Exception:

        return DiscoveryEvidence(
            method=DiscoveryMethod.ICMP,
            status=DiscoveryStatus.UNKNOWN,
        )


# ==========================================
# ARP / NEIGHBOR DISCOVERY
# ==========================================

def arp_discovery(
    target: str,
) -> DiscoveryEvidence:

    try:

        system = platform.system().lower()

        if system == "linux":

            result = subprocess.run(
                [
                    "ip",
                    "neigh",
                    "show",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=2,
            )

            output = result.stdout.strip()

            if output:

                parts = output.split()

                for i, part in enumerate(parts):

                    if part.upper() == "lladdr":
                        if i + 1 < len(parts):

                            mac = parts[i + 1]

                            return DiscoveryEvidence(
                                method=DiscoveryMethod.ARP,
                                status=DiscoveryStatus.ALIVE,
                                mac_address=mac,
                            )

        return DiscoveryEvidence(
            method=DiscoveryMethod.ARP,
            status=DiscoveryStatus.UNKNOWN,
        )

    except Exception:

        return DiscoveryEvidence(
            method=DiscoveryMethod.ARP,
            status=DiscoveryStatus.UNKNOWN,
        )


# ==========================================
# TCP SYN DISCOVERY
# ==========================================

def tcp_syn_discovery(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> DiscoveryEvidence:

    try:

        from scapy.all import IP, TCP, sr1

        start = time.monotonic()

        packet = IP(dst=target) / TCP(
            dport=port,
            flags="S",
        )

        response = sr1(
            packet,
            timeout=timeout,
            verbose=0,
        )

        elapsed = (
            time.monotonic() - start
        ) * 1000

        if response is None:

            return DiscoveryEvidence(
                method=DiscoveryMethod.TCP,
                status=DiscoveryStatus.UNKNOWN,
                tcp_method=TCPMethod.SYN,
            )

        tcp_layer = response.getlayer(TCP)

        if tcp_layer is None:

            return DiscoveryEvidence(
                method=DiscoveryMethod.TCP,
                status=DiscoveryStatus.UNKNOWN,
                tcp_method=TCPMethod.SYN,
            )

        # SYN/ACK means the port is reachable/listening.
        if (
            tcp_layer.flags & 0x12
        ) == 0x12:

            # Send RST so we don't complete
            # the TCP handshake.
            rst = IP(dst=target) / TCP(
                dport=port,
                sport=tcp_layer.dport,
                seq=tcp_layer.ack,
                ack=tcp_layer.seq + 1,
                flags="R",
            )

            from scapy.all import send

            send(
                rst,
                verbose=0,
            )

            return DiscoveryEvidence(
                method=DiscoveryMethod.TCP,
                status=DiscoveryStatus.ALIVE,
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                port=port,
                tcp_method=TCPMethod.SYN,
            )

        # RST means the host responded but
        # the selected port is not listening.
        if (
            tcp_layer.flags & 0x04
        ) == 0x04:

            return DiscoveryEvidence(
                method=DiscoveryMethod.TCP,
                status=DiscoveryStatus.ALIVE,
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                port=port,
                tcp_method=TCPMethod.SYN,
            )

        return DiscoveryEvidence(
            method=DiscoveryMethod.TCP,
            status=DiscoveryStatus.UNKNOWN,
            tcp_method=TCPMethod.SYN,
        )

    except ImportError:

        return DiscoveryEvidence(
            method=DiscoveryMethod.TCP,
            status=DiscoveryStatus.UNKNOWN,
            tcp_method=TCPMethod.SYN,
        )

    except PermissionError:

        return DiscoveryEvidence(
            method=DiscoveryMethod.TCP,
            status=DiscoveryStatus.UNKNOWN,
            tcp_method=TCPMethod.SYN,
        )

    except Exception:

        return DiscoveryEvidence(
            method=DiscoveryMethod.TCP,
            status=DiscoveryStatus.UNKNOWN,
            tcp_method=TCPMethod.SYN,
        )


# ==========================================
# TCP CONNECT FALLBACK
# ==========================================

def tcp_connect_discovery(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> DiscoveryEvidence:

    start = time.monotonic()

    try:

        with socket.create_connection(
            (target, port),
            timeout=timeout,
        ):

            elapsed = (
                time.monotonic() - start
            ) * 1000

            return DiscoveryEvidence(
                method=DiscoveryMethod.TCP,
                status=DiscoveryStatus.ALIVE,
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                port=port,
                tcp_method=TCPMethod.CONNECT,
            )

    except ConnectionRefusedError:

        # Host responded with TCP RST.
        return DiscoveryEvidence(
            method=DiscoveryMethod.TCP,
            status=DiscoveryStatus.ALIVE,
            port=port,
            tcp_method=TCPMethod.CONNECT,
        )

    except socket.timeout:

        return DiscoveryEvidence(
            method=DiscoveryMethod.TCP,
            status=DiscoveryStatus.UNKNOWN,
            port=port,
            tcp_method=TCPMethod.CONNECT,
        )

    except OSError:

        return DiscoveryEvidence(
            method=DiscoveryMethod.TCP,
            status=DiscoveryStatus.UNKNOWN,
            port=port,
            tcp_method=TCPMethod.CONNECT,
        )


# ==========================================
# TCP DISCOVERY
# ==========================================

def tcp_discovery(
    target: str,
    ports: Optional[list[int]] = None,
    timeout: float = 1.0,
    rate_limiter: Optional[RateLimiter] = None,
) -> DiscoveryEvidence:

    if ports is None:

        ports = [
            22,
            80,
            443,
        ]

    if rate_limiter is None:

        rate_limiter = RateLimiter(
            max_requests_per_second=10
        )

    # --------------------------------------
    # Preferred method: SYN
    # --------------------------------------

    for port in ports:

        rate_limiter.wait()

        syn_result = tcp_syn_discovery(
            target,
            port,
            timeout,
        )

        if syn_result.status == DiscoveryStatus.ALIVE:

            return syn_result

    # --------------------------------------
    # Fallback: TCP CONNECT
    # --------------------------------------

    for port in ports:

        rate_limiter.wait()

        connect_result = tcp_connect_discovery(
            target,
            port,
            timeout,
        )

        if connect_result.status == DiscoveryStatus.ALIVE:

            return connect_result

    return DiscoveryEvidence(
        method=DiscoveryMethod.TCP,
        status=DiscoveryStatus.UNKNOWN,
    )


# ==========================================
# COMBINED HOST DISCOVERY
# ==========================================

def discover_host(
    target: str,
    rate_limiter: Optional[RateLimiter] = None,
) -> DiscoveryResult:

    if rate_limiter is None:

        rate_limiter = RateLimiter(
            max_requests_per_second=10
        )

    evidence = []

    # --------------------------------------
    # ICMP
    # --------------------------------------

    rate_limiter.wait()

    icmp_result = icmp_discovery(target)

    evidence.append(icmp_result)

    # --------------------------------------
    # ARP / Neighbor
    # --------------------------------------

    rate_limiter.wait()

    arp_result = arp_discovery(target)

    evidence.append(arp_result)

    # --------------------------------------
    # TCP
    # --------------------------------------

    tcp_result = tcp_discovery(
        target,
        rate_limiter=rate_limiter,
    )

    evidence.append(tcp_result)

    # --------------------------------------
    # FINAL STATUS
    # --------------------------------------

    if any(
        item.status == DiscoveryStatus.ALIVE
        for item in evidence
    ):

        final_status = DiscoveryStatus.ALIVE

    elif all(
        item.status == DiscoveryStatus.DOWN
        for item in evidence
    ):

        final_status = DiscoveryStatus.DOWN

    else:

        final_status = DiscoveryStatus.UNKNOWN

    return DiscoveryResult(
        target=target,
        status=final_status,
        evidence=evidence,
    )


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    target = "192.168.56.129"

    print("=" * 55)
    print("          HOST DISCOVERY TEST")
    print("=" * 55)

    print(f"Target: {target}")

    limiter = RateLimiter(
        max_requests_per_second=10
    )

    result = discover_host(
        target,
        rate_limiter=limiter,
    )

    print(
        f"\nFINAL STATUS: "
        f"{result.status.value}"
    )

    print("\nDISCOVERY EVIDENCE:\n")

    for item in result.evidence:

        print(
            f"  Method: "
            f"{item.method.value}"
        )

        print(
            f"  Status: "
            f"{item.status.value}"
        )

        if item.tcp_method:

            print(
                f"  TCP Method: "
                f"{item.tcp_method.value}"
            )

        if item.response_time_ms is not None:

            print(
                f"  Response Time: "
                f"{item.response_time_ms} ms"
            )

        if item.port is not None:

            print(
                f"  Responding Port: "
                f"{item.port}"
            )

        if item.mac_address:

            print(
                f"  MAC Address: "
                f"{item.mac_address}"
            )

        print()