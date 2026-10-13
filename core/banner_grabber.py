import socket
from typing import Optional


class BannerGrabber:
    """
    Safe, lightweight TCP banner grabbing.

    This module only establishes a TCP connection and reads
    data that the service voluntarily sends. Protocol-specific
    probes are handled separately.
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def grab_tcp_banner(
        self,
        host: str,
        port: int,
    ) -> Optional[str]:
        """
        Connect to a TCP service and collect an initial banner.

        Returns:
            Decoded banner string, or None if no banner is received.
        """

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((host, port))

            data = sock.recv(4096)

            if not data:
                return None

            return data.decode(
                "utf-8",
                errors="replace",
            ).strip()

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

        finally:
            sock.close()

    def probe_http(
        self,
        host: str,
        port: int,
    ) -> Optional[str]:
        """
        Send a minimal HTTP request and return the response headers.
        """

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((host, port))
            sock.sendall(request.encode("ascii"))

            data = sock.recv(8192)

            if not data:
                return None

            return data.decode(
                "utf-8",
                errors="replace",
            ).strip()

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

        finally:
            sock.close()

    def probe_smtp(
        self,
        host: str,
        port: int = 25,
    ) -> Optional[str]:
        """
        Connect to an SMTP service and collect its initial greeting.

        No authentication, mail delivery, or destructive commands
        are performed.
        """

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((host, port))

            data = sock.recv(4096)

            if not data:
                return None

            return data.decode(
                "utf-8",
                errors="replace",
            ).strip()

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

        finally:
            sock.close()