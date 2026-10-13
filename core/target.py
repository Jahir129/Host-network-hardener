from enum import Enum
from ipaddress import ip_address, ip_network

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    IP_RANGE = "ip_range"


class Target(BaseModel):
    raw_input: str = Field(
        description="Original user-provided target"
    )

    normalized_value: str = Field(
        description="Normalized target value"
    )

    target_type: TargetType


def parse_target(value: str) -> Target:
    """Validate and classify a user-provided target."""

    raw_value = value
    value = value.strip()

    if not value:
        raise ValueError("Target cannot be empty.")

    # ---------------------------------------------------------
    # Single IP address
    # ---------------------------------------------------------

    try:
        ip_address(value)

        return Target(
            raw_input=raw_value,
            normalized_value=value,
            target_type=TargetType.IP,
        )

    except ValueError:
        pass

    # ---------------------------------------------------------
    # CIDR network
    # ---------------------------------------------------------

    try:
        ip_network(value, strict=False)

        return Target(
            raw_input=raw_value,
            normalized_value=value,
            target_type=TargetType.CIDR,
        )

    except ValueError:
        pass

    # ---------------------------------------------------------
    # IPv4 range: start-end
    # ---------------------------------------------------------

    if "-" in value:
        parts = value.split("-", 1)

        if len(parts) == 2:
            start, end = parts[0].strip(), parts[1].strip()

            try:
                ip_address(start)
                ip_address(end)

                return Target(
                    raw_input=raw_value,
                    normalized_value=f"{start}-{end}",
                    target_type=TargetType.IP_RANGE,
                )

            except ValueError:
                pass

    # ---------------------------------------------------------
    # Basic domain validation
    # ---------------------------------------------------------

    if "." in value and " " not in value:
        return Target(
            raw_input=raw_value,
            normalized_value=value.lower().rstrip("."),
            target_type=TargetType.DOMAIN,
        )

    raise ValueError(
        f"Invalid or unsupported target: {value}"
    )


def is_in_scope(
    target: Target,
    allowed_networks: list[str],
    allowed_domains: list[str] | None = None,
) -> bool:
    """
    Check whether the target is inside the explicitly
    authorized scope.

    IP/CIDR/range targets are checked against allowed networks.

    Domain targets are checked against the explicit
    allowed_domains list.
    """

    allowed_domains = allowed_domains or []

    # Normalize authorized domains once.
    normalized_domains = {
        domain.strip().lower().rstrip(".")
        for domain in allowed_domains
        if domain.strip()
    }

    # ---------------------------------------------------------
    # Single IP
    # ---------------------------------------------------------

    if target.target_type == TargetType.IP:

        target_ip = ip_address(
            target.normalized_value
        )

        return any(
            target_ip in ip_network(
                network,
                strict=False
            )
            for network in allowed_networks
        )

    # ---------------------------------------------------------
    # CIDR
    # ---------------------------------------------------------

    if target.target_type == TargetType.CIDR:

        target_network = ip_network(
            target.normalized_value,
            strict=False
        )

        return any(
            target_network.subnet_of(
                ip_network(
                    network,
                    strict=False
                )
            )
            for network in allowed_networks
        )

    # ---------------------------------------------------------
    # IP range
    # ---------------------------------------------------------

    if target.target_type == TargetType.IP_RANGE:

        start, end = target.normalized_value.split(
            "-",
            1
        )

        start_ip = ip_address(start)
        end_ip = ip_address(end)

        # Reject reversed ranges.
        if int(start_ip) > int(end_ip):
            return False

        return any(
            start_ip in network
            and end_ip in network
            for network in (
                ip_network(
                    value,
                    strict=False
                )
                for value in allowed_networks
            )
        )

    # ---------------------------------------------------------
    # Domain
    # ---------------------------------------------------------

    if target.target_type == TargetType.DOMAIN:

        domain = (
            target.normalized_value
            .strip()
            .lower()
            .rstrip(".")
        )

        # IMPORTANT:
        # A domain is authorized explicitly by name.
        #
        # We do NOT require its resolved IP address to be
        # inside the private allowed network.
        #
        # This allows authorized external test domains such
        # as scanme.nmap.org while keeping authorization
        # explicit.
        return domain in normalized_domains

    return False


def expand_target(target: Target) -> list[str]:
    """
    Expand any target into individual IPv4 address strings.
    """

    # ---------------------------------------------------------
    # Single IP
    # ---------------------------------------------------------

    if target.target_type == TargetType.IP:

        return [
            target.normalized_value
        ]

    # ---------------------------------------------------------
    # CIDR
    # ---------------------------------------------------------

    if target.target_type == TargetType.CIDR:

        net = ip_network(
            target.normalized_value,
            strict=False
        )

        # Single-address network.
        if net.num_addresses == 1:
            return [
                str(net.network_address)
            ]

        return [
            str(ip)
            for ip in net.hosts()
        ]

    # ---------------------------------------------------------
    # IP range
    # ---------------------------------------------------------

    if target.target_type == TargetType.IP_RANGE:

        start_str, end_str = (
            target.normalized_value.split(
                "-",
                1
            )
        )

        start_int = int(
            ip_address(start_str)
        )

        end_int = int(
            ip_address(end_str)
        )

        if start_int > end_int:
            raise ValueError(
                f"Invalid IP range: "
                f"{start_str} is greater than "
                f"{end_str}"
            )

        return [
            str(ip_address(i))
            for i in range(
                start_int,
                end_int + 1
            )
        ]

    # ---------------------------------------------------------
    # Domain
    # ---------------------------------------------------------

    if target.target_type == TargetType.DOMAIN:

        from core.dns import resolve_domain

        dns_res = resolve_domain(target)

        return dns_res.a_records

    return []


def expand_and_validate_targets(
    raw_targets: list[str],
    allowed_networks: list[str],
    allowed_domains: list[str] | None = None,
) -> dict[str, list[str]]:
    """
    Parse, expand, and partition mixed targets into
    allowed and blocked IP lists.

    Domain authorization is based on the explicit
    allowed_domains list.

    IP/CIDR/range authorization is based on the
    allowed_networks list.
    """

    allowed_domains = allowed_domains or []

    normalized_domains = {
        domain.strip().lower().rstrip(".")
        for domain in allowed_domains
        if domain.strip()
    }

    allowed_ips = set()
    blocked_ips = set()

    for raw in raw_targets:

        target = parse_target(raw)

        # -----------------------------------------------------
        # Domain target
        # -----------------------------------------------------

        if target.target_type == TargetType.DOMAIN:

            domain = (
                target.normalized_value
                .strip()
                .lower()
                .rstrip(".")
            )

            # Domain must be explicitly authorized.
            if domain not in normalized_domains:
                continue

            # Resolve the explicitly authorized domain.
            candidate_ips = expand_target(target)

            # The resolved IPs inherit authorization from
            # the explicitly authorized domain.
            for ip_str in candidate_ips:
                allowed_ips.add(ip_str)

            continue

        # -----------------------------------------------------
        # IP / CIDR / IP range
        # -----------------------------------------------------

        candidate_ips = expand_target(target)

        for ip_str in candidate_ips:

            ip_obj = ip_address(ip_str)

            if any(
                ip_obj in ip_network(
                    network,
                    strict=False
                )
                for network in allowed_networks
            ):
                allowed_ips.add(ip_str)

            else:
                blocked_ips.add(ip_str)

    return {
        "allowed": sorted(
            list(allowed_ips),
            key=lambda ip: ip_address(ip)
        ),

        "blocked": sorted(
            list(blocked_ips),
            key=lambda ip: ip_address(ip)
        ),
    }