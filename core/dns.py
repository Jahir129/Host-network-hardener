import dns.resolver
from pydantic import BaseModel, Field
from core.target import Target, TargetType


class DNSResult(BaseModel):
    domain: str

    a_records: list[str] = Field(
        default_factory=list,
        description="Resolved IPv4 addresses"
    )

    aaaa_records: list[str] = Field(
        default_factory=list,
        description="Resolved IPv6 addresses"
    )

    cname_records: list[str] = Field(
        default_factory=list,
        description="Canonical name / aliases"
    )

    ns_records: list[str] = Field(
        default_factory=list,
        description="Authoritative nameservers"
    )

    mx_records: list[str] = Field(
        default_factory=list,
        description="Mail exchange servers"
    )

    errors: list[str] = Field(
        default_factory=list,
        description="Errors encountered during query"
    )


def _query_record(domain: str, record_type: str) -> list[str]:
    """Helper to query a specific DNS record type safely."""

    try:
        answers = dns.resolver.resolve(domain, record_type)

        if record_type == "MX":
            # Lower preference number = higher priority
            sorted_records = sorted(
                answers,
                key=lambda r: r.preference
            )

            return [
                f"{r.preference} {r.exchange.to_text().rstrip('.')}"
                for r in sorted_records
            ]

        return [
            rdata.to_text().rstrip(".")
            for rdata in answers
        ]

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN
    ):
        # Normal condition:
        # domain exists but does not have this record type
        return []

    except dns.resolver.NoNameservers:
        return []

    except dns.resolver.LifetimeTimeout:
        return []


def resolve_domain(target: Target) -> DNSResult:
    """Safely resolve DNS infrastructure for a validated domain target."""

    if target.target_type != TargetType.DOMAIN:
        raise ValueError(
            f"Expected a DOMAIN target, got: {target.target_type}"
        )

    domain = target.normalized_value
    result = DNSResult(domain=domain)

    try:
        result.a_records = _query_record(domain, "A")
        result.aaaa_records = _query_record(domain, "AAAA")
        result.cname_records = _query_record(domain, "CNAME")
        result.ns_records = _query_record(domain, "NS")
        result.mx_records = _query_record(domain, "MX")

    except Exception as e:
        result.errors.append(
            f"Unexpected DNS error: {e}"
        )

    return result