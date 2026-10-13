from typing import Optional

import nmap
from pydantic import BaseModel, Field


class OSEvidence(BaseModel):
    """
    One piece of evidence supporting an OS fingerprint.
    """

    source: str
    evidence_type: str
    value: str


class OSFingerprint(BaseModel):
    """
    Normalized OS/platform fingerprint for a host.
    """

    host: str

    os_family: Optional[str] = None
    os_name: Optional[str] = None

    # Additional interpreted information
    distribution_hint: Optional[str] = None
    kernel_generation: Optional[str] = None
    kernel_range: Optional[str] = None

    device_type: Optional[str] = None
    vendor: Optional[str] = None

    # Nmap-specific confidence
    nmap_accuracy: Optional[int] = None

    # CPE identifiers
    cpes: list[str] = Field(
        default_factory=list
    )

    # Platform hints obtained from previous pipeline stages
    platform_hints: list[str] = Field(
        default_factory=list
    )

    confidence: str = "unknown"

    evidence: list[OSEvidence] = Field(
        default_factory=list
    )

    conflicts: list[str] = Field(
        default_factory=list
    )


class OSFingerprinter:
    """
    Performs non-exploitative OS/platform fingerprinting.

    The scanner uses Nmap OS detection and then correlates
    the result with platform hints already collected during
    Step 5 service enumeration.
    """

    def __init__(
        self,
        timeout: int = 300,
    ):
        self.nm = nmap.PortScanner()
        self.timeout = timeout

    # ============================================================
    # PUBLIC API
    # ============================================================

    def fingerprint_host(
        self,
        host: str,
        service_results=None,
    ) -> Optional[OSFingerprint]:
        """
        Fingerprint one host.

        service_results is optional and contains Step 5
        ServiceResult objects for correlation.
        """

        try:
            self.nm.scan(
                hosts=host,
                arguments="-O -Pn -T3",
                timeout=self.timeout,
            )

        except Exception as error:

            print(
                f"[!] OS fingerprinting failed for "
                f"{host}: {error}"
            )

            return None

        if host not in self.nm.all_hosts():
            return None

        host_data = self.nm[host]

        os_matches = host_data.get(
            "osmatch",
            [],
        )

        evidence: list[OSEvidence] = []
        conflicts: list[str] = []

        # --------------------------------------------------------
        # Step 5 platform hints
        # --------------------------------------------------------

        service_hints = self._collect_service_hints(
            host,
            service_results,
        )

        # --------------------------------------------------------
        # No OS match
        # --------------------------------------------------------

        if not os_matches:

            evidence.extend(
                self._build_service_hint_evidence(
                    service_hints
                )
            )

            return OSFingerprint(
                host=host,

                os_family=self._infer_family_from_hints(
                    service_hints
                ),

                os_name=self._infer_name_from_hints(
                    service_hints
                ),

                distribution_hint=self._infer_distribution_hint(
                    service_hints
                ),

                os_version=None,
                kernel_generation=None,
                kernel_range=None,
                device_type=None,
                vendor=None,
                nmap_accuracy=None,

                platform_hints=service_hints,

                confidence=(
                    "low"
                    if service_hints
                    else "unknown"
                ),

                evidence=evidence,
                conflicts=conflicts,
            )

        # --------------------------------------------------------
        # Best Nmap OS match
        # --------------------------------------------------------

        best_match = os_matches[0]

        os_name = best_match.get(
            "name"
        )

        nmap_accuracy = self._safe_int(
            best_match.get("accuracy")
        )

        if os_name:

            evidence.append(
                OSEvidence(
                    source="nmap",
                    evidence_type="os_match",
                    value=str(os_name),
                )
            )

        if nmap_accuracy is not None:

            evidence.append(
                OSEvidence(
                    source="nmap",
                    evidence_type="accuracy",
                    value=str(nmap_accuracy),
                )
            )

        # --------------------------------------------------------
        # Parse OS classes
        # --------------------------------------------------------

        os_family = None
        kernel_generation = None
        device_type = None
        vendor = None

        cpes: list[str] = []

        os_classes = best_match.get(
            "osclass",
            [],
        )

        if isinstance(
            os_classes,
            dict,
        ):
            os_classes = [os_classes]

        if os_classes:

            best_class = os_classes[0]

            os_family = self._clean_value(
                best_class.get("osfamily")
            )

            kernel_generation = self._clean_value(
                best_class.get("osgen")
            )

            device_type = self._clean_value(
                best_class.get("type")
            )

            vendor = self._clean_value(
                best_class.get("vendor")
            )

            if os_family:

                evidence.append(
                    OSEvidence(
                        source="nmap",
                        evidence_type="os_family",
                        value=os_family,
                    )
                )

            if kernel_generation:

                evidence.append(
                    OSEvidence(
                        source="nmap",
                        evidence_type="os_generation",
                        value=kernel_generation,
                    )
                )

            if device_type:

                evidence.append(
                    OSEvidence(
                        source="nmap",
                        evidence_type="device_type",
                        value=device_type,
                    )
                )

            if vendor:

                evidence.append(
                    OSEvidence(
                        source="nmap",
                        evidence_type="vendor",
                        value=vendor,
                    )
                )

            cpe_values = best_class.get(
                "cpe",
                [],
            )

            if isinstance(
                cpe_values,
                str,
            ):
                cpe_values = [cpe_values]

            for cpe in cpe_values:

                if not cpe:
                    continue

                cpe = str(cpe)

                if cpe not in cpes:

                    cpes.append(cpe)

                    evidence.append(
                        OSEvidence(
                            source="nmap",
                            evidence_type="cpe",
                            value=cpe,
                        )
                    )

        # --------------------------------------------------------
        # Kernel / OS version range
        # --------------------------------------------------------

        kernel_range = self._extract_kernel_range(
            os_name
        )

        if kernel_range:

            evidence.append(
                OSEvidence(
                    source="nmap",
                    evidence_type="kernel_range",
                    value=kernel_range,
                )
            )

        # --------------------------------------------------------
        # Port evidence used by Nmap
        # --------------------------------------------------------

        port_used = host_data.get(
            "portused",
            [],
        )

        if isinstance(
            port_used,
            dict,
        ):
            port_used = [port_used]

        for port_info in port_used:

            state = port_info.get(
                "state"
            )

            protocol = port_info.get(
                "proto"
            )

            port_id = port_info.get(
                "portid"
            )

            value_parts = []

            if protocol:
                value_parts.append(
                    str(protocol)
                )

            if port_id:
                value_parts.append(
                    str(port_id)
                )

            if state:
                value_parts.append(
                    f"state={state}"
                )

            if value_parts:

                evidence.append(
                    OSEvidence(
                        source="nmap",
                        evidence_type="port_used",
                        value=" ".join(
                            value_parts
                        ),
                    )
                )

        # --------------------------------------------------------
        # Step 5 evidence
        # --------------------------------------------------------

        evidence.extend(
            self._build_service_hint_evidence(
                service_hints
            )
        )

        # --------------------------------------------------------
        # Normalize OS name
        # --------------------------------------------------------

        normalized_name = (
            self._normalize_os_name(
                os_name
            )
        )

        # --------------------------------------------------------
        # If Nmap did not provide family,
        # infer it from OS name.
        # --------------------------------------------------------

        if not os_family:

            os_family = (
                self._infer_family_from_name(
                    normalized_name
                )
            )

        # --------------------------------------------------------
        # If Nmap did not provide a name,
        # infer it from service hints.
        # --------------------------------------------------------

        if not normalized_name:

            normalized_name = (
                self._infer_name_from_hints(
                    service_hints
                )
            )

        # --------------------------------------------------------
        # Distribution hint
        #
        # This remains a HINT unless Nmap explicitly identifies
        # the distribution.
        # --------------------------------------------------------

        distribution_hint = (
            self._infer_distribution_hint(
                service_hints
            )
        )

        # --------------------------------------------------------
        # Detect conflicts
        # --------------------------------------------------------

        conflicts.extend(
            self._detect_conflicts(
                os_family=os_family,
                os_name=normalized_name,
                service_hints=service_hints,
            )
        )

        # --------------------------------------------------------
        # Calculate final confidence
        # --------------------------------------------------------

        confidence = (
            self._calculate_confidence(
                nmap_accuracy=nmap_accuracy,
                service_hints=service_hints,
                conflicts=conflicts,
            )
        )

        return OSFingerprint(
            host=host,

            os_family=os_family,
            os_name=normalized_name,

            distribution_hint=distribution_hint,

            kernel_generation=kernel_generation,
            kernel_range=kernel_range,

            device_type=device_type,
            vendor=vendor,

            nmap_accuracy=nmap_accuracy,

            cpes=cpes,

            platform_hints=service_hints,

            confidence=confidence,

            evidence=evidence,
            conflicts=conflicts,
        )

    # ============================================================
    # MULTIPLE HOSTS
    # ============================================================

    def fingerprint_hosts(
        self,
        hosts: list[str],
        service_results=None,
    ) -> list[OSFingerprint]:
        """
        Fingerprint multiple hosts.
        """

        results: list[OSFingerprint] = []

        for host in hosts:

            result = self.fingerprint_host(
                host=host,
                service_results=service_results,
            )

            if result:

                results.append(result)

        return results

    # ============================================================
    # STEP 5 CORRELATION
    # ============================================================

    def _collect_service_hints(
        self,
        host: str,
        service_results,
    ) -> list[str]:
        """
        Collect platform hints produced by Step 5.
        """

        if not service_results:
            return []

        hints: list[str] = []

        for result in service_results:

            if result.host != host:
                continue

            fingerprint = getattr(
                result,
                "fingerprint",
                None,
            )

            if not fingerprint:
                continue

            hint = getattr(
                fingerprint,
                "platform_hint",
                None,
            )

            if not hint:
                continue

            hint = str(
                hint
            ).strip()

            if (
                hint
                and hint not in hints
            ):

                hints.append(
                    hint
                )

        return hints

    def _build_service_hint_evidence(
        self,
        hints: list[str],
    ) -> list[OSEvidence]:

        evidence = []

        for hint in hints:

            evidence.append(
                OSEvidence(
                    source="step5",
                    evidence_type="platform_hint",
                    value=hint,
                )
            )

        return evidence

    # ============================================================
    # KERNEL RANGE
    # ============================================================

    def _extract_kernel_range(
        self,
        os_match_name: Optional[str],
    ) -> Optional[str]:

        if not os_match_name:
            return None

        if "Linux " not in os_match_name:
            return None

        value = (
            os_match_name
            .replace(
                "Linux ",
                "",
                1,
            )
            .strip()
        )

        return value or None

    # ============================================================
    # OS NORMALIZATION
    # ============================================================

    def _normalize_os_name(
        self,
        name: Optional[str],
    ) -> Optional[str]:

        if not name:
            return None

        value = name.strip()

        lower = value.lower()

        # --------------------------------------------------------
        # Linux
        # --------------------------------------------------------

        if "ubuntu" in lower:
            return "Ubuntu Linux"

        if "debian" in lower:
            return "Debian Linux"

        if "centos" in lower:
            return "CentOS Linux"

        if "red hat" in lower:
            return (
                "Red Hat Enterprise Linux"
            )

        if "rhel" in lower:
            return (
                "Red Hat Enterprise Linux"
            )

        if "fedora" in lower:
            return "Fedora Linux"

        if "linux" in lower:
            return "Linux"

        # --------------------------------------------------------
        # Windows
        # --------------------------------------------------------

        if "windows" in lower:
            return "Microsoft Windows"

        # --------------------------------------------------------
        # BSD
        # --------------------------------------------------------

        if "freebsd" in lower:
            return "FreeBSD"

        if "openbsd" in lower:
            return "OpenBSD"

        if "netbsd" in lower:
            return "NetBSD"

        # --------------------------------------------------------
        # Network appliances / other
        # --------------------------------------------------------

        if "cisco" in lower:
            return "Cisco IOS"

        return value

    # ============================================================
    # FAMILY INFERENCE
    # ============================================================

    def _infer_family_from_name(
        self,
        name: Optional[str],
    ) -> Optional[str]:

        if not name:
            return None

        lower = name.lower()

        if any(
            value in lower
            for value in [
                "linux",
                "ubuntu",
                "debian",
                "centos",
                "fedora",
                "red hat",
            ]
        ):
            return "Linux"

        if "windows" in lower:
            return "Windows"

        if any(
            value in lower
            for value in [
                "freebsd",
                "openbsd",
                "netbsd",
            ]
        ):
            return "BSD"

        if "cisco" in lower:
            return "Network OS"

        return None

    def _infer_family_from_hints(
        self,
        hints: list[str],
    ) -> Optional[str]:

        if not hints:
            return None

        lower_hints = [
            hint.lower()
            for hint in hints
        ]

        if any(
            value in hint
            for hint in lower_hints
            for value in [
                "ubuntu",
                "debian",
                "centos",
                "fedora",
                "red hat",
                "linux",
            ]
        ):
            return "Linux"

        if any(
            "windows" in hint
            for hint in lower_hints
        ):
            return "Windows"

        return None

    def _infer_name_from_hints(
        self,
        hints: list[str],
    ) -> Optional[str]:

        if not hints:
            return None

        # Prefer more specific distribution hints.

        for hint in hints:

            lower = hint.lower()

            if "ubuntu" in lower:
                return "Ubuntu Linux"

            if "debian" in lower:
                return "Debian Linux"

            if "centos" in lower:
                return "CentOS Linux"

            if "red hat" in lower:
                return (
                    "Red Hat Enterprise Linux"
                )

            if "fedora" in lower:
                return "Fedora Linux"

            if "windows" in lower:
                return "Microsoft Windows"

        return None

    def _infer_distribution_hint(
        self,
        hints: list[str],
    ) -> Optional[str]:

        distributions = [
            "Ubuntu",
            "Debian",
            "CentOS",
            "RHEL",
            "Red Hat",
            "Fedora",
            "Alpine",
            "Arch",
            "SUSE",
            "OpenSUSE",
        ]

        for hint in hints:

            for distribution in distributions:

                if (
                    distribution.lower()
                    in hint.lower()
                ):

                    return distribution

        return None

    # ============================================================
    # CONFLICT DETECTION
    # ============================================================

    def _detect_conflicts(
        self,
        os_family: Optional[str],
        os_name: Optional[str],
        service_hints: list[str],
    ) -> list[str]:

        conflicts = []

        if not service_hints:
            return conflicts

        family = (
            os_family.lower()
            if os_family
            else ""
        )

        name = (
            os_name.lower()
            if os_name
            else ""
        )

        for hint in service_hints:

            hint_lower = hint.lower()

            # ----------------------------------------------------
            # Nmap says Windows but service says Linux.
            # ----------------------------------------------------

            if (
                "windows" in family
                or "windows" in name
            ):

                if any(
                    linux_value
                    in hint_lower
                    for linux_value in [
                        "linux",
                        "ubuntu",
                        "debian",
                        "centos",
                        "fedora",
                        "red hat",
                    ]
                ):

                    conflicts.append(
                        "OS conflict: Nmap suggests "
                        "Windows, while Step 5 service "
                        f"evidence suggests {hint}."
                    )

            # ----------------------------------------------------
            # Nmap says Linux but service says Windows.
            # ----------------------------------------------------

            if (
                "linux" in family
                or "linux" in name
                or "ubuntu" in name
                or "debian" in name
            ):

                if "windows" in hint_lower:

                    conflicts.append(
                        "OS conflict: Nmap suggests "
                        "Linux, while Step 5 service "
                        "evidence suggests Windows."
                    )

        return conflicts

    # ============================================================
    # CONFIDENCE
    # ============================================================

    def _calculate_confidence(
        self,
        nmap_accuracy: Optional[int],
        service_hints: list[str],
        conflicts: list[str],
    ) -> str:

        score = 0

        # --------------------------------------------------------
        # Nmap accuracy
        # --------------------------------------------------------

        if nmap_accuracy is not None:

            if nmap_accuracy >= 90:
                score += 5

            elif nmap_accuracy >= 80:
                score += 4

            elif nmap_accuracy >= 70:
                score += 3

            elif nmap_accuracy >= 50:
                score += 2

            elif nmap_accuracy > 0:
                score += 1

        # --------------------------------------------------------
        # Step 5 corroboration
        # --------------------------------------------------------

        if service_hints:
            score += 2

        if len(service_hints) >= 2:
            score += 1

        # --------------------------------------------------------
        # Conflicts
        # --------------------------------------------------------

        if conflicts:
            score -= 3

        # --------------------------------------------------------
        # Final classification
        # --------------------------------------------------------

        if score >= 7:
            return "high"

        if score >= 4:
            return "medium"

        if score >= 1:
            return "low"

        return "unknown"

    # ============================================================
    # HELPERS
    # ============================================================

    def _safe_int(
        self,
        value,
    ) -> Optional[int]:

        if value is None:
            return None

        try:
            return int(value)

        except (
            TypeError,
            ValueError,
        ):
            return None

    def _clean_value(
        self,
        value,
    ) -> Optional[str]:

        if value is None:
            return None

        value = str(
            value
        ).strip()

        return value or None