from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ============================================================
# EVIDENCE
# ============================================================

class RiskEvidence(BaseModel):
    source: str
    evidence_type: str
    value: str


# ============================================================
# RISK ASSESSMENT
# ============================================================

class RiskAssessment(BaseModel):
    category: str
    title: str

    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None

    confidence: str = "unknown"
    confidence_score: int = 1

    # --------------------------------------------------------
    # Exposure
    # --------------------------------------------------------

    exposure_level: str
    exposure_score: int

    # --------------------------------------------------------
    # Service criticality
    # --------------------------------------------------------

    service_criticality: str
    service_criticality_score: int

    # --------------------------------------------------------
    # Exploitability
    # --------------------------------------------------------

    exploitability: str
    exploitability_score: int
    exploitability_source: str = "not_assessed"

    # --------------------------------------------------------
    # Business impact
    # --------------------------------------------------------

    business_impact: str
    business_impact_score: int

    # --------------------------------------------------------
    # False-positive reduction
    # --------------------------------------------------------

    false_positive_adjustment: str

    # --------------------------------------------------------
    # Final calculation
    # --------------------------------------------------------

    impact_score: int
    likelihood_score: int

    risk_score: int
    severity: str

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    description: str = ""
    rationale: str = ""

    evidence: list[RiskEvidence] = Field(
        default_factory=list
    )

    sources: list[str] = Field(
        default_factory=list
    )

    tags: list[str] = Field(
        default_factory=list
    )

    # Original correlation finding information
    occurrence_count: int = 1


# ============================================================
# RISK ANALYZER
# ============================================================

class RiskAnalyzer:
    """
    Step 10: Correlation & Risk Scoring.

    Consumes the deduplicated findings produced by Step 9H.

    The analyzer does NOT:
        - scan hosts
        - exploit services
        - authenticate
        - modify systems
        - perform remediation

    It only assesses already-collected evidence.
    """

    # --------------------------------------------------------
    # Risk thresholds
    # --------------------------------------------------------

    SEVERITY_THRESHOLDS = {
        "informational": (1, 4),
        "low": (5, 9),
        "medium": (10, 14),
        "high": (15, 20),
        "critical": (21, 25),
    }

    # --------------------------------------------------------
    # Category exposure scores
    # --------------------------------------------------------

    EXPOSURE_RULES = {
        "DATABASE_EXPOSURE": (
            "network_reachable",
            4,
        ),
        "REMOTE_ADMINISTRATION_EXPOSURE": (
            "broadly_reachable_within_assessed_scope",
            4,
        ),
        "INFRASTRUCTURE_EXPOSURE": (
            "network_reachable",
            3,
        ),
        "FILE_SHARING_EXPOSURE": (
            "network_reachable",
            3,
        ),
        "INSECURE_PROTOCOL": (
            "network_reachable",
            4,
        ),
        "WEB_EXPOSURE": (
            "network_reachable",
            3,
        ),
        "METADATA_LEAKAGE": (
            "limited_exposure",
            2,
        ),
        "MISCONFIGURATION": (
            "network_reachable",
            3,
        ),
    }

    # --------------------------------------------------------
    # Service criticality
    # --------------------------------------------------------

    CRITICALITY_RULES = {
        "DATABASE_EXPOSURE": (
            "high",
            5,
        ),
        "REMOTE_ADMINISTRATION_EXPOSURE": (
            "critical",
            5,
        ),
        "INFRASTRUCTURE_EXPOSURE": (
            "high",
            4,
        ),
        "FILE_SHARING_EXPOSURE": (
            "high",
            4,
        ),
        "INSECURE_PROTOCOL": (
            "high",
            4,
        ),
        "WEB_EXPOSURE": (
            "moderate",
            3,
        ),
        "METADATA_LEAKAGE": (
            "low",
            2,
        ),
        "MISCONFIGURATION": (
            "moderate",
            3,
        ),
    }

    # --------------------------------------------------------
    # Business impact
    # --------------------------------------------------------

    BUSINESS_IMPACT_RULES = {
        "DATABASE_EXPOSURE": (
            "high",
            5,
        ),
        "REMOTE_ADMINISTRATION_EXPOSURE": (
            "high",
            5,
        ),
        "INFRASTRUCTURE_EXPOSURE": (
            "high",
            4,
        ),
        "FILE_SHARING_EXPOSURE": (
            "high",
            4,
        ),
        "INSECURE_PROTOCOL": (
            "high",
            4,
        ),
        "WEB_EXPOSURE": (
            "moderate",
            3,
        ),
        "METADATA_LEAKAGE": (
            "low",
            2,
        ),
        "MISCONFIGURATION": (
            "moderate",
            3,
        ),
    }

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    CONFIDENCE_SCORES = {
        "high": 5,
        "medium": 3,
        "low": 2,
        "unknown": 1,
    }

    # --------------------------------------------------------
    # Initialization
    # --------------------------------------------------------

    def __init__(
        self,
        vulnerability_intelligence: Optional[
            dict[tuple[str, str], dict[str, Any]]
        ] = None,
    ):
        """
        vulnerability_intelligence is intentionally optional.

        Future example:

            {
                ("vsftpd", "2.3.4"): {
                    "exploitability": "high",
                    "score": 5,
                    "source": "CVE database",
                    "reference": "..."
                }
            }

        For now, no external vulnerability database is assumed.
        """

        self.vulnerability_intelligence = (
            vulnerability_intelligence or {}
        )

    # ========================================================
    # GENERIC HELPERS
    # ========================================================

    @staticmethod
    def _get(
        obj: Any,
        field: str,
        default: Any = None,
    ) -> Any:

        if isinstance(obj, dict):
            return obj.get(field, default)

        return getattr(
            obj,
            field,
            default,
        )

    @staticmethod
    def _normalize(value: Any) -> str:

        if value is None:
            return ""

        return str(value).strip()

    # ========================================================
    # CONFIDENCE
    # ========================================================

    def _confidence(
        self,
        finding: Any,
    ) -> tuple[str, int]:

        value = self._normalize(
            self._get(
                finding,
                "confidence",
                "unknown",
            )
        ).lower()

        score = self.CONFIDENCE_SCORES.get(
            value,
            1,
        )

        return value or "unknown", score

    # ========================================================
    # EXPOSURE
    # ========================================================

    def _exposure(
        self,
        finding: Any,
    ) -> tuple[str, int]:

        category = self._normalize(
            self._get(
                finding,
                "category",
                "",
            )
        ).upper()

        if category in self.EXPOSURE_RULES:
            return self.EXPOSURE_RULES[
                category
            ]

        # Unknown finding category:
        # do not assume maximum exposure.
        return (
            "network_reachable",
            3,
        )

    # ========================================================
    # SERVICE CRITICALITY
    # ========================================================

    def _criticality(
        self,
        finding: Any,
    ) -> tuple[str, int]:

        category = self._normalize(
            self._get(
                finding,
                "category",
                "",
            )
        ).upper()

        if category in self.CRITICALITY_RULES:
            return self.CRITICALITY_RULES[
                category
            ]

        return (
            "moderate",
            3,
        )

    # ========================================================
    # BUSINESS IMPACT
    # ========================================================

    def _business_impact(
        self,
        finding: Any,
    ) -> tuple[str, int]:

        category = self._normalize(
            self._get(
                finding,
                "category",
                "",
            )
        ).upper()

        if category in self.BUSINESS_IMPACT_RULES:
            return self.BUSINESS_IMPACT_RULES[
                category
            ]

        return (
            "moderate",
            3,
        )

    # ========================================================
    # SERVICE INFORMATION
    # ========================================================

    def _service_information(
        self,
        finding: Any,
    ) -> tuple[str, str]:

        service = self._normalize(
            self._get(
                finding,
                "service",
                "",
            )
        )

        product = self._normalize(
            self._get(
                finding,
                "product",
                "",
            )
        )

        version = self._normalize(
            self._get(
                finding,
                "version",
                "",
            )
        )

        # CorrelationFinding may not directly contain
        # service/product/version, so also inspect tags.
        if not service:
            tags = self._get(
                finding,
                "tags",
                [],
            )

            if tags:
                service = ", ".join(
                    str(tag)
                    for tag in tags
                )

        product_key = product.lower()
        version_key = version.lower()

        return (
            product_key,
            version_key,
        )

    # ========================================================
    # EXPLOITABILITY
    # ========================================================

    def _exploitability(
        self,
        finding: Any,
    ) -> tuple[str, int, str]:

        product, version = (
            self._service_information(
                finding
            )
        )

        # ----------------------------------------------------
        # Future CVE / vulnerability intelligence
        # ----------------------------------------------------

        if product and version:

            intelligence = (
                self.vulnerability_intelligence.get(
                    (
                        product,
                        version,
                    )
                )
            )

            if intelligence:

                exploitability = self._normalize(
                    intelligence.get(
                        "exploitability",
                        "unknown",
                    )
                ).lower()

                score = int(
                    intelligence.get(
                        "score",
                        3,
                    )
                )

                score = max(
                    1,
                    min(score, 5),
                )

                source = self._normalize(
                    intelligence.get(
                        "source",
                        "vulnerability_intelligence",
                    )
                )

                return (
                    exploitability or "unknown",
                    score,
                    source or "vulnerability_intelligence",
                )

        # ----------------------------------------------------
        # No vulnerability intelligence available
        # ----------------------------------------------------

        return (
            "unknown",
            3,
            "not_assessed",
        )

    # ========================================================
    # IMPACT
    # ========================================================

    @staticmethod
    def _calculate_impact(
        business_impact_score: int,
        criticality_score: int,
    ) -> int:

        value = (
            (business_impact_score * 0.60)
            +
            (criticality_score * 0.40)
        )

        return max(
            1,
            min(
                5,
                int(round(value)),
            ),
        )

    # ========================================================
    # LIKELIHOOD
    # ========================================================

    @staticmethod
    def _calculate_likelihood(
        exposure_score: int,
        exploitability_score: int,
        confidence_score: int,
    ) -> int:

        value = (
            (exposure_score * 0.40)
            +
            (exploitability_score * 0.40)
            +
            (confidence_score * 0.20)
        )

        return max(
            1,
            min(
                5,
                int(round(value)),
            ),
        )

    # ========================================================
    # SEVERITY
    # ========================================================

    @classmethod
    def _severity(
        cls,
        risk_score: int,
    ) -> str:

        for severity, (
            minimum,
            maximum,
        ) in cls.SEVERITY_THRESHOLDS.items():

            if minimum <= risk_score <= maximum:
                return severity

        return "unknown"

    # ========================================================
    # FALSE-POSITIVE REDUCTION
    # ========================================================

    @staticmethod
    def _false_positive_adjustment(
        confidence: str,
        confidence_score: int,
    ) -> str:

        if confidence == "high":
            return (
                "strong_evidence_no_downward_adjustment"
            )

        if confidence == "medium":
            return (
                "moderate_evidence_likelihood_constrained"
            )

        if confidence == "low":
            return (
                "weak_evidence_likelihood_constrained"
            )

        return (
            "insufficient_evidence_likelihood_constrained"
        )

    # ========================================================
    # RATIONALE
    # ========================================================

    @staticmethod
    def _rationale(
        exposure_level: str,
        exposure_score: int,
        criticality: str,
        criticality_score: int,
        exploitability: str,
        exploitability_score: int,
        business_impact: str,
        business_impact_score: int,
        confidence: str,
        impact_score: int,
        likelihood_score: int,
        risk_score: int,
        severity: str,
    ) -> str:

        return (
            f"Exposure was assessed as "
            f"{exposure_level} ({exposure_score}/5). "
            f"Service criticality was assessed as "
            f"{criticality} ({criticality_score}/5). "
            f"Exploitability is "
            f"{exploitability} "
            f"({exploitability_score}/5). "
            f"Business impact was assessed as "
            f"{business_impact} "
            f"({business_impact_score}/5). "
            f"Evidence confidence is "
            f"{confidence}. "
            f"Impact score = {impact_score}/5; "
            f"likelihood score = {likelihood_score}/5; "
            f"risk score = {risk_score}/25; "
            f"severity = {severity}."
        )

    # ========================================================
    # EVIDENCE CONVERSION
    # ========================================================

    @staticmethod
    def _convert_evidence(
        finding: Any,
    ) -> list[RiskEvidence]:

        raw_evidence = (
            RiskAnalyzer._get(
                finding,
                "evidence",
                [],
            )
        )

        result = []

        for item in raw_evidence or []:

            if isinstance(item, dict):

                source = str(
                    item.get(
                        "source",
                        "unknown",
                    )
                )

                evidence_type = str(
                    item.get(
                        "evidence_type",
                        "unknown",
                    )
                )

                value = str(
                    item.get(
                        "value",
                        "",
                    )
                )

            else:

                source = str(
                    getattr(
                        item,
                        "source",
                        "unknown",
                    )
                )

                evidence_type = str(
                    getattr(
                        item,
                        "evidence_type",
                        "unknown",
                    )
                )

                value = str(
                    getattr(
                        item,
                        "value",
                        "",
                    )
                )

            result.append(
                RiskEvidence(
                    source=source,
                    evidence_type=evidence_type,
                    value=value,
                )
            )

        return result

    # ========================================================
    # SINGLE FINDING
    # ========================================================

    def assess(
        self,
        finding: Any,
    ) -> RiskAssessment:

        category = self._normalize(
            self._get(
                finding,
                "category",
                "UNKNOWN",
            )
        )

        title = self._normalize(
            self._get(
                finding,
                "title",
                "Unnamed finding",
            )
        )

        host = self._normalize(
            self._get(
                finding,
                "host",
                "",
            )
        )

        port = self._get(
            finding,
            "port",
            None,
        )

        protocol = self._get(
            finding,
            "protocol",
            None,
        )

        confidence, confidence_score = (
            self._confidence(
                finding
            )
        )

        exposure_level, exposure_score = (
            self._exposure(
                finding
            )
        )

        criticality, criticality_score = (
            self._criticality(
                finding
            )
        )

        business_impact, business_impact_score = (
            self._business_impact(
                finding
            )
        )

        exploitability, exploitability_score, exploitability_source = (
            self._exploitability(
                finding
            )
        )

        impact_score = self._calculate_impact(
            business_impact_score=business_impact_score,
            criticality_score=criticality_score,
        )

        likelihood_score = self._calculate_likelihood(
            exposure_score=exposure_score,
            exploitability_score=exploitability_score,
            confidence_score=confidence_score,
        )

        risk_score = (
            impact_score
            *
            likelihood_score
        )

        risk_score = max(
            1,
            min(
                25,
                risk_score,
            ),
        )

        severity = self._severity(
            risk_score
        )

        false_positive_adjustment = (
            self._false_positive_adjustment(
                confidence=confidence,
                confidence_score=confidence_score,
            )
        )

        description = self._normalize(
            self._get(
                finding,
                "description",
                "",
            )
        )

        rationale = self._rationale(
            exposure_level=exposure_level,
            exposure_score=exposure_score,
            criticality=criticality,
            criticality_score=criticality_score,
            exploitability=exploitability,
            exploitability_score=exploitability_score,
            business_impact=business_impact,
            business_impact_score=business_impact_score,
            confidence=confidence,
            impact_score=impact_score,
            likelihood_score=likelihood_score,
            risk_score=risk_score,
            severity=severity,
        )

        sources = list(
            self._get(
                finding,
                "sources",
                [],
            ) or []
        )

        tags = list(
            self._get(
                finding,
                "tags",
                [],
            ) or []
        )

        occurrence_count = int(
            self._get(
                finding,
                "occurrence_count",
                1,
            ) or 1
        )

        return RiskAssessment(
            category=category,
            title=title,
            host=host,
            port=port,
            protocol=protocol,
            confidence=confidence,
            confidence_score=confidence_score,
            exposure_level=exposure_level,
            exposure_score=exposure_score,
            service_criticality=criticality,
            service_criticality_score=criticality_score,
            exploitability=exploitability,
            exploitability_score=exploitability_score,
            exploitability_source=exploitability_source,
            business_impact=business_impact,
            business_impact_score=business_impact_score,
            false_positive_adjustment=false_positive_adjustment,
            impact_score=impact_score,
            likelihood_score=likelihood_score,
            risk_score=risk_score,
            severity=severity,
            description=description,
            rationale=rationale,
            evidence=self._convert_evidence(
                finding
            ),
            sources=sources,
            tags=tags,
            occurrence_count=occurrence_count,
        )

    # ========================================================
    # ALL FINDINGS
    # ========================================================

    def analyze(
        self,
        correlated_findings: list[Any],
    ) -> list[RiskAssessment]:

        assessments = []

        for finding in correlated_findings:

            try:

                assessment = self.assess(
                    finding
                )

                assessments.append(
                    assessment
                )

            except Exception as error:

                # Risk analysis must not destroy
                # the complete pipeline because of
                # one malformed finding.
                host = self._normalize(
                    self._get(
                        finding,
                        "host",
                        "",
                    )
                )

                title = self._normalize(
                    self._get(
                        finding,
                        "title",
                        "Unknown finding",
                    )
                )

                assessments.append(
                    RiskAssessment(
                        category=self._normalize(
                            self._get(
                                finding,
                                "category",
                                "UNKNOWN",
                            )
                        ),
                        title=title,
                        host=host,
                        port=self._get(
                            finding,
                            "port",
                            None,
                        ),
                        protocol=self._get(
                            finding,
                            "protocol",
                            None,
                        ),
                        confidence="unknown",
                        confidence_score=1,
                        exposure_level="unknown",
                        exposure_score=1,
                        service_criticality="unknown",
                        service_criticality_score=1,
                        exploitability="unknown",
                        exploitability_score=1,
                        exploitability_source="analysis_error",
                        business_impact="unknown",
                        business_impact_score=1,
                        false_positive_adjustment=(
                            "risk_assessment_error"
                        ),
                        impact_score=1,
                        likelihood_score=1,
                        risk_score=1,
                        severity="informational",
                        description=(
                            f"Risk assessment failed: "
                            f"{error}"
                        ),
                        rationale=(
                            "The finding was preserved "
                            "but could not be fully "
                            "assessed."
                        ),
                        evidence=[],
                        sources=["risk_analyzer"],
                        tags=["risk-assessment-error"],
                    )
                )

        # Highest risk first.
        assessments.sort(
            key=lambda item: (
                item.risk_score,
                item.impact_score,
                item.likelihood_score,
            ),
            reverse=True,
        )

        return assessments

    # ========================================================
    # SUMMARY
    # ========================================================

    @staticmethod
    def summarize(
        assessments: list[RiskAssessment],
    ) -> dict[str, Any]:

        summary = {
            "total_assessed": len(
                assessments
            ),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "average_risk_score": 0.0,
            "highest_risk_score": 0,
        }

        if not assessments:
            return summary

        scores = []

        for assessment in assessments:

            severity = assessment.severity.lower()

            if severity in summary:
                summary[severity] += 1

            scores.append(
                assessment.risk_score
            )

        summary["average_risk_score"] = round(
            sum(scores) / len(scores),
            2,
        )

        summary["highest_risk_score"] = max(
            scores
        )

        return summary