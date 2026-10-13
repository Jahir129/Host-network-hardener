from pathlib import Path
import yaml


CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "scope.yaml"


def _load_config() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def load_scope() -> list[str]:
    """Load authorized IP/network scope."""

    config = _load_config()

    allowed = config.get("allowed", [])

    if not isinstance(allowed, list):
        raise ValueError("'allowed' must be a list in scope.yaml")

    return [
        str(item).strip()
        for item in allowed
        if str(item).strip()
    ]


def load_allowed_domains() -> list[str]:
    """Load explicitly authorized domain targets."""

    config = _load_config()

    allowed_domains = config.get("allowed_domains", [])

    if not isinstance(allowed_domains, list):
        raise ValueError(
            "'allowed_domains' must be a list in scope.yaml"
        )

    return [
        str(domain).strip().lower().rstrip(".")
        for domain in allowed_domains
        if str(domain).strip()
    ]

