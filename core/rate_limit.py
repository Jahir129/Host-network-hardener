import time
from dataclasses import dataclass


@dataclass
class RateLimiter:
    """
    Simple rate limiter for discovery/scanning operations.

    max_requests_per_second:
        Maximum number of probe operations allowed per second.
    """

    max_requests_per_second: float = 10.0

    def __post_init__(self):
        if self.max_requests_per_second <= 0:
            raise ValueError(
                "max_requests_per_second must be greater than 0"
            )

        self.min_interval = 1.0 / self.max_requests_per_second
        self.last_request_time = 0.0

    def wait(self):
        """
        Wait long enough before allowing the next probe.
        """

        now = time.monotonic()

        elapsed = now - self.last_request_time

        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

        self.last_request_time = time.monotonic()