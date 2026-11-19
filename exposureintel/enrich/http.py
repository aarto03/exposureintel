import time

import httpx

MAX_ATTEMPTS = 4


class SourceError(RuntimeError):
    """Raised when an intel source cannot be reached or returns something unusable."""

    def __init__(self, source: str, message: str):
        super().__init__(f"{source}: {message}")


def fetch_json(
    client: httpx.Client, url: str, *, source: str, params: dict | None = None
) -> dict:
    """GET a JSON object, retrying transient failures with exponential backoff."""
    delay = 1.0
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = client.get(url, params=params, follow_redirects=True)
        except httpx.TransportError as exc:
            problem = str(exc) or type(exc).__name__
        else:
            if resp.status_code == 429 or resp.status_code >= 500:
                problem = f"HTTP {resp.status_code}"
            elif resp.status_code >= 400:
                raise SourceError(source, f"request rejected (HTTP {resp.status_code})")
            else:
                try:
                    data = resp.json()
                except ValueError as exc:
                    raise SourceError(source, "returned invalid JSON") from exc
                if not isinstance(data, dict):
                    raise SourceError(source, "returned an unexpected response")
                return data
        if attempt == MAX_ATTEMPTS - 1:
            raise SourceError(source, f"request failed after {MAX_ATTEMPTS} attempts: {problem}")
        time.sleep(delay)
        delay *= 2
    raise SourceError(source, "unreachable")  # pragma: no cover
