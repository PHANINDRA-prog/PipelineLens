"""Request-scoped, loopback-only dashboard client; provider tokens are never retained."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import httpx


class ApiClientError(RuntimeError):
    """Safe API error for dashboard display."""


class PipelineLensApiClient:
    def __init__(self, base_url: str) -> None:
        try:
            parts = urlsplit(base_url)
            host = parts.hostname or ""
            local = host.lower() == "localhost"
            if not local:
                local = ip_address(host).is_loopback
            valid = (
                local and parts.scheme in {"http", "https"}
                and parts.username is None and parts.password is None
                and parts.path in {"", "/"} and not parts.query and not parts.fragment
                and parts.port != 0 and not any(char.isspace() for char in base_url)
                and "\\" not in base_url
            )
        except ValueError:
            valid = False
        if not valid:
            raise ApiClientError(
                "Configure the dashboard API with a loopback address (localhost, 127.0.0.1 "
                "or ::1), without credentials, a path, query parameters or fragments."
            )
        self.base_url = base_url.rstrip("/")

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        return self._request("POST", path, json=payload)

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        if (
            not path.startswith("/") or path.startswith("//")
            or any(char in path for char in "?#\\")
            or ".." in path.split("/")
        ):
            raise ApiClientError("The local API route is invalid.")
        local = path.startswith("/api/v1/local/") or path == "/api/v1/local"
        headers = {"X-PipelineLens-Local": "1"} if local else {}
        # The inspection API has a 150-second work budget. Allow its bounded reads
        # to finish, but fail quickly on a missing local service or a stalled write.
        timeout = httpx.Timeout(180.0 if local else 45.0, connect=5.0, write=15.0, pool=5.0)
        try:
            with httpx.Client(
                base_url=self.base_url, timeout=timeout,
                trust_env=False, follow_redirects=False,
            ) as client:
                response = client.request(method, path, headers=headers, **kwargs)
        except httpx.TimeoutException:
            raise ApiClientError(
                "The bounded inspection timed out. Try a specific job link, or retry after "
                "checking GitLab and runner connectivity."
            ) from None
        except httpx.HTTPError:
            raise ApiClientError(
                "The local PipelineLens API is unreachable. Start the local API and try again."
            ) from None
        except (TypeError, ValueError):
            raise ApiClientError("The local API request could not be encoded.") from None
        if not 200 <= response.status_code < 300:
            # Never echo upstream bodies, Location headers, or Pydantic validation
            # details: even a JSON validation error can contain the submitted token.
            raise ApiClientError(_status_error(response.status_code))
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            raise ApiClientError(
                "The local API returned unreadable JSON. Restart or update the local API "
                "and try again."
            ) from None


def _status_error(status: int) -> str:
    if status in {400, 422}:
        return (
            "The request was not accepted. Check the GitLab URL, connection selection and "
            "read-only token. Automatic reuse requires a saved or configured same-host connection."
        )
    if status in {401, 403}:
        return (
            "Access could not be verified. Check the link and token scope or expiry, or use "
            "a different read-only connection. Local routes require the localhost dashboard."
        )
    if status == 404:
        return (
            "The project, link or local API route was not found. Verify the link and read "
            "access, and check that the local API is up to date."
        )
    if status == 409:
        return "The resource changed during inspection. Verify the link and try Force refresh."
    if status == 429:
        return "The inspection was rate-limited. Try again later; no automatic retry was sent."
    if status == 504:
        return "The bounded inspection timed out. Try a specific job link or retry later."
    if 300 <= status < 400:
        return "The local API returned a redirect. It was not followed; check the API address."
    return "The local API could not complete the request. Check the local service and try again."
