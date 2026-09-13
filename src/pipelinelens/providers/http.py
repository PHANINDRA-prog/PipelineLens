"""Small safe HTTP foundation for read-only CI provider adapters."""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from pipelinelens.providers.base import ProviderError
from pipelinelens.services.redaction import redact_text


class ReadOnlyHttpProvider:
    """Makes bounded, token-redacted provider API calls."""

    provider_name = "provider"

    def __init__(self, base_url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._transport = transport
        self._shared_client: httpx.AsyncClient | None = None

    def _headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            follow_redirects=True,
            timeout=httpx.Timeout(20.0, connect=8.0),
            transport=self._transport,
        )

    async def __aenter__(self):
        if self._shared_client is not None:
            raise RuntimeError("Provider request scope is already active.")
        self._shared_client = self._new_client()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._shared_client is not None:
            await self._shared_client.aclose()
            self._shared_client = None

    @retry(
        retry=retry_if_exception_type(httpx.TransportError),
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=0.25, max=2),
        reraise=True,
    )
    async def _request(
        self,
        token: str,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        request_headers = self._headers(token)
        if headers:
            request_headers.update(headers)
        if self._shared_client is not None:
            response = await self._shared_client.request(
                method,
                path,
                params=params,
                headers=request_headers,
            )
        else:
            async with self._new_client() as client:
                response = await client.request(
                    method,
                    path,
                    params=params,
                    headers=request_headers,
                )

        if response.is_error:
            raise ProviderError(
                self.provider_name, response.status_code, self._safe_error_message(response)
            )
        return response

    def _safe_error_message(self, response: httpx.Response) -> str:
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            message = str(payload.get("message") or payload.get("error") or "request was rejected")
        else:
            message = response.text[:300] or "request was rejected"
        return redact_text(message).replace("\n", " ").strip()
