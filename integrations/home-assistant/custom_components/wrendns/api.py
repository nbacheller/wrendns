"""A small async client for the WrenDNS REST API (`/api/v1`).

Only what the integration uses. Every change sends `X-Wrendns-Reason` (agent tokens must
give one, and it goes into WrenDNS's audit log either way).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import aiohttp

TIMEOUT = aiohttp.ClientTimeout(total=15)


class WrendnsError(Exception):
    """A request failed."""

    def __init__(self, message: str, status: int | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class WrendnsAuthError(WrendnsError):
    """The token is wrong, expired, or revoked (HTTP 401)."""


class WrendnsForbidden(WrendnsError):
    """The token can't do this (HTTP 403: a missing scope, or agents switched off)."""


class WrendnsConnectionError(WrendnsError):
    """WrenDNS didn't answer."""


@dataclass(slots=True)
class Problem:
    """An RFC 9457 problem from WrenDNS."""

    status: int
    code: str | None
    detail: str
    hint: str | None

    def message(self) -> str:
        text = self.detail or f"HTTP {self.status}"
        return f"{text} ({self.hint})" if self.hint else text


class WrendnsClient:
    """Talks to one WrenDNS node (in a cluster, any node answers for the cluster)."""

    def __init__(self, session: aiohttp.ClientSession, url: str, token: str, *, verify_ssl: bool = True) -> None:
        self._session = session
        self._base = url.rstrip("/")
        self._token = token
        self._ssl = None if verify_ssl else False

    @property
    def url(self) -> str:
        return self._base

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: Any = None,
        reason: str | None = None,
    ) -> Any:
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "X-Wrendns-Client": "home-assistant/0.1.0",
        }
        if reason:
            headers["X-Wrendns-Reason"] = reason[:500]
        try:
            async with self._session.request(
                method,
                f"{self._base}{path}",
                params=params,
                json=json,
                headers=headers,
                timeout=TIMEOUT,
                ssl=self._ssl,
            ) as resp:
                if resp.status >= 400:
                    problem = await _problem(resp)
                    if resp.status == 401:
                        raise WrendnsAuthError(problem.message(), resp.status, problem.code)
                    if resp.status == 403:
                        raise WrendnsForbidden(problem.message(), resp.status, problem.code)
                    raise WrendnsError(problem.message(), resp.status, problem.code)
                if resp.status == 204:
                    return None
                return await resp.json(content_type=None)
        except (aiohttp.ClientConnectionError, TimeoutError) as err:
            raise WrendnsConnectionError(f"{self._base}: {err or type(err).__name__}") from err

    # Reads (analytics:read, config:read).
    async def system_info(self) -> dict[str, Any]:
        return await self._request("GET", "/api/v1/system/info")

    async def health(self) -> dict[str, Any]:
        return await self._request("GET", "/api/v1/system/health")

    async def summary(self, since: str = "-24h") -> dict[str, Any]:
        return await self._request("GET", "/api/v1/stats/summary", params={"from": since})

    async def blocking(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/api/v1/blocking"))["items"]

    async def groups(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/api/v1/groups"))["items"]

    async def clients(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "/api/v1/clients"))["items"]

    async def anomalies(self, since: str = "-24h") -> list[dict[str, Any]]:
        params = {"since": since, "acknowledged": "false"}
        return (await self._request("GET", "/api/v1/analytics/anomalies", params=params))["items"]

    async def devices(self) -> list[dict[str, Any]]:
        """Devices the routers, Home Assistant, and mDNS found (`/dhcp/leases`)."""
        return (await self._request("GET", "/api/v1/dhcp/leases"))["items"]

    async def networks(self) -> list[dict[str, Any]]:
        """The networks the routers report (the fork's `/networks`; 404 on older builds)."""
        return (await self._request("GET", "/api/v1/networks"))["items"]

    # Changes (ops:pause, ops:anomalies, config:write:clients).
    async def pause(self, minutes: int, group: str | None, reason: str) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"minutes": minutes}
        if group:
            body["group"] = group
        return (await self._request("POST", "/api/v1/blocking/pause", json=body, reason=reason))["items"]

    async def resume(self, group: str | None, reason: str) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"group": group} if group else {}
        return (await self._request("POST", "/api/v1/blocking/resume", json=body, reason=reason))["items"]

    async def acknowledge(self, ids: list[str], note: str | None, reason: str) -> dict[str, Any]:
        body: dict[str, Any] = {"ids": ids}
        if note:
            body["note"] = note[:200]
        return await self._request("POST", "/api/v1/analytics/anomalies/acknowledge", json=body, reason=reason)

    async def put_client(
        self, name: str, match: list[str], groups: list[str], reason: str, *, kind: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"match": match, "groups": groups}
        if kind:
            body["kind"] = kind
        return await self._request("PUT", f"/api/v1/clients/{quote(name, safe='')}", json=body, reason=reason)

    async def delete_client(self, name: str, reason: str) -> None:
        await self._request("DELETE", f"/api/v1/clients/{quote(name, safe='')}", reason=reason)


async def _problem(resp: aiohttp.ClientResponse) -> Problem:
    try:
        body = await resp.json(content_type=None)
    except (aiohttp.ContentTypeError, ValueError):
        body = None
    if not isinstance(body, dict):
        return Problem(resp.status, None, f"HTTP {resp.status}", None)
    return Problem(
        resp.status,
        body.get("code"),
        str(body.get("detail") or body.get("title") or f"HTTP {resp.status}"),
        body.get("hint"),
    )
