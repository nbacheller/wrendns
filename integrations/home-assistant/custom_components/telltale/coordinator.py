"""Polls TelltaleDNS and turns new anomaly findings into Home Assistant events."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field, replace
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    TelltaleAuthError,
    TelltaleClient,
    TelltaleConnectionError,
    TelltaleError,
    TelltaleForbidden,
)
from .const import (
    CONF_ANOMALY_EVENTS,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_ANOMALY,
)

_LOGGER = logging.getLogger(__name__)

type TelltaleConfigEntry = ConfigEntry[TelltaleCoordinator]


@dataclass(slots=True)
class TelltaleData:
    """One poll's worth of TelltaleDNS."""

    info: dict[str, Any]
    health: dict[str, Any]
    summary: dict[str, Any]
    blocking: list[dict[str, Any]]
    groups: list[dict[str, Any]] | None
    anomalies: list[dict[str, Any]] | None
    devices: list[dict[str, Any]] | None
    networks: list[dict[str, Any]] | None
    # Reads this token may not make (a scope it lacks), or this build doesn't have.
    unavailable: dict[str, str] = field(default_factory=dict)

    def paused(self, group: str | None) -> dict[str, Any] | None:
        """The pause for `group` (`None`: everyone) on any node, if one is on."""
        for node in self.blocking:
            for p in node.get("pauses", []):
                if p.get("group") == group:
                    return p
        return None

    def latency_ms(self, key: str, percentile: str = "p90Ms") -> float | None:
        for row in self.summary.get("latency", []):
            if row.get("key") == key:
                return row.get(percentile)
        return None


class TelltaleCoordinator(DataUpdateCoordinator[TelltaleData]):
    """Reads the node every 30 seconds."""

    config_entry: TelltaleConfigEntry

    def __init__(self, hass: HomeAssistant, entry: TelltaleConfigEntry, client: TelltaleClient) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=DEFAULT_SCAN_INTERVAL,
        )
        self.client = client
        # Anomaly IDs already seen: the first poll only learns them, so a restart doesn't
        # replay a day of findings as events.
        self._seen: set[str] | None = None

    async def _optional(self, name: str, call: Any, unavailable: dict[str, str]) -> Any:
        try:
            return await call
        except TelltaleAuthError:
            raise
        except TelltaleForbidden as err:
            unavailable[name] = f"the token can't read this: {err}"
        except TelltaleError as err:
            if err.status in (404, 405):
                unavailable[name] = "this TelltaleDNS build doesn't have it"
            else:
                unavailable[name] = str(err)
        return None

    async def _async_update_data(self) -> TelltaleData:
        c = self.client
        unavailable: dict[str, str] = {}
        try:
            info, health, summary, blocking = await asyncio.gather(
                c.system_info(), c.health(), c.summary(), c.blocking()
            )
            groups, anomalies, devices, networks = await asyncio.gather(
                self._optional("groups", c.groups(), unavailable),
                self._optional("anomalies", c.anomalies(), unavailable),
                self._optional("devices", c.devices(), unavailable),
                self._optional("networks", c.networks(), unavailable),
            )
        except TelltaleAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except TelltaleForbidden as err:
            raise UpdateFailed(f"the token needs the analytics:read scope ({err})") from err
        except TelltaleConnectionError as err:
            raise UpdateFailed(str(err)) from err
        except TelltaleError as err:
            raise UpdateFailed(str(err)) from err
        data = TelltaleData(
            info=info,
            health=health,
            summary=summary,
            blocking=blocking,
            groups=groups,
            anomalies=anomalies,
            devices=devices,
            networks=networks,
            unavailable=unavailable,
        )
        self._fire_new_anomalies(data)
        return data

    def set_blocking(self, blocking: list[dict[str, Any]]) -> None:
        """Apply the pause state a pause or resume answered with (no extra poll)."""
        if self.data is not None:
            self.async_set_updated_data(replace(self.data, blocking=blocking))

    def _fire_new_anomalies(self, data: TelltaleData) -> None:
        if data.anomalies is None:
            return
        ids = {a["id"] for a in data.anomalies if "id" in a}
        if self._seen is None:
            self._seen = ids
            return
        if not self.config_entry.options.get(CONF_ANOMALY_EVENTS, True):
            self._seen |= ids
            return
        for a in data.anomalies:
            fid = a.get("id")
            if not fid or fid in self._seen or a.get("mutedBy"):
                continue
            self.hass.bus.async_fire(
                EVENT_ANOMALY,
                {
                    "config_entry_id": self.config_entry.entry_id,
                    "id": fid,
                    "kind": a.get("kind"),
                    "client": a.get("client"),
                    "client_name": a.get("clientName"),
                    "domain": a.get("domain"),
                    "detail": a.get("detail"),
                    "observed": a.get("observed"),
                    "baseline": a.get("baseline"),
                    "informational": a.get("informational", False),
                    "window_start": a.get("windowStart"),
                },
            )
        # Only the current window's findings are kept, so the set doesn't grow forever.
        self._seen = ids
