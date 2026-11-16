"""TelltaleDNS for Home Assistant: see what your devices ask DNS, pause blocking, and react
to device anomalies (a camera calling 30 new domains, a plug beaconing every 5 minutes).

Talks to TelltaleDNS's REST API with an API token (an agent token with only the scopes it
needs is best). Read-only unless you use the switches or the actions.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

import voluptuous as vol
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
    HomeAssistantError,
    ServiceValidationError,
)
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.typing import ConfigType

from .api import TelltaleAuthError, TelltaleClient, TelltaleConnectionError, TelltaleError
from .const import (
    ATTR_DEVICE,
    ATTR_ENTRY_ID,
    ATTR_GROUP,
    ATTR_IDS,
    ATTR_MINUTES,
    ATTR_NOTE,
    ATTR_REASON,
    CONF_QUARANTINE_GROUP,
    CONF_TOKEN,
    DEFAULT_QUARANTINE_GROUP,
    DOMAIN,
    MAX_PAUSE_MINUTES,
    SERVICE_ACKNOWLEDGE,
    SERVICE_PAUSE,
    SERVICE_QUARANTINE,
    SERVICE_RELEASE,
    SERVICE_RESUME,
)
from .coordinator import TelltaleConfigEntry, TelltaleCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)

_ENTRY = vol.Optional(ATTR_ENTRY_ID)
_REASON = vol.Optional(ATTR_REASON)
PAUSE_SCHEMA = vol.Schema(
    {
        _ENTRY: cv.string,
        vol.Required(ATTR_MINUTES): vol.All(vol.Coerce(int), vol.Range(min=1, max=MAX_PAUSE_MINUTES)),
        vol.Optional(ATTR_GROUP): cv.string,
        _REASON: cv.string,
    }
)
RESUME_SCHEMA = vol.Schema({_ENTRY: cv.string, vol.Optional(ATTR_GROUP): cv.string, _REASON: cv.string})
DEVICE_SCHEMA = vol.Schema({_ENTRY: cv.string, vol.Required(ATTR_DEVICE): cv.string, _REASON: cv.string})
ACK_SCHEMA = vol.Schema(
    {
        _ENTRY: cv.string,
        vol.Required(ATTR_IDS): vol.All(cv.ensure_list, [cv.string], vol.Length(min=1, max=1000)),
        vol.Optional(ATTR_NOTE): cv.string,
        _REASON: cv.string,
    }
)

STORE_VERSION = 1


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the actions once, for every TelltaleDNS entry."""
    store: Store[dict[str, Any]] = Store(hass, STORE_VERSION, f"{DOMAIN}.quarantine")
    hass.data[DOMAIN] = {"store": store}

    def entry_for(call: ServiceCall) -> TelltaleConfigEntry:
        entries = [e for e in hass.config_entries.async_loaded_entries(DOMAIN)]
        wanted = call.data.get(ATTR_ENTRY_ID)
        if wanted:
            entries = [e for e in entries if e.entry_id == wanted]
        if len(entries) != 1:
            raise ServiceValidationError(
                "Name the TelltaleDNS entry (config_entry_id): "
                + ("none is loaded" if not entries else "more than one is loaded")
            )
        return entries[0]

    def reason(call: ServiceCall, what: str) -> str:
        return call.data.get(ATTR_REASON) or f"Home Assistant: {what}"

    async def pause(call: ServiceCall) -> None:
        entry = entry_for(call)
        group = call.data.get(ATTR_GROUP)
        minutes = call.data[ATTR_MINUTES]
        state = await _run(entry.runtime_data.client.pause(minutes, group, reason(call, f"pause {minutes} min")))
        entry.runtime_data.set_blocking(state)

    async def resume(call: ServiceCall) -> None:
        entry = entry_for(call)
        state = await _run(entry.runtime_data.client.resume(call.data.get(ATTR_GROUP), reason(call, "resume")))
        entry.runtime_data.set_blocking(state)

    async def acknowledge(call: ServiceCall) -> ServiceResponse:
        entry = entry_for(call)
        result = await _run(
            entry.runtime_data.client.acknowledge(
                call.data[ATTR_IDS], call.data.get(ATTR_NOTE), reason(call, "acknowledge anomalies")
            )
        )
        await entry.runtime_data.async_request_refresh()
        return {"changed": result.get("changed", 0), "unknown": result.get("unknown", [])}

    async def quarantine(call: ServiceCall) -> ServiceResponse:
        entry = entry_for(call)
        return await _quarantine(hass, store, entry, call.data[ATTR_DEVICE], reason(call, "quarantine"))

    async def release(call: ServiceCall) -> ServiceResponse:
        entry = entry_for(call)
        return await _release(hass, store, entry, call.data[ATTR_DEVICE], reason(call, "release from quarantine"))

    hass.services.async_register(DOMAIN, SERVICE_PAUSE, pause, schema=PAUSE_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_RESUME, resume, schema=RESUME_SCHEMA)
    hass.services.async_register(
        DOMAIN, SERVICE_ACKNOWLEDGE, acknowledge, schema=ACK_SCHEMA, supports_response=SupportsResponse.OPTIONAL
    )
    hass.services.async_register(
        DOMAIN, SERVICE_QUARANTINE, quarantine, schema=DEVICE_SCHEMA, supports_response=SupportsResponse.OPTIONAL
    )
    hass.services.async_register(
        DOMAIN, SERVICE_RELEASE, release, schema=DEVICE_SCHEMA, supports_response=SupportsResponse.OPTIONAL
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: TelltaleConfigEntry) -> bool:
    session = async_get_clientsession(hass, verify_ssl=entry.data.get(CONF_VERIFY_SSL, True))
    client = TelltaleClient(
        session, entry.data[CONF_URL], entry.data[CONF_TOKEN], verify_ssl=entry.data.get(CONF_VERIFY_SSL, True)
    )
    coordinator = TelltaleCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_options_updated))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: TelltaleConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _options_updated(hass: HomeAssistant, entry: TelltaleConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def _run(call: Any) -> Any:
    try:
        return await call
    except TelltaleAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except TelltaleConnectionError as err:
        raise ConfigEntryNotReady(str(err)) from err
    except TelltaleError as err:
        raise HomeAssistantError(f"TelltaleDNS refused: {err}") from err


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def _find(entry: TelltaleConfigEntry, device: str) -> tuple[dict[str, Any] | None, list[str], str]:
    """The configured client for `device` (a name, IP, or MAC), what to match it by, and its name.

    A device TelltaleDNS doesn't know by name yet is matched by its MAC when a router, Home
    Assistant, or the neighbor table knows it (so the quarantine follows it to a new address),
    else by the address given.
    """
    client = entry.runtime_data.client
    wanted = device.strip()
    low = wanted.lower()
    clients = await _run(client.clients())
    for c in clients:
        if c.get("name", "").lower() == low or low in (m.lower() for m in c.get("match", [])):
            return c, list(c.get("match", [])), c["name"]
    match: list[str]
    if _MAC.match(wanted):
        match = [low.replace("-", ":")]
    elif _is_ip(wanted):
        match = [wanted]
    else:
        match = []
    name = wanted
    devices = entry.runtime_data.data.devices or []
    for d in devices:
        hit = (
            d.get("ip") == wanted
            or (d.get("mac") or "").lower() == low.replace("-", ":")
            or (d.get("clientName") or "").lower() == low
            or (d.get("hostname") or "").lower() == low
            or (d.get("dnsName") or "").lower().rstrip(".") == low.rstrip(".")
        )
        if hit:
            match = [d["mac"]] if d.get("mac") else [d["ip"]]
            name = d.get("clientName") or d.get("hostname") or wanted
            break
    if not match:
        raise ServiceValidationError(f"TelltaleDNS doesn't know a device called {wanted!r}: give its IP or MAC address")
    return None, match, name


async def _quarantine(
    hass: HomeAssistant, store: Store[dict[str, Any]], entry: TelltaleConfigEntry, device: str, reason: str
) -> dict[str, Any]:
    group = entry.options.get(CONF_QUARANTINE_GROUP, DEFAULT_QUARANTINE_GROUP)
    existing, match, name = await _find(entry, device)
    data = await store.async_load() or {}
    saved = data.setdefault(entry.entry_id, {})
    if name not in saved:
        saved[name] = {
            "groups": list(existing.get("groups", [])) if existing else [],
            "created": existing is None,
        }
    try:
        await entry.runtime_data.client.put_client(name, match, [group], reason)
    except TelltaleError as err:
        hint = {
            422: f" Create a group called {group!r} in TelltaleDNS first (see the integration's README).",
            409: f" {name!r} is defined in TelltaleDNS's configuration files; change its groups there.",
            403: " The token needs the config:write:clients scope.",
        }.get(err.status or 0, "")
        raise HomeAssistantError(f"TelltaleDNS refused the quarantine: {err}.{hint}") from err
    await store.async_save(data)
    await entry.runtime_data.async_request_refresh()
    return {"device": name, "match": match, "group": group}


async def _release(
    hass: HomeAssistant, store: Store[dict[str, Any]], entry: TelltaleConfigEntry, device: str, reason: str
) -> dict[str, Any]:
    existing, match, name = await _find(entry, device)
    data = await store.async_load() or {}
    saved = data.get(entry.entry_id, {}).pop(name, None)
    client = entry.runtime_data.client
    if saved and saved.get("created"):
        await _run(client.delete_client(name, reason))
        result = {"device": name, "deleted": True}
    else:
        groups = (saved or {}).get("groups") or ["default"]
        await _run(client.put_client(name, match, groups, reason))
        result = {"device": name, "groups": groups}
    await store.async_save(data)
    await entry.runtime_data.async_request_refresh()
    return result
