"""REQ: T24.21 — seeds the test devices (see const.py). Test fixture only; never shipped."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import DEVICES, DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    devices = dr.async_get(hass)
    entities = er.async_get(hass)
    for dev in DEVICES:
        mac = str(dev["mac"])
        device = devices.async_get_or_create(
            config_entry_id=entry.entry_id,
            connections={(dr.CONNECTION_NETWORK_MAC, mac)},
            name=str(dev["name"]),
        )
        if dev["name_by_user"]:
            device = devices.async_update_device(device.id, name_by_user=str(dev["name_by_user"]))
        slug = str(dev["name"]).lower().replace(" ", "_")
        ent = entities.async_get_or_create(
            "sensor",
            DOMAIN,
            mac,
            config_entry=entry,
            device_id=device.id,
            suggested_object_id=f"{slug}_presence",
        )
        hass.states.async_set(ent.entity_id, "home", {"friendly_name": str(dev["name"])})
        if dev["address"]:
            # A device_tracker state carries the MAC and address TelltaleDNS matches on.
            hass.states.async_set(
                f"device_tracker.{slug}",
                "home",
                {"mac": mac, "ip": dev["address"], "source_type": "router"},
            )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    return True
