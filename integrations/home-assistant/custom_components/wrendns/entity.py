"""The base entity: one Home Assistant device per WrenDNS node (or cluster)."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import WrendnsCoordinator


class WrendnsEntity(CoordinatorEntity[WrendnsCoordinator]):
    """Shares the device and the unique-ID prefix."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: WrendnsCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id or entry.entry_id}_{key}"
        info = coordinator.data.info if coordinator.data else {}
        cluster = info.get("cluster") or {}
        build = info.get("build") or {}
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id or entry.entry_id)},
            name=cluster.get("name") or info.get("node") or "WrenDNS",
            manufacturer="WrenDNS",
            model="Cluster" if cluster else "DNS resolver",
            sw_version=build.get("version") or info.get("version"),
            configuration_url=coordinator.client.url,
            entry_type=DeviceEntryType.SERVICE,
        )
