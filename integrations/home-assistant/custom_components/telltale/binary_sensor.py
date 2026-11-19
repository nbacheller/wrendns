"""A problem sensor: on while TelltaleDNS reports itself degraded or severe."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import TelltaleConfigEntry
from .entity import TelltaleEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: TelltaleConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([TelltaleProblem(entry.runtime_data)])


class TelltaleProblem(TelltaleEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_translation_key = "problem"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "problem")

    @property
    def is_on(self) -> bool:
        return self.coordinator.data.health.get("level", "healthy") != "healthy"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        reasons = self.coordinator.data.health.get("reasons", [])
        return {"reasons": [r.get("summary") for r in reasons]}
