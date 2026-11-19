"""Blocking switches: everyone's, and one per client group.

Off pauses blocking for the configured minutes (WrenDNS turns it back on by itself when
the pause ends); on resumes it. Turning the "everyone" switch on resumes every pause, groups'
too, which is what WrenDNS's resume does without a group.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .api import WrendnsError
from .const import CONF_PAUSE_MINUTES, DEFAULT_PAUSE_MINUTES
from .coordinator import WrendnsConfigEntry, WrendnsCoordinator
from .entity import WrendnsEntity

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: WrendnsConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    known: set[str] = set()

    @callback
    def add_groups() -> None:
        new = [g["name"] for g in coordinator.data.groups or [] if g.get("name") and g["name"] not in known]
        known.update(new)
        async_add_entities(WrendnsBlocking(coordinator, g) for g in new)

    async_add_entities([WrendnsBlocking(coordinator, None)])
    add_groups()
    # A group added in WrenDNS later gets its switch on the next poll.
    entry.async_on_unload(coordinator.async_add_listener(add_groups))


class WrendnsBlocking(WrendnsEntity, SwitchEntity):
    """Blocking for everyone (`group` None) or for one group."""

    def __init__(self, coordinator: WrendnsCoordinator, group: str | None) -> None:
        super().__init__(coordinator, f"blocking_{group}" if group else "blocking")
        self._group = group
        if group:
            self._attr_translation_key = "group_blocking"
            self._attr_translation_placeholders = {"group": group}
        else:
            self._attr_translation_key = "blocking"

    @property
    def available(self) -> bool:
        if not super().available:
            return False
        if self._group is None:
            return True
        return any(g.get("name") == self._group for g in self.coordinator.data.groups or [])

    @property
    def is_on(self) -> bool:
        return self.coordinator.data.paused(self._group) is None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        p = self.coordinator.data.paused(self._group)
        return {"paused_until": p.get("until") if p else None, "group": self._group}

    def _reason(self, what: str) -> str:
        who = self._group or "everyone"
        return f"Home Assistant: {what} blocking for {who}"

    async def async_turn_off(self, **kwargs: Any) -> None:
        minutes = int(self.coordinator.config_entry.options.get(CONF_PAUSE_MINUTES, DEFAULT_PAUSE_MINUTES))
        try:
            state = await self.coordinator.client.pause(minutes, self._group, self._reason(f"pause ({minutes} min)"))
        except WrendnsError as err:
            raise HomeAssistantError(f"Couldn't pause blocking: {err}") from err
        self.coordinator.set_blocking(state)

    async def async_turn_on(self, **kwargs: Any) -> None:
        try:
            state = await self.coordinator.client.resume(self._group, self._reason("resume"))
        except WrendnsError as err:
            raise HomeAssistantError(f"Couldn't resume blocking: {err}") from err
        self.coordinator.set_blocking(state)
