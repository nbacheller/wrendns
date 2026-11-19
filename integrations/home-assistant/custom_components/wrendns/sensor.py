"""Sensors: the last 24 hours' numbers, health, open anomalies, and the device inventory."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import WrendnsConfigEntry, WrendnsData
from .entity import WrendnsEntity

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class WrendnsSensorDescription(SensorEntityDescription):
    value: Callable[[WrendnsData], Any]
    attrs: Callable[[WrendnsData], dict[str, Any]] | None = None
    # The read this sensor needs (`WrendnsData.unavailable` key), if not a required one.
    needs: str | None = None


def _open_anomalies(d: WrendnsData) -> int | None:
    if d.anomalies is None:
        return None
    return sum(1 for a in d.anomalies if not a.get("informational") and not a.get("mutedBy"))


def _anomaly_attrs(d: WrendnsData) -> dict[str, Any]:
    items = [a for a in d.anomalies or [] if not a.get("informational") and not a.get("mutedBy")]
    return {
        "findings": [
            {
                "id": a.get("id"),
                "kind": a.get("kind"),
                "device": a.get("clientName") or a.get("client"),
                "domain": a.get("domain"),
                "detail": a.get("detail"),
            }
            for a in items[:20]
        ]
    }


def _health_attrs(d: WrendnsData) -> dict[str, Any]:
    return {
        "reasons": [r.get("summary") for r in d.health.get("reasons", [])],
        "codes": [r.get("code") for r in d.health.get("reasons", [])],
    }


def _devices_attrs(d: WrendnsData) -> dict[str, Any]:
    by_source: dict[str, int] = {}
    for x in d.devices or []:
        key = x.get("router") or x.get("source") or "unknown"
        by_source[key] = by_source.get(key, 0) + 1
    return {
        "by_source": by_source,
        "with_dns_name": sum(1 for x in d.devices or [] if x.get("dnsName")),
    }


def _networks_attrs(d: WrendnsData) -> dict[str, Any]:
    return {
        "networks": [
            {
                "name": n.get("name"),
                "subnet": n.get("subnet"),
                "vlan": n.get("vlan"),
                "devices": n.get("devices"),
                "used_percent": n.get("usedPercent"),
                "group": n.get("group"),
            }
            for n in d.networks or []
        ]
    }


SENSORS: tuple[WrendnsSensorDescription, ...] = (
    WrendnsSensorDescription(
        key="queries_24h",
        translation_key="queries_24h",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="queries",
        value=lambda d: d.summary.get("queries"),
    ),
    WrendnsSensorDescription(
        key="blocked_24h",
        translation_key="blocked_24h",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement="queries",
        value=lambda d: d.summary.get("blocked"),
    ),
    WrendnsSensorDescription(
        key="blocked_percent",
        translation_key="blocked_percent",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        suggested_display_precision=1,
        value=lambda d: d.summary.get("blockedPercent"),
    ),
    WrendnsSensorDescription(
        key="cache_hit_percent",
        translation_key="cache_hit_percent",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        suggested_display_precision=1,
        value=lambda d: d.summary.get("cacheHitPercent"),
    ),
    WrendnsSensorDescription(
        key="active_clients",
        translation_key="active_clients",
        state_class=SensorStateClass.MEASUREMENT,
        value=lambda d: d.summary.get("activeClients"),
    ),
    WrendnsSensorDescription(
        key="upstream_p90",
        translation_key="upstream_p90",
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfTime.MILLISECONDS,
        suggested_display_precision=1,
        value=lambda d: d.latency_ms("upstream"),
    ),
    WrendnsSensorDescription(
        key="health",
        translation_key="health",
        device_class=SensorDeviceClass.ENUM,
        options=["healthy", "degraded", "severe"],
        value=lambda d: d.health.get("level"),
        attrs=_health_attrs,
    ),
    WrendnsSensorDescription(
        key="open_anomalies",
        translation_key="open_anomalies",
        state_class=SensorStateClass.MEASUREMENT,
        value=_open_anomalies,
        attrs=_anomaly_attrs,
        needs="anomalies",
    ),
    WrendnsSensorDescription(
        key="known_devices",
        translation_key="known_devices",
        state_class=SensorStateClass.MEASUREMENT,
        value=lambda d: None if d.devices is None else len(d.devices),
        attrs=_devices_attrs,
        needs="devices",
    ),
    WrendnsSensorDescription(
        key="networks",
        translation_key="networks",
        state_class=SensorStateClass.MEASUREMENT,
        value=lambda d: None if d.networks is None else len(d.networks),
        attrs=_networks_attrs,
        needs="networks",
    ),
    WrendnsSensorDescription(
        key="version",
        translation_key="version",
        entity_category=EntityCategory.DIAGNOSTIC,
        value=lambda d: (d.info.get("build") or {}).get("version") or d.info.get("version"),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: WrendnsConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        WrendnsSensor(coordinator, d)
        for d in SENSORS
        # A read this token or build can't make gets no entity (it would only ever be unknown).
        if d.needs is None or d.needs not in coordinator.data.unavailable
    )


class WrendnsSensor(WrendnsEntity, SensorEntity):
    entity_description: WrendnsSensorDescription

    def __init__(self, coordinator, description: WrendnsSensorDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        return self.entity_description.value(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs is None:
            return None
        return self.entity_description.attrs(self.coordinator.data)
