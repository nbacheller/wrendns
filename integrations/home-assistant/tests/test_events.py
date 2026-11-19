"""Anomaly findings become events once, and missing scopes degrade instead of failing."""

from __future__ import annotations

from typing import Any

from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_capture_events
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.wrendns.const import CONF_TOKEN, DOMAIN, EVENT_ANOMALY

URL = "http://wrendns.test:8053"


def _mock(aioclient_mock: AiohttpClientMocker, findings: list[dict[str, Any]], *, inventory: bool = True) -> None:
    aioclient_mock.clear_requests()
    aioclient_mock.get(
        f"{URL}/api/v1/system/info", json={"node": "pi", "version": "0.8.0", "build": {"version": "0.8.0"}}
    )
    aioclient_mock.get(f"{URL}/api/v1/system/health", json={"level": "healthy", "reasons": [], "checkedAt": ""})
    aioclient_mock.get(
        f"{URL}/api/v1/stats/summary",
        json={
            "queries": 10,
            "blocked": 2,
            "blockedPercent": 20.0,
            "cacheHitPercent": 50.0,
            "activeClients": 3,
            "latency": [{"key": "upstream", "p90Ms": 12.5}],
        },
    )
    aioclient_mock.get(f"{URL}/api/v1/blocking", json={"items": [{"pauses": []}]})
    aioclient_mock.get(f"{URL}/api/v1/groups", json={"items": [{"name": "default"}]})
    aioclient_mock.get(f"{URL}/api/v1/analytics/anomalies", json={"items": findings})
    if inventory:
        aioclient_mock.get(f"{URL}/api/v1/dhcp/leases", json={"items": []})
        aioclient_mock.get(f"{URL}/api/v1/networks", json={"items": []})
    else:
        # An upstream WrenDNS build: agents can't read the leases, and there's no /networks.
        aioclient_mock.get(f"{URL}/api/v1/dhcp/leases", status=403, json={"code": "forbidden", "detail": "scope"})
        aioclient_mock.get(f"{URL}/api/v1/networks", status=404, json={"code": "not_found", "detail": "no"})


FINDING = {
    "id": "f1",
    "kind": "beacon",
    "client": "192.168.20.9 (plug)",
    "clientName": "plug",
    "detail": "every 300 s",
    "observed": 12,
    "baseline": 0,
}


async def test_new_findings_fire_once(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    _mock(aioclient_mock, [FINDING])
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=URL, data={CONF_URL: URL, CONF_TOKEN: "tt_x_y", CONF_VERIFY_SSL: True}
    )
    entry.add_to_hass(hass)
    events = async_capture_events(hass, EVENT_ANOMALY)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert events == [], "findings that were already there aren't replayed"
    new = {
        "id": "f2",
        "kind": "drift",
        "client": "192.168.20.7",
        "detail": "30 new domains",
        "observed": 30,
        "baseline": 0,
    }
    muted = {"id": "f3", "kind": "rate_spike", "client": "192.168.20.8", "detail": "x", "mutedBy": "lg-tv-ptr"}
    _mock(aioclient_mock, [FINDING, new, muted])
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert [e.data["id"] for e in events] == ["f2"]
    assert events[0].data["kind"] == "drift" and events[0].data["config_entry_id"] == entry.entry_id
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert len(events) == 1, "once"
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_older_builds_and_narrow_tokens(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    _mock(aioclient_mock, [], inventory=False)
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=URL, data={CONF_URL: URL, CONF_TOKEN: "tt_x_y", CONF_VERIFY_SSL: True}
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    data = entry.runtime_data.data
    assert set(data.unavailable) == {"devices", "networks"}
    ids = [s.entity_id for s in hass.states.async_all("sensor")]
    assert not any("known_devices" in i or i.endswith("_networks") for i in ids), ids
    assert any("queries" in i for i in ids)
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_bad_token_starts_reauth(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    aioclient_mock.get(f"{URL}/api/v1/system/info", status=401, json={"code": "unauthorized", "detail": "bad token"})
    for p in ("system/health", "stats/summary", "blocking"):
        aioclient_mock.get(f"{URL}/api/v1/{p}", status=401, json={"code": "unauthorized", "detail": "bad token"})
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=URL, data={CONF_URL: URL, CONF_TOKEN: "tt_x_y", CONF_VERIFY_SSL: True}
    )
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    flows = hass.config_entries.flow.async_progress()
    assert [f["context"]["source"] for f in flows] == ["reauth"]
