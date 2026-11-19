"""The integration against a real TelltaleDNS node: setup, entities, pausing, quarantine."""

from __future__ import annotations

import asyncio

from homeassistant.config_entries import SOURCE_USER
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.telltale.const import CONF_TOKEN, DOMAIN

from .conftest import Node, ask_dns


async def _setup(hass: HomeAssistant, node: Node) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=node.url,
        data={CONF_URL: node.url, CONF_TOKEN: node.token, CONF_VERIFY_SSL: True},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _entity(hass: HomeAssistant, entry: MockConfigEntry, key: str) -> str:
    reg = er.async_get(hass)
    for e in er.async_entries_for_config_entry(reg, entry.entry_id):
        if e.unique_id == f"{entry.unique_id}_{key}":
            return e.entity_id
    raise AssertionError(f"no entity {key}")


async def test_config_flow(hass: HomeAssistant, telltale_node: Node, socket_enabled) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    bad = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_URL: telltale_node.url, CONF_TOKEN: "tt_nope_nope", CONF_VERIFY_SSL: True}
    )
    assert bad["errors"] == {"base": "invalid_auth"}
    down = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_URL: "http://127.0.0.1:9", CONF_TOKEN: telltale_node.token, CONF_VERIFY_SSL: True}
    )
    assert down["errors"] == {"base": "cannot_connect"}
    ok = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_URL: telltale_node.url.replace("http://", "") + "/",
            CONF_TOKEN: telltale_node.token,
            CONF_VERIFY_SSL: True,
        },
    )
    assert ok["type"] is FlowResultType.CREATE_ENTRY, ok
    assert ok["data"][CONF_URL] == telltale_node.url
    await hass.async_block_till_done()
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_entities(hass: HomeAssistant, telltale_node: Node, socket_enabled) -> None:
    ask_dns("nas.ha-test.arpa")
    entry = await _setup(hass, telltale_node)
    # The node's counters catch up within a second or two of the query.
    for _ in range(30):
        await entry.runtime_data.async_refresh()
        await hass.async_block_till_done()
        if int(hass.states.get(_entity(hass, entry, "queries_24h")).state) >= 1:
            break
        await asyncio.sleep(0.2)
    health = hass.states.get(_entity(hass, entry, "health"))
    assert health.state in ("healthy", "degraded", "severe")
    problem = hass.states.get(_entity(hass, entry, "problem"))
    assert problem.state == ("off" if health.state == "healthy" else "on")
    queries = hass.states.get(_entity(hass, entry, "queries_24h"))
    assert int(queries.state) >= 1
    assert hass.states.get(_entity(hass, entry, "open_anomalies")).state == "0"
    # The fork's inventory endpoints: readable with config:read.
    assert hass.states.get(_entity(hass, entry, "known_devices")).state == "0"
    networks = hass.states.get(_entity(hass, entry, "networks"))
    assert networks.state == "1", "the kids group's network (no router here)"
    assert networks.attributes["networks"][0] == {
        "name": "kids",
        "subnet": "10.9.0.0/24",
        "vlan": None,
        "devices": 0,
        "used_percent": 0.0,
        "group": "kids",
    }
    for key in ("blocking", "blocking_kids", "blocking_quarantine"):
        assert hass.states.get(_entity(hass, entry, key)).state == "on", key
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_pause_and_resume_a_group(hass: HomeAssistant, telltale_node: Node, socket_enabled) -> None:
    entry = await _setup(hass, telltale_node)
    kids = _entity(hass, entry, "blocking_kids")
    await hass.services.async_call("switch", "turn_off", {"entity_id": kids}, blocking=True)
    await hass.async_block_till_done()
    assert hass.states.get(kids).state == "off"
    pauses = [p for n in telltale_node.admin("GET", "/api/v1/blocking")["items"] for p in n["pauses"]]
    assert [p.get("group") for p in pauses] == ["kids"]
    assert hass.states.get(_entity(hass, entry, "blocking")).state == "on", "everyone else still blocks"
    await hass.services.async_call("switch", "turn_on", {"entity_id": kids}, blocking=True)
    await hass.async_block_till_done()
    assert hass.states.get(kids).state == "on"
    pauses = [p for n in telltale_node.admin("GET", "/api/v1/blocking")["items"] for p in n["pauses"]]
    assert pauses == []
    # The action does the same, for everyone, and the switch follows at once.
    await hass.services.async_call(DOMAIN, "pause_blocking", {"minutes": 5}, blocking=True)
    assert hass.states.get(_entity(hass, entry, "blocking")).state == "off"
    await hass.services.async_call(DOMAIN, "resume_blocking", {}, blocking=True)
    assert hass.states.get(_entity(hass, entry, "blocking")).state == "on"
    # The audit log has the reason Home Assistant gave.
    audit = telltale_node.admin("GET", "/api/v1/audit?limit=20")
    assert any("Home Assistant" in (a.get("reason") or "") for a in audit["items"]), audit["items"][:3]
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_quarantine_and_release(hass: HomeAssistant, telltale_node: Node, socket_enabled) -> None:
    entry = await _setup(hass, telltale_node)
    resp = await hass.services.async_call(
        DOMAIN, "quarantine_device", {"device": "127.0.0.9"}, blocking=True, return_response=True
    )
    assert resp == {"device": "127.0.0.9", "match": ["127.0.0.9"], "group": "quarantine"}
    clients = {c["name"]: c for c in telltale_node.admin("GET", "/api/v1/clients")["items"]}
    assert clients["127.0.0.9"]["groups"] == ["quarantine"]
    # The quarantine group's schedule blocks everything for that device; others are unaffected.
    blocked = ask_dns("example.com", source="127.0.0.9")
    assert blocked[3] & 0x0F in (0, 3), "an answer, not a SERVFAIL"
    assert b"\x00\x01\x00\x01" in blocked and (blocked.endswith(b"\x00\x00\x00\x00") or blocked[3] & 0x0F == 3)
    resp = await hass.services.async_call(
        DOMAIN, "release_device", {"device": "127.0.0.9"}, blocking=True, return_response=True
    )
    assert resp == {"device": "127.0.0.9", "deleted": True}
    clients = {c["name"] for c in telltale_node.admin("GET", "/api/v1/clients")["items"]}
    assert "127.0.0.9" not in clients
    assert await hass.config_entries.async_unload(entry.entry_id)
