"""The fork's Home Assistant naming source, against a real Home Assistant.

1. The template TelltaleDNS sends (copied out of `crates/telltale/src/routers.rs`, so the two
   can't drift) renders through Home Assistant's real `/api/template` endpoint to the JSON the
   Rust side parses.
2. A real TelltaleDNS process reads this Home Assistant test server as a `[[router]]` and names
   the devices: a name given in Home Assistant, at the address a device tracker reports.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from .conftest import BIN, ROOT

ROUTERS_RS = ROOT / "crates" / "telltale" / "src" / "routers.rs"


def ha_template() -> str:
    src = ROUTERS_RS.read_text()
    m = re.search(r'pub\(crate\) const HA_TEMPLATE: &str = r"(.*?)";\n', src, re.S)
    assert m, "HA_TEMPLATE not found in routers.rs"
    return m.group(1)


async def _devices(hass: HomeAssistant) -> None:
    """A Shelly you renamed, a TV with its integration's name, a Zigbee bulb without a MAC,
    and a phone tracked by a router integration."""
    entry = MockConfigEntry(domain="test")
    entry.add_to_hass(hass)
    devices = dr.async_get(hass)
    entities = er.async_get(hass)
    porch = ar.async_get(hass).async_create("Porch")
    shelly = devices.async_get_or_create(
        config_entry_id=entry.entry_id,
        connections={(dr.CONNECTION_NETWORK_MAC, "A8:03:2A:00:00:01")},
        name="Shelly Plus 1",
        manufacturer="Shelly",
    )
    devices.async_update_device(shelly.id, name_by_user="Porch light", area_id=porch.id)
    tv = devices.async_get_or_create(
        config_entry_id=entry.entry_id,
        connections={(dr.CONNECTION_NETWORK_MAC, "a8:03:2a:00:00:02")},
        name="Living Room TV",
    )
    bulb = devices.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={("zha", "00:17:88:01:02:03:04:05")},
        name="Hue bulb",
    )
    for dev, eid in ((shelly, "switch.porch"), (tv, "media_player.tv"), (bulb, "light.bulb")):
        domain, obj = eid.split(".")
        entities.async_get_or_create(domain, "test", obj, device_id=dev.id, suggested_object_id=obj)
        hass.states.async_set(eid, "on")
    hass.states.async_set(
        "device_tracker.phone", "home", {"mac": "A8:03:2A:00:00:03", "ip": "127.0.0.33", "source_type": "router"}
    )
    hass.states.async_set("device_tracker.gps", "home", {"source_type": "gps"})
    # The Shelly's and the TV's addresses, as a router integration's trackers report them.
    hass.states.async_set("device_tracker.shelly", "home", {"mac": "a8:03:2a:00:00:01", "ip": "127.0.0.31"})
    hass.states.async_set("device_tracker.tv", "home", {"mac": "a8:03:2a:00:00:02", "ip": "127.0.0.32"})


async def test_template_renders_through_the_api(hass: HomeAssistant, hass_client) -> None:
    assert await async_setup_component(hass, "api", {})
    await _devices(hass)
    client = await hass_client()
    resp = await client.post("/api/template", json={"template": ha_template()})
    assert resp.status == 200, await resp.text()
    out = json.loads(await resp.text())
    by_name = {d["name"]: d for d in out["devices"]}
    assert set(by_name) == {"Shelly Plus 1", "Living Room TV"}, "only devices with a MAC"
    assert by_name["Shelly Plus 1"]["name_by_user"] == "Porch light"
    assert by_name["Shelly Plus 1"]["area"] == "Porch"
    assert [m.lower() for m in by_name["Shelly Plus 1"]["macs"]] == ["a8:03:2a:00:00:01"]
    assert by_name["Living Room TV"]["name_by_user"] == ""
    trackers = {t["mac"].lower(): t["ip"] for t in out["trackers"]}
    assert trackers == {
        "a8:03:2a:00:00:03": "127.0.0.33",
        "a8:03:2a:00:00:01": "127.0.0.31",
        "a8:03:2a:00:00:02": "127.0.0.32",
    }


async def test_template_needs_an_administrator(hass: HomeAssistant, hass_client, hass_read_only_access_token) -> None:
    assert await async_setup_component(hass, "api", {})
    client = await hass_client(hass_read_only_access_token)
    resp = await client.post("/api/template", json={"template": ha_template()})
    assert resp.status == 401


async def test_telltale_reads_home_assistant(
    hass: HomeAssistant, hass_client, hass_access_token, socket_enabled
) -> None:
    if not BIN.exists():
        pytest.skip(f"no TelltaleDNS binary at {BIN}")
    assert await async_setup_component(hass, "api", {})
    await _devices(hass)
    client = await hass_client()
    ha_url = str(client.make_url("")).rstrip("/")
    tmp = Path(tempfile.mkdtemp(prefix="tt-ha-src-"))
    (tmp / "ha-token").write_text(hass_access_token)
    (tmp / "telltale.toml").write_text(
        f"""
[node]
data_dir = "{tmp / "data"}"
[[listen]]
proto = "udp"
addr = "127.0.0.1:35993"
[api]
listen = "127.0.0.1:36993"
[telemetry.metrics]
listen = "127.0.0.1:37993"
[[router]]
name = "home-assistant"
type = "home_assistant"
url = "{ha_url}"
api_key_file = "{tmp / "ha-token"}"
[local]
device_domain = "home.arpa"
"""
    )
    log = open(tmp / "node.log", "w")  # noqa: SIM115 (open for the process's lifetime; closed below)
    proc = subprocess.Popen([str(BIN), "run", "-c", str(tmp / "telltale.toml")], stdout=log, stderr=log)
    try:
        # TelltaleDNS reads Home Assistant in its own process while this test's event loop
        # serves the requests, so wait without blocking the loop.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            await hass.async_block_till_done()
            text = (tmp / "node.log").read_text()
            if "Home Assistant: devices read" in text or "router integration failed" in text:
                break
            await _sleep(hass, 0.2)
        text = (tmp / "node.log").read_text()
        assert "Home Assistant: devices read" in text, text[-2000:]
        assert "matched=2" in text, text[-2000:]
        # The leases API needs a user: make the admin, then read it.
        import http.cookiejar

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        setup = (tmp / "data" / "setup-token").read_text().strip()
        req = urllib.request.Request(
            "http://127.0.0.1:36993/api/v1/auth/setup",
            data=json.dumps({"setupToken": setup, "username": "admin", "password": "ha-src-pass-1"}).encode(),
            headers={"content-type": "application/json"},
        )
        await hass.async_add_executor_job(lambda: opener.open(req, timeout=10).read())
        raw = await hass.async_add_executor_job(
            lambda: opener.open("http://127.0.0.1:36993/api/v1/dhcp/leases", timeout=10).read()
        )
        leases = {x["ip"]: x for x in json.loads(raw)["items"]}
        assert leases["127.0.0.31"]["hostname"] == "Porch light", leases
        assert leases["127.0.0.31"]["router"] == "home-assistant"
        assert leases["127.0.0.32"]["hostname"] == "Living Room TV"
        assert "127.0.0.33" not in leases, "a tracker alone (no registry device) names nothing"
        # Device names reach DNS within one rebuild (10 s).
        deadline = time.monotonic() + 15
        dns_name = None
        while time.monotonic() < deadline:
            raw = await hass.async_add_executor_job(
                lambda: opener.open("http://127.0.0.1:36993/api/v1/dhcp/leases", timeout=10).read()
            )
            dns_name = {x["ip"]: x for x in json.loads(raw)["items"]}["127.0.0.31"].get("dnsName")
            if dns_name:
                break
            await _sleep(hass, 0.5)
        assert dns_name == "porch-light.home.arpa"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()


async def _sleep(hass: HomeAssistant, seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)
