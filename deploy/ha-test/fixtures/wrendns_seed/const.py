"""The fake devices the test Home Assistant starts with (REQ: T24.21).

Each device has a MAC connection, an entity, and optionally a device_tracker state with an
address (the states WrenDNS's Home Assistant source reads). The garage sensor has no
address, so it must not appear in WrenDNS's answer.
"""

from __future__ import annotations

DOMAIN = "wrendns_seed"

# REQ: T25.10 (DSC-009, ADR-912) - registry devices with a MAC and NO entity. A template can reach one
# only through an area or a label, so the first sits in the Hall area and is read; the second sits in
# no area and has no label, which no template can list: the test checks it is absent (the known limit).
AREA = "Hall"
ENTITYLESS: list[dict[str, str | None]] = [
    {"mac": "aa:bb:cc:00:00:05", "name": "Hub", "name_by_user": "Hall Hub", "area": AREA},
    {"mac": "aa:bb:cc:00:00:06", "name": "Loose Bridge", "name_by_user": None, "area": None},
]

# name_by_user: the name a person gave the device in Home Assistant (ranks first).
# name: the integration's name. address: the device_tracker's IP, or None.
DEVICES: list[dict[str, str | None]] = [
    {
        "mac": "aa:bb:cc:00:00:01",
        "name": "Porch Light",
        "name_by_user": "Porch Light",
        "address": "192.168.1.31",
    },
    {
        "mac": "aa:bb:cc:00:00:02",
        "name": "Living Room TV",
        "name_by_user": None,
        "address": "192.168.1.42",
    },
    {
        "mac": "aa:bb:cc:00:00:03",
        "name": "Tablet",
        "name_by_user": "Kitchen Tablet",
        "address": "192.168.1.43",
    },
    {
        "mac": "aa:bb:cc:00:00:04",
        "name": "Garage Sensor",
        "name_by_user": None,
        "address": None,
    },
]
