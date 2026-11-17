"""The fake devices the test Home Assistant starts with (REQ: T24.21).

Each device has a MAC connection, an entity, and optionally a device_tracker state with an
address (the states TelltaleDNS's Home Assistant source reads). The garage sensor has no
address, so it must not appear in TelltaleDNS's answer.
"""

from __future__ import annotations

DOMAIN = "telltale_seed"

# name_by_user: the name a person gave the device in Home Assistant (ranks first).
# name: the integration's name. address: the device_tracker's IP, or None.
DEVICES: list[dict[str, str | None]] = [
    {
        "mac": "aa:bb:cc:00:00:01",
        "name": "Porch Light",
        "name_by_user": "Porch Light",
        "address": "192.0.2.31",
    },
    {
        "mac": "aa:bb:cc:00:00:02",
        "name": "Living Room TV",
        "name_by_user": None,
        "address": "192.0.2.42",
    },
    {
        "mac": "aa:bb:cc:00:00:03",
        "name": "Tablet",
        "name_by_user": "Kitchen Tablet",
        "address": "192.0.2.43",
    },
    {
        "mac": "aa:bb:cc:00:00:04",
        "name": "Garage Sensor",
        "name_by_user": None,
        "address": None,
    },
]
