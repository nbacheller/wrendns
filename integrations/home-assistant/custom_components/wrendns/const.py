"""Constants for the WrenDNS integration."""

from __future__ import annotations

from datetime import timedelta
from typing import Final

DOMAIN: Final = "wrendns"

CONF_TOKEN: Final = "token"
CONF_PAUSE_MINUTES: Final = "pause_minutes"
CONF_QUARANTINE_GROUP: Final = "quarantine_group"
CONF_ANOMALY_EVENTS: Final = "anomaly_events"

DEFAULT_PORT: Final = 8053
DEFAULT_SCAN_INTERVAL: Final = timedelta(seconds=30)
DEFAULT_PAUSE_MINUTES: Final = 30
DEFAULT_QUARANTINE_GROUP: Final = "quarantine"

# Agent tokens may pause for at most 60 minutes; user tokens up to a day.
MAX_PAUSE_MINUTES: Final = 1440

EVENT_ANOMALY: Final = "wrendns_anomaly"

SERVICE_PAUSE: Final = "pause_blocking"
SERVICE_RESUME: Final = "resume_blocking"
SERVICE_QUARANTINE: Final = "quarantine_device"
SERVICE_RELEASE: Final = "release_device"
SERVICE_ACKNOWLEDGE: Final = "acknowledge_anomalies"

ATTR_ENTRY_ID: Final = "config_entry_id"
ATTR_GROUP: Final = "group"
ATTR_MINUTES: Final = "minutes"
ATTR_DEVICE: Final = "device"
ATTR_IDS: Final = "ids"
ATTR_NOTE: Final = "note"
ATTR_REASON: Final = "reason"

# The scopes the integration asks for when you create an agent token (Settings → Users →
# API tokens in WrenDNS). Each is optional: without one, that feature reports what's
# missing instead of failing the whole integration.
SCOPES: Final = (
    "analytics:read",
    "config:read",
    "ops:pause",
    "ops:anomalies",
    "config:write:clients",
)
