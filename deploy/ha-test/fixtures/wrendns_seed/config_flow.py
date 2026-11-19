"""REQ: T24.21 — a one-step flow so the test script can add the seeded devices through the API."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .const import DOMAIN


class SeedConfigFlow(ConfigFlow, domain=DOMAIN):
    """Creates the one entry that seeds the devices."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if self._async_current_entries():
            return self.async_abort(reason="already_configured")
        if user_input is not None:
            return self.async_create_entry(title="WrenDNS test devices", data={})
        return self.async_show_form(step_id="user")
