"""Set up TelltaleDNS: its address and an API token; options for pausing and quarantine."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import TelltaleAuthError, TelltaleClient, TelltaleConnectionError, TelltaleError, TelltaleForbidden
from .const import (
    CONF_ANOMALY_EVENTS,
    CONF_PAUSE_MINUTES,
    CONF_QUARANTINE_GROUP,
    CONF_TOKEN,
    DEFAULT_PAUSE_MINUTES,
    DEFAULT_QUARANTINE_GROUP,
    DOMAIN,
    MAX_PAUSE_MINUTES,
)


def _normalize(url: str) -> str:
    url = url.strip().rstrip("/")
    if "://" not in url:
        url = f"http://{url}"
    return url


class TelltaleConfigFlow(ConfigFlow, domain=DOMAIN):
    """The UI setup."""

    VERSION = 1

    async def _check(self, url: str, token: str, verify_ssl: bool) -> tuple[dict[str, Any] | None, dict[str, str]]:
        client = TelltaleClient(
            async_get_clientsession(self.hass, verify_ssl=verify_ssl), url, token, verify_ssl=verify_ssl
        )
        try:
            return await client.system_info(), {}
        except TelltaleAuthError:
            return None, {"base": "invalid_auth"}
        except TelltaleForbidden:
            return None, {"base": "missing_scope"}
        except TelltaleConnectionError:
            return None, {"base": "cannot_connect"}
        except TelltaleError:
            return None, {"base": "unknown"}

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            url = _normalize(user_input[CONF_URL])
            info, errors = await self._check(url, user_input[CONF_TOKEN], user_input[CONF_VERIFY_SSL])
            if info is not None:
                cluster = info.get("cluster") or {}
                # A cluster is one entry whichever node you point at; a standalone node is its URL.
                await self.async_set_unique_id(cluster.get("clusterId") or url.lower())
                self._abort_if_unique_id_configured(updates={CONF_URL: url})
                title = cluster.get("name") or info.get("node") or "TelltaleDNS"
                return self.async_create_entry(
                    title=title,
                    data={
                        CONF_URL: url,
                        CONF_TOKEN: user_input[CONF_TOKEN],
                        CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL],
                    },
                )
        schema = vol.Schema(
            {
                vol.Required(CONF_URL, default=(user_input or {}).get(CONF_URL, "http://")): str,
                vol.Required(CONF_TOKEN): str,
                vol.Required(CONF_VERIFY_SSL, default=True): bool,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            info, errors = await self._check(
                entry.data[CONF_URL], user_input[CONF_TOKEN], entry.data.get(CONF_VERIFY_SSL, True)
            )
            if info is not None:
                return self.async_update_reload_and_abort(entry, data_updates={CONF_TOKEN: user_input[CONF_TOKEN]})
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_TOKEN): str}),
            errors=errors,
            description_placeholders={"url": entry.data[CONF_URL]},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> TelltaleOptionsFlow:
        return TelltaleOptionsFlow()


class TelltaleOptionsFlow(OptionsFlow):
    """How long a pause lasts, the quarantine group, and anomaly events."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        o = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(CONF_PAUSE_MINUTES, default=o.get(CONF_PAUSE_MINUTES, DEFAULT_PAUSE_MINUTES)): vol.All(
                    vol.Coerce(int), vol.Range(min=1, max=MAX_PAUSE_MINUTES)
                ),
                vol.Required(
                    CONF_QUARANTINE_GROUP, default=o.get(CONF_QUARANTINE_GROUP, DEFAULT_QUARANTINE_GROUP)
                ): str,
                vol.Required(CONF_ANOMALY_EVENTS, default=o.get(CONF_ANOMALY_EVENTS, True)): bool,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
