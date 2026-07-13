"""Light platform for the Govee H6099 integration.

A single :class:`~homeassistant.components.light.LightEntity` instance is
created per physical light:

``GoveeMainLight``  (``light.<name>``)
    Master power switch for the entire light.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from homeassistant.components.light import (
    ColorMode,
    LightEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_ON
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import (
    CONF_MAC,
    DOMAIN,
    MANUFACTURER,
    MODEL,
)
from .coordinator import GoveeCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the three light entities for a config entry.

    Called by HA when the platform is set up.  Retrieves the coordinator from
    ``hass.data`` and creates the three entity objects.

    Args:
        hass:               Home Assistant instance.
        entry:              Config entry for this light.
        async_add_entities: Callback to register the new entities with HA.
    """
    coordinator: GoveeCoordinator = hass.data[DOMAIN][entry.entry_id]
    name: str = entry.data.get("name", "Govee H6099")

    async_add_entities(
        [
            GoveeMainLight(coordinator, entry, name),
        ]
    )


# ── Shared device-registry info ────────────────────────────────────────────────

def _device_info(entry: ConfigEntry, name: str) -> DeviceInfo:
    """Build the shared :class:`DeviceInfo` used by all three entities.

    All three lights (main, centre, ring) belong to the same HA device so that
    they appear together on one device card.

    Args:
        entry: Config entry.
        name:  User-assigned display name.

    Returns:
        DeviceInfo for the device registry.
    """
    return DeviceInfo(
        identifiers={(DOMAIN, entry.data[CONF_MAC])},
        name=name,
        manufacturer=MANUFACTURER,
        model=MODEL,
        sw_version=None,
    )


# ═════════════════════════════════════════════════════════════════════════════
# Base entity
# ═════════════════════════════════════════════════════════════════════════════

class _GoveeBaseLight(LightEntity, RestoreEntity):
    """Shared base class for Govee H6099 light entities.

    Handles coordinator subscription, availability tracking, and HA state
    restoration across restarts (via :class:`~homeassistant.helpers.restore_state.RestoreEntity`).
    """

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        coordinator: GoveeCoordinator,
        entry: ConfigEntry,
        name: str,
    ) -> None:
        """Initialise the base entity.

        Args:
            coordinator: Coordinator managing this light's BLE connection.
            entry:       Config entry.
            name:        User-assigned display name of the light.
        """
        self._coordinator = coordinator
        self._entry = entry
        self._friendly_name = name
        self._remove_callback: Callable[[], None] | None = None

    @property
    def available(self) -> bool:
        """Return ``True`` when the coordinator has an active session."""
        return self._coordinator.available

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry info shared by all three entities."""
        return _device_info(self._entry, self._friendly_name)

    async def async_added_to_hass(self) -> None:
        """Subscribe to coordinator state updates when the entity is added."""
        self._remove_callback = self._coordinator.register_update_callback(
            self.async_write_ha_state
        )

    async def async_will_remove_from_hass(self) -> None:
        """Unsubscribe from coordinator state updates."""
        if self._remove_callback is not None:
            self._remove_callback()
            self._remove_callback = None


# ═════════════════════════════════════════════════════════════════════════════
# Main light  (on/off only)
# ═════════════════════════════════════════════════════════════════════════════

class GoveeMainLight(_GoveeBaseLight):
    """Master on/off light entity for the Govee H6099.

    Turning this light on or off sends the global power command which affects
    both the centre panel and the outer ring simultaneously.
    """

    _attr_color_mode = ColorMode.ONOFF
    _attr_supported_color_modes = {ColorMode.ONOFF}

    def __init__(
        self,
        coordinator: GoveeCoordinator,
        entry: ConfigEntry,
        name: str,
    ) -> None:
        """Initialise the main-light entity."""
        super().__init__(coordinator, entry, name)
        self._attr_unique_id = entry.data[CONF_MAC]
        self._attr_name = None  # Uses the device name directly

    async def async_added_to_hass(self) -> None:
        """Restore last known power state and subscribe to coordinator updates.

        Seeds the coordinator's power state from HA's persisted last state so
        that ring/centre entities do not send a spurious power-on command on the
        first action after a restart (which would happen if ``state.is_on``
        stayed ``False``).
        """
        await super().async_added_to_hass()
        if (last_state := await self.async_get_last_state()) is not None:
            is_on = last_state.state == STATE_ON
            self._coordinator.state.is_on = is_on
            _LOGGER.debug(
                "[%s] Restored power state from HA: is_on=%s",
                self._coordinator.address,
                is_on,
            )

    @property
    def is_on(self) -> bool:
        """Return ``True`` when the light is powered on."""
        return self._coordinator.state.is_on

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the light on."""
        await self._coordinator.async_turn_on()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the light off."""
        await self._coordinator.async_turn_off()
