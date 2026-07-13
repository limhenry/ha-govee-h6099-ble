# Govee TV Backlight 3 Lite (H6099/H6097) – Home Assistant Custom Integration

Local-push Bluetooth LE control for the **Govee TV Backlight 3 Lite (H6099/H6097)**, with no cloud dependency. All communication happens directly over BLE using a cryptographic protocol reverse-engineered from the official Govee Android APK.

---

## Features

| Entity | Description |
|--------|-------------|
| `light.<name>` | Master on/off for the TV Backlight |
| `switch.<name>_persistent_connection` | Toggle between persistent and on-demand BLE mode |

### Connection modes

| Mode | Description |
|------|-------------|
| **Persistent** *(default)* | One permanent BLE session per backlight device. Notifications and heartbeats are processed in real time. Recommended for fast response. |
| **On-demand** | BLE connects only to send a command, then disconnects. Lower radio usage; slightly higher latency per command. |

---

## Requirements

- Home Assistant **2023.3** or later
- The **Bluetooth** integration enabled (built-in, no extra hardware needed on most hosts running HA OS or Supervised)
- The backlight device within Bluetooth range of the HA host
- Python package **pycryptodome** ≥ 3.19 (installed automatically via `requirements` in `manifest.json`)
- Python package **bleak-retry-connector** ≥ 3.6 (installed automatically)

---

## Installation

### Via HACS (recommended)

1. Open HACS → **Integrations** → three-dot menu → **Custom repositories**.
2. Add `https://github.com/limhenry/govee-h6099-ha` as an **Integration** repository.
3. Search for **Govee TV Backlight 3 Lite** and install.
4. Restart Home Assistant.
5. Go to **Settings → Devices & Services → Add Integration** and search for **Govee TV Backlight 3 Lite**.

### Manual

1. Copy the `custom_components/govee_h6099` folder into `<config>/custom_components/govee_h6099/`.
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration** and search for **Govee TV Backlight 3 Lite**.

---

## Configuration

The integration is fully configured through the UI config flow.

### Auto-discovery

If your backlight is advertising nearby, HA will show a notification in **Settings → Devices & Services** offering to set it up automatically. Click **Configure**, confirm the device name and select the desired connection mode.

### Manual setup

1. **Settings → Devices & Services → Add Integration → Govee TV Backlight 3 Lite**.
2. Select a discovered device from the list *or* enter the BLE address manually (`AA:BB:CC:DD:EE:FF` on Linux/Windows, `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` CoreBluetooth UUID on macOS).
3. Assign a display name and choose a connection mode.

### Multiple devices

Repeat the setup process for each physical device. Each device gets its own Home Assistant device with one light entity and one switch.

---

## Cryptographic protocol

The H6099/H6097 uses a hybrid encryption scheme (reverse-engineered from `com.govee.encryp.ble`):

1. **Static communication key** (`commKey = b"MakingLifeSmarte"`) – embedded in the APK, decrypted from `strings.xml` using `AESUtils.decode`.
2. **Handshake** – two-step exchange (HS1 / HS2) using AES-ECB + commKey to negotiate a per-session 16-byte key.
3. **Commands** – every command frame is encrypted with the session key using the same AES-ECB + RC4 hybrid (`safe_encrypt` from `Safe.Companion`).

All protocol logic lives in `govee/device.py` with no Home Assistant dependencies, so it can be tested and reused independently.

---

## Known limitations

- **State readback** – Power-on/off state is tracked *optimistically* at command send time and persisted across restarts via `RestoreEntity`.
- **macOS / CoreBluetooth** – On macOS the BLE address is a UUID assigned by CoreBluetooth rather than the hardware MAC. This UUID is stable per host but differs from the MAC shown on the device label.

---

## Development

### Project structure

```
custom_components/govee_h6099/
├── __init__.py          – Integration setup / teardown
├── manifest.json        – HA metadata + Bluetooth advertisement filters
├── config_flow.py       – UI config flow (discovery + manual) + options flow
├── const.py             – All shared constants
├── coordinator.py       – BLE connection manager + command dispatcher
├── diagnostics.py       – Diagnostics download support
├── light.py             – Master power LightEntity
├── switch.py            – Connection-mode SwitchEntity
├── strings.json         – UI strings (config flow, options, repair issues)
├── translations/
│   └── en.json          – English translations (mirrors strings.json)
└── govee/
    ├── __init__.py      – Package marker
    ├── device.py        – Protocol layer (crypto, frames, state model, notification parsing)
    └── scanner.py       – BLE advertisement detection helpers
```

### Running tests (example)

```bash
# Install dev dependencies
pip install pycryptodome pytest

# Run protocol tests (no HA required)
pytest tests/
```

### Adding support for new commands

1. Add a `cmd_*` builder function in `govee/device.py`.
2. Add the corresponding `async_set_*` method on `GoveeCoordinator`.
3. Wire it up in the appropriate light / switch entity.

---

## Acknowledgements

Protocol analysis based on reverse engineering of the Govee Home Android APK (v7.3.15). Relevant APK classes:

- `com.govee.encryp.ble.Safe` – AES-ECB + RC4 hybrid
- `com.govee.encryp.ble.Controller4Aes` – Handshake frame builders
- `com.govee.encryp.ble.EncryptionManager` – V1 session protocol
- `com.govee.h604a.ble.controller.ComposeLightHeartController` – Heartbeat response format
- `com.govee.base2home.Constant.Y1` – Kelvin→RGB lookup table

---

## License

MIT – see `LICENSE` for details.
