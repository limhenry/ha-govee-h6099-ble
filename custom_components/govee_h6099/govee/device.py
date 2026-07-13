"""Govee H6099 protocol layer.

This module contains **all** protocol logic for the Govee TV Backlight 3 Lite (H6099/H6097).  It has **no** dependency on Home Assistant; every function and class
here can be tested with plain Python + pycryptodome.

Cryptography (reverse-engineered from com.govee.encryp.ble.Safe):
  * AES/ECB/NoPadding for the first 16 bytes of every frame.
  * RC4 (PRGA) for any bytes beyond the first 16 (bytes 16–19 of a 20-byte
    frame).
  * ``safe_encrypt`` / ``safe_decrypt`` implement this hybrid scheme exactly as
    the APK does.

Handshake (com.govee.encryp.ble.EncryptionManager V1):
  1. Client sends HS1 (safe_encrypt with commKey → session-key request).
  2. Device replies with HS1 response (safe_decrypt → extract 16-byte SK).
  3. Client sends HS2 (safe_encrypt with commKey → session confirmation).
  4. Device echoes HS2.

All subsequent commands are ``safe_encrypt``-ed with the negotiated session key.

Frame layout (BleUtils.generate20Bytes):
  ``[proType, cmdType, payload(0-17 bytes, zero-padded), xor_checksum]``
  Total: 20 bytes.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum

from Crypto.Cipher import AES as _AES  # type: ignore[import-untyped]

_LOGGER = logging.getLogger(__name__)

# ── BLE UUIDs (defined here so govee/device.py is self-contained) ─────────────

WRITE_UUID = "00010203-0405-0607-0809-0a0b0c0d2b11"
"""GATT characteristic UUID for writing commands (write-without-response)."""

NOTIFY_UUID = "00010203-0405-0607-0809-0a0b0c0d2b10"
"""GATT characteristic UUID for receiving device notifications."""

SERVICE_UUID = "00010203-0405-0607-0809-0a0b0c0d1910"
"""Primary GATT service UUID advertised by the H6099."""

# ── Static communication key ───────────────────────────────────────────────────
# Derived from APK: AESUtils.decode(app_communication, app_session)
#   app_communication → AES-256-ECB-encrypted hex string (strings.xml)
#   app_session       → "chiygnveeihhmme_govee_sessioniyz" (decrypt password)
# Result: parseHexStr2Byte("4D616B696E674C696665536D61727465")
#       = b"MakingLifeSmarte"  (16 bytes, ASCII)

COMM_KEY: bytes = bytes.fromhex("4d616b696e674c696665536d61727465")
"""Static 16-byte AES key shared by all Govee BLE devices in this family."""

# ═════════════════════════════════════════════════════════════════════════════
# State model
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class GoveeDeviceState:
    """Complete state snapshot of a single Govee H6099 device.

    Home-Assistant entities read from and write to this object via the
    coordinator.  Fields are updated both optimistically (on command send) and
    from device notification echoes parsed by :func:`parse_notification`.
    """

    is_on: bool = False
    """Master power state."""
    is_video_mode: bool = False
    """True if Video Mode is active, False if Color Mode is active."""

@dataclass
class StateUpdate:
    """Partial state delta extracted from a device notification echo.

    Fields default to ``None`` meaning "not carried by this notification".
    The coordinator merges only the non-``None`` fields into
    :class:`GoveeDeviceState`.
    """

    # ── Power ─────────────────────────────────────────────────────────────────
    is_on: bool | None = None
    is_video_mode: bool | None = None


# ═════════════════════════════════════════════════════════════════════════════
# Crypto primitives  (Safe.Companion from com.govee.encryp.ble.Safe)
# ═════════════════════════════════════════════════════════════════════════════

def _rc4_init(key: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm (KSA).

    Directly mirrors ``Safe.Companion.f()`` from the APK.

    Args:
        key: AES key (16 bytes) reused as the RC4 key.

    Returns:
        Initialised 256-element permutation table S.
    """
    s: list[int] = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 Pseudo-Random Generation Algorithm (PRGA) – encrypt or decrypt.

    RC4 is symmetric, so this function is used for both directions.
    Mirrors ``Safe.Companion.g()`` from the APK.

    Args:
        data: Plaintext or ciphertext bytes to process.
        key:  16-byte RC4 key (same as AES key).

    Returns:
        XOR-transformed bytes of the same length as *data*.
    """
    s = _rc4_init(key)
    result = bytearray(len(data))
    i = j = 0
    for idx in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        result[idx] = s[(s[i] + s[j]) & 0xFF] ^ data[idx]
    return bytes(result)


def safe_encrypt(data: bytes, key: bytes) -> bytes:
    """Govee hybrid encryption: AES/ECB for 16-byte blocks + RC4 for the tail.

    Implements ``Safe.Companion.d()`` from the APK.  For a 20-byte frame:
      * Bytes  0–15 → AES-128/ECB/NoPadding encrypt.
      * Bytes 16–19 → RC4(key) XOR plaintext[16:20].

    Args:
        data: Plaintext frame to encrypt (typically 20 bytes).
        key:  16-byte AES/RC4 key (commKey or session key).

    Returns:
        Encrypted frame of the same length as *data*.

    Raises:
        ValueError: If *key* is not exactly 16 bytes.
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    n_blocks, remainder = divmod(len(data), 16)
    result = bytearray()
    for i in range(n_blocks):
        cipher = _AES.new(key, _AES.MODE_ECB)
        result.extend(cipher.encrypt(data[i * 16 : (i + 1) * 16]))
    if remainder:
        result.extend(_rc4_crypt(data[n_blocks * 16 :], key))
    return bytes(result)


def safe_decrypt(data: bytes, key: bytes) -> bytes:
    """Govee hybrid decryption: AES/ECB decrypt + RC4 for the tail.

    Implements ``Safe.Companion.b()`` from the APK.  Inverse of
    :func:`safe_encrypt`.

    Args:
        data: Encrypted frame to decrypt.
        key:  16-byte AES/RC4 key.

    Returns:
        Decrypted frame of the same length as *data*.

    Raises:
        ValueError: If *key* is not exactly 16 bytes.
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    n_blocks, remainder = divmod(len(data), 16)
    result = bytearray()
    for i in range(n_blocks):
        cipher = _AES.new(key, _AES.MODE_ECB)
        result.extend(cipher.decrypt(data[i * 16 : (i + 1) * 16]))
    if remainder:
        result.extend(_rc4_crypt(data[n_blocks * 16 :], key))
    return bytes(result)


# ═════════════════════════════════════════════════════════════════════════════
# Frame helpers  (BleUtils / Controller4Aes from APK)
# ═════════════════════════════════════════════════════════════════════════════

def _xor_checksum(data: bytes) -> int:
    """XOR of all bytes – ``Controller4Aes.Companion.c()`` from APK.

    Args:
        data: Bytes to checksum (normally the first 19 bytes of a frame).

    Returns:
        Single-byte XOR result (0–255).
    """
    result = 0
    for b in data:
        result ^= b
    return result


def _make_govee_frame(proto_type: int, cmd_type: int, payload: bytes = b"") -> bytes:
    """Build a 20-byte Govee BLE frame (plaintext, before encryption).

    Implements ``BleUtils.generate20Bytes(proType, cmdType, payload)`` from APK.

    Frame layout::

        [0]     proto_type
        [1]     cmd_type
        [2..18] payload (zero-padded to 17 bytes)
        [19]    XOR checksum of bytes [0..18]

    Args:
        proto_type: Protocol type byte (e.g. 0x33 for commands, 0xAA for keepalive).
        cmd_type:   Command type byte (e.g. 0x01 for power, 0x04 for brightness).
        payload:    Command-specific payload bytes (at most 17 bytes; longer
                    payloads are silently truncated to fit).

    Returns:
        20-byte plaintext frame ready to be encrypted and sent.
    """
    frame = bytearray(20)
    frame[0] = proto_type & 0xFF
    frame[1] = cmd_type & 0xFF
    for i, b in enumerate(payload[:17]):
        frame[2 + i] = b
    frame[19] = _xor_checksum(bytes(frame[:19]))
    return bytes(frame)

# ═════════════════════════════════════════════════════════════════════════════
# Command frame builders
# ═════════════════════════════════════════════════════════════════════════════

def cmd_keepalive() -> bytes:
    """Build a keep-alive / heartbeat response frame.

    Source: ``ComposeLightHeartController`` (proType=0xAA, cmdType=0x36).
    Plaintext: ``[0xAA, 0x36, 0x00×17, 0x9C]``.

    Returns:
        20-byte plaintext frame.
    """
    return _make_govee_frame(0xAA, 0x36)

def cmd_power(on: bool) -> bytes:
    """Build a power on/off frame.

    Source: ``ControllerSwitch`` (proType=0x33, cmdType=0x01).

    Args:
        on: ``True`` to switch on, ``False`` to switch off.

    Returns:
        20-byte plaintext frame.
    """
    return _make_govee_frame(0x33, 0x01, bytes([0x01 if on else 0x00]))

def cmd_set_video_mode() -> bytes:
    """Build the frame to switch the device to Video Mode.

    Uses Govee Mode command type 0x05, submode 0x00 (Video V2).
    Configured for: Part (segment control) and Movie (drama) mode.

    Returns:
        20-byte plaintext frame.
    """
    # Payload format derived from com.govee.pact_tvlightv4.detail.mode.VideoVm:
    # [0x05 (Mode), 0x00 (Video V2), 0x00 (Part=0/All=1), 0x00 (Movie=0/Game=1), 0x32 (Vividness=50), 0x00 (VoiceSync=0), 0x32 (Sensitivity=50), 0x32 (Padding=50)]
    payload = bytes([
        0x05, 0x00, 0x00, 0x00, 0x32, 0x00, 0x32, 0x32,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
    return _make_govee_frame(0x33, 0x05, payload)

def cmd_set_color_mode() -> bytes:
    """Build the frame to switch the device to Color Mode.

    Uses Govee Mode command type 0x05, submode 0x15 (Color V2).
    Configured for: Solid White color (RGB: 255, 255, 255) with all segments selected.

    Returns:
        20-byte plaintext frame.
    """
    # Payload format derived from com.govee.pact_tvlightv4.ble.SubModeColorV2:
    # [0x05 (Mode), 0x15 (Color V2), 0x01 (Static), R, G, B, 0x00, 0x00, 0x00, 0x00, 0xFF (Segs 0-7), 0x0F (Segs 8-11)]
    payload = bytes([
        0x05, 0x15, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0xFF, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
    return _make_govee_frame(0x33, 0x05, payload)

# ═════════════════════════════════════════════════════════════════════════════
# Handshake frame builders  (Controller4Aes from com.govee.encryp.ble)
# ═════════════════════════════════════════════════════════════════════════════

def make_hs1_frame() -> bytes:
    """Build the HS1 (session-key request) frame.

    Implements ``Controller4Aes.e()`` from the APK.

    Plaintext: ``[0xE7, 0x01, <17 random bytes>, xor_checksum]``
    Returned:  ``safe_encrypt(plaintext, COMM_KEY)``

    Returns:
        20-byte encrypted HS1 frame.
    """
    plain = bytearray(20)
    plain[0] = 0xE7
    plain[1] = 0x01
    plain[2:19] = os.urandom(17)
    plain[19] = _xor_checksum(bytes(plain[:19]))
    _LOGGER.debug("HS1 plaintext: %s", bytes(plain).hex())
    encrypted = safe_encrypt(bytes(plain), COMM_KEY)
    _LOGGER.debug("HS1 encrypted: %s", encrypted.hex())
    return encrypted


def parse_hs1_response(data: bytes) -> bytes | None:
    """Parse the device's HS1 response and extract the 16-byte session key.

    Implements ``Controller4Aes.g()`` from the APK.

    Expected decrypted layout: ``[0xE7, 0x01, SK[0..15], xor_checksum]``

    Args:
        data: Raw 20-byte notification received from the device.

    Returns:
        16-byte session key, or ``None`` on parsing failure.
    """
    if len(data) < 20:
        _LOGGER.error("HS1 response too short: %d bytes (expected 20)", len(data))
        return None

    decrypted = safe_decrypt(data[:20], COMM_KEY)
    _LOGGER.debug("HS1 response decrypted: %s", decrypted.hex())

    if decrypted[0] != 0xE7 or decrypted[1] != 0x01:
        _LOGGER.warning(
            "Unexpected HS1 header: 0x%02x 0x%02x (expected 0xe7 0x01)",
            decrypted[0], decrypted[1],
        )
        return None

    expected_xor = _xor_checksum(decrypted[:19])
    if decrypted[19] != expected_xor:
        _LOGGER.warning(
            "HS1 checksum mismatch (got 0x%02x, expected 0x%02x) – continuing anyway",
            decrypted[19], expected_xor,
        )

    session_key = bytes(decrypted[2:18])
    _LOGGER.debug("Session key extracted (16 bytes)")
    return session_key


def make_hs2_frame() -> bytes:
    """Build the HS2 (session confirmation) frame.

    Implements ``Controller4Aes.f()`` from the APK.

    Plaintext: ``[0xE7, 0x02, <17 random bytes>, xor_checksum]``
    Returned:  ``safe_encrypt(plaintext, COMM_KEY)``

    Returns:
        20-byte encrypted HS2 frame.
    """
    plain = bytearray(20)
    plain[0] = 0xE7
    plain[1] = 0x02
    plain[2:19] = os.urandom(17)
    plain[19] = _xor_checksum(bytes(plain[:19]))
    _LOGGER.debug("HS2 plaintext: %s", bytes(plain).hex())
    return safe_encrypt(bytes(plain), COMM_KEY)


def encrypt_command(session_key: bytes, plain_frame: bytes) -> bytes:
    """Encrypt a plaintext command frame with the active session key.

    Implements ``AESEncryptionStrategy.encrypt()`` (= ``Safe.d(plain, sk)``).

    Args:
        session_key: 16-byte session key obtained during handshake.
        plain_frame: 20-byte plaintext frame built by one of the ``cmd_*``
                     functions.

    Returns:
        20-byte encrypted frame ready to be written to the GATT characteristic.

    Raises:
        ValueError: If *plain_frame* is not exactly 20 bytes.
    """
    if len(plain_frame) != 20:
        raise ValueError(f"Frame must be 20 bytes, got {len(plain_frame)}")
    return safe_encrypt(plain_frame, session_key)


# ═════════════════════════════════════════════════════════════════════════════
# Notification parser
# ═════════════════════════════════════════════════════════════════════════════

class NotificationType(str, Enum):
    """Category of an inbound BLE notification from the device."""
    HS1_RESPONSE = "hs1_response"
    HS2_ECHO = "hs2_echo"
    HEARTBEAT = "heartbeat"
    STATE_UPDATE = "state_update"
    UNKNOWN = "unknown"


@dataclass
class ParsedNotification:
    """Decoded BLE notification.

    Attributes:
        type:         Category of the notification.
        raw:          The original raw bytes.
        plain:        Decrypted plaintext (if a session key was available).
        session_key:  Extracted session key (only set for HS1_RESPONSE).
        state_update: Parsed state delta (set for HEARTBEAT and STATE_UPDATE).
    """
    type: NotificationType
    raw: bytes
    plain: bytes | None = None
    session_key: bytes | None = None
    state_update: StateUpdate | None = None

# ── Notification payload parsers ──────────────────────────────────────────────

def _parse_heartbeat(plain: bytes) -> StateUpdate:
    """Parse a decrypted 0xAA/0x36 keepalive echo.

    The H6099 sends proactive keepalive notifications every few seconds with
    ``plain[2]=0, plain[3]=0`` regardless of physical power state.  Unlike the
    H604a (where those bytes encode ``center_on`` / ``ring_on`` per
    ``ComposeLightHeartController.parseValidBytes()``), the H6099 always zeroes
    them out, so extracting power state here would reset HA state to "off"
    every 2–3 seconds.

    Power state is therefore tracked exclusively via optimistic updates (set at
    command send time) and ``RestoreEntity`` persistence across restarts.

    Args:
        plain: 20-byte decrypted heartbeat frame.

    Returns:
        Empty :class:`StateUpdate` (no fields set).
    """
    return StateUpdate()


def _parse_0x33_0x01(plain: bytes) -> StateUpdate:
    """Parse a 0x33/0x01 power-command echo.

    Power state is intentionally NOT extracted here.  Some devices echo the
    state *before* processing the command (i.e. the device echoes "off" in
    response to an ON command), which would override the optimistic update set
    at send time and produce a spurious "on → off" logbook entry.

    Power state is tracked via:
    * Optimistic updates in ``async_turn_on`` / ``async_turn_off``.
    * The keepalive echo (0xAA/0x36) which is authoritative after the 2-second
      command-suppression window expires.
    """
    return StateUpdate()

def parse_notification(
    data: bytes,
    session_key: bytes | None = None,
) -> ParsedNotification:
    """Parse an inbound BLE notification.

    Determines the notification type by inspecting the decrypted content.
    During the handshake no session key exists yet; post-handshake the
    session key is used to decrypt state-update frames.

    Args:
        data:        Raw notification bytes (20 bytes expected).
        session_key: Active session key, or ``None`` during handshake.

    Returns:
        :class:`ParsedNotification` with type and decrypted content.
    """
    if len(data) < 20:
        _LOGGER.debug("Notification too short (%d bytes), skipping", len(data))
        return ParsedNotification(type=NotificationType.UNKNOWN, raw=data)

    # Try to decrypt with commKey first (handshake messages are always
    # encrypted with commKey, not the session key).
    # pycryptodome raises ValueError on AES failures; our safe_decrypt also
    # raises ValueError for bad key length.  Any other exception is unexpected.
    try:
        plain_comm = safe_decrypt(data[:20], COMM_KEY)
    except ValueError:
        plain_comm = None

    if plain_comm and plain_comm[0] == 0xE7 and plain_comm[1] == 0x01:
        sk = parse_hs1_response(data)
        return ParsedNotification(
            type=NotificationType.HS1_RESPONSE,
            raw=data,
            plain=plain_comm,
            session_key=sk,
        )

    if plain_comm and plain_comm[0] == 0xE7 and plain_comm[1] == 0x02:
        return ParsedNotification(
            type=NotificationType.HS2_ECHO,
            raw=data,
            plain=plain_comm,
        )

    # Post-handshake: try session key decryption
    if session_key is not None:
        try:
            plain_sk = safe_decrypt(data[:20], session_key)
        except ValueError:
            plain_sk = None

        if plain_sk:
            if plain_sk[0] == 0xAA and plain_sk[1] == 0x36:
                return ParsedNotification(
                    type=NotificationType.HEARTBEAT,
                    raw=data,
                    plain=plain_sk,
                    state_update=_parse_heartbeat(plain_sk),
                )

            if plain_sk[0] == 0x33:
                cmd = plain_sk[1]
                if cmd == 0x01:
                    su: StateUpdate | None = _parse_0x33_0x01(plain_sk)
                else:
                    su = None
                return ParsedNotification(
                    type=NotificationType.STATE_UPDATE,
                    raw=data,
                    plain=plain_sk,
                    state_update=su,
                )

            return ParsedNotification(
                type=NotificationType.STATE_UPDATE,
                raw=data,
                plain=plain_sk,
            )

    _LOGGER.debug("Unknown notification (no key matched): %s", data.hex())
    return ParsedNotification(type=NotificationType.UNKNOWN, raw=data)
