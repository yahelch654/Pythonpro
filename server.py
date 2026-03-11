# server.py
import argparse
import json
import os
import threading
from pathlib import Path

import cv2
import numpy as np
from mss import mss

# Symmetric encryption (password-derived key). No public/private keys used.
# Preferred backend: `cryptography` (AESGCM). Fallback: `pycryptodome` (AES GCM).
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except Exception:
    AESGCM = None
    PBKDF2HMAC = None
    hashes = None

# Fallback backend (often installed as `pycryptodome`)
try:
    from Crypto.Cipher import AES as PYAES
    from Crypto.Protocol.KDF import PBKDF2 as PYPBKDF2
    from Crypto.Hash import SHA256 as PYSHA256
except Exception:
    PYAES = None
    PYPBKDF2 = None
    PYSHA256 = None

# NOTE: Kept for compatibility in case UI/side effects are expected elsewhere.
# If unused in your project, you can remove this import safely.
from InterFace import *

from proto import (
    ANNOUNCE_PORT,
    DEFAULT_GROUP,
    DEFAULT_PORT,
    MAX_DATAGRAM,
    HEADER_SIZE,
    pack_header,
)

# Local control channel (UI -> Server)
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 50099
CONTROL_TOGGLE_STOP = b"toggle_stop_sender"
CONTROL_TOGGLE_GO = b"toggle_go_sender"
CONTROL_FREEZE = b"freeze_ten_times"
CONTROL_UNFREEZE = b"unfreeze_ten_times"
CONTROL_DEATH = b"death_message"

# Prefix: UI sends b"set_password:" + password_bytes
CONTROL_SET_PASSWORD_PREFIX = b"set_password:"

def make_multicast_sender(group: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # Create a UDP socket using IPv4
    # Optional: enable TTL if crossing subnets (default=1 => local)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)  # Set the TTL for multicast packets to 1 (local network only)
    addr = (group, port)  # Tuple of multicast group address and port
    return s, addr  # Return the socket and the multicast address tuple

def broadcaster(name: str, group: str, port: int, fps: int, width: int, height: int):
    """Prepare a broadcast socket + announcement template for discovery."""
    msg = {
        "type": "screenshare_announce",
        "name": name,
        "group": group,
        "port": port,
        "fps": fps,
        "width": width,
        "height": height,
        "ts": time.time(),
    }
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return b, msg


#shut down system



_stop_sender_running = False
_stop_sender_thread = None
_go_sender_running = False
_go_sender_thread = None


# --- Encryption state (set via UI confirm) ---
_crypto_enabled = False
_crypto_salt = None  # 16 bytes
_crypto_backend = None  # "cryptography" or "pycryptodome"
_crypto_aesgcm = None  # cryptography AESGCM instance
_crypto_key = None     # bytes for pycryptodome backend

def set_password_encryption(password: str) -> None:
    """Derive a symmetric key from the UI password and enable encryption.

    Backend preference order:
      1) cryptography (AES-GCM)
      2) pycryptodome (AES GCM)

    The salt is generated once per server run (or per password set) and is prepended
    to each encrypted frame.
    """
    global _crypto_enabled, _crypto_salt, _crypto_backend, _crypto_aesgcm, _crypto_key

    pw = (password or "").encode("utf-8")
    if not pw:
        print("[CRYPTO] Empty password; encryption disabled")
        _crypto_enabled = False
        _crypto_salt = None
        _crypto_backend = None
        _crypto_aesgcm = None
        _crypto_key = None
        return

    _crypto_salt = os.urandom(16)

    # --- Preferred backend: cryptography ---
    if AESGCM is not None and PBKDF2HMAC is not None and hashes is not None:
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=_crypto_salt,
                iterations=200_000,
            )
            key = kdf.derive(pw)
            _crypto_aesgcm = AESGCM(key)
            _crypto_key = None
            _crypto_backend = "cryptography"
            _crypto_enabled = True
            print("[CRYPTO] Encryption enabled (AES-GCM via cryptography)")
            return
        except Exception as ex:
            print(f"[CRYPTO] cryptography backend failed: {ex}")

    # --- Fallback backend: pycryptodome ---
    if PYAES is not None and PYPBKDF2 is not None and PYSHA256 is not None:
        try:
            key = PYPBKDF2(pw, _crypto_salt, dkLen=32, count=200_000, hmac_hash_module=PYSHA256)
            _crypto_key = key
            _crypto_aesgcm = None
            _crypto_backend = "pycryptodome"
            _crypto_enabled = True
            print("[CRYPTO] Encryption enabled (AES-GCM via pycryptodome)")
            return
        except Exception as ex:
            print(f"[CRYPTO] pycryptodome backend failed: {ex}")

    # No backend available
    print("[CRYPTO] No supported crypto backend found (install 'cryptography' or 'pycryptodome'); encryption disabled")
    _crypto_enabled = False
    _crypto_salt = None
    _crypto_backend = None
    _crypto_aesgcm = None
    _crypto_key = None


def encrypt_frame_bytes(plain: bytes, frame_id: int) -> bytes:
    """Encrypt one frame.

    Output format:
        b"ENC1" + salt(16) + nonce(12) + ciphertext + tag(16)

    For the cryptography backend, AESGCM returns ciphertext+tag, so we split the last 16 bytes.
    """
    if not _crypto_enabled or _crypto_salt is None:
        return plain

    nonce = os.urandom(12)
    aad = frame_id.to_bytes(4, "big", signed=False)

    if _crypto_backend == "cryptography" and _crypto_aesgcm is not None:
        try:
            ct_and_tag = _crypto_aesgcm.encrypt(nonce, plain, aad)
            if len(ct_and_tag) < 16:
                return plain
            ciphertext = ct_and_tag[:-16]
            tag = ct_and_tag[-16:]
            return b"ENC1" + _crypto_salt + nonce + ciphertext + tag
        except Exception:
            return plain

    if _crypto_backend == "pycryptodome" and _crypto_key is not None and PYAES is not None:
        try:
            cipher = PYAES.new(_crypto_key, PYAES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plain)
            return b"ENC1" + _crypto_salt + nonce + ciphertext + tag
        except Exception:
            return plain

    return plain

def toggle_stop_sender(sock, addr):
    """Toggle a background task that sends 'stop' every second.

    If GO loop is running, it will be stopped first.
    Call again to stop the STOP loop.
    """
    global _stop_sender_running, _stop_sender_thread
    global _go_sender_running

    def _send_loop():
        global _stop_sender_running
        while _stop_sender_running:
            try:
                sock.sendto(b"stop", addr)
            except Exception:
                pass
            time.sleep(1)

    # If GO is running, stop it when STOP is requested
    _go_sender_running = False

    if not _stop_sender_running:
        _stop_sender_running = True
        _stop_sender_thread = threading.Thread(target=_send_loop, daemon=True)
        _stop_sender_thread.start()
    else:
        _stop_sender_running = False


# Alias kept for requested naming style

toggleStopSender = toggle_stop_sender

def toggle_go_sender(sock, addr):
    """Toggle a background task that sends 'go' every second.

    If STOP loop is running, it will be stopped first.
    Call again to stop the GO loop.
    """
    global _go_sender_running, _go_sender_thread
    global _stop_sender_running

    def _send_loop():
        global _go_sender_running
        while _go_sender_running:
            try:
                sock.sendto(b"go", addr)
            except Exception:
                pass
            time.sleep(1)

    # If STOP is running, stop it when GO is requested
    _stop_sender_running = False

    if not _go_sender_running:
        _go_sender_running = True
        _go_sender_thread = threading.Thread(target=_send_loop, daemon=True)
        _go_sender_thread.start()
    else:
        _go_sender_running = False


# Alias kept for requested naming style

toggleGoSender = toggle_go_sender

def send_freeze_ten_times(sock, addr):
    """
    Sends the word 'freeze' ten times in a row
    to the given socket and address.
    """
    for _ in range(10):
        try:
            sock.sendto(b"freeze", addr)
        except Exception:
            pass

def send_unfreeze_ten_times(sock, addr):
    """
    Sends the word 'freeze' ten times in a row
    to the given socket and address.
    """
    for _ in range(10):
        try:
            sock.sendto(b"unfreeze", addr)
        except Exception:
            pass

def send_death_message(sock, addr):
    """
    Sends the word 'death' once to the given socket and address.
    """
    try:
        sock.sendto(b"death", addr)
    except Exception:
        pass

def main():
    ap = argparse.ArgumentParser(description="UDP Screen Share Server (multicast)")  # Initialize argument parser with description
    ap.add_argument("--name", default="Server-1", help="Server display name")  # Add argument for server name with default
    ap.add_argument("--group", default=DEFAULT_GROUP, help="Multicast group (239.x.x.x recommended)")  # Multicast group argument with default
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="Multicast UDP port")  # UDP port argument with default
    ap.add_argument("--fps", type=int, default=12, help="Target frames per second")  # FPS argument with default
    ap.add_argument("--width", type=int, default=1280, help="Resize width (maintains aspect)")  # Width argument for resizing screen capture
    ap.add_argument("--quality", type=int, default=60, help="JPEG quality (1-100)")  # JPEG quality argument with default
    ap.add_argument("--no-ui", action="store_true", help="Do not launch the control interface")
    args = ap.parse_args()  # Parse command-line arguments into args namespace

    ui_proc = None
    if not args.no_ui:
        try:
            ui_path = Path(__file__).with_name("InterFace.py")
            ui_proc = subprocess.Popen([sys.executable, str(ui_path)])
        except Exception as ex:
            print(f"[UI] Failed to launch InterFace.py: {ex}")

    sender, maddr = make_multicast_sender(args.group, args.port)  # Create multicast sender socket and address tuple
    ann_sock, ann_msg = broadcaster(args.name, args.group, args.port, args.fps, args.width, 0)

    # Control socket to receive commands from the UI (localhost only)
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    control_sock.bind((CONTROL_HOST, CONTROL_PORT))
    control_sock.setblocking(False)

    sct = mss()  # Initialize MSS screen capture instance
    monitor = sct.monitors[0]  # Select the full virtual screen (all monitors combined)
    frame_id = 0  # Initialize frame ID counter
    period = 1.0 / max(1, args.fps)  # Calculate time period per frame to achieve target FPS, avoid division by zero
    last_announce = 0.0  # Timestamp of last announcement sent
    send_screenshots = True  # or False

    try:
        while True:  # Infinite loop to capture and send frames continuously
            t0 = time.time()  # Record start time of this loop iteration

            # Poll UI control messages (non-blocking)
            try:
                cmd, _ = control_sock.recvfrom(1024)
                cmd = cmd.strip()

                if cmd.startswith(CONTROL_SET_PASSWORD_PREFIX):
                    pw_bytes = cmd[len(CONTROL_SET_PASSWORD_PREFIX):]
                    try:
                        pw = pw_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        pw = ""
                    pw = (pw or "").strip()
                    print(f"[CONTROL] Received password message (len={len(pw)})")
                    set_password_encryption(pw)

                elif cmd == CONTROL_TOGGLE_STOP:
                    toggleStopSender(sender, maddr)
                elif cmd == CONTROL_TOGGLE_GO:
                    toggleGoSender(sender, maddr)
                elif cmd == CONTROL_FREEZE:
                    send_freeze_ten_times(sender, maddr)
                elif cmd == CONTROL_UNFREEZE:
                    send_unfreeze_ten_times(sender, maddr)
                elif cmd == CONTROL_DEATH:
                    send_death_message(sender, maddr)
            except BlockingIOError:
                pass
            except Exception:
                pass

            # If the UI hasn't provided the password yet, we still ANNOUNCE the server
            # (so discovery works), but we skip sending frames to avoid unencrypted output.
            if _crypto_enabled:
                # Grab screen
                raw = sct.grab(monitor)  # Capture the screen contents of the selected monitor region
                img = np.array(raw)  # Convert raw capture to a numpy array (BGRA format)
                img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)  # Convert BGRA image to BGR format (drop alpha channel)

                # Resize keeping aspect
                if args.width and img.shape[1] != args.width:  # If desired width is set and different from current width
                    h = int(img.shape[0] * (args.width / img.shape[1]))  # Calculate new height to maintain aspect ratio
                    img = cv2.resize(img, (args.width, h), interpolation=cv2.INTER_AREA)  # Resize image to new dimensions

                # Encode JPEG
                encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), args.quality]  # Set JPEG encoding parameters with quality level
                ok, jpg = cv2.imencode(".jpg", img, encode_params)  # Encode the image as JPEG, returns success flag and encoded image
                if not ok:  # If encoding failed
                    time.sleep(0.01)
                else:
                    payload = jpg.tobytes()  # Convert encoded JPEG to bytes for transmission

                    # Encrypt the frame bytes if a password was set via the UI.
                    payload = encrypt_frame_bytes(payload, frame_id)

                    # Chunk into UDP-sized pieces
                    max_payload = MAX_DATAGRAM - HEADER_SIZE  # subtract protocol header size
                    total_chunks = (len(payload) + max_payload - 1) // max_payload or 1  # Calculate number of chunks needed to send entire payload

                    for idx in range(total_chunks):  # Iterate over each chunk index
                        start = idx * max_payload  # Calculate start byte of this chunk
                        part = payload[start:start + max_payload]  # Extract chunk bytes from payload
                        header = pack_header(frame_id, idx, total_chunks, len(part))  # Pack header with frame ID, chunk index, total chunks, and chunk size
                        sender.sendto(header + part, maddr)  # Send the header and chunk data as a UDP packet to multicast address

                    frame_id = (frame_id + 1) & 0xFFFFFFFF  # Increment frame ID and wrap around at 32-bit unsigned int max
            else:
                # No password yet; don't send frames.
                time.sleep(0.01)

            # Broadcast presence ~once/sec
            now = time.time()  # Get current time
            if now - last_announce > 1.0:
                ann_msg["height"] = img.shape[0] if _crypto_enabled else 0
                ann_msg["ts"] = now
                ann_payload = json.dumps(ann_msg).encode("utf-8")
                ann_sock.sendto(ann_payload, ("255.255.255.255", ANNOUNCE_PORT))
                last_announce = now

            # Throttle to FPS
            elapsed = time.time() - t0  # Calculate elapsed time for this loop iteration
            sleep = period - elapsed  # Calculate remaining time to sleep to maintain target FPS
            if sleep > 0:  # If there is time left to sleep
                time.sleep(sleep)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sender.close()
        except Exception:
            pass
        try:
            ann_sock.close()
        except Exception:
            pass
        try:
            control_sock.close()
        except Exception:
            pass
        if ui_proc is not None:
            try:
                ui_proc.terminate()
            except Exception:
                pass

if __name__ == "__main__":
    main()  # Run main function if this script is executed directly