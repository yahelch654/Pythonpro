# This client connects to a multicast screensharing server, receives UDP packets,
# reassembles fragmented JPEG frames, decodes them, and displays the video stream in real time.
# client.py
import json
import socket
import struct
import subprocess
import time
from collections import defaultdict

import cv2
import numpy as np
import pynput

from proto import unpack_header, ANNOUNCE_PORT, HEADER_SIZE

# Symmetric decryption (password-derived key). Matches server.py AES-GCM + PBKDF2.
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

ENC_MAGIC = b"ENC1"  # server prepends this when encryption is enabled


# Listen for broadcast announcements from servers to automatically discover available screen-share hosts.
# Each server periodically sends JSON metadata containing its name, group, port, and video resolution.
def discover_servers(timeout=5.0):
    # Create UDP socket and bind to the announcement port so we can hear broadcast messages.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", ANNOUNCE_PORT))
    sock.settimeout(timeout)

    found = {}
    end = time.time() + timeout
    # Loop for the duration of the timeout, collecting any announcement packets.
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(2048)
            msg = json.loads(data.decode("utf-8"))
            if msg.get("type") == "screenshare_announce":
                name = msg.get("name", f"{addr[0]}:{msg.get('port')}")
                found[name] = (msg["group"], int(msg["port"]), msg)
        except socket.timeout:
            break
        except Exception:
            pass
    sock.close()
    return found
def shutdown():
    subprocess.run(["shutdown", "-h"])


stop_bool = True

def stop(_=None):
    global stop_bool
    stop_bool = False

def go(_=None):
    global stop_bool
    stop_bool = True

def freeze(freeze_bool, keyboard_listener=None, mouse_listener=None):
    # Source - https://stackoverflow.com/a
    # Posted by ProblemsLoop
    # Retrieved 2026-01-09, License - CC BY-SA 4.0
    if freeze_bool:
        # Disable mouse and keyboard events
        mouse_listener = pynput.mouse.Listener(suppress=True)
        mouse_listener.start()
        keyboard_listener = pynput.keyboard.Listener(suppress=True)
        keyboard_listener.start()
    elif freeze_bool==False:
        # Enable mouse and keyboard events
        mouse_listener.stop()
        keyboard_listener.stop()


# Join a multicast group so we can receive the actual video stream.
# Multicast allows many clients to receive the same video feed without additional load on the server.
def join_multicast(group: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the port so we can receive packets sent to the multicast group.
    # Some platforms require binding directly to the multicast address.
    try:
        s.bind(("", port))
    except OSError:
        # On Windows you may need to bind to the group addr
        s.bind((group, port))

    mreq = struct.pack("=4sl", socket.inet_aton(group), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    # (Optional) increase receive buffer
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    s.settimeout(3.0)
    return s


# Main entry point for the client: discovers servers, connects, receives frames, and displays video.
def main():
    # Attempt automatic discovery first; if no servers respond, request manual input from user.
    print("Discovering servers for 5 seconds...")
    servers = discover_servers(timeout=5.0)
    if not servers:
        print("No servers found. You can still connect if you know group/port.")
        group = input("Multicast group [e.g., 11.42.56.219]: ").strip()
        port = int(input("Port [e.g., 5004]: ").strip())
    else:
        print("\nAvailable servers:")
        for i, (name, (_, __, meta)) in enumerate(servers.items(), 1):
            print(
                f"{i}. {name}  @ {meta['group']}:{meta['port']}  ({meta['width']}x{meta['height']} ~{meta['fps']}fps)")
        choice = input("Select number (or press Enter for 1): ").strip() or "1"
        idx = int(choice) - 1
        key = list(servers.keys())[idx]
        group, port, meta = servers[key]
        print(f"Connecting to {key} @ {group}:{port}")

    if servers:
        pass
    else:
        meta = {"width": 0, "height": 0, "fps": 0}
    s = join_multicast(group, port)
    print("Client connected to the server.")

    # Password for decrypting frames (must match the server UI password).
    # The server will NOT send frames until encryption is enabled.
    password = ""
    try:
        password = input("Password (required): ").strip()
    except Exception:
        password = ""

    # Cache derived keys per-salt so we don't run PBKDF2 every frame.
    # Value is a tuple: (backend_name, backend_obj)
    #   backend_name == "cryptography" -> backend_obj is AESGCM
    #   backend_name == "pycryptodome" -> backend_obj is raw key bytes
    _crypto_by_salt = {}

    def _get_crypto_for_salt(salt16: bytes):
        if not password:
            return None
        if salt16 in _crypto_by_salt:
            return _crypto_by_salt[salt16]

        pw_bytes = password.encode("utf-8")

        # --- Preferred backend: cryptography ---
        if AESGCM is not None and PBKDF2HMAC is not None and hashes is not None:
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt16,
                    iterations=200_000,
                )
                key = kdf.derive(pw_bytes)
                a = AESGCM(key)
                _crypto_by_salt[salt16] = ("cryptography", a)
                return _crypto_by_salt[salt16]
            except Exception:
                pass

        # --- Fallback backend: pycryptodome ---
        if PYAES is not None and PYPBKDF2 is not None and PYSHA256 is not None:
            try:
                key = PYPBKDF2(pw_bytes, salt16, dkLen=32, count=200_000, hmac_hash_module=PYSHA256)
                _crypto_by_salt[salt16] = ("pycryptodome", key)
                return _crypto_by_salt[salt16]
            except Exception:
                pass

        return None

    def decrypt_if_needed(blob: bytes, frame_id: int) -> bytes:
        """If blob starts with ENC1, decrypt it and return plaintext JPEG bytes."""
        if not blob or len(blob) < 4:
            return blob
        if not blob.startswith(ENC_MAGIC):
            return blob

        # Format: ENC1 + salt(16) + nonce(12) + ciphertext + tag(16)
        if len(blob) < 4 + 16 + 12 + 16 + 1:
            return b""  # malformed
        salt16 = blob[4:20]
        nonce12 = blob[20:32]
        ct_and_tag = blob[32:]
        if len(ct_and_tag) < 16:
            return b""

        aad = frame_id.to_bytes(4, "big", signed=False)

        crypto = _get_crypto_for_salt(salt16)
        if crypto is None:
            return b""  # can't decrypt

        backend, obj = crypto
        try:
            if backend == "cryptography":
                # AESGCM expects ciphertext+tag concatenated
                return obj.decrypt(nonce12, ct_and_tag, aad)

            if backend == "pycryptodome":
                # Split ciphertext/tag for pycryptodome verify
                ciphertext = ct_and_tag[:-16]
                tag = ct_and_tag[-16:]
                cipher = PYAES.new(obj, PYAES.MODE_GCM, nonce=nonce12)
                cipher.update(aad)
                return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            return b""

        return b""

    # Per-frame reassembly context:
    # current_frames = maps frame_id -> (dict of chunk_index -> bytes, set of received indexes)
    # chunk_counters   = counts chunks received per frame (for debugging or diagnostics)
    # MAX_STASH_AGE    = how long we keep incomplete frames before discarding them
    current_frames = {}
    chunk_counters = defaultdict(int)
    last_completed = time.time()
    MAX_STASH_AGE = 1.5  # seconds

    try:
        while True:
            # Receive next UDP packet. Each packet contains a header followed by one JPEG fragment.
            try:
                pkt, addr = s.recvfrom(2048)
                print("got", len(pkt), "bytes from", addr)
                # --- command handling (STOP / FREEZE) ---
                try:
                    cmd = pkt.decode("utf-8").strip().lower()

                    if cmd == "go":
                        print("Got go")
                        go(stop_bool)
                        continue

                    if cmd == "stop":
                        print("Got stop")
                        stop(stop_bool)  # call stop function
                        continue  # skip video handling

                    if cmd == "freeze":
                        freeze(True)  # call freeze function
                        continue

                    if cmd == "unfreeze":
                        freeze(False)
                        continue

                    # Server sends "death" (not "dead")
                    if cmd == "death":
                        shutdown()
                        continue

                except UnicodeDecodeError:
                    pass  # not a text command, continue as normal
            except socket.timeout:
                print("recv timeout (no UDP packets)")
                # If idle, keep window responsive
                if cv2.waitKey(1) == 27:  # ESC
                    break
                continue

            # Ignore any packet that is too small to contain our header
            if len(pkt) < HEADER_SIZE:
                continue

            (frame_id, chunk_idx, total_chunks, payload_len, _), payload = unpack_header(pkt)
            # The header tells us which frame this chunk belongs to, its index, and how many total chunks exist.
            payload = payload[:payload_len]

            # Look up or create storage for this frame.
            # Frames arrive as multiple unordered chunks, so we store them individually until the frame is complete.
            buf, received = current_frames.get(frame_id, (bytearray(), set()))
            # Ensure buffer can fit in orderless appends; we’ll simply store chunks then concatenate later
            # Store as dict of idx->bytes for correctness
            if not received:
                current_frames[frame_id] = (dict(), set())
                buf, received = current_frames[frame_id]
            buf[chunk_idx] = payload
            received.add(chunk_idx)

            # All chunks for this frame have arrived — time to reassemble the JPEG image.
            if len(received) == total_chunks:
                # Reassemble chunk list in correct order and combine into a full JPEG byte sequence.
                parts = [buf[i] for i in range(total_chunks)]
                jpg = b"".join(parts)

                # If encrypted, decrypt to obtain the original JPEG bytes.
                jpg = decrypt_if_needed(jpg, frame_id)
                if not jpg:
                    del current_frames[frame_id]
                    last_completed = time.time()
                    continue

                # Decode the JPEG bytes into an OpenCV BGR image.
                arr = np.frombuffer(jpg, dtype=np.uint8)
                frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                # Display the decoded frame in a window. ESC closes the stream.
                if frame is not None:
                    if stop_bool:
                        cv2.imshow("UDP Screen Share", frame)
                    if cv2.waitKey(1) == 27:  # ESC to quit
                        break
                # cleanup completed
                del current_frames[frame_id]
                last_completed = time.time()

            # Discard all incomplete frames if nothing has completed recently. Prevents memory buildup on packet loss.
            if time.time() - last_completed > MAX_STASH_AGE:
                current_frames.clear()
    finally:
        s.close()
        cv2.destroyAllWindows()


if __name__ == "__main__":
    main()