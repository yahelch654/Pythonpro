import argparse
import json
import os
import threading
from pathlib import Path
import sys
import subprocess
import socket
import time
import cv2
import numpy as np

from mss import mss
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES as PYAES
from Crypto.Protocol.KDF import PBKDF2 as PYPBKDF2
from Crypto.Hash import SHA256 as PYSHA256

from proto import (
    BROADCAST_DISCOVERY_PORT,
    DEFAULT_MULTICAST_GROUP_IP,
    DEFAULT_MULTICAST_PORT,
    MAXIMUM_DATAGRAM_SIZE_BYTES,
    HEADER_SIZE_IN_BYTES,
    create_packet_header,
)

CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 50099
CONTROL_TOGGLE_STOP = b"toggle_stop_sender"
CONTROL_TOGGLE_GO = b"toggle_go_sender"
CONTROL_FREEZE = b"freeze_ten_times"
CONTROL_UNFREEZE = b"unfreeze_ten_times"
CONTROL_DEATH = b"death_message"
CONTROL_SET_PASSWORD_PREFIX = b"set_password:"


def create_multicast_sender_socket(group_ip: str, port: int):
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sender_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    multicast_address = (group_ip, port)
    return sender_socket, multicast_address

def create_discovery_broadcaster(server_name: str, group_ip: str, port: int, fps: int, width: int):
    announcement_message = {
        "type": "screenshare_announce",
        "name": server_name,
        "group": group_ip,
        "port": port,
        "fps": fps,
        "width": width,
        "height": 0,
        "ts": time.time(),
    }
    broadcaster_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcaster_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return broadcaster_socket, announcement_message

_is_stop_command_loop_running = False
_stop_command_thread = None
_is_go_command_loop_running = False
_go_command_thread = None

_is_encryption_active = False
_encryption_salt = None
_active_crypto_backend = None
_aesgcm_instance = None
_pycrypto_key_bytes = None

def derive_encryption_key_and_enable(password_string: str) -> None:
    global _is_encryption_active, _encryption_salt, _active_crypto_backend, _aesgcm_instance, _pycrypto_key_bytes

    password_bytes = (password_string or "").encode("utf-8")
    if not password_bytes:
        _is_encryption_active = False
        _encryption_salt, _active_crypto_backend, _aesgcm_instance, _pycrypto_key_bytes = None, None, None, None
        return

    _encryption_salt = os.urandom(16)

    if AESGCM is not None and PBKDF2HMAC is not None and hashes is not None:
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=_encryption_salt,
                iterations=200_000,
            )
            key = kdf.derive(password_bytes)
            _aesgcm_instance = AESGCM(key)
            _pycrypto_key_bytes = None
            _active_crypto_backend = "cryptography"
            _is_encryption_active = True
            return
        except Exception:
            pass

    if PYAES is not None and PYPBKDF2 is not None and PYSHA256 is not None:
        try:
            _pycrypto_key_bytes = PYPBKDF2(password_bytes, _encryption_salt, dkLen=32, count=200_000, hmac_hash_module=PYSHA256)
            _aesgcm_instance = None
            _active_crypto_backend = "pycryptodome"
            _is_encryption_active = True
            return
        except Exception:
            pass

    _is_encryption_active = False
    _encryption_salt, _active_crypto_backend, _aesgcm_instance, _pycrypto_key_bytes = None, None, None, None


def encrypt_payload(plaintext_bytes: bytes, frame_id: int) -> bytes:
    if not _is_encryption_active or _encryption_salt is None:
        return plaintext_bytes

    nonce = os.urandom(12)
    associated_data = frame_id.to_bytes(4, "big", signed=False)

    if _active_crypto_backend == "cryptography" and _aesgcm_instance is not None:
        try:
            ciphertext_and_tag = _aesgcm_instance.encrypt(nonce, plaintext_bytes, associated_data)
            if len(ciphertext_and_tag) < 16:
                return plaintext_bytes
            ciphertext = ciphertext_and_tag[:-16]
            authentication_tag = ciphertext_and_tag[-16:]
            return b"ENC1" + _encryption_salt + nonce + ciphertext + authentication_tag
        except Exception:
            return plaintext_bytes

    if _active_crypto_backend == "pycryptodome" and _pycrypto_key_bytes is not None and PYAES is not None:
        try:
            cipher = PYAES.new(_pycrypto_key_bytes, PYAES.MODE_GCM, nonce=nonce)
            cipher.update(associated_data)
            ciphertext, authentication_tag = cipher.encrypt_and_digest(plaintext_bytes)
            return b"ENC1" + _encryption_salt + nonce + ciphertext + authentication_tag
        except Exception:
            return plaintext_bytes

    return plaintext_bytes


def start_looping_stop_command(sender_socket, multicast_address):
    global _is_stop_command_loop_running, _stop_command_thread, _is_go_command_loop_running
    
    _is_go_command_loop_running = False

    def loop_stop_command():
        while _is_stop_command_loop_running:
            try:
                sender_socket.sendto(b"stop", multicast_address)
            except Exception:
                pass
            time.sleep(1)

    if not _is_stop_command_loop_running:
        _is_stop_command_loop_running = True
        _stop_command_thread = threading.Thread(target=loop_stop_command, daemon=True)
        _stop_command_thread.start()
    else:
        _is_stop_command_loop_running = False

def start_looping_go_command(sender_socket, multicast_address):
    global _is_go_command_loop_running, _go_command_thread, _is_stop_command_loop_running
    
    _is_stop_command_loop_running = False

    def loop_go_command():
        while _is_go_command_loop_running:
            try:
                sender_socket.sendto(b"go", multicast_address)
            except Exception:
                pass
            time.sleep(1)

    if not _is_go_command_loop_running:
        _is_go_command_loop_running = True
        _go_command_thread = threading.Thread(target=loop_go_command, daemon=True)
        _go_command_thread.start()
    else:
        _is_go_command_loop_running = False

def send_burst_command(sender_socket, multicast_address, command_string: str, repetitions: int = 10):
    command_bytes = command_string.encode('utf-8')
    for _ in range(repetitions):
        try:
            sender_socket.sendto(command_bytes, multicast_address)
        except Exception:
            pass

def start_ui_process():
    try:
        ui_script_path = Path(__file__).with_name("interface.py")
        return subprocess.Popen([sys.executable, str(ui_script_path), "--managed"])
    except Exception:
        return None

def process_control_socket_commands(control_socket, sender_socket, multicast_address):
    try:
        incoming_command, _ = control_socket.recvfrom(1024)
        incoming_command = incoming_command.strip()

        if incoming_command.startswith(CONTROL_SET_PASSWORD_PREFIX):
            password_bytes = incoming_command[len(CONTROL_SET_PASSWORD_PREFIX):]
            password_string = password_bytes.decode("utf-8", errors="ignore").strip()
            derive_encryption_key_and_enable(password_string)
        elif incoming_command == CONTROL_TOGGLE_STOP:
            start_looping_stop_command(sender_socket, multicast_address)
        elif incoming_command == CONTROL_TOGGLE_GO:
            start_looping_go_command(sender_socket, multicast_address)
        elif incoming_command == CONTROL_FREEZE:
            send_burst_command(sender_socket, multicast_address, "freeze")
        elif incoming_command == CONTROL_UNFREEZE:
            send_burst_command(sender_socket, multicast_address, "unfreeze")
        elif incoming_command == CONTROL_DEATH:
            send_burst_command(sender_socket, multicast_address, "death", repetitions=1)
    except BlockingIOError:
        pass
    except Exception:
        pass

def capture_and_encode_screen(screen_capture_tool, capture_monitor, target_width: int, jpeg_quality: int):
    raw_capture = screen_capture_tool.grab(capture_monitor)
    image_array = np.array(raw_capture)
    bgr_image = cv2.cvtColor(image_array, cv2.COLOR_BGRA2BGR)

    if target_width and bgr_image.shape[1] != target_width:
        scaled_height = int(bgr_image.shape[0] * (target_width / bgr_image.shape[1]))
        bgr_image = cv2.resize(bgr_image, (target_width, scaled_height), interpolation=cv2.INTER_AREA)

    encoding_parameters = [int(cv2.IMWRITE_JPEG_QUALITY), jpeg_quality]
    is_encode_successful, encoded_jpeg = cv2.imencode(".jpg", bgr_image, encoding_parameters)
    
    if is_encode_successful:
        return encoded_jpeg.tobytes(), bgr_image.shape[0]
    return None, 0

def extract_and_send_payload_chunks(payload_bytes: bytes, frame_id: int, sender_socket, multicast_address):
    max_payload_per_packet = MAXIMUM_DATAGRAM_SIZE_BYTES - HEADER_SIZE_IN_BYTES
    total_chunks_required = (len(payload_bytes) + max_payload_per_packet - 1) // max_payload_per_packet or 1

    for chunk_index in range(total_chunks_required):
        start_byte_index = chunk_index * max_payload_per_packet
        chunk_segment = payload_bytes[start_byte_index:start_byte_index + max_payload_per_packet]
        packet_header = create_packet_header(frame_id, chunk_index, total_chunks_required, len(chunk_segment))
        sender_socket.sendto(packet_header + chunk_segment, multicast_address)

def broadcast_discovery_message(announcement_socket, announcement_message, current_image_height):
    announcement_message["height"] = current_image_height if _is_encryption_active else 0
    announcement_message["ts"] = time.time()
    payload_json_bytes = json.dumps(announcement_message).encode("utf-8")
    announcement_socket.sendto(payload_json_bytes, ("255.255.255.255", BROADCAST_DISCOVERY_PORT))


def main():
    cli_parser = argparse.ArgumentParser(description="UDP Screen Share Server")
    cli_parser.add_argument("--name", default="Server-1")
    cli_parser.add_argument("--group", default=DEFAULT_MULTICAST_GROUP_IP)
    cli_parser.add_argument("--port", type=int, default=DEFAULT_MULTICAST_PORT)
    cli_parser.add_argument("--fps", type=int, default=12)
    cli_parser.add_argument("--width", type=int, default=1280)
    cli_parser.add_argument("--height", type=int, default=720)
    cli_parser.add_argument("--quality", type=int, default=60)
    cli_parser.add_argument("--no-ui", action="store_true")
    arguments = cli_parser.parse_args()

    ui_process_handle = None
    if not arguments.no_ui:
        ui_process_handle = start_ui_process()

    multicast_sender_socket, multicast_address_tuple = create_multicast_sender_socket(arguments.group, arguments.port)
    discovery_socket, announcement_message_dict = create_discovery_broadcaster(
        arguments.name, arguments.group, arguments.port, arguments.fps, arguments.width
    )

    local_control_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_control_socket.bind((CONTROL_HOST, CONTROL_PORT))
    local_control_socket.setblocking(False)

    screen_capture_tool = mss()
    primary_monitor = screen_capture_tool.monitors[0]
    current_frame_id = 0
    target_frame_duration_seconds = 1.0 / max(1, arguments.fps)
    timestamp_of_last_announcement = 0.0

    try:
        while True:
            loop_start_time = time.time()

            process_control_socket_commands(local_control_socket, multicast_sender_socket, multicast_address_tuple)

            if _is_encryption_active:
                jpeg_bytes, image_height = capture_and_encode_screen(screen_capture_tool, primary_monitor, arguments.width, arguments.quality)
                
                if jpeg_bytes:
                    encrypted_payload = encrypt_payload(jpeg_bytes, current_frame_id)
                    extract_and_send_payload_chunks(encrypted_payload, current_frame_id, multicast_sender_socket, multicast_address_tuple)
                    current_frame_id = (current_frame_id + 1) & 0xFFFFFFFF
            else:
                image_height = 0
                time.sleep(0.01)

            current_time = time.time()
            if current_time - timestamp_of_last_announcement > 1.0:
                broadcast_discovery_message(discovery_socket, announcement_message_dict, image_height)
                timestamp_of_last_announcement = current_time

            elapsed_processing_time = time.time() - loop_start_time
            sleep_duration = target_frame_duration_seconds - elapsed_processing_time
            if sleep_duration > 0:
                time.sleep(sleep_duration)
                
    except KeyboardInterrupt:
        pass
    finally:
        for resource in [multicast_sender_socket, discovery_socket, local_control_socket]:
            try:
                resource.close()
            except Exception:
                pass
        if ui_process_handle is not None:
            try:
                ui_process_handle.terminate()
            except Exception:
                pass

if __name__ == "__main__":
    main()
