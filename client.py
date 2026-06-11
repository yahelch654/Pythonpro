import json
import socket
import struct
import subprocess
import time
import cv2
import numpy as np
import pynput

from proto import extract_header_and_payload, BROADCAST_DISCOVERY_PORT, HEADER_SIZE_IN_BYTES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES as PYAES
from Crypto.Protocol.KDF import PBKDF2 as PYPBKDF2
from Crypto.Hash import SHA256 as PYSHA256

# This prefix marks encrypted frame payloads.
ENC_MAGIC = b"ENC1"

# Cache derived keys per salt to avoid repeated expensive PBKDF2 work.
_crypto_keys_cache = {}

# Derives or retrieves the AES key for the server password and salt.
def get_crypto_backend_and_key_for_salt(password: str, salt_bytes: bytes):
    # Return None if no password provided.
    if not password:
        return None
    # Return cached key if available.
    if salt_bytes in _crypto_keys_cache:
        return _crypto_keys_cache[salt_bytes]

    # Encode password to bytes.
    password_bytes = password.encode("utf-8")

    # Try the 'cryptography' backend for key derivation.
    if AESGCM is not None and PBKDF2HMAC is not None and hashes is not None:
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=200_000,
            )
            derived_key = kdf.derive(password_bytes)
            aesgcm_instance = AESGCM(derived_key)
            _crypto_keys_cache[salt_bytes] = ("cryptography", aesgcm_instance)
            return _crypto_keys_cache[salt_bytes]
        except Exception:
            pass

    # Try the 'pycryptodome' backend for key derivation.
    if PYAES is not None and PYPBKDF2 is not None and PYSHA256 is not None:
        try:
            derived_key = PYPBKDF2(password_bytes, salt_bytes, dkLen=32, count=200_000, hmac_hash_module=PYSHA256)
            _crypto_keys_cache[salt_bytes] = ("pycryptodome", derived_key)
            return _crypto_keys_cache[salt_bytes]
        except Exception:
            pass

    # Return None if key derivation failed.
    return None


# Decrypts encrypted frames and returns normal payloads unchanged.
def decrypt_payload_if_necessary(password: str, payload_blob: bytes, frame_id: int) -> bytes:
    # Return original if payload is too short.
    if not payload_blob or len(payload_blob) < 4:
        return payload_blob
    # Return original if payload does not start with encryption magic.
    if not payload_blob.startswith(ENC_MAGIC):
        return payload_blob

    # Return empty if payload is too short to be valid encrypted data.
    if len(payload_blob) < 4 + 16 + 12 + 16 + 1:
        return b""

    # Parse salt, nonce, ciphertext+tag from payload.
    salt_16_bytes = payload_blob[4:20]
    nonce_12_bytes = payload_blob[20:32]
    ciphertext_and_tag = payload_blob[32:]

    # Return empty if ciphertext+tag is too short.
    if len(ciphertext_and_tag) < 16:
        return b""

    # Create associated data from frame ID.
    associated_data = frame_id.to_bytes(4, "big", signed=False)

    # Retrieve crypto backend and key for salt.
    crypto_tuple = get_crypto_backend_and_key_for_salt(password, salt_16_bytes)
    if crypto_tuple is None:
        return b""

    backend_name, backend_key_object = crypto_tuple
    try:
        # Decrypt using cryptography backend.
        if backend_name == "cryptography":
            return backend_key_object.decrypt(nonce_12_bytes, ciphertext_and_tag, associated_data)

        # Decrypt using pycryptodome backend.
        if backend_name == "pycryptodome":
            ciphertext = ciphertext_and_tag[:-16]
            authentication_tag = ciphertext_and_tag[-16:]
            cipher = PYAES.new(backend_key_object, PYAES.MODE_GCM, nonce=nonce_12_bytes)
            cipher.update(associated_data)
            return cipher.decrypt_and_verify(ciphertext, authentication_tag)
    except Exception:
        # Return empty on any decryption error.
        return b""

    # Return empty if no decryption succeeded.
    return b""


# Listens for broadcast announcements from servers.
def discover_available_servers(timeout_seconds=2.0):
    # Create and bind UDP socket to discovery port.
    discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    discovery_socket.bind(("", BROADCAST_DISCOVERY_PORT))
    discovery_socket.settimeout(timeout_seconds)

    # Dictionary to hold discovered servers.
    discovered_servers = {}
    end_time = time.time() + timeout_seconds

    # Loop until timeout.
    while time.time() < end_time:
        try:
            # Receive broadcast packet.
            data_bytes, sender_address = discovery_socket.recvfrom(2048)
            # Parse JSON announcement.
            message_dict = json.loads(data_bytes.decode("utf-8"))
            # Add valid server announcements.
            if message_dict.get("type") == "screenshare_announce":
                server_name = message_dict.get("name", f"{sender_address[0]}:{message_dict.get('port')}")
                discovered_servers[server_name] = (message_dict["group"], int(message_dict["port"]), message_dict)
        except socket.timeout:
            # Timeout ends discovery.
            break
        except Exception:
            # Ignore invalid packets.
            pass

    # Close socket and return discovered servers.
    discovery_socket.close()
    return discovered_servers


# Shuts down the client machine when the server sends the death command.
def shutdown_machine():
    subprocess.run(["shutdown", "-h"])


# Starts or stops keyboard and mouse suppression.
def toggle_input_freeze(should_freeze: bool, keyboard_listener=None, mouse_listener=None):
    if should_freeze:
        # Start listeners that suppress input.
        mouse_listener = pynput.mouse.Listener(suppress=True)
        mouse_listener.start()
        keyboard_listener = pynput.keyboard.Listener(suppress=True)
        keyboard_listener.start()
    else:
        # Stop listeners to restore input.
        if mouse_listener: mouse_listener.stop()
        if keyboard_listener: keyboard_listener.stop()


# Joins the server multicast group.
def connect_to_multicast_group(group_ip: str, port: int):
    # Create UDP socket for multicast.
    multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to any address on the port.
    try:
        multicast_socket.bind(("", port))
    except OSError:
        # Fallback bind to group IP if needed.
        multicast_socket.bind((group_ip, port))

    # Join the multicast group.
    multicast_request_bytes = struct.pack("=4sl", socket.inet_aton(group_ip), socket.INADDR_ANY)
    multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request_bytes)
    # Set receive buffer size and timeout.
    multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    multicast_socket.settimeout(3.0)

    # Return the configured socket.
    return multicast_socket


# Discovers servers and asks the user which one to connect to.
def prompt_user_for_server_selection():
    # Discover servers for 2 seconds.
    print("Discovering servers for 2 seconds...")
    available_servers = discover_available_servers(timeout_seconds=2.0)

    # If no servers found, ask for manual input.
    if not available_servers:
        print("No servers found. You can still connect if you know group/port.")
        group_ip = input("Multicast group [e.g., 239.10.10.10]: ").strip()
        port = int(input("Port [e.g., 5004]: ").strip())
        return group_ip, port

    # Print discovered servers.
    print("\nAvailable servers:")
    server_names = list(available_servers.keys())
    for index, server_name in enumerate(server_names, 1):
        _, _, metadata = available_servers[server_name]
        print(
            f"{index}. {server_name}  @ {metadata['group']}:{metadata['port']}  ({metadata['width']}x{metadata['height']} ~{metadata['fps']}fps)")

    # Get user selection.
    choice = input("Select number (or press Enter for 1): ").strip() or "1"
    selected_index = int(choice) - 1
    selected_server_key = server_names[selected_index]
    selected_group_ip, selected_port, _ = available_servers[selected_server_key]

    # Return selected server info.
    print(f"Connecting to {selected_server_key} @ {selected_group_ip}:{selected_port}")
    return selected_group_ip, selected_port


# Checks whether a packet is a text command instead of a video packet.
def handle_remote_commands(packet_bytes: bytes, is_video_playing: bool, stop_video_callback,
                           resume_video_callback) -> str:
    try:
        # Decode command string.
        command_string = packet_bytes.decode("utf-8").strip().lower()

        # Handle recognized commands.
        if command_string == "go":
            resume_video_callback()
            return "command_go"
        if command_string == "stop":
            stop_video_callback()
            return "command_stop"
        if command_string == "freeze":
            toggle_input_freeze(True)
            return "command_freeze"
        if command_string == "unfreeze":
            toggle_input_freeze(False)
            return "command_unfreeze"
        if command_string == "death":
            shutdown_machine()
            return "command_death"

        # Return empty if unknown text.
        return ""
    except UnicodeDecodeError:
        # Return empty if not text.
        return ""


# Joins chunks, decrypts if needed, decodes the JPEG, and displays it.
def reassemble_and_display_frame(frame_buffer_dict: dict, total_chunks: int, frame_id: int, password: str,
                                 is_video_playing: bool) -> bool:
    # Join all chunks into one JPEG byte array.
    chunk_pieces = [frame_buffer_dict[i] for i in range(total_chunks)]
    full_jpeg_bytes = b"".join(chunk_pieces)

    # Decrypt if encryption enabled.
    decrypted_jpeg_bytes = decrypt_payload_if_necessary(password, full_jpeg_bytes, frame_id)
    if not decrypted_jpeg_bytes:
        return False

    # Decode JPEG bytes to OpenCV image.
    image_array = np.frombuffer(decrypted_jpeg_bytes, dtype=np.uint8)
    decoded_frame = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

    if decoded_frame is not None:
        # Show frame if playing.
        if is_video_playing:
            cv2.imshow("UDP Screen Share", decoded_frame)
        # Quit on ESC key.
        if cv2.waitKey(1) == 27:  # ESC to quit
            return True  # signal to quit

    # Continue running.
    return False


# Connects to a selected server and continuously receives commands/video frames.
def main():
    # Prompt user for server group and port.
    group_ip, port = prompt_user_for_server_selection()
    # Join multicast group.
    multicast_socket = connect_to_multicast_group(group_ip, port)
    print("Client connected to the server.")

    # Prompt for password.
    try:
        server_password = input("Password (required): ").strip()
    except Exception:
        server_password = ""

    # Buffers for incomplete frames.
    incomplete_frames_buffer = {}
    timestamp_of_last_completed_frame = time.time()
    MAXIMUM_INCOMPLETE_FRAME_AGE_SECONDS = 1.5

    # Playback state.
    is_video_playing = True

    # Callback to stop video display.
    def stop_video_callback():
        nonlocal is_video_playing
        is_video_playing = False

    # Callback to resume video display.
    def resume_video_callback():
        nonlocal is_video_playing
        is_video_playing = True

    # Counters for received packet types.
    packet_counters = {
        "command_go": 0, "command_stop": 0,
        "command_freeze": 0, "command_unfreeze": 0,
        "command_death": 0, "ignored_short": 0,
        "video_chunk": 0
    }

    # Prints a summary of received packet counts.
    def print_packet_summary():
        print(
            f"(death: {packet_counters['command_death']} | freeze {packet_counters['command_freeze']} | unfreeze {packet_counters['command_unfreeze']} | go {packet_counters['command_go']} | stop {packet_counters['command_stop']} | video {packet_counters['video_chunk']} | ignored {packet_counters['ignored_short']})")

    try:
        while True:
            try:
                # Receive one UDP packet.
                packet_bytes, sender_address = multicast_socket.recvfrom(2048)

                # Check if packet is a command.
                command_type = handle_remote_commands(packet_bytes, is_video_playing, stop_video_callback,
                                                      resume_video_callback)
                if command_type:
                    # Increment command counter and print summary.
                    packet_counters[command_type] += 1
                    print_packet_summary()
                    continue

            except socket.timeout:
                # On timeout, check for ESC key to quit.
                if cv2.waitKey(1) == 27:
                    break
                continue

            # Ignore packets too short to contain header.
            if len(packet_bytes) < HEADER_SIZE_IN_BYTES:
                packet_counters["ignored_short"] += 1
                print_packet_summary()
                continue

            # Count video chunk packets.
            packet_counters["video_chunk"] += 1
            print_packet_summary()

            # Parse protocol header and payload.
            parsed_header_tuple, payload_segment = extract_header_and_payload(packet_bytes)
            frame_id, chunk_index, total_chunks, payload_length, _ = parsed_header_tuple
            payload_segment = payload_segment[:payload_length]

            # Create new frame buffer if needed.
            if frame_id not in incomplete_frames_buffer:
                incomplete_frames_buffer[frame_id] = (dict(), set())

            # Store chunk and mark as received.
            frame_chunks_dict, received_chunk_indices_set = incomplete_frames_buffer[frame_id]
            frame_chunks_dict[chunk_index] = payload_segment
            received_chunk_indices_set.add(chunk_index)

            # If all chunks received, reassemble and display.
            if len(received_chunk_indices_set) == total_chunks:
                should_quit = reassemble_and_display_frame(frame_chunks_dict, total_chunks, frame_id, server_password,
                                                           is_video_playing)
                if should_quit:
                    break

                # Remove completed frame buffer.
                del incomplete_frames_buffer[frame_id]
                timestamp_of_last_completed_frame = time.time()

            # Clear old incomplete frames.
            if time.time() - timestamp_of_last_completed_frame > MAXIMUM_INCOMPLETE_FRAME_AGE_SECONDS:
                incomplete_frames_buffer.clear()

    finally:
        # Cleanup sockets and windows on exit.
        multicast_socket.close()
        cv2.destroyAllWindows()


# Start client when run directly.
if __name__ == "__main__":
    main()
