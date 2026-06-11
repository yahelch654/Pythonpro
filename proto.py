# Packet-format helpers shared by client and server
import struct
from typing import Tuple

# Datagram header format: unsigned int, 4 unsigned shorts
HEADER_FORMAT = "!IHHHH"
# Struct object to pack/unpack header fields
DATAGRAM_HEADER_STRUCT = struct.Struct(HEADER_FORMAT)
# Size of header in bytes
HEADER_SIZE_IN_BYTES = DATAGRAM_HEADER_STRUCT.size

# Maximum datagram size for UDP packets
MAXIMUM_DATAGRAM_SIZE_BYTES = 1300
# UDP port used for broadcast discovery messages
BROADCAST_DISCOVERY_PORT = 9999
# Default multicast group IP address for streaming
DEFAULT_MULTICAST_GROUP_IP = "239.10.10.10"
# Default multicast port for streaming
DEFAULT_MULTICAST_PORT = 5004


def create_packet_header(frame_identifier: int, chunk_index: int, total_chunks_in_frame: int, payload_length_in_bytes: int) -> bytes:
    # Reserved field is always zero for now
    reserved_empty_field = 0
    # Pack the header fields into a binary struct
    return DATAGRAM_HEADER_STRUCT.pack(
        frame_identifier,
        chunk_index,
        total_chunks_in_frame,
        payload_length_in_bytes,
        reserved_empty_field
    )

def extract_header_and_payload(packet_data: bytes) -> Tuple[tuple, bytes]:
    # Extract the header bytes from the start of the packet
    header_bytes = packet_data[:HEADER_SIZE_IN_BYTES]
    # Extract the payload bytes after the header
    payload_bytes = packet_data[HEADER_SIZE_IN_BYTES:]
    # Unpack the header fields into a tuple
    parsed_header_tuple = DATAGRAM_HEADER_STRUCT.unpack(header_bytes)
    # Return the header tuple and payload bytes
    return parsed_header_tuple, payload_bytes