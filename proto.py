import struct
from typing import Tuple

HEADER_FORMAT = "!IHHHH"
DATAGRAM_HEADER_STRUCT = struct.Struct(HEADER_FORMAT)
HEADER_SIZE_IN_BYTES = DATAGRAM_HEADER_STRUCT.size

MAXIMUM_DATAGRAM_SIZE_BYTES = 1300
BROADCAST_DISCOVERY_PORT = 9999
DEFAULT_MULTICAST_GROUP_IP = "239.10.10.10"
DEFAULT_MULTICAST_PORT = 5004


def create_packet_header(frame_identifier: int, chunk_index: int, total_chunks_in_frame: int, payload_length_in_bytes: int) -> bytes:
    reserved_empty_field = 0
    return DATAGRAM_HEADER_STRUCT.pack(
        frame_identifier,
        chunk_index,
        total_chunks_in_frame,
        payload_length_in_bytes,
        reserved_empty_field
    )

def extract_header_and_payload(packet_data: bytes) -> Tuple[tuple, bytes]:
    header_bytes = packet_data[:HEADER_SIZE_IN_BYTES]
    payload_bytes = packet_data[HEADER_SIZE_IN_BYTES:]
    parsed_header_tuple = DATAGRAM_HEADER_STRUCT.unpack(header_bytes)
    return parsed_header_tuple, payload_bytes