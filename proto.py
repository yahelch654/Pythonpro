# proto.py
import struct

# Datagram header: frame_id (uint32), chunk_idx (uint16), total_chunks (uint16), payload_len (uint16), reserved (uint16)
HDR_STRUCT = struct.Struct("!IHHHH")
HEADER_SIZE = HDR_STRUCT.size
MAX_DATAGRAM = 1300                    # stay under typical MTU
ANNOUNCE_PORT = 9999                   # UDP broadcast discovery port
DEFAULT_GROUP = "239.10.10.10"         # default multicast group (can be overridden)
DEFAULT_PORT = 5004                    # default multicast port

def pack_header(frame_id: int, chunk_idx: int, total_chunks: int, payload_len: int) -> bytes:
    return HDR_STRUCT.pack(frame_id, chunk_idx, total_chunks, payload_len, 0)

def unpack_header(data: bytes):
    return HDR_STRUCT.unpack(data[:HDR_STRUCT.size]), data[HDR_STRUCT.size:]