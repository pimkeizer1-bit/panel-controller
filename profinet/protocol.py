"""PROFINET protocol constants, packet structures, and binary helpers.

Defines all packet formats needed for DCE/RPC connection establishment
and cyclic RTC data exchange with a Siemens ET200SP.

All values verified against Proneta IO Test Wireshark capture.
"""

import struct
import uuid
from enum import IntEnum


# --- PROFINET Constants ---

PROFINET_ETHERTYPE = 0x8892
PROFINET_EPM_PORT = 34964  # 0x8894 - Endpoint Mapper port

# Frame IDs (from capture)
FRAME_ID_INPUT_CR = 0xBB80   # Device → Controller (proposed in Connect)
FRAME_ID_OUTPUT_CR = 0xBB81  # Controller → Device (proposed; device returns 0x8000)

# DCE/RPC UUIDs
UUID_PNIO_DEVICE_INTERFACE = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d")
UUID_PNIO_CONTROLLER_INTERFACE = uuid.UUID("dea00002-6c97-11d1-8271-00a02442df7d")
UUID_EPM = uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")
UUID_NDR_32BIT = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
UUID_NIL = uuid.UUID("00000000-0000-0000-0000-000000000000")

# DCE/RPC data representation: little-endian, ASCII, IEEE float
DREP = bytes([0x10, 0x00, 0x00])


class RPCPacketType(IntEnum):
    REQUEST = 0
    RESPONSE = 2
    FAULT = 3


class RPCOperation(IntEnum):
    CONNECT = 0
    RELEASE = 1
    READ = 2
    WRITE = 3
    CONTROL = 4
    READ_IMPLICIT = 5


class BlockType(IntEnum):
    AR_BLOCK_REQ = 0x0101
    AR_BLOCK_RES = 0x8101
    IOCR_BLOCK_REQ = 0x0102
    IOCR_BLOCK_RES = 0x8102
    ALARM_CR_BLOCK_REQ = 0x0103
    ALARM_CR_BLOCK_RES = 0x8103
    EXPECTED_SUBMODULE_BLOCK = 0x0104
    IOD_WRITE_REQ_HEADER = 0x0008
    IOD_WRITE_RES_HEADER = 0x8008
    IOD_CONTROL_REQ_PRM_END = 0x0110
    IOD_CONTROL_RES_PRM_END = 0x8110
    IOX_BLOCK_REQ_APP_READY = 0x0112
    IOX_BLOCK_RES_APP_READY = 0x8112
    IOD_READ_REQ_HEADER = 0x0009
    IOD_READ_RES_HEADER = 0x8009


class ARType(IntEnum):
    IOC_AR = 0x0001  # IO Controller AR


class IOCRType(IntEnum):
    INPUT_CR = 0x0001
    OUTPUT_CR = 0x0002


class IOCRProperties(IntEnum):
    RT_CLASS_1 = 0x00000001
    RT_CLASS_2 = 0x00000002
    RT_CLASS_3 = 0x00000003


# --- ET200SP Module Configuration (from capture) ---

VENDOR_ID = 0x002A
DEVICE_ID = 0x0313
API = 0x00000000

# Object UUID encodes Vendor/Device IDs
# Format: dea00000-6c97-11d1-8271-0001{DeviceID}{VendorID}
UUID_PNIO_OBJECT = uuid.UUID(
    f"dea00000-6c97-11d1-8271-0001{DEVICE_ID:04x}{VENDOR_ID:04x}")

# DAP (Slot 0) - IM 155-6 PN BA
DAP_MODULE_IDENT = 0x00064704
DAP_SUBMODULE_IDENT = 0x00000002          # subslot 0x0001
INTERFACE_SUBMODULE_IDENT = 0x00008002    # subslot 0x8000
PORT1_SUBMODULE_IDENT = 0x0000C000        # subslot 0x8001
PORT2_SUBMODULE_IDENT = 0x0000C000        # subslot 0x8002

# DQ 8x24VDC/0.5A (Slot 1)
DQ_MODULE_IDENT = 0x00004D9C
DQ_SUBMODULE_IDENT = 0x00000008
DQ_OUTPUT_LENGTH = 1  # 1 byte output

# AI 8xRTD/TC 2-wire HF (Slot 2)
AI_MODULE_IDENT = 0x00004A7F
AI_SUBMODULE_IDENT = 0x00000008
AI_INPUT_LENGTH = 16  # 16 bytes input (8 channels x 2 bytes)

# Server module (Slot 3)
SERVER_MODULE_IDENT = 0x00004710
SERVER_SUBMODULE_IDENT = 0x00000000

# IOCR timing (from capture)
SEND_CLOCK_FACTOR = 32      # 32 * 31.25µs = 1ms base clock
REDUCTION_RATIO = 128        # send every 128th cycle = 128ms
IOCR_DATA_LENGTH = 40        # total RTC payload per frame (both CRs)
WATCHDOG_FACTOR = 3
DATA_HOLD_FACTOR = 3

# RTC data layout offsets for Input CR (device → controller)
# Verified from capture frame 538
INPUT_DAP_IOPS_OFFSET = 0       # DAP subslot 1 IOPS
INPUT_PORT0_IOPS_OFFSET = 1     # Port 0 IOPS
INPUT_PORT1_IOPS_OFFSET = 2     # Port 1 IOPS
INPUT_PORT2_IOPS_OFFSET = 3     # Port 2 IOPS
INPUT_DQ_IOCS_OFFSET = 4        # DQ consumer status
INPUT_AI_DATA_OFFSET = 5        # AI data starts here (16 bytes)
INPUT_AI_IOPS_OFFSET = 21       # AI provider status
INPUT_SERVER_IOPS_OFFSET = 22   # Server provider status

# RTC data layout offsets for Output CR (controller → device)
# Verified from capture frame 533
OUTPUT_DAP_IOCS_OFFSET = 0      # DAP consumer status
OUTPUT_PORT0_IOCS_OFFSET = 1    # Port 0 consumer status
OUTPUT_PORT1_IOCS_OFFSET = 2    # Port 1 consumer status
OUTPUT_PORT2_IOCS_OFFSET = 3    # Port 2 consumer status
OUTPUT_DQ_DATA_OFFSET = 4       # DQ data byte
OUTPUT_DQ_IOPS_OFFSET = 5       # DQ provider status
OUTPUT_AI_IOCS_OFFSET = 6       # AI consumer status
OUTPUT_SERVER_IOCS_OFFSET = 7   # Server consumer status


# --- Packet Building Helpers ---

def pack_block_header(block_type: int, data_length: int,
                      version_high=1, version_low=0) -> bytes:
    """Pack a PROFINET block header (6 bytes).

    BlockType(u16) + BlockLength(u16) + VersionHigh(u8) + VersionLow(u8)
    BlockLength = 2 (version) + data_length
    """
    block_length = 2 + data_length
    return struct.pack("!HHBB", block_type, block_length, version_high,
                       version_low)


def uuid_to_bytes_le(u: uuid.UUID) -> bytes:
    """Convert UUID to DCE/RPC mixed-endian wire format (16 bytes).

    Used ONLY in the 80-byte DCE/RPC header and EPM request body.

    DCE/RPC UUID on-wire:
    - time_low: little-endian 4 bytes
    - time_mid: little-endian 2 bytes
    - time_hi_and_version: little-endian 2 bytes
    - clock_seq_hi + clock_seq_low: 2 bytes big-endian
    - node: 6 bytes big-endian
    """
    fields = u.fields  # (time_low, time_mid, time_hi_ver, clk_hi, clk_lo, node)
    return (struct.pack("<IHH", fields[0], fields[1], fields[2])
            + struct.pack("!BB", fields[3], fields[4])
            + struct.pack("!Q", fields[5])[2:])  # last 6 bytes


def uuid_from_bytes_le(data: bytes) -> uuid.UUID:
    """Parse UUID from DCE/RPC mixed-endian format."""
    time_low = struct.unpack("<I", data[0:4])[0]
    time_mid = struct.unpack("<H", data[4:6])[0]
    time_hi = struct.unpack("<H", data[6:8])[0]
    clk_hi, clk_lo = struct.unpack("!BB", data[8:10])
    node = int.from_bytes(data[10:16], "big")
    return uuid.UUID(fields=(time_low, time_mid, time_hi, clk_hi, clk_lo, node))


def uuid_to_bytes_be(u: uuid.UUID) -> bytes:
    """Convert UUID to big-endian wire format (16 bytes).

    Used inside PROFINET block payloads (ARBlockReq, IODWriteReq, etc.).
    PROFINET blocks use network byte order (big-endian) for ALL fields,
    including UUIDs — unlike the DCE/RPC header which uses mixed-endian.
    """
    fields = u.fields
    return (struct.pack("!IHH", fields[0], fields[1], fields[2])
            + struct.pack("!BB", fields[3], fields[4])
            + struct.pack("!Q", fields[5])[2:])


def uuid_from_bytes_be(data: bytes) -> uuid.UUID:
    """Parse UUID from big-endian format (inside PROFINET blocks)."""
    time_low = struct.unpack("!I", data[0:4])[0]
    time_mid = struct.unpack("!H", data[4:6])[0]
    time_hi = struct.unpack("!H", data[6:8])[0]
    clk_hi, clk_lo = struct.unpack("!BB", data[8:10])
    node = int.from_bytes(data[10:16], "big")
    return uuid.UUID(fields=(time_low, time_mid, time_hi, clk_hi, clk_lo, node))


def make_ar_uuid(device_mac: bytes) -> uuid.UUID:
    """Create ARUUID from device MAC (Proneta convention).

    Format: 00000000-0000-0000-0000-{device_mac}
    """
    node = int.from_bytes(device_mac, "big")
    return uuid.UUID(fields=(0, 0, 0, 0, 0, node))


def make_object_uuid(vendor_id: int = VENDOR_ID,
                     device_id: int = DEVICE_ID,
                     instance: int = 1) -> uuid.UUID:
    """Create PROFINET Object UUID encoding vendor/device IDs.

    Format: dea00000-6c97-11d1-8271-{instance:04x}{device_id:04x}{vendor_id:04x}
    """
    node_bytes = struct.pack("!HHH", instance, device_id, vendor_id)
    node = int.from_bytes(node_bytes, "big")
    return uuid.UUID(fields=(0xDEA00000, 0x6C97, 0x11D1, 0x82, 0x71, node))


class RPCHeader:
    """DCE/RPC Connectionless (CL) header — 80 bytes.

    Wire format (per DCE/RPC spec):
        Offset  Size  Field
        0       1     rpc_vers
        1       1     ptype
        2       1     flags1
        3       1     flags2
        4       3     drep
        7       1     serial_hi
        8       16    object UUID
        24      16    if_id UUID
        40      16    act_id UUID
        56      4     server_boot
        60      4     if_vers
        64      4     seqnum
        68      2     opnum
        70      2     ihint
        72      2     ahint
        74      2     len (body length)
        76      2     fragnum
        78      1     auth_proto
        79      1     serial_lo
    """
    SIZE = 80

    def __init__(self):
        self.rpc_version = 4
        self.packet_type = RPCPacketType.REQUEST
        self.flags1 = 0x20  # Idempotent
        self.flags2 = 0x00
        self.drep = DREP
        self.serial_high = 0
        self.object_uuid = UUID_NIL
        self.interface_uuid = UUID_PNIO_DEVICE_INTERFACE
        self.activity_uuid = uuid.uuid4()
        self.server_boot_time = 0
        self.interface_version = 0
        self.sequence_number = 0
        self.operation = RPCOperation.CONNECT
        self.interface_hint = 0xFFFF
        self.activity_hint = 0xFFFF
        self.body_length = 0
        self.fragment_number = 0
        self.auth_protocol = 0
        self.serial_low = 0

    def pack(self) -> bytes:
        data = struct.pack("!BB", self.rpc_version, self.packet_type)
        data += struct.pack("!BB", self.flags1, self.flags2)
        data += self.drep
        data += struct.pack("!B", self.serial_high)
        data += uuid_to_bytes_le(self.object_uuid)
        data += uuid_to_bytes_le(self.interface_uuid)
        data += uuid_to_bytes_le(self.activity_uuid)
        data += struct.pack("<I", self.server_boot_time)
        data += struct.pack("<I", self.interface_version)
        data += struct.pack("<I", self.sequence_number)
        data += struct.pack("<H", self.operation)
        data += struct.pack("<HH", self.interface_hint, self.activity_hint)
        data += struct.pack("<H", self.body_length)
        data += struct.pack("<H", self.fragment_number)
        data += struct.pack("!BB", self.auth_protocol, self.serial_low)
        return data

    @classmethod
    def unpack(cls, data: bytes) -> "RPCHeader":
        hdr = cls()
        hdr.rpc_version = data[0]
        hdr.packet_type = data[1]
        hdr.flags1 = data[2]
        hdr.flags2 = data[3]
        hdr.drep = data[4:7]
        hdr.serial_high = data[7]
        hdr.object_uuid = uuid_from_bytes_le(data[8:24])
        hdr.interface_uuid = uuid_from_bytes_le(data[24:40])
        hdr.activity_uuid = uuid_from_bytes_le(data[40:56])
        hdr.server_boot_time = struct.unpack("<I", data[56:60])[0]
        hdr.interface_version = struct.unpack("<I", data[60:64])[0]
        hdr.sequence_number = struct.unpack("<I", data[64:68])[0]
        hdr.operation = struct.unpack("<H", data[68:70])[0]
        hdr.interface_hint = struct.unpack("<H", data[70:72])[0]
        hdr.activity_hint = struct.unpack("<H", data[72:74])[0]
        hdr.body_length = struct.unpack("<H", data[74:76])[0]
        hdr.fragment_number = struct.unpack("<H", data[76:78])[0]
        hdr.auth_protocol = data[78]
        hdr.serial_low = data[79]
        return hdr


# --- PROFINET IO Connect Request Block Builders ---

def build_ar_block_req(ar_uuid: uuid.UUID, controller_mac: bytes,
                       station_name: str = "panel-controller") -> bytes:
    """Build ARBlockReq for PROFINET Connect Request.

    Matches Proneta's ARBlockReq exactly per capture packet 528.

    IMPORTANT: UUIDs inside PROFINET blocks use big-endian encoding,
    NOT the DCE/RPC mixed-endian used in the RPC header.
    """
    station_name_bytes = station_name.encode("ascii")
    # No padding — Proneta does not pad station names (verified from capture)

    # CMInitiatorObjectUUID - encodes our identity
    # Using format: dea00000-6c97-11d1-8271-{arbitrary}
    cm_init_obj_uuid = make_object_uuid(VENDOR_ID, DEVICE_ID)

    data = struct.pack("!H", ARType.IOC_AR)
    data += uuid_to_bytes_be(ar_uuid)          # Big-endian in PROFINET blocks
    data += struct.pack("!H", 1)  # SessionKey
    data += controller_mac  # 6 bytes CMInitiatorMacAdd
    data += uuid_to_bytes_be(cm_init_obj_uuid)  # Big-endian in PROFINET blocks
    data += struct.pack("!I", 0x00000011)  # ARProperties: Active + PrmServer=CMInitiator
    data += struct.pack("!H", 200)  # CMInitiatorActivityTimeoutFactor (200 * 100ms = 20s)
    data += struct.pack("!H", PROFINET_ETHERTYPE)  # InitiatorUDPRTPort
    data += struct.pack("!H", len(station_name_bytes))  # StationNameLength
    data += station_name_bytes

    block = pack_block_header(BlockType.AR_BLOCK_REQ, len(data))
    return block + data


def build_iocr_block_req(iocr_type: int, iocr_ref: int, frame_id: int,
                         io_data_objects: list[dict],
                         io_cs: list[dict]) -> bytes:
    """Build IOCRBlockReq for PROFINET Connect Request.

    Matches capture packet 528 IOCR structure exactly.

    Args:
        iocr_type: IOCRType.INPUT_CR or IOCRType.OUTPUT_CR
        iocr_ref: Reference number (1=input, 2=output)
        frame_id: Proposed RTC frame ID
        io_data_objects: List of {"slot", "subslot", "frame_offset"} for data
        io_cs: List of {"slot", "subslot", "frame_offset"} for consumer status
    """
    # API entry with IODataObjects and IOCS
    api_data = struct.pack("!I", API)  # API
    api_data += struct.pack("!H", len(io_data_objects))  # NumberOfIODataObjects
    for obj in io_data_objects:
        api_data += struct.pack("!HHH", obj["slot"], obj["subslot"],
                                obj["frame_offset"])
    api_data += struct.pack("!H", len(io_cs))  # NumberOfIOCS
    for cs in io_cs:
        api_data += struct.pack("!HHH", cs["slot"], cs["subslot"],
                                cs["frame_offset"])

    data = struct.pack("!H", iocr_type)
    data += struct.pack("!H", iocr_ref)  # IOCRReference
    data += struct.pack("!H", PROFINET_ETHERTYPE)  # LT
    data += struct.pack("!I", IOCRProperties.RT_CLASS_2)  # IOCRProperties
    data += struct.pack("!H", IOCR_DATA_LENGTH)  # DataLength
    data += struct.pack("!H", frame_id)  # FrameID
    data += struct.pack("!H", SEND_CLOCK_FACTOR)  # SendClockFactor (GatingCycle)
    data += struct.pack("!H", REDUCTION_RATIO)  # ReductionRatio
    data += struct.pack("!H", 1)  # Phase
    data += struct.pack("!H", 0)  # Sequence
    data += struct.pack("!I", 0xFFFFFFFF)  # FrameSendOffset (best effort)
    data += struct.pack("!H", WATCHDOG_FACTOR)  # WatchdogFactor
    data += struct.pack("!H", DATA_HOLD_FACTOR)  # DataHoldFactor
    data += struct.pack("!H", 0xC000)  # IOCRTagHeader (VLAN prio)
    data += b'\x00' * 6  # IOCRMulticastMACAdd (zeros = unicast)
    data += struct.pack("!H", 1)  # NumberOfAPIs
    data += api_data

    block = pack_block_header(BlockType.IOCR_BLOCK_REQ, len(data))
    return block + data


def build_expected_submodule_block_single(
        slot: int, module_ident: int,
        submodules: list[dict]) -> bytes:
    """Build one ExpectedSubmoduleBlockReq for a single slot.

    Capture shows one block per slot, not one combined block.

    Args:
        slot: Slot number
        module_ident: Module identification number
        submodules: List of dicts with keys: subslot, submodule_ident,
                    input_length (optional), output_length (optional)
    """
    # NumberOfAPIs(u16) = 1
    # API(u32) + SlotNumber(u16) + ModuleIdentNumber(u32) +
    # ModuleProperties(u16) + NumberOfSubmodules(u16)
    data = struct.pack("!H", 1)  # NumberOfAPIs
    data += struct.pack("!I", API)
    data += struct.pack("!H", slot)
    data += struct.pack("!I", module_ident)
    data += struct.pack("!H", 0)  # ModuleProperties
    data += struct.pack("!H", len(submodules))

    for sub in submodules:
        data += struct.pack("!H", sub["subslot"])
        data += struct.pack("!I", sub["submodule_ident"])

        has_input = sub.get("input_length", 0) > 0
        has_output = sub.get("output_length", 0) > 0
        if has_input and has_output:
            sub_type = 3
        elif has_output:
            sub_type = 2
        elif has_input:
            sub_type = 1
        else:
            sub_type = 0
        data += struct.pack("!H", sub_type)  # SubmoduleProperties

        # DataDescription: always at least one (Input type for no-data modules)
        if has_output:
            # Output data description
            data += struct.pack("!H", 2)  # DataDescription type = Output
            data += struct.pack("!H", sub["output_length"])
            data += struct.pack("!B", 1)  # LengthIOCS
            data += struct.pack("!B", 1)  # LengthIOPS
        else:
            # Input data description (even for no-data submodules)
            data += struct.pack("!H", 1)  # DataDescription type = Input
            data += struct.pack("!H", sub.get("input_length", 0))
            data += struct.pack("!B", 1)  # LengthIOCS
            data += struct.pack("!B", 1)  # LengthIOPS

    block = pack_block_header(BlockType.EXPECTED_SUBMODULE_BLOCK, len(data))
    return block + data


def build_alarm_cr_block_req() -> bytes:
    """Build AlarmCRBlockReq. Values from capture packet 528."""
    data = struct.pack("!H", 0x0001)  # AlarmCRType
    data += struct.pack("!H", PROFINET_ETHERTYPE)  # LT
    data += struct.pack("!I", 0x00000000)  # AlarmCRProperties
    data += struct.pack("!H", 1)  # RTATimeoutFactor (1 from capture)
    data += struct.pack("!H", 3)  # RTARetries
    data += struct.pack("!H", 0)  # LocalAlarmReference (0 from capture)
    data += struct.pack("!H", 200)  # MaxAlarmDataLength
    data += struct.pack("!H", 0xC000)  # AlarmCRTagHeaderHigh
    data += struct.pack("!H", 0xA000)  # AlarmCRTagHeaderLow

    block = pack_block_header(BlockType.ALARM_CR_BLOCK_REQ, len(data))
    return block + data


def build_iod_write_req_header(ar_uuid: uuid.UUID, api: int, slot: int,
                               subslot: int, index: int,
                               record_data_length: int,
                               seq_number: int = 0) -> bytes:
    """Build IODWriteReqHeader block (64 bytes total)."""
    data = struct.pack("!H", seq_number)
    data += uuid_to_bytes_be(ar_uuid)  # Big-endian in PROFINET blocks
    data += struct.pack("!I", api)
    data += struct.pack("!H", slot)
    data += struct.pack("!H", subslot)
    data += struct.pack("!H", 0)  # padding
    data += struct.pack("!H", index)
    data += struct.pack("!I", record_data_length)
    data += b'\x00' * 24  # padding to fill 60 bytes of data

    block = pack_block_header(BlockType.IOD_WRITE_REQ_HEADER, len(data))
    return block + data


def build_iod_control_req(ar_uuid: uuid.UUID, session_key: int = 1,
                          command: int = 0x0001) -> bytes:
    """Build IODControlReq block.

    command=0x0001 for PrmEnd, command=0x0002 for ApplicationReady.
    """
    block_type = BlockType.IOD_CONTROL_REQ_PRM_END
    if command == 0x0002:
        block_type = BlockType.IOX_BLOCK_REQ_APP_READY

    data = struct.pack("!H", 0)  # Reserved
    data += uuid_to_bytes_be(ar_uuid)  # Big-endian in PROFINET blocks
    data += struct.pack("!H", session_key)
    data += struct.pack("!H", 0)  # Reserved
    data += struct.pack("!H", command)  # ControlCommand
    data += struct.pack("!H", 0)  # ControlBlockProperties

    block = pack_block_header(block_type, len(data))
    return block + data


def pack_nrd(payload: bytes, args_maximum: int = 0) -> bytes:
    """Pack NDR array wrapper for RPC stub data.

    Format: ArgsMaximum(u32) + ArgsLength(u32) + MaxCount(u32) +
            Offset(u32) + ActualCount(u32) + payload
    """
    if args_maximum == 0:
        args_maximum = len(payload)
    nrd = struct.pack("<I", args_maximum)  # ArgsMaximum
    nrd += struct.pack("<I", len(payload))  # ArgsLength
    nrd += struct.pack("<I", args_maximum)  # MaxCount
    nrd += struct.pack("<I", 0)  # Offset
    nrd += struct.pack("<I", len(payload))  # ActualCount
    nrd += payload
    return nrd


def build_connect_request_nrd(ar_uuid: uuid.UUID, controller_mac: bytes,
                              station_name: str = "panel-controller") -> bytes:
    """Build the complete NRD payload for Connect Request.

    Structure matches Proneta capture packet 528 exactly.
    """
    # --- AR Block ---
    ar_block = build_ar_block_req(ar_uuid, controller_mac, station_name)

    # --- Input IOCR (Device → Controller) ---
    # IODataObjects: all submodules that provide INPUT data in this frame
    input_data_objects = [
        {"slot": 0x0000, "subslot": 0x0001, "frame_offset": 0},   # DAP
        {"slot": 0x0000, "subslot": 0x8000, "frame_offset": 1},   # Port 0
        {"slot": 0x0000, "subslot": 0x8001, "frame_offset": 2},   # Port 1
        {"slot": 0x0000, "subslot": 0x8002, "frame_offset": 3},   # Port 2
        {"slot": 0x0002, "subslot": 0x0001, "frame_offset": 5},   # AI module
        {"slot": 0x0003, "subslot": 0x0001, "frame_offset": 22},  # Server
    ]
    # IOCS: consumer status for OUTPUT submodules
    input_iocs = [
        {"slot": 0x0001, "subslot": 0x0001, "frame_offset": 4},   # DQ module
    ]
    input_iocr = build_iocr_block_req(
        iocr_type=IOCRType.INPUT_CR,
        iocr_ref=1,
        frame_id=FRAME_ID_INPUT_CR,
        io_data_objects=input_data_objects,
        io_cs=input_iocs,
    )

    # --- Output IOCR (Controller → Device) ---
    # IODataObjects: submodules that receive OUTPUT data in this frame
    output_data_objects = [
        {"slot": 0x0001, "subslot": 0x0001, "frame_offset": 4},   # DQ module
    ]
    # IOCS: consumer status for INPUT submodules
    output_iocs = [
        {"slot": 0x0000, "subslot": 0x0001, "frame_offset": 0},   # DAP
        {"slot": 0x0000, "subslot": 0x8000, "frame_offset": 1},   # Port 0
        {"slot": 0x0000, "subslot": 0x8001, "frame_offset": 2},   # Port 1
        {"slot": 0x0000, "subslot": 0x8002, "frame_offset": 3},   # Port 2
        {"slot": 0x0002, "subslot": 0x0001, "frame_offset": 6},   # AI module
        {"slot": 0x0003, "subslot": 0x0001, "frame_offset": 7},   # Server
    ]
    output_iocr = build_iocr_block_req(
        iocr_type=IOCRType.OUTPUT_CR,
        iocr_ref=2,
        frame_id=FRAME_ID_OUTPUT_CR,
        io_data_objects=output_data_objects,
        io_cs=output_iocs,
    )

    # --- Expected Submodule Blocks (one per slot) ---
    esm_slot0 = build_expected_submodule_block_single(
        slot=0, module_ident=DAP_MODULE_IDENT, submodules=[
            {"subslot": 0x0001, "submodule_ident": DAP_SUBMODULE_IDENT},
            {"subslot": 0x8000, "submodule_ident": INTERFACE_SUBMODULE_IDENT},
            {"subslot": 0x8001, "submodule_ident": PORT1_SUBMODULE_IDENT},
            {"subslot": 0x8002, "submodule_ident": PORT2_SUBMODULE_IDENT},
        ])

    esm_slot1 = build_expected_submodule_block_single(
        slot=1, module_ident=DQ_MODULE_IDENT, submodules=[
            {"subslot": 0x0001, "submodule_ident": DQ_SUBMODULE_IDENT,
             "output_length": DQ_OUTPUT_LENGTH},
        ])

    esm_slot2 = build_expected_submodule_block_single(
        slot=2, module_ident=AI_MODULE_IDENT, submodules=[
            {"subslot": 0x0001, "submodule_ident": AI_SUBMODULE_IDENT,
             "input_length": AI_INPUT_LENGTH},
        ])

    esm_slot3 = build_expected_submodule_block_single(
        slot=3, module_ident=SERVER_MODULE_IDENT, submodules=[
            {"subslot": 0x0001, "submodule_ident": SERVER_SUBMODULE_IDENT},
        ])

    # --- Alarm CR Block ---
    alarm_block = build_alarm_cr_block_req()

    # --- Assemble ---
    blocks = (ar_block + input_iocr + output_iocr
              + esm_slot0 + esm_slot1 + esm_slot2 + esm_slot3
              + alarm_block)

    return pack_nrd(blocks)


def build_write_request_nrd(ar_uuid: uuid.UUID, device_mac: bytes,
                            write_records: list[dict]) -> bytes:
    """Build a MultipleWrite NRD payload.

    Args:
        ar_uuid: Application Relation UUID
        device_mac: Device MAC for ARUUID field in headers
        write_records: List of {"api", "slot", "subslot", "index", "data"}
    """
    # Calculate total inner payload size for the MultipleWrite header
    # Pad inter-record gaps to 4-byte boundary, but NOT the last record
    inner_size = 0
    for i, rec in enumerate(write_records):
        inner_size += 64  # IODWriteReqHeader is always 64 bytes
        data_len = len(rec["data"])
        inner_size += data_len
        # Pad to 4-byte boundary between records (not after the last one)
        if i < len(write_records) - 1 and data_len % 4 != 0:
            inner_size += 4 - (data_len % 4)

    # Outer MultipleWrite header (seq=0, api=0xFFFFFFFF, slot=0xFFFF, index=0xE040)
    outer_header = build_iod_write_req_header(
        ar_uuid=ar_uuid,
        api=0xFFFFFFFF,
        slot=0xFFFF,
        subslot=0xFFFF,
        index=0xE040,  # MultipleWrite
        record_data_length=inner_size,
        seq_number=0,
    )

    payload = outer_header
    for i, rec in enumerate(write_records):
        rec_header = build_iod_write_req_header(
            ar_uuid=ar_uuid,
            api=rec.get("api", API),
            slot=rec["slot"],
            subslot=rec["subslot"],
            index=rec["index"],
            record_data_length=len(rec["data"]),
            seq_number=i + 1,
        )
        payload += rec_header
        payload += rec["data"]
        # Pad to 4-byte boundary between records (not after the last one)
        if i < len(write_records) - 1:
            pad = len(rec["data"]) % 4
            if pad != 0:
                payload += b'\x00' * (4 - pad)

    return pack_nrd(payload)


def parse_connect_response(data: bytes) -> dict:
    """Parse the NRD payload of a Connect Response.

    Response format: PNIOStatus(4) + ArgsLen(4) + MaxCount(4) + Offset(4) +
                     ActualCount(4) + blocks
    OR:              ArgsMax(4) + ArgsLen(4) + MaxCount(4) + Offset(4) +
                     ActualCount(4) + blocks

    Returns dict with AR UUID, IOCR frame IDs, and success status.
    """
    import logging
    log = logging.getLogger(__name__)

    result = {"success": False, "error": None}

    if len(data) < 20:
        result["error"] = f"Response too short ({len(data)} bytes)"
        return result

    log.info("Connect response: %d bytes, first 24: %s",
             len(data), data[:min(24, len(data))].hex())

    # Check PNIO status (first 4 bytes may be status or ArgsMaximum)
    pnio_status = data[0:4]
    if pnio_status != b'\x00\x00\x00\x00':
        err_code = pnio_status[0]
        err_decode = pnio_status[1]
        err_code1 = pnio_status[2]
        err_code2 = pnio_status[3]
        log.warning("PNIO Status: code=%d decode=%d code1=0x%02x code2=0x%02x",
                    err_code, err_decode, err_code1, err_code2)
        # If first byte is non-zero, this is an error response
        if err_code != 0:
            result["error"] = (f"PNIO error: code={err_code} decode={err_decode} "
                               f"code1=0x{err_code1:02x} code2=0x{err_code2:02x}")
            return result

    # NDR header (skip first 4 bytes = PNIOStatus or ArgsMaximum)
    args_len = struct.unpack("<I", data[4:8])[0]
    max_count = struct.unpack("<I", data[8:12])[0]
    offset_val = struct.unpack("<I", data[12:16])[0]
    actual_count = struct.unpack("<I", data[16:20])[0]

    log.info("NDR: args_len=%d max_count=%d offset=%d actual_count=%d",
             args_len, max_count, offset_val, actual_count)

    if actual_count == 0:
        result["error"] = "Response contains no blocks (actual_count=0)"
        return result

    blocks_data = data[20:20 + actual_count]

    if len(blocks_data) < actual_count:
        log.warning("Truncated response: expected %d bytes, got %d",
                    actual_count, len(blocks_data))

    pos = 0
    block_count = 0

    while pos + 4 <= len(blocks_data):
        block_type = struct.unpack("!H", blocks_data[pos:pos + 2])[0]
        block_length = struct.unpack("!H", blocks_data[pos + 2:pos + 4])[0]
        block_end = pos + 4 + block_length
        block_count += 1

        log.debug("Block %d: type=0x%04x length=%d at pos=%d",
                  block_count, block_type, block_length, pos)

        if block_type == BlockType.AR_BLOCK_RES:
            result["success"] = True
            if block_length >= 20:
                ar_data = blocks_data[pos + 6:]  # skip type+len+version
                result["ar_type"] = struct.unpack("!H", ar_data[0:2])[0]
                result["ar_uuid"] = uuid_from_bytes_be(ar_data[2:18])
                result["session_key"] = struct.unpack("!H", ar_data[18:20])[0]
                result["responder_mac"] = ar_data[20:26]
                log.info("AR_BLOCK_RES: AR=%s session=%d",
                         result["ar_uuid"], result["session_key"])

        elif block_type == BlockType.IOCR_BLOCK_RES:
            if "iocrs" not in result:
                result["iocrs"] = []
            if block_length >= 8:
                iocr_data = blocks_data[pos + 6:]
                iocr_info = {
                    "iocr_type": struct.unpack("!H", iocr_data[0:2])[0],
                    "iocr_ref": struct.unpack("!H", iocr_data[2:4])[0],
                    "frame_id": struct.unpack("!H", iocr_data[4:6])[0],
                }
                result["iocrs"].append(iocr_info)
                log.info("IOCR_BLOCK_RES: type=%d ref=%d frame_id=0x%04x",
                         iocr_info["iocr_type"], iocr_info["iocr_ref"],
                         iocr_info["frame_id"])

        elif block_type == BlockType.ALARM_CR_BLOCK_RES:
            if block_length >= 8:
                alarm_data = blocks_data[pos + 6:]
                result["alarm_ref"] = struct.unpack("!H", alarm_data[2:4])[0]

        else:
            log.debug("Unknown block type 0x%04x (length=%d)", block_type,
                      block_length)

        if block_end <= pos:
            log.warning("Block parsing stuck at pos=%d, breaking", pos)
            break
        pos = block_end

    if not result["success"]:
        result["error"] = (f"No AR_BLOCK_RES found in {block_count} blocks "
                           f"({len(blocks_data)} bytes)")
        log.warning("Connect response had no AR_BLOCK_RES. "
                    "Blocks data hex: %s", blocks_data[:64].hex())

    return result


def parse_pnio_status(data: bytes) -> dict:
    """Parse PNIO status from response stub data (first 4 bytes after NDR)."""
    if len(data) < 4:
        return {"error_code": 0xFF, "error_decode": 0xFF,
                "error_code1": 0xFF, "error_code2": 0xFF}
    return {
        "error_code": data[0],
        "error_decode": data[1],
        "error_code1": data[2],
        "error_code2": data[3],
    }


# --- EPM (Endpoint Mapper) Helpers ---

def build_epm_lookup_request(interface_uuid: uuid.UUID) -> bytes:
    """Build EPM Lookup request stub data.

    Queries the endpoint mapper for a specific interface UUID
    to discover which port the PNIO service listens on.
    """
    # Inquiry type: rpc_c_ep_all_elts = 0
    # Object UUID referent (nil)
    # Interface UUID referent
    # Version option, handle, max_entries

    data = struct.pack("<I", 0)  # InquiryType = rpc_c_ep_all_elts
    data += struct.pack("<I", 1)  # Object referent ID
    data += uuid_to_bytes_le(UUID_NIL)  # Object UUID (nil)
    data += struct.pack("<I", 2)  # Interface referent ID
    data += uuid_to_bytes_le(interface_uuid)  # Interface UUID
    data += struct.pack("<H", 1)  # Version Major
    data += struct.pack("<H", 0)  # Version Minor
    data += struct.pack("<I", 1)  # Version option
    # Handle (20 bytes of zeros for first request)
    data += b'\x00' * 20
    data += struct.pack("<I", 1)  # Max entries

    return data


def parse_epm_lookup_response(data: bytes) -> int | None:
    """Parse EPM Lookup response to extract the UDP port number.

    Returns the port number, or None if not found.
    """
    # The response contains tower data with floor entries.
    # We look for the UDP port floor (protocol ID 0x08).
    # Search for the byte pattern: 0x01 0x08 (LHS=1, Protocol=UDP)
    # followed by 0x00 0x02 (RHS=2) and then the port in big-endian.

    # Simple approach: search for the UDP floor pattern
    for i in range(len(data) - 6):
        # Floor: LHS_Length(u16_LE) Protocol(u8) RHS_Length(u16_LE) Data
        if i + 5 < len(data):
            lhs_len = struct.unpack("<H", data[i:i + 2])[0]
            if lhs_len == 1:
                protocol = data[i + 2]
                rhs_len = struct.unpack("<H", data[i + 3:i + 5])[0]
                if protocol == 0x08 and rhs_len == 2:
                    # This is the UDP floor, next 2 bytes are port (big-endian)
                    if i + 7 <= len(data):
                        port = struct.unpack("!H", data[i + 5:i + 7])[0]
                        if port > 0 and port != PROFINET_EPM_PORT:
                            return port

    return None
