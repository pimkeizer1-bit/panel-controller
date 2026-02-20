"""PROFINET DCE/RPC connection manager.

Handles EPM port discovery, Connect Request, parameterization,
PrmEnd, and Application Ready sequence to establish cyclic IO
communication with an ET200SP.

Verified against Proneta IO Test Wireshark capture.
"""

import logging
import socket
import struct
import uuid

from profinet.protocol import (
    RPCHeader, RPCPacketType, RPCOperation,
    UUID_PNIO_DEVICE_INTERFACE, UUID_PNIO_CONTROLLER_INTERFACE,
    UUID_PNIO_OBJECT, UUID_NIL, UUID_EPM,
    PROFINET_EPM_PORT, DREP,
    build_connect_request_nrd, parse_connect_response,
    build_iod_control_req, build_write_request_nrd,
    pack_nrd, make_ar_uuid, make_object_uuid,
    uuid_to_bytes_le, BlockType,
    build_epm_lookup_request, parse_epm_lookup_response,
    API, DQ_OUTPUT_LENGTH, AI_INPUT_LENGTH,
)

log = logging.getLogger(__name__)


class RPCConnectionError(Exception):
    pass


class RPCConnection:
    """Manages DCE/RPC communication with a PROFINET IO device.

    Connection sequence (from capture):
    1. EPM Lookup on port 34964 → discover PNIO port (e.g. 49156)
    2. Connect Request (opnum 0) → AR + IOCR + ExpectedSubmodule + AlarmCR
    3. Write (opnum 3) → Module parameterization (MultipleWrite)
    4. PrmEnd (opnum 4) → Signal parameterization complete
    5. Wait for ApplicationReady from device (opnum 4 on Controller Interface)
    6. Respond to ApplicationReady
    """

    def __init__(self, device_ip: str, device_mac: bytes, controller_mac: bytes,
                 controller_ip: str = "", timeout: float = 5.0):
        self.device_ip = device_ip
        self.device_mac = device_mac
        self.controller_mac = controller_mac
        self.controller_ip = controller_ip  # bind sockets to this IP
        self.timeout = timeout

        self._sock: socket.socket | None = None
        self._seq_number = 0
        self._activity_uuid = self._make_activity_uuid()
        self._ar_uuid = make_ar_uuid(device_mac)
        self._session_key = 1
        self._connected = False
        self._pnio_port: int | None = None  # discovered via EPM

        # Populated after connect
        self.input_frame_id: int | None = None
        self.output_frame_id: int | None = None

    def _make_activity_uuid(self) -> uuid.UUID:
        """Create an activity UUID incorporating our MAC address."""
        # Proneta uses a pattern with controller MAC in the activity UUID
        # We'll generate a random one for simplicity
        return uuid.uuid4()

    @property
    def is_connected(self) -> bool:
        return self._connected

    def _open_socket(self):
        if self._sock is not None:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self.timeout)
        # Bind to controller IP so responses route correctly.
        # If the specific IP isn't available yet, fall back to 0.0.0.0.
        bind_ip = self.controller_ip or ""
        if bind_ip:
            try:
                self._sock.bind((bind_ip, 0))
                log.info("RPC socket bound to %s:%d",
                         bind_ip, self._sock.getsockname()[1])
            except OSError as e:
                log.warning("Cannot bind to %s (%s), falling back to 0.0.0.0",
                            bind_ip, e)
                self._sock.bind(("", 0))
        else:
            self._sock.bind(("", 0))

    def _close_sockets(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None

    def _next_seq(self) -> int:
        seq = self._seq_number
        self._seq_number += 2  # increment by 2 (even = request)
        return seq

    def _build_rpc_header(self, operation: int, body_length: int,
                          flags1: int = 0x28) -> RPCHeader:
        """Build an RPC request header for PNIO Device Interface.

        Default flags1=0x28 = Idempotent + NoFack (matches capture for
        Connect/PrmEnd). Write uses 0x20 = Idempotent only.
        """
        hdr = RPCHeader()
        hdr.packet_type = RPCPacketType.REQUEST
        hdr.flags1 = flags1
        hdr.object_uuid = UUID_PNIO_OBJECT
        hdr.interface_uuid = UUID_PNIO_DEVICE_INTERFACE
        hdr.activity_uuid = self._activity_uuid
        hdr.interface_version = 1  # PNIO Device Interface v1
        hdr.sequence_number = self._next_seq()
        hdr.operation = operation
        hdr.body_length = body_length
        return hdr

    def _send_rpc(self, operation: int, payload: bytes,
                  port: int | None = None,
                  flags1: int = 0x28) -> bytes:
        """Send an RPC request and receive the response."""
        self._open_socket()
        target_port = port or self._pnio_port or PROFINET_EPM_PORT

        hdr = self._build_rpc_header(operation, len(payload), flags1)
        packet = hdr.pack() + payload

        log.debug("Sending RPC op=%d seq=%d len=%d to %s:%d",
                  operation, hdr.sequence_number, len(packet),
                  self.device_ip, target_port)

        self._sock.sendto(packet, (self.device_ip, target_port))

        try:
            response, addr = self._sock.recvfrom(65536)
        except socket.timeout:
            raise RPCConnectionError(
                f"Timeout waiting for RPC response (op={operation})")

        if len(response) < RPCHeader.SIZE:
            raise RPCConnectionError(
                f"Response too short: {len(response)} bytes")

        resp_hdr = RPCHeader.unpack(response[:RPCHeader.SIZE])
        resp_body = response[RPCHeader.SIZE:]

        if resp_hdr.packet_type == RPCPacketType.FAULT:
            raise RPCConnectionError(
                f"RPC Fault received for operation {operation}")

        log.debug("Received RPC response: type=%d seq=%d body_len=%d",
                  resp_hdr.packet_type, resp_hdr.sequence_number,
                  len(resp_body))

        return resp_body

    def discover_pnio_port(self) -> int:
        """Discover the PNIO service port via EPM Lookup or port probing.

        First tries EPM Lookup (2 attempts). If that fails, falls back to
        probing known PNIO ports by sending a lightweight RPC request and
        checking for any response.

        Returns:
            The discovered port number (e.g. 49156 or 34964).
        """
        # Try EPM Lookup first (2 attempts, quick)
        port = self._try_epm_lookup()
        if port is not None:
            self._pnio_port = port
            return port

        # EPM failed — probe known PNIO ports directly
        log.info("EPM Lookup failed, probing known PNIO ports...")
        # 49152-49156 are common dynamic ports for Siemens PNIO service.
        # 49156 is the port from our Proneta capture. Do NOT probe 34964
        # here — that's the EPM-only port, not the PNIO service port.
        candidate_ports = [49156, 49155, 49154, 49153, 49152]

        port = self._probe_ports(candidate_ports)
        if port is not None:
            self._pnio_port = port
            return port

        # Last resort: use the most common Siemens PNIO port
        log.warning("No port responded to probe, defaulting to 49156")
        self._pnio_port = 49156
        return 49156

    def _try_epm_lookup(self) -> int | None:
        """Try EPM Lookup to discover the PNIO service port.

        Returns the port number, or None if EPM fails.
        """
        log.info("Trying EPM Lookup on port %d...", PROFINET_EPM_PORT)
        self._open_socket()
        epm_activity = uuid.uuid4()

        handle = b'\x00' * 20

        for attempt in range(2):  # only 2 attempts
            hdr = RPCHeader()
            hdr.packet_type = RPCPacketType.REQUEST
            hdr.flags1 = 0x20  # Idempotent
            hdr.object_uuid = UUID_NIL
            hdr.interface_uuid = UUID_EPM
            hdr.activity_uuid = epm_activity
            hdr.interface_version = 3  # EPM interface v3
            hdr.sequence_number = self._next_seq()
            hdr.operation = 2  # EPM Lookup

            stub = build_epm_lookup_request(UUID_PNIO_DEVICE_INTERFACE)
            # Handle is at byte offset 52 (20 bytes), patch it for continuation
            stub = stub[:52] + handle + stub[72:]

            hdr.body_length = len(stub)
            packet = hdr.pack() + stub

            self._sock.sendto(packet, (self.device_ip, PROFINET_EPM_PORT))

            try:
                old_timeout = self._sock.gettimeout()
                self._sock.settimeout(2.0)  # short timeout for EPM
                response, addr = self._sock.recvfrom(65536)
                self._sock.settimeout(old_timeout)
            except socket.timeout:
                self._sock.settimeout(self.timeout)
                log.warning("EPM Lookup timeout (attempt %d)", attempt + 1)
                continue

            if len(response) < RPCHeader.SIZE:
                continue

            resp_body = response[RPCHeader.SIZE:]

            if len(resp_body) >= 20:
                handle = resp_body[:20]

            port = parse_epm_lookup_response(resp_body)
            if port is not None:
                log.info("EPM: Found PNIO service on port %d", port)
                return port

            if len(resp_body) >= 24:
                num_entries = struct.unpack("<I", resp_body[20:24])[0]
                if num_entries == 0:
                    break

        log.info("EPM Lookup did not find PNIO port")
        return None

    def _probe_ports(self, ports: list[int]) -> int | None:
        """Probe candidate ports by sending a lightweight RPC Read Implicit.

        Sends a short RPC request to each port and checks if the device
        sends any response (even an error response means the port is alive).

        Returns the first port that responds, or None.
        """
        self._open_socket()

        for port in ports:
            log.debug("Probing port %d...", port)

            # Build a minimal RPC Read Implicit request (opnum 5)
            # Read I&M0 record (index 0xAFF0) from slot 0, subslot 1
            # This should work even without an AR established
            probe_activity = uuid.uuid4()

            hdr = RPCHeader()
            hdr.packet_type = RPCPacketType.REQUEST
            hdr.flags1 = 0x28  # Idempotent + NoFack
            hdr.object_uuid = UUID_PNIO_OBJECT
            hdr.interface_uuid = UUID_PNIO_DEVICE_INTERFACE
            hdr.activity_uuid = probe_activity
            hdr.interface_version = 1  # PNIO Device Interface v1
            hdr.sequence_number = 0
            hdr.operation = RPCOperation.READ_IMPLICIT

            # Build ReadImplicit stub: read I&M0 (index 0xAFF0) from slot 0
            # NDR: ArgsMaximum(u32) + ArgsLength(u32) + MaxCount(u32) +
            #       Offset(u32) + ActualCount(u32) + IODReadReqHeader
            read_hdr = struct.pack("!HH", 0x0009, 60)  # BlockType=ReadReqHdr, Length=60
            read_hdr += struct.pack("!BB", 1, 0)  # Version 1.0
            read_hdr += struct.pack("!H", 0)  # SeqNumber
            read_hdr += b'\x00' * 16  # ARUUID (nil for implicit read)
            read_hdr += struct.pack("!I", API)  # API
            read_hdr += struct.pack("!H", 0)  # Slot
            read_hdr += struct.pack("!H", 1)  # Subslot
            read_hdr += struct.pack("!H", 0)  # Padding
            read_hdr += struct.pack("!H", 0xAFF0)  # Index (I&M0)
            read_hdr += struct.pack("!I", 64)  # RecordDataLength
            read_hdr += b'\x00' * 24  # Padding (to fill 60 bytes of block data)

            nrd = struct.pack("<I", len(read_hdr))  # ArgsMaximum
            nrd += struct.pack("<I", len(read_hdr))  # ArgsLength
            nrd += struct.pack("<I", len(read_hdr))  # MaxCount
            nrd += struct.pack("<I", 0)  # Offset
            nrd += struct.pack("<I", len(read_hdr))  # ActualCount
            nrd += read_hdr

            hdr.body_length = len(nrd)
            packet = hdr.pack() + nrd

            self._sock.sendto(packet, (self.device_ip, port))

            try:
                old_timeout = self._sock.gettimeout()
                self._sock.settimeout(1.5)  # quick probe timeout
                response, addr = self._sock.recvfrom(65536)
                self._sock.settimeout(old_timeout)

                # Any response means this port is alive
                if len(response) >= RPCHeader.SIZE:
                    resp_hdr = RPCHeader.unpack(response[:RPCHeader.SIZE])
                    log.info("Port %d responded (type=%d) — using this port",
                             port, resp_hdr.packet_type)
                    return port
            except socket.timeout:
                self._sock.settimeout(self.timeout)
                log.debug("Port %d: no response", port)
                continue

        return None

    def connect(self, station_name: str = "panel-controller") -> dict:
        """Establish a PROFINET IO connection (Application Relation).

        Sends Connect Request with AR, IOCR, ExpectedSubmodule, and
        AlarmCR blocks. Returns parsed connect response.
        """
        log.info("Connecting to %s (MAC: %s)...",
                 self.device_ip,
                 ":".join(f"{b:02x}" for b in self.device_mac))

        # Discover PNIO port if not already known
        if self._pnio_port is None:
            port = self.discover_pnio_port()
            log.info("Using PNIO port: %d", port)

        # Build the Connect Request NRD payload
        nrd = build_connect_request_nrd(
            ar_uuid=self._ar_uuid,
            controller_mac=self.controller_mac,
            station_name=station_name,
        )

        # Send Connect Request (flags1=0x28 = Idempotent + NoFack)
        log.info("Sending Connect to port %d (%d bytes payload)",
                 self._pnio_port or PROFINET_EPM_PORT, len(nrd))
        resp_body = self._send_rpc(RPCOperation.CONNECT, nrd, flags1=0x28)

        log.info("Got Connect response: %d bytes", len(resp_body))

        # Parse response
        result = parse_connect_response(resp_body)

        if not result.get("success"):
            error_msg = result.get("error") or "unknown error (no AR_BLOCK_RES)"
            raise RPCConnectionError(f"Connect rejected: {error_msg}")

        # Extract frame IDs from IOCR responses
        for iocr in result.get("iocrs", []):
            if iocr["iocr_type"] == 1:  # Input CR
                self.input_frame_id = iocr["frame_id"]
            elif iocr["iocr_type"] == 2:  # Output CR
                self.output_frame_id = iocr["frame_id"]

        self._connected = True
        log.info("Connected! AR: %s, Input: 0x%04X, Output: 0x%04X",
                 self._ar_uuid,
                 self.input_frame_id or 0,
                 self.output_frame_id or 0)

        return result

    def write_parameters(self) -> bool:
        """Send module parameterization records via MultipleWrite.

        Sends the same parameterization records that Proneta sends.
        This is required before PrmEnd can be sent.
        """
        log.info("Writing module parameters...")

        # Build parameter records from capture data
        # The exact parameter data was captured from Proneta
        write_records = []

        # Record 1: DAP parameter (Slot 0, Subslot 1, Index 0x0002, 8 bytes)
        write_records.append({
            "slot": 0, "subslot": 1, "index": 0x0002,
            "data": bytes([0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        })

        # Record 2: DQ parameter (Slot 1, Subslot 1, Index 0x00F3, 4 bytes)
        write_records.append({
            "slot": 1, "subslot": 1, "index": 0x00F3,
            "data": bytes([0x01, 0x00, 0x00, 0x00]),
        })

        # Record 3: DQ parameter (Slot 1, Subslot 1, Index 0x0080, 18 bytes)
        # Module-specific parameterization for DQ 8x24VDC
        dq_param = bytes([
            0x00, 0x02, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        ])
        write_records.append({
            "slot": 1, "subslot": 1, "index": 0x0080,
            "data": dq_param,
        })

        # Record 4: AI parameter (Slot 2, Subslot 1, Index 0x00F3, 4 bytes)
        write_records.append({
            "slot": 2, "subslot": 1, "index": 0x00F3,
            "data": bytes([0x00, 0x00, 0x00, 0x00]),
        })

        # Record 5: AI parameter (Slot 2, Subslot 1, Index 0x0080, 178 bytes)
        # Module-specific parameterization for AI 8xRTD/TC
        # Structure: 2-byte header (10 16) + 8 identical 22-byte channel blocks
        # Channel config (from GSDML analysis):
        #   Bytes 0-1: 0x0A08 = TC Type K [NiCr-Ni]
        #   Byte  2:   0x00   = temp coefficient (N/A for TC)
        #   Byte  3:   0x20   = smoothing=none, integration=50Hz
        #   Byte  4:   0x30   = Celsius + internal reference junction
        #   Bytes 5-9: alarm/diag config
        #   Bytes 10-17: alarm limits (OG1=8500, UG1=-2000, OG2=8500, UG2=-2000)
        #   Bytes 18-21: conductor resistance=0, temp offset=0
        ai_channel = bytes([
            0x0A, 0x08, 0x00, 0x20, 0x30, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x21, 0x34, 0xf8, 0x30, 0x21, 0x34,
            0xf8, 0x30, 0x00, 0x00, 0x00, 0x00,
        ])  # 22 bytes per channel
        ai_param = bytes([0x10, 0x16]) + ai_channel * 8  # 2 + 8*22 = 178 bytes

        write_records.append({
            "slot": 2, "subslot": 1, "index": 0x0080,
            "data": ai_param,
        })

        nrd = build_write_request_nrd(self._ar_uuid, self.device_mac,
                                      write_records)

        try:
            resp = self._send_rpc(RPCOperation.WRITE, nrd, flags1=0x20)
            log.info("Write response: %d bytes, first 24: %s",
                     len(resp), resp[:min(24, len(resp))].hex())
            if len(resp) < 20:
                log.error("Write error response (too short): %s", resp.hex())
                return False
            # Check PNIO status (first 4 bytes: should be 00 00 00 00 for success)
            pnio_status = resp[0:4]
            if pnio_status != b'\x00\x00\x00\x00':
                log.error("Write PNIO error: ErrorCode=0x%02x ErrorDecode=0x%02x "
                          "ErrorCode1=0x%02x ErrorCode2=0x%02x",
                          pnio_status[0], pnio_status[1],
                          pnio_status[2], pnio_status[3])
                return False
            # Check ArgsLength (bytes 4-7 LE) — should be >0 for successful write
            args_len = struct.unpack("<I", resp[4:8])[0]
            log.info("Write parameters: OK (ArgsLength=%d)", args_len)
            return True
        except RPCConnectionError as e:
            log.error("Write parameters failed: %s", e)
            return False

    def prm_end(self) -> bool:
        """Send PrmEnd control to signal parameterization complete.

        After this, the device enters data exchange mode.
        """
        log.info("Sending PrmEnd...")

        control_block = build_iod_control_req(
            ar_uuid=self._ar_uuid,
            session_key=self._session_key,
            command=0x0001,  # PrmEnd
        )

        nrd = pack_nrd(control_block, args_maximum=32)

        try:
            resp = self._send_rpc(RPCOperation.CONTROL, nrd, flags1=0x28)
            log.info("PrmEnd response: %d bytes, first 24: %s",
                     len(resp), resp[:min(24, len(resp))].hex())
            if len(resp) < 20:
                # Short response = likely PNIO error (no NDR header)
                log.error("PrmEnd error response: %s", resp.hex())
                return False
            log.info("PrmEnd: OK")
            return True
        except RPCConnectionError as e:
            log.error("PrmEnd failed: %s", e)
            return False

    def _respond_to_app_ready(self, data: bytes, addr: tuple,
                              sock: socket.socket) -> bool:
        """Parse an ApplicationReady request and send a proper response.

        The response differs from the request in three ways (per Proneta capture):
        1. First 4 bytes: PNIOStatus=0x00000000 (replaces ArgsMaximum)
        2. Block type: 0x8112 (IOXBlockRes, replaces 0x0112 IOXBlockReq)
        3. ControlCommand: 0x0008 (Done, replaces 0x0002 ApplicationReady)
        """
        if len(data) < RPCHeader.SIZE:
            log.warning("AppReady packet too short: %d bytes", len(data))
            return False

        req_hdr = RPCHeader.unpack(data[:RPCHeader.SIZE])
        log.info("Received AppReady from %s (type=%d, op=%d, seq=%d, body=%d)",
                 addr, req_hdr.packet_type, req_hdr.operation,
                 req_hdr.sequence_number, len(data) - RPCHeader.SIZE)

        # Only respond to REQUEST packets (type 0)
        if req_hdr.packet_type != RPCPacketType.REQUEST:
            log.debug("Not a request packet (type=%d), ignoring", req_hdr.packet_type)
            return False

        # Build response header
        resp_hdr = RPCHeader()
        resp_hdr.packet_type = RPCPacketType.RESPONSE
        resp_hdr.flags1 = 0x0A  # NoFack + LastFragment
        resp_hdr.object_uuid = req_hdr.object_uuid
        resp_hdr.interface_uuid = UUID_PNIO_CONTROLLER_INTERFACE
        resp_hdr.activity_uuid = req_hdr.activity_uuid
        resp_hdr.server_boot_time = 0
        resp_hdr.interface_version = 1
        resp_hdr.sequence_number = req_hdr.sequence_number
        resp_hdr.operation = req_hdr.operation

        # Build proper response body (not just echo)
        # Request body: ArgsMax(4) + ArgsLen(4) + MaxCount(4) + Offset(4) +
        #               ActualCount(4) + IOXBlockReq(32)
        req_body = bytearray(data[RPCHeader.SIZE:])
        if len(req_body) < 52:
            log.warning("AppReady body too short: %d bytes", len(req_body))
            return False

        resp_body = bytearray(req_body)
        # 1. Replace ArgsMaximum with PNIOStatus = OK (0x00000000)
        resp_body[0:4] = b'\x00\x00\x00\x00'
        # 2. Change BlockType from 0x0112 (IOXBlockReq) to 0x8112 (IOXBlockRes)
        #    Block starts at NDR offset 20
        resp_body[20:22] = struct.pack("!H", 0x8112)
        # 3. Change ControlCommand from 0x0002 (ApplicationReady) to 0x0008 (Done)
        #    ControlCommand is at block offset 20 + 6(hdr) + 2(reserved) +
        #    16(ARUUID) + 2(SessionKey) + 2(reserved) = offset 48
        resp_body[48:50] = struct.pack("!H", 0x0008)

        resp_hdr.body_length = len(resp_body)
        resp_packet = resp_hdr.pack() + bytes(resp_body)

        sock.sendto(resp_packet, addr)
        log.info("Application Ready confirmed — sent response to %s", addr)
        return True

    def application_ready(self) -> bool:
        """Complete the full PrmEnd + AppReady sequence.

        Opens the AppReady listening socket BEFORE sending PrmEnd to avoid
        a race condition (the device responds within milliseconds).
        """
        # Step 1: Open listening socket on port 34964 BEFORE PrmEnd
        # The device sends ApplicationReady to this well-known port.
        ctrl_sock = None
        bind_ip = self.controller_ip or ""
        try:
            ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ctrl_sock.settimeout(10.0)
            ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ctrl_sock.bind((bind_ip, PROFINET_EPM_PORT))
            log.info("AppReady socket listening on %s:%d", bind_ip, PROFINET_EPM_PORT)
        except OSError as e:
            log.warning("Cannot bind AppReady socket to %s:%d: %s",
                        bind_ip, PROFINET_EPM_PORT, e)
            if ctrl_sock:
                ctrl_sock.close()
            ctrl_sock = None

        # Step 2: Send PrmEnd
        if not self.prm_end():
            if ctrl_sock:
                ctrl_sock.close()
            return False

        # Step 3: Wait for Application Ready on both sockets
        log.info("Waiting for Application Ready from device...")
        received = False

        # Try the dedicated port 34964 socket first
        if ctrl_sock:
            try:
                data, addr = ctrl_sock.recvfrom(65536)
                log.info("Received %d bytes on port %d from %s",
                         len(data), PROFINET_EPM_PORT, addr)
                received = self._respond_to_app_ready(data, addr, ctrl_sock)
            except socket.timeout:
                log.warning("No AppReady on port %d, trying main socket...",
                            PROFINET_EPM_PORT)

        # Fallback: try receiving on the main RPC socket (device might send
        # AppReady to the port we used for Connect/Write/PrmEnd)
        if not received:
            try:
                self._sock.settimeout(5.0)
                data, addr = self._sock.recvfrom(65536)
                log.info("Received %d bytes on main socket from %s", len(data), addr)
                received = self._respond_to_app_ready(data, addr, self._sock)
            except socket.timeout:
                log.warning("No AppReady on main socket either")
            finally:
                self._sock.settimeout(self.timeout)

        # Cleanup
        if ctrl_sock:
            ctrl_sock.close()

        if not received:
            log.warning("Did not receive AppReady, continuing anyway...")

        return True

    def release(self) -> bool:
        """Release the Application Relation (disconnect)."""
        if not self._connected:
            return True

        log.info("Releasing AR connection...")
        try:
            control_block = build_iod_control_req(
                ar_uuid=self._ar_uuid,
                session_key=self._session_key,
                command=0x0004,  # Release
            )
            nrd = pack_nrd(control_block)
            self._send_rpc(RPCOperation.RELEASE, nrd)
        except Exception as e:
            log.warning("Release failed (may be OK): %s", e)

        self._connected = False
        self._close_sockets()
        return True
