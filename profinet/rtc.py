"""PROFINET Real-Time Cyclic (RTC) data exchange.

Sends/receives cyclic IO data frames using raw Ethernet (Layer 2)
via Scapy's L2 socket through Npcap.

Data layout verified against Proneta IO Test Wireshark capture:
- Input frames from device: VLAN-tagged (802.1Q prio 6), FrameID 0xBB80
- Output frames to device: No VLAN tag, FrameID 0x8000
- Both frames: 40 bytes payload + 2 cycle counter + 1 DataStatus + 1 TransferStatus
"""

import logging
import struct
import threading
import time

from scapy.all import conf as scapy_conf
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, AsyncSniffer

from profinet.protocol import (
    PROFINET_ETHERTYPE, IOCR_DATA_LENGTH, REDUCTION_RATIO,
    SEND_CLOCK_FACTOR,
    OUTPUT_DAP_IOCS_OFFSET, OUTPUT_PORT0_IOCS_OFFSET,
    OUTPUT_PORT1_IOCS_OFFSET, OUTPUT_PORT2_IOCS_OFFSET,
    OUTPUT_DQ_DATA_OFFSET, OUTPUT_DQ_IOPS_OFFSET,
    OUTPUT_AI_IOCS_OFFSET, OUTPUT_SERVER_IOCS_OFFSET,
    INPUT_AI_DATA_OFFSET, INPUT_AI_IOPS_OFFSET,
)

log = logging.getLogger(__name__)

# IOxS byte values
IOXS_GOOD = 0x80
IOXS_BAD = 0x00

# Cycle time calculation: SEND_CLOCK_FACTOR * 31.25µs * REDUCTION_RATIO
# 32 * 31.25µs * 128 = 128ms
CYCLE_TIME_MS = int(SEND_CLOCK_FACTOR * 31.25e-3 * REDUCTION_RATIO)


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to colon-separated lowercase (aa:bb:cc:dd:ee:ff)."""
    mac = mac.replace("-", ":").replace(".", ":")
    return mac.lower()


class RTCExchange:
    """Manages cyclic PROFINET RTC frame exchange.

    Sends output frames (DQ data) and receives input frames (AI data)
    using raw Ethernet frames with EtherType 0x8892.
    """

    def __init__(self, interface: str, controller_mac: str, device_mac: str,
                 output_frame_id: int = 0x8000,
                 input_frame_id: int = 0xBB80,
                 cycle_time_ms: int = CYCLE_TIME_MS):
        """
        Args:
            interface: Network interface name (Scapy/Npcap format).
            controller_mac: Controller MAC address string (any format).
            device_mac: Device MAC address string (any format).
            output_frame_id: Frame ID for output CR (from Connect Response).
            input_frame_id: Frame ID for input CR (from Connect Response).
            cycle_time_ms: Cycle time in milliseconds.
        """
        self.interface = interface
        self.controller_mac = _normalize_mac(controller_mac)
        self.device_mac = _normalize_mac(device_mac)
        self.output_frame_id = output_frame_id
        self.input_frame_id = input_frame_id
        self.cycle_time_ms = cycle_time_ms

        # Thread-safe data access
        self._lock = threading.Lock()
        self._dq_byte = 0x00  # single byte for DQ output
        self._input_data = bytearray(IOCR_DATA_LENGTH)  # full input payload
        self._input_valid = False
        self._cycle_counter = 0

        # Threading
        self._running = False
        self._send_thread: threading.Thread | None = None
        self._sniffer: AsyncSniffer | None = None

        # Statistics
        self._frames_sent = 0
        self._frames_received = 0
        self._last_receive_time = 0.0
        self._comm_error = False

    def start(self):
        """Start cyclic data exchange."""
        if self._running:
            return

        log.info("Starting RTC exchange on %s (cycle=%dms, out=0x%04X, in=0x%04X)",
                 self.interface, self.cycle_time_ms,
                 self.output_frame_id, self.input_frame_id)
        log.info("RTC MACs: controller=%s device=%s",
                 self.controller_mac, self.device_mac)
        self._running = True
        self._comm_error = False

        # Use PROFINET ethertype filter — the device may send from a port MAC
        # that differs from the DCP-discovered MAC (Siemens uses device_mac+1
        # for port 1), so we cannot filter by source MAC alone.
        pn_filter = "ether proto 0x8892"
        log.info("RTC sniffer filter: %s", pn_filter)
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=pn_filter,
            prn=self._on_frame_received,
            store=False,
        )
        self._sniffer.start()

        # Start send thread IMMEDIATELY — the device's AR watchdog starts
        # after ApplicationReady, so output frames must flow without delay.
        self._send_thread = threading.Thread(target=self._send_loop, daemon=True)
        self._send_thread.start()

    def stop(self):
        """Stop cyclic data exchange."""
        self._running = False

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        if self._send_thread:
            self._send_thread.join(timeout=2.0)
            self._send_thread = None

        log.info("RTC exchange stopped (sent=%d, received=%d)",
                 self._frames_sent, self._frames_received)

    def set_output(self, dq_byte: int):
        """Set the DQ output byte to be sent in next cycle.

        Args:
            dq_byte: The DQ output byte (bit 0=contactor, bits 1-4=SSRs).
        """
        with self._lock:
            self._dq_byte = dq_byte & 0xFF

    def get_input_data(self) -> tuple[bytearray, bool]:
        """Get the full input payload received from device.

        Returns:
            Tuple of (40-byte input payload, is_valid).
        """
        with self._lock:
            return bytearray(self._input_data), self._input_valid

    def get_temperatures(self) -> list[float]:
        """Extract thermocouple temperatures from input data.

        Returns:
            List of 4 temperatures [TC0, TC1, TC2, TC3] in °C.
            Returns 0.0 for channels reading 0x7FFF (disconnected).
        """
        with self._lock:
            data = bytes(self._input_data)
            valid = self._input_valid

        if not valid:
            return [0.0, 0.0, 0.0, 0.0]

        temps = []
        for ch in range(4):
            offset = INPUT_AI_DATA_OFFSET + ch * 2
            if offset + 2 <= len(data):
                raw = struct.unpack("!h", data[offset:offset + 2])[0]
                if raw == 0x7FFF:
                    temps.append(0.0)  # disconnected channel
                else:
                    temps.append(raw / 10.0)  # value in 0.1°C
            else:
                temps.append(0.0)

        return temps

    @property
    def is_communication_ok(self) -> bool:
        """Check if communication is healthy (frames received recently)."""
        if not self._running:
            return False
        return not self._comm_error

    def _build_output_frame(self) -> bytes:
        """Build an RTC output frame (no VLAN tag, per capture)."""
        with self._lock:
            dq_byte = self._dq_byte

        # Build 40-byte RTC payload matching capture layout
        payload = bytearray(IOCR_DATA_LENGTH)

        # Set IOCS bytes (consumer status for input submodules - all good)
        payload[OUTPUT_DAP_IOCS_OFFSET] = IOXS_GOOD
        payload[OUTPUT_PORT0_IOCS_OFFSET] = IOXS_GOOD
        payload[OUTPUT_PORT1_IOCS_OFFSET] = IOXS_GOOD
        payload[OUTPUT_PORT2_IOCS_OFFSET] = IOXS_GOOD

        # Set DQ data and provider status
        payload[OUTPUT_DQ_DATA_OFFSET] = dq_byte
        payload[OUTPUT_DQ_IOPS_OFFSET] = IOXS_GOOD

        # Set consumer status for AI and Server modules
        payload[OUTPUT_AI_IOCS_OFFSET] = IOXS_GOOD
        payload[OUTPUT_SERVER_IOCS_OFFSET] = IOXS_GOOD

        # Remaining bytes are zero (padding)

        # Increment cycle counter
        self._cycle_counter = (self._cycle_counter + 1) & 0xFFFF

        # Build Ethernet frame (NO VLAN tag for output)
        dst_mac = bytes.fromhex(self.device_mac.replace(":", ""))
        src_mac = bytes.fromhex(self.controller_mac.replace(":", ""))

        frame = struct.pack("!6s6sH", dst_mac, src_mac, PROFINET_ETHERTYPE)
        frame += struct.pack("!H", self.output_frame_id)
        frame += bytes(payload)
        frame += struct.pack("!H", self._cycle_counter)
        frame += struct.pack("!BB", 0x35, 0x00)  # DataStatus + TransferStatus

        return frame

    def _send_loop(self):
        """Background thread: send output frames at configured cycle time."""
        cycle_s = self.cycle_time_ms / 1000.0
        watchdog_timeout = max(2.0, cycle_s * 30)  # 30 missed cycles = error
        start_time = time.monotonic()
        startup_timeout = 5.0  # expect first input frame within 5s
        last_stats_time = start_time

        log.info("RTC send loop started (cycle=%.3fs)", cycle_s)

        while self._running:
            try:
                frame = self._build_output_frame()
                # Send raw Ethernet frame
                sendp(Ether(frame), iface=self.interface, verbose=False)
                self._frames_sent += 1
                if self._frames_sent == 1:
                    log.info("First RTC output frame sent (%d bytes)", len(frame))

                now = time.monotonic()

                # Periodic stats (every 5 seconds)
                if now - last_stats_time >= 5.0:
                    log.info("RTC stats: sent=%d received=%d valid=%s",
                             self._frames_sent, self._frames_received,
                             self._input_valid)
                    last_stats_time = now

                # Check watchdog
                if self._last_receive_time > 0:
                    elapsed = now - self._last_receive_time
                    if elapsed > watchdog_timeout:
                        if not self._comm_error:
                            log.error("RTC watchdog timeout (%.1fs, threshold %.1fs)",
                                      elapsed, watchdog_timeout)
                            self._comm_error = True
                    else:
                        self._comm_error = False
                elif now - start_time > startup_timeout:
                    # Never received any frames after startup period
                    if not self._comm_error:
                        log.error("RTC: no input frames received after %.1fs "
                                  "(sent %d frames)", now - start_time,
                                  self._frames_sent)
                        self._comm_error = True

            except Exception as e:
                log.error("RTC send error: %s", e)
                self._comm_error = True

            time.sleep(cycle_s)

    def _on_frame_received(self, packet):
        """Callback: process received RTC frame from device.

        Handles both VLAN-tagged and non-VLAN frames from device.
        """
        try:
            raw = bytes(packet)
            if len(raw) < 20:
                return

            # Determine if frame is VLAN-tagged
            ethertype_or_vlan = struct.unpack("!H", raw[12:14])[0]

            if ethertype_or_vlan == 0x8100:
                # VLAN-tagged frame: Dst(6) + Src(6) + 0x8100(2) + TCI(2) +
                #                    EtherType(2) + FrameID(2) + Data(40) + ...
                if len(raw) < 22:
                    return
                ethertype = struct.unpack("!H", raw[16:18])[0]
                if ethertype != PROFINET_ETHERTYPE:
                    return
                frame_id = struct.unpack("!H", raw[18:20])[0]
                rtc_data_start = 20
            elif ethertype_or_vlan == PROFINET_ETHERTYPE:
                # Non-VLAN frame: Dst(6) + Src(6) + EtherType(2) + FrameID(2) + Data
                frame_id = struct.unpack("!H", raw[14:16])[0]
                rtc_data_start = 16
            else:
                return  # not a PROFINET frame

            # Log non-matching FrameIDs with full payload for alarm decoding
            if frame_id != self.input_frame_id:
                if not hasattr(self, '_skipped_frames'):
                    self._skipped_frames = 0
                self._skipped_frames += 1
                src = ":".join(f"{b:02x}" for b in raw[6:12])
                if self._skipped_frames <= 5:
                    # Log full hex dump for device frames (not our own echoed output)
                    our_mac = self.controller_mac.replace(":", "")
                    src_hex = src.replace(":", "")
                    if src_hex != our_mac:
                        log.info("DEVICE frame: src=%s frame_id=0x%04X len=%d\n  hex: %s",
                                 src, frame_id, len(raw), raw.hex())
                    else:
                        log.debug("Own output echoed: frame_id=0x%04X", frame_id)
                return

            # Extract the full RTC payload (40 bytes)
            rtc_data = raw[rtc_data_start:rtc_data_start + IOCR_DATA_LENGTH]
            if len(rtc_data) < IOCR_DATA_LENGTH:
                return

            with self._lock:
                self._input_data[:] = rtc_data
                self._input_valid = True

            self._frames_received += 1
            self._last_receive_time = time.monotonic()
            if self._frames_received == 1:
                log.info("First RTC input frame received! frame_id=0x%04X, %d bytes data",
                         frame_id, len(rtc_data))

        except Exception as e:
            log.error("RTC receive error: %s", e)
