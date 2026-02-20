"""High-level PROFINET IO Controller.

Orchestrates DCP discovery → RPC connection → RTC cyclic exchange
and provides a simple API for reading temperatures and writing outputs.

Connection sequence (from Proneta Wireshark capture):
1. DCP Set IP → assign temporary IP to device
2. EPM Lookup → discover PNIO service port (e.g. 49156)
3. RPC Connect → establish Application Relation with IOCR/Submodule config
4. RPC Write → send module parameterization (MultipleWrite)
5. PrmEnd → signal parameterization complete
6. Wait for ApplicationReady from device
7. Start cyclic RTC exchange (Layer 2 frames at 128ms cycle)
"""

import logging
import socket
import struct
import subprocess
import threading
import time

from PyQt6.QtCore import QObject, pyqtSignal

from profinet.dcp import DCPManager, DeviceInfo
from profinet.rpc import RPCConnection, RPCConnectionError
from profinet.rtc import RTCExchange
from utils.network import mac_str_to_bytes, AdapterInfo

log = logging.getLogger(__name__)

# Default network config (matches Proneta defaults)
DEFAULT_DEVICE_IP = "192.168.0.1"
DEFAULT_SUBNET = "255.255.255.0"
DEFAULT_GATEWAY = "0.0.0.0"


def _on_same_subnet(ip1: str, ip2: str, mask: str) -> bool:
    """Check if two IPs are on the same subnet."""
    a = struct.unpack("!I", socket.inet_aton(ip1))[0]
    b = struct.unpack("!I", socket.inet_aton(ip2))[0]
    m = struct.unpack("!I", socket.inet_aton(mask))[0]
    return (a & m) == (b & m)


def _pick_controller_ip(device_ip: str, subnet: str) -> str:
    """Pick a controller IP on the same subnet as the device, avoiding collision.

    Prefers .253 to match Proneta's behavior.
    """
    dev = struct.unpack("!I", socket.inet_aton(device_ip))[0]
    mask = struct.unpack("!I", socket.inet_aton(subnet))[0]
    network = dev & mask
    host = dev & ~mask

    # Use .253 if device isn't .253, otherwise .254 (matches Proneta)
    ctrl_host = 253 if host != 253 else 254
    ctrl_ip = network | ctrl_host
    return socket.inet_ntoa(struct.pack("!I", ctrl_ip))


class ProfinetController(QObject):
    """High-level controller for PROFINET IO communication with ET200SP.

    Signals:
        connected: Emitted when connection is established.
        disconnected: Emitted when connection is lost or closed.
        error: Emitted with error message string.
        data_updated: Emitted when new input data is available.
    """

    connected = pyqtSignal()
    disconnected = pyqtSignal()
    error = pyqtSignal(str)
    data_updated = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._dcp: DCPManager | None = None
        self._rpc: RPCConnection | None = None
        self._rtc: RTCExchange | None = None
        self._adapter: AdapterInfo | None = None
        self._device: DeviceInfo | None = None
        self._is_connected = False

        # Cached state
        self._temperatures = [0.0, 0.0, 0.0, 0.0]
        self._output_byte = 0x00
        self._lock = threading.Lock()

        # Monitor thread
        self._monitor_running = False
        self._monitor_thread: threading.Thread | None = None

        # Adapter IP we added (so we can remove it on disconnect)
        self._added_ip: str | None = None
        self._added_subnet: str | None = None
        self._added_adapter: str | None = None

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    def scan(self, adapter: AdapterInfo) -> list[DeviceInfo]:
        """Scan for PROFINET devices on the given adapter."""
        self._adapter = adapter
        self._dcp = DCPManager(adapter.ip)
        devices = self._dcp.discover_devices()
        log.info("Found %d PROFINET device(s)", len(devices))
        return devices

    def connect(self, adapter: AdapterInfo, device: DeviceInfo,
                device_ip: str = DEFAULT_DEVICE_IP,
                subnet: str = DEFAULT_SUBNET) -> bool:
        """Full connection sequence: DCP → RPC Connect → Write → PrmEnd/AppReady → RTC.

        Args:
            adapter: Local network adapter to use.
            device: Device discovered via scan().
            device_ip: IP to assign to the device.
            subnet: Subnet mask for the device.

        Returns:
            True if connection was successful.
        """
        try:
            self._adapter = adapter
            self._device = device

            # Step 1: Assign IP to device via DCP
            log.info("Step 1: Assigning IP %s to device %s", device_ip, device.mac)
            if self._dcp is None:
                self._dcp = DCPManager(adapter.ip)

            if not self._dcp.set_ip(device.mac, device_ip, subnet, DEFAULT_GATEWAY,
                                     persistent=False):
                self.error.emit("Failed to assign IP to device")
                return False

            time.sleep(2.0)  # Give device time to configure IP stack

            # Step 1b: Ensure our adapter is on the same subnet as device IP
            # We need a controller IP on the device's subnet for RPC to work
            if _on_same_subnet(adapter.ip, device_ip, subnet):
                controller_ip = adapter.ip
                log.info("Adapter %s already on correct subnet", adapter.ip)
            else:
                controller_ip = _pick_controller_ip(device_ip, subnet)
                log.info("Step 1b: Adding IP %s/%s to adapter %s",
                         controller_ip, subnet, adapter.name)
                try:
                    result_netsh = subprocess.run(
                        ["netsh", "interface", "ip", "add", "address",
                         adapter.name, controller_ip, subnet],
                        capture_output=True, text=True, timeout=10,
                    )
                    log.info("netsh rc=%d stdout=%r stderr=%r",
                             result_netsh.returncode,
                             result_netsh.stdout.strip(),
                             result_netsh.stderr.strip())
                    if result_netsh.returncode == 0:
                        self._added_ip = controller_ip
                        self._added_subnet = subnet
                        self._added_adapter = adapter.name
                        log.info("Added IP %s to adapter", controller_ip)
                        time.sleep(3.0)  # Give Windows time to apply
                    else:
                        log.warning("netsh failed — running without admin?")
                        self.error.emit(
                            f"Could not set adapter IP (need Administrator). "
                            f"Try running as Administrator, or manually set "
                            f"adapter IP to {controller_ip}/{subnet}")
                        return False
                except Exception as e:
                    log.error("Failed to configure adapter IP: %s", e)
                    self.error.emit(f"Failed to set adapter IP: {e}")
                    return False

            # Step 2: Establish RPC connection (includes EPM port discovery)
            log.info("Step 2: Establishing RPC connection...")
            log.info("Controller IP: %s, Device IP: %s", controller_ip, device_ip)
            controller_mac = mac_str_to_bytes(adapter.mac)
            device_mac = mac_str_to_bytes(device.mac)

            self._rpc = RPCConnection(
                device_ip=device_ip,
                device_mac=device_mac,
                controller_mac=controller_mac,
                controller_ip=controller_ip,
            )

            result = self._rpc.connect()
            if not result.get("success"):
                self.error.emit("RPC Connect failed")
                return False

            # Step 3: Write module parameterization
            log.info("Step 3: Writing module parameters...")
            if not self._rpc.write_parameters():
                self.error.emit("Parameter write failed")
                return False

            # Step 4: PrmEnd + wait for Application Ready from device
            log.info("Step 4: PrmEnd and Application Ready...")
            if not self._rpc.application_ready():
                self.error.emit("Application Ready sequence failed")
                return False

            # Step 5: Start cyclic RTC exchange — NO DELAY, device watchdog is ticking
            log.info("Step 5: Starting cyclic data exchange...")
            self._rtc = RTCExchange(
                interface=adapter.name,
                controller_mac=adapter.mac,
                device_mac=device.mac,
                output_frame_id=self._rpc.output_frame_id or 0x8000,
                input_frame_id=self._rpc.input_frame_id or 0xBB80,
            )
            self._rtc.start()

            # Step 6: Start monitor thread
            self._is_connected = True
            self._start_monitor()

            self.connected.emit()
            log.info("Connection established successfully!")
            return True

        except RPCConnectionError as e:
            log.error("Connection failed: %s", e)
            self.error.emit(f"Connection failed: {e}")
            return False
        except Exception as e:
            log.error("Unexpected connection error: %s", e)
            self.error.emit(f"Unexpected error: {e}")
            return False

    def disconnect(self):
        """Disconnect from the device, ensuring all outputs are OFF."""
        log.info("Disconnecting...")

        # Safety: turn off all outputs before disconnecting
        self.write_outputs(contactor=False, ssrs=[False, False, False, False])
        time.sleep(0.1)

        self._stop_monitor()

        if self._rtc:
            self._rtc.stop()
            self._rtc = None

        if self._rpc:
            self._rpc.release()
            self._rpc = None

        # Remove the IP we added to the adapter
        if self._added_ip and self._added_adapter:
            log.info("Removing IP %s from adapter %s",
                     self._added_ip, self._added_adapter)
            try:
                subprocess.run(
                    ["netsh", "interface", "ip", "delete", "address",
                     self._added_adapter, self._added_ip],
                    capture_output=True, text=True, timeout=10,
                )
            except Exception as e:
                log.warning("Failed to remove adapter IP: %s", e)
            self._added_ip = None
            self._added_subnet = None
            self._added_adapter = None

        self._is_connected = False
        self.disconnected.emit()
        log.info("Disconnected")

    def read_temperatures(self) -> list[float]:
        """Read current thermocouple temperatures in °C.

        Returns:
            List of 4 temperatures [TC0, TC1, TC2, TC3] in °C.
            Returns 0.0 for disconnected channels (reading 0x7FFF).
        """
        if not self._rtc:
            return [0.0, 0.0, 0.0, 0.0]

        temps = self._rtc.get_temperatures()

        with self._lock:
            self._temperatures = temps

        return temps

    def write_outputs(self, contactor: bool,
                      ssrs: list[bool] | None = None):
        """Write digital outputs.

        Args:
            contactor: True to enable main contactor (output 0).
            ssrs: List of 4 booleans for SSR outputs 1-4. None to leave unchanged.
        """
        if not self._rtc:
            return

        with self._lock:
            dq_byte = self._output_byte

        # Bit 0 = contactor
        if contactor:
            dq_byte |= 0x01
        else:
            dq_byte &= ~0x01
            # Safety: if contactor is off, all SSRs must be off
            dq_byte &= 0x01

        # Bits 1-4 = SSRs (only if contactor is on)
        if ssrs and contactor:
            for i, on in enumerate(ssrs[:4]):
                bit = 1 << (i + 1)
                if on:
                    dq_byte |= bit
                else:
                    dq_byte &= ~bit

        with self._lock:
            self._output_byte = dq_byte

        self._rtc.set_output(dq_byte)

    def emergency_stop(self):
        """Emergency stop: turn off ALL outputs immediately."""
        log.warning("EMERGENCY STOP - all outputs OFF")
        with self._lock:
            self._output_byte = 0x00
        if self._rtc:
            self._rtc.set_output(0x00)

    def _start_monitor(self):
        """Start background thread that monitors communication health."""
        self._monitor_running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _stop_monitor(self):
        self._monitor_running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
            self._monitor_thread = None

    def _monitor_loop(self):
        """Monitor communication health and emit data_updated signals."""
        while self._monitor_running and self._is_connected:
            try:
                # Read temperatures
                self.read_temperatures()
                self.data_updated.emit()

                # Check communication health
                if self._rtc and not self._rtc.is_communication_ok:
                    log.error("Communication error detected!")
                    self.emergency_stop()
                    self.error.emit("Communication lost - all outputs OFF")
                    break  # Stop monitoring after comm loss

            except Exception as e:
                log.error("Monitor error: %s", e)

            time.sleep(0.1)  # 10 Hz update rate
