"""PROFINET DCP (Discovery and Configuration Protocol) layer.

Wraps the pnio-dcp library for device discovery and IP assignment.
"""

import logging
from dataclasses import dataclass

from pnio_dcp import DCP, DcpTimeoutError

log = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    mac: str
    name: str
    ip: str
    netmask: str
    gateway: str
    vendor_id: int | None = None
    device_id: int | None = None


class DCPManager:
    """Manages PROFINET DCP operations for device discovery and IP assignment."""

    def __init__(self, host_ip: str):
        """Create DCP manager.

        Args:
            host_ip: IP address of the local network adapter to use.
        """
        self._host_ip = host_ip
        self._dcp = DCP(host_ip)

    def discover_devices(self, timeout_s: float = 5.0) -> list[DeviceInfo]:
        """Discover all PROFINET devices on the network."""
        log.info("Scanning for PROFINET devices on %s...", self._host_ip)
        try:
            devices = self._dcp.identify_all()
        except Exception as e:
            log.error("DCP identify_all failed: %s", e)
            return []

        result = []
        for dev in devices:
            info = DeviceInfo(
                mac=dev.MAC,
                name=getattr(dev, "name_of_station", "") or "",
                ip=getattr(dev, "IP", "") or "",
                netmask=getattr(dev, "netmask", "") or "",
                gateway=getattr(dev, "gateway", "") or "",
            )
            log.info("Found device: MAC=%s name=%s ip=%s", info.mac, info.name, info.ip)
            result.append(info)
        return result

    def set_ip(self, mac: str, ip: str, netmask: str = "255.255.255.0",
               gateway: str = "0.0.0.0", persistent: bool = False) -> bool:
        """Assign an IP address to a device.

        Args:
            mac: Device MAC address.
            ip: IP address to assign.
            netmask: Subnet mask.
            gateway: Default gateway.
            persistent: If True, store in flash. If False, temporary (lost on reboot).
        """
        log.info("Setting IP on %s: %s/%s gw=%s (persistent=%s)",
                 mac, ip, netmask, gateway, persistent)
        try:
            self._dcp.set_ip_address(mac, [ip, netmask, gateway], persistent)
            return True
        except DcpTimeoutError:
            log.error("Timeout setting IP on device %s", mac)
            return False
        except Exception as e:
            log.error("Failed to set IP on %s: %s", mac, e)
            return False

    def get_device_name(self, mac: str) -> str | None:
        """Get the station name of a device."""
        try:
            return self._dcp.get_name_of_station(mac)
        except DcpTimeoutError:
            return None

    def get_device_ip(self, mac: str) -> str | None:
        """Get the current IP address of a device."""
        try:
            return self._dcp.get_ip_address(mac)
        except DcpTimeoutError:
            return None
