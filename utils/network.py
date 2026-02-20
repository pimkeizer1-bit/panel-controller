import psutil
import socket
import struct
from dataclasses import dataclass


@dataclass
class AdapterInfo:
    name: str
    description: str
    ip: str
    netmask: str
    mac: str


def list_adapters() -> list[AdapterInfo]:
    """List network adapters that have an IPv4 address."""
    adapters = []
    stats = psutil.net_if_addrs()
    for name, addrs in stats.items():
        ipv4 = None
        mac = None
        netmask = None
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                ipv4 = addr.address
                netmask = addr.netmask
            if addr.family == psutil.AF_LINK:
                mac = addr.address
        if ipv4 and mac:
            adapters.append(AdapterInfo(
                name=name,
                description=name,
                ip=ipv4,
                netmask=netmask or "255.255.255.0",
                mac=mac,
            ))
    return adapters


def mac_str_to_bytes(mac: str) -> bytes:
    """Convert MAC string (xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx) to bytes."""
    mac = mac.replace("-", ":").replace(".", ":")
    return bytes(int(b, 16) for b in mac.split(":"))


def mac_bytes_to_str(mac: bytes) -> str:
    """Convert MAC bytes to string xx:xx:xx:xx:xx:xx."""
    return ":".join(f"{b:02x}" for b in mac)


def ip_str_to_int(ip: str) -> int:
    """Convert IP string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def ip_int_to_str(ip: int) -> str:
    """Convert integer to IP string."""
    return socket.inet_ntoa(struct.pack("!I", ip))
