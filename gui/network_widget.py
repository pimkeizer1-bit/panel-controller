"""Network adapter selection and device connection widget."""

import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QComboBox, QLabel, QPushButton, QLineEdit, QListWidget,
    QListWidgetItem, QMessageBox,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor

from utils.network import list_adapters, AdapterInfo
from profinet.dcp import DeviceInfo

log = logging.getLogger(__name__)


class NetworkWidget(QWidget):
    """Widget for network adapter selection, device scanning, and connection."""

    scan_requested = pyqtSignal(object)  # AdapterInfo
    connect_requested = pyqtSignal(object, object, str, str)  # adapter, device, ip, subnet
    disconnect_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._adapters: list[AdapterInfo] = []
        self._devices: list[DeviceInfo] = []
        self._connected = False
        self._setup_ui()
        self._refresh_adapters()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        group = QGroupBox("Network Connection")
        group_layout = QVBoxLayout(group)

        # Adapter selection row
        adapter_row = QHBoxLayout()
        adapter_row.addWidget(QLabel("Adapter:"))
        self._adapter_combo = QComboBox()
        self._adapter_combo.setMinimumWidth(300)
        self._adapter_combo.currentIndexChanged.connect(self._update_auto_ip)
        adapter_row.addWidget(self._adapter_combo, 1)
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._refresh_adapters)
        adapter_row.addWidget(self._refresh_btn)
        group_layout.addLayout(adapter_row)

        # IP configuration row
        ip_row = QHBoxLayout()
        ip_row.addWidget(QLabel("Device IP:"))
        self._ip_edit = QLineEdit("192.168.0.1")
        self._ip_edit.setMaximumWidth(150)
        ip_row.addWidget(self._ip_edit)
        ip_row.addWidget(QLabel("Subnet:"))
        self._subnet_edit = QLineEdit("255.255.255.0")
        self._subnet_edit.setMaximumWidth(150)
        ip_row.addWidget(self._subnet_edit)
        ip_row.addStretch()
        group_layout.addLayout(ip_row)

        # Scan and device list row
        scan_row = QHBoxLayout()
        self._scan_btn = QPushButton("Scan for Devices")
        self._scan_btn.clicked.connect(self._on_scan)
        scan_row.addWidget(self._scan_btn)

        self._device_list = QListWidget()
        self._device_list.setMaximumHeight(80)
        scan_row.addWidget(self._device_list, 1)
        group_layout.addLayout(scan_row)

        # Connect/disconnect row
        connect_row = QHBoxLayout()
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.clicked.connect(self._on_connect)
        self._connect_btn.setEnabled(False)
        self._connect_btn.setMinimumWidth(120)
        connect_row.addWidget(self._connect_btn)

        self._disconnect_btn = QPushButton("Disconnect")
        self._disconnect_btn.clicked.connect(self._on_disconnect)
        self._disconnect_btn.setEnabled(False)
        self._disconnect_btn.setMinimumWidth(120)
        connect_row.addWidget(self._disconnect_btn)

        self._status_label = QLabel("Disconnected")
        self._status_label.setStyleSheet("color: red; font-weight: bold;")
        connect_row.addWidget(self._status_label)
        connect_row.addStretch()
        group_layout.addLayout(connect_row)

        layout.addWidget(group)

    def _refresh_adapters(self):
        self._adapter_combo.blockSignals(True)
        self._adapter_combo.clear()
        self._adapters = list_adapters()
        for adapter in self._adapters:
            self._adapter_combo.addItem(
                f"{adapter.description} ({adapter.ip})", adapter)
        self._adapter_combo.blockSignals(False)
        self._update_auto_ip()

    def _update_auto_ip(self):
        """Auto-fill device IP. Always uses 192.168.0.1/24 like Proneta.

        The controller will auto-add a secondary IP (192.168.0.253) to the
        adapter if it's not already on the 192.168.0.x subnet. This matches
        how Proneta handles IP assignment.
        """
        self._ip_edit.setText("192.168.0.1")
        self._subnet_edit.setText("255.255.255.0")

    def _get_selected_adapter(self) -> AdapterInfo | None:
        idx = self._adapter_combo.currentIndex()
        if 0 <= idx < len(self._adapters):
            return self._adapters[idx]
        return None

    def _on_scan(self):
        """Handle scan button click."""
        adapter = self._get_selected_adapter()
        if not adapter:
            QMessageBox.warning(self, "Error", "Please select a network adapter.")
            return

        self._scan_btn.setEnabled(False)
        self._scan_btn.setText("Scanning...")
        self._device_list.clear()

        self.scan_requested.emit(adapter)

    def set_scan_results(self, devices: list[DeviceInfo]):
        """Called by main window after scan completes."""
        self._devices = devices
        self._device_list.clear()
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("Scan for Devices")

        if not devices:
            self._device_list.addItem("No devices found")
            self._connect_btn.setEnabled(False)
            return

        for dev in devices:
            item = QListWidgetItem(
                f"{dev.mac}  |  {dev.name or '(unnamed)'}  |  {dev.ip or '(no IP)'}")
            self._device_list.addItem(item)

        self._device_list.setCurrentRow(0)
        self._connect_btn.setEnabled(True)

    def _on_connect(self):
        adapter = self._get_selected_adapter()
        if not adapter:
            return

        idx = self._device_list.currentRow()
        if idx < 0 or idx >= len(self._devices):
            QMessageBox.warning(self, "Error", "Please select a device.")
            return

        device = self._devices[idx]
        ip = self._ip_edit.text().strip()
        subnet = self._subnet_edit.text().strip()

        self._connect_btn.setEnabled(False)
        self.connect_requested.emit(adapter, device, ip, subnet)

    def _on_disconnect(self):
        self.disconnect_requested.emit()

    def set_connected(self, connected: bool):
        """Update UI state based on connection status."""
        self._connected = connected
        self._connect_btn.setEnabled(not connected)
        self._disconnect_btn.setEnabled(connected)
        self._scan_btn.setEnabled(not connected)
        self._adapter_combo.setEnabled(not connected)
        self._ip_edit.setEnabled(not connected)
        self._subnet_edit.setEnabled(not connected)

        if connected:
            self._status_label.setText("Connected")
            self._status_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            self._status_label.setText("Disconnected")
            self._status_label.setStyleSheet("color: red; font-weight: bold;")
