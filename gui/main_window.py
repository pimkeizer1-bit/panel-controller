"""Main application window.

Assembles network widget, panel widgets, and control buttons.
Connects GUI events to the PROFINET controller and panel manager.
"""

import logging
import sys
import threading

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QPushButton, QLabel, QStatusBar, QMessageBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QCloseEvent

from gui.network_widget import NetworkWidget
from gui.panel_widget import PanelWidget
from profinet.controller import ProfinetController
from control.panel_manager import PanelManager

log = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


class MainWindow(QMainWindow):
    """Main application window for panel heating controller."""

    # Signals for thread-safe GUI updates from worker threads
    _scan_finished = pyqtSignal(list)       # list of DeviceInfo
    _scan_error = pyqtSignal(str)           # error message
    _connect_finished = pyqtSignal(bool)    # success

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Panel Heating Controller")
        self.setMinimumSize(800, 700)

        # Core objects
        self._controller = ProfinetController()
        self._panel_manager = PanelManager(self._controller)

        # Connect signals
        self._controller.connected.connect(self._on_connected)
        self._controller.disconnected.connect(self._on_disconnected)
        self._controller.error.connect(self._on_error)
        self._panel_manager.state_updated.connect(self._on_state_updated)

        self._setup_ui()

        # Connect worker thread signals
        self._scan_finished.connect(self._on_scan_done)
        self._scan_error.connect(self._on_scan_failed)
        self._connect_finished.connect(self._on_connect_done)

        # GUI refresh timer
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_gui)
        self._refresh_timer.start(100)  # 10 Hz GUI refresh

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(10)

        # Network widget (top)
        self._network_widget = NetworkWidget()
        self._network_widget.scan_requested.connect(self._on_scan)
        self._network_widget.connect_requested.connect(self._on_connect_requested)
        self._network_widget.disconnect_requested.connect(self._on_disconnect_requested)
        main_layout.addWidget(self._network_widget)

        # Panel widgets (center, 2x2 grid)
        panel_grid = QGridLayout()
        panel_grid.setSpacing(10)
        self._panel_widgets = []
        for i in range(4):
            pw = PanelWidget(i)
            pw.setpoint_changed.connect(self._on_setpoint_changed)
            pw.enabled_changed.connect(self._on_enabled_changed)
            pw.set_controls_enabled(False)
            self._panel_widgets.append(pw)
            row = i // 2
            col = i % 2
            panel_grid.addWidget(pw, row, col)
        main_layout.addLayout(panel_grid)

        # Bottom control bar
        control_bar = QHBoxLayout()

        # Contactor toggle
        self._contactor_btn = QPushButton("Contactor: OFF")
        self._contactor_btn.setCheckable(True)
        self._contactor_btn.setMinimumWidth(150)
        self._contactor_btn.setMinimumHeight(40)
        self._contactor_btn.setStyleSheet(
            "QPushButton { background-color: #555; color: white; font-weight: bold; }"
            "QPushButton:checked { background-color: #228B22; }")
        self._contactor_btn.toggled.connect(self._on_contactor_toggled)
        self._contactor_btn.setEnabled(False)
        control_bar.addWidget(self._contactor_btn)

        control_bar.addStretch()

        # Emergency stop
        self._estop_btn = QPushButton("EMERGENCY\nSTOP")
        self._estop_btn.setMinimumWidth(120)
        self._estop_btn.setMinimumHeight(50)
        estop_font = QFont()
        estop_font.setBold(True)
        estop_font.setPointSize(11)
        self._estop_btn.setFont(estop_font)
        self._estop_btn.setStyleSheet(
            "QPushButton { background-color: #CC0000; color: white; "
            "border: 2px solid #880000; border-radius: 5px; }"
            "QPushButton:pressed { background-color: #880000; }")
        self._estop_btn.clicked.connect(self._on_emergency_stop)
        control_bar.addWidget(self._estop_btn)

        main_layout.addLayout(control_bar)

        # Status bar
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._statusbar.showMessage("Ready — select a network adapter and scan for devices")

    def _on_scan(self, adapter):
        """Handle scan request — runs in background thread."""
        self._statusbar.showMessage("Scanning for PROFINET devices...")

        def _do_scan():
            try:
                devices = self._controller.scan(adapter)
                self._scan_finished.emit(devices)
            except Exception as e:
                self._scan_error.emit(str(e))

        threading.Thread(target=_do_scan, daemon=True).start()

    def _on_scan_done(self, devices):
        """Called on GUI thread when scan completes."""
        self._network_widget.set_scan_results(devices)
        self._statusbar.showMessage(f"Found {len(devices)} device(s)")

    def _on_scan_failed(self, message):
        """Called on GUI thread when scan fails."""
        self._network_widget.set_scan_results([])
        self._statusbar.showMessage(f"Scan failed: {message}")
        QMessageBox.warning(self, "Scan Error", message)

    def _on_connect_requested(self, adapter, device, ip, subnet):
        """Handle connect request — runs in background thread."""
        self._statusbar.showMessage(f"Connecting to {device.mac} at {ip}...")

        def _do_connect():
            success = self._controller.connect(adapter, device, ip, subnet)
            self._connect_finished.emit(success)

        threading.Thread(target=_do_connect, daemon=True).start()

    def _on_connect_done(self, success):
        """Called on GUI thread when connect completes."""
        if success:
            self._panel_manager.start()
        else:
            self._network_widget.set_connected(False)

    def _on_disconnect_requested(self):
        """Handle disconnect request."""
        self._panel_manager.stop()
        self._controller.disconnect()

    def _on_connected(self):
        """Handle successful connection."""
        self._network_widget.set_connected(True)
        self._contactor_btn.setEnabled(True)
        for pw in self._panel_widgets:
            pw.set_controls_enabled(True)
        self._statusbar.showMessage("Connected — ready for operation")

    def _on_disconnected(self):
        """Handle disconnection."""
        self._network_widget.set_connected(False)
        self._contactor_btn.setEnabled(False)
        self._contactor_btn.setChecked(False)
        for pw in self._panel_widgets:
            pw.set_controls_enabled(False)
        self._statusbar.showMessage("Disconnected")

    def _on_error(self, message):
        """Handle error from controller. Shows one dialog at a time."""
        self._statusbar.showMessage(f"Error: {message}")
        log.error("Controller error: %s", message)
        # Guard against stacking multiple dialogs
        if getattr(self, '_error_dialog_open', False):
            return
        self._error_dialog_open = True
        box = QMessageBox(QMessageBox.Icon.Warning, "Error", message, parent=self)
        box.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        box.exec()
        self._error_dialog_open = False

    def _on_contactor_toggled(self, checked):
        """Handle contactor toggle."""
        self._panel_manager.contactor_on = checked
        if checked:
            self._contactor_btn.setText("Contactor: ON")
        else:
            self._contactor_btn.setText("Contactor: OFF")

    def _on_setpoint_changed(self, panel_index, value):
        self._panel_manager.set_setpoint(panel_index, value)

    def _on_enabled_changed(self, panel_index, enabled):
        self._panel_manager.set_enabled(panel_index, enabled)

    def _on_emergency_stop(self):
        """Handle emergency stop button."""
        self._panel_manager.emergency_stop()
        self._contactor_btn.setChecked(False)
        for pw in self._panel_widgets:
            pw.set_heating_enabled(False)
        self._statusbar.showMessage("EMERGENCY STOP — all outputs OFF")

    def _on_state_updated(self):
        """Signal from panel manager that state changed (used for async updates)."""
        pass  # GUI refresh is handled by timer

    def _refresh_gui(self):
        """Timer-driven GUI refresh at 10 Hz."""
        if not self._controller.is_connected:
            return

        for i, pw in enumerate(self._panel_widgets):
            panel = self._panel_manager.get_panel(i)
            pw.update_state(
                temperature=panel.temperature,
                pid_output=panel.pid_output,
                heater_on=panel.heater_on,
                fault=panel.fault,
                fault_message=panel.fault_message,
            )

    def closeEvent(self, event: QCloseEvent):
        """Ensure safe shutdown on window close."""
        if self._controller.is_connected:
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "System is connected. Disconnect and exit?\n\n"
                "All outputs will be turned OFF.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return

            self._panel_manager.stop()
            self._controller.disconnect()

        event.accept()
