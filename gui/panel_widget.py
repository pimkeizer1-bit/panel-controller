"""Individual panel control widget showing temperature, setpoint, and status."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QDoubleSpinBox, QCheckBox, QProgressBar,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette


class PanelWidget(QWidget):
    """Widget for a single heated panel showing temp, setpoint, and heater status."""

    setpoint_changed = pyqtSignal(int, float)  # panel_index, new_setpoint
    enabled_changed = pyqtSignal(int, bool)  # panel_index, enabled

    def __init__(self, panel_index: int, parent=None):
        super().__init__(parent)
        self._index = panel_index
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        group = QGroupBox(f"Panel {self._index + 1}")
        group_layout = QVBoxLayout(group)

        # Temperature display
        self._temp_label = QLabel("-- °C")
        temp_font = QFont()
        temp_font.setPointSize(28)
        temp_font.setBold(True)
        self._temp_label.setFont(temp_font)
        self._temp_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._temp_label.setMinimumHeight(60)
        group_layout.addWidget(self._temp_label)

        # Setpoint row
        sp_row = QHBoxLayout()
        sp_row.addWidget(QLabel("Target:"))
        self._setpoint_spin = QDoubleSpinBox()
        self._setpoint_spin.setRange(0.0, 200.0)
        self._setpoint_spin.setValue(120.0)
        self._setpoint_spin.setSuffix(" °C")
        self._setpoint_spin.setDecimals(1)
        self._setpoint_spin.setSingleStep(5.0)
        self._setpoint_spin.valueChanged.connect(self._on_setpoint_changed)
        sp_row.addWidget(self._setpoint_spin)
        group_layout.addLayout(sp_row)

        # PID output bar
        pid_row = QHBoxLayout()
        pid_row.addWidget(QLabel("PID:"))
        self._pid_bar = QProgressBar()
        self._pid_bar.setRange(0, 100)
        self._pid_bar.setValue(0)
        self._pid_bar.setFormat("%v%")
        self._pid_bar.setMaximumHeight(20)
        pid_row.addWidget(self._pid_bar)
        group_layout.addLayout(pid_row)

        # Heater status indicator
        status_row = QHBoxLayout()
        self._heater_indicator = QLabel("OFF")
        self._heater_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._heater_indicator.setMinimumWidth(60)
        self._heater_indicator.setStyleSheet(
            "background-color: #555; color: white; padding: 4px; border-radius: 3px;")
        status_row.addWidget(QLabel("Heater:"))
        status_row.addWidget(self._heater_indicator)

        self._enable_check = QCheckBox("Enable")
        self._enable_check.toggled.connect(self._on_enabled_changed)
        status_row.addWidget(self._enable_check)
        status_row.addStretch()
        group_layout.addLayout(status_row)

        # Fault display
        self._fault_label = QLabel("")
        self._fault_label.setStyleSheet("color: red; font-weight: bold;")
        self._fault_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        group_layout.addWidget(self._fault_label)

        layout.addWidget(group)

    def _on_setpoint_changed(self, value):
        self.setpoint_changed.emit(self._index, value)

    def _on_enabled_changed(self, checked):
        self.enabled_changed.emit(self._index, checked)

    def update_state(self, temperature: float, pid_output: float,
                     heater_on: bool, fault: bool, fault_message: str):
        """Update all display elements with current panel state."""
        # Temperature display with color coding
        self._temp_label.setText(f"{temperature:.1f} °C")

        if fault:
            color = "#FF0000"
        elif temperature > 140:
            color = "#FF4444"
        elif temperature > 100:
            color = "#FF8800"
        elif temperature > 50:
            color = "#CCCC00"
        else:
            color = "#4488FF"

        self._temp_label.setStyleSheet(f"color: {color};")

        # PID output
        self._pid_bar.setValue(int(pid_output))

        # Heater indicator
        if heater_on:
            self._heater_indicator.setText("ON")
            self._heater_indicator.setStyleSheet(
                "background-color: #FF6600; color: white; padding: 4px; "
                "border-radius: 3px; font-weight: bold;")
        else:
            self._heater_indicator.setText("OFF")
            self._heater_indicator.setStyleSheet(
                "background-color: #555; color: white; padding: 4px; "
                "border-radius: 3px;")

        # Fault
        if fault:
            self._fault_label.setText(fault_message)
        else:
            self._fault_label.setText("")

    def set_controls_enabled(self, enabled: bool):
        """Enable/disable interactive controls."""
        self._setpoint_spin.setEnabled(enabled)
        self._enable_check.setEnabled(enabled)

    def set_heating_enabled(self, enabled: bool):
        """Programmatically set the enable checkbox state."""
        self._enable_check.setChecked(enabled)
