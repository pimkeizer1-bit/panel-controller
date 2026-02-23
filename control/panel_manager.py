"""Panel heating manager.

Runs PID control loops for 4 heated panels, reading thermocouple
temperatures and controlling SSR outputs via time-proportional control.
"""

import logging
import threading
import time

from PyQt6.QtCore import QObject, pyqtSignal

from control.data_logger import DataLogger
from control.pid import PIDController, TimeProportionalOutput
from profinet.controller import ProfinetController

log = logging.getLogger(__name__)

# Safety limits
MAX_TEMPERATURE = 150.0  # °C - emergency shutoff above this
MIN_TEMPERATURE = -10.0  # °C - wire break / fault below this
DEFAULT_SETPOINT = 120.0  # °C


class PanelState:
    """State tracking for a single heated panel."""

    def __init__(self, index: int, setpoint: float = DEFAULT_SETPOINT):
        self.index = index
        self.enabled = False
        self.setpoint = setpoint
        self.temperature = 0.0
        self.pid_output = 0.0
        self.heater_on = False
        self.fault = False
        self.fault_message = ""

        self.pid = PIDController(
            kp=5.0, ki=0.02, kd=1.0,
            setpoint=setpoint,
            output_min=0.0, output_max=100.0,
        )
        self.tpo = TimeProportionalOutput(window_seconds=2.0)


class PanelManager(QObject):
    """Manages 4 heated panels with PID temperature control.

    Signals:
        state_updated: Emitted when panel states change (connect to GUI refresh).
    """

    state_updated = pyqtSignal()

    def __init__(self, controller: ProfinetController, parent=None):
        super().__init__(parent)
        self._controller = controller
        self._contactor_on = False
        self._panels = [PanelState(i) for i in range(4)]
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._logger = DataLogger()

    @property
    def contactor_on(self) -> bool:
        return self._contactor_on

    @contactor_on.setter
    def contactor_on(self, value: bool):
        self._contactor_on = value
        if not value:
            # Contactor off → all heaters off
            for panel in self._panels:
                panel.heater_on = False

    def get_panel(self, index: int) -> PanelState:
        return self._panels[index]

    def set_setpoint(self, panel_index: int, setpoint: float):
        """Set target temperature for a panel."""
        panel = self._panels[panel_index]
        panel.setpoint = setpoint
        panel.pid.setpoint = setpoint

    def set_enabled(self, panel_index: int, enabled: bool):
        """Enable/disable heating for a panel."""
        panel = self._panels[panel_index]
        panel.enabled = enabled
        if not enabled:
            panel.pid.reset()
            panel.heater_on = False
            panel.pid_output = 0.0

    def set_pid_params(self, panel_index: int, kp: float, ki: float, kd: float):
        """Update PID tuning parameters for a panel."""
        panel = self._panels[panel_index]
        panel.pid.kp = kp
        panel.pid.ki = ki
        panel.pid.kd = kd

    def start(self):
        """Start the control loop."""
        if self._running:
            return
        self._running = True
        self._logger.start()
        self._thread = threading.Thread(target=self._control_loop, daemon=True)
        self._thread.start()
        log.info("Panel manager control loop started")

    def stop(self):
        """Stop the control loop and turn off all outputs."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._logger.stop()
        self._controller.emergency_stop()
        log.info("Panel manager stopped")

    def emergency_stop(self):
        """Emergency stop: disable all panels and outputs."""
        log.warning("Panel manager EMERGENCY STOP")
        self._contactor_on = False
        for panel in self._panels:
            panel.enabled = False
            panel.heater_on = False
            panel.pid_output = 0.0
            panel.pid.reset()
        self._controller.emergency_stop()
        self.state_updated.emit()

    def _control_loop(self):
        """Main control loop running at ~10 Hz.

        Reads temperatures, runs PID, computes time-proportional output,
        writes DQ outputs.
        """
        while self._running:
            try:
                if not self._controller.is_connected:
                    time.sleep(0.1)
                    continue

                # Read temperatures from PROFINET
                temps = self._controller.read_temperatures()

                ssrs = [False, False, False, False]

                for i, panel in enumerate(self._panels):
                    panel.temperature = temps[i]
                    was_fault = panel.fault

                    # Safety checks
                    if panel.temperature > MAX_TEMPERATURE:
                        panel.fault = True
                        panel.fault_message = f"Over-temp: {panel.temperature:.1f}°C"
                        panel.enabled = False
                        panel.heater_on = False
                        panel.pid.reset()
                        if not was_fault:
                            log.warning("Panel %d over-temperature: %.1f°C", i + 1, panel.temperature)
                        continue

                    if panel.temperature < MIN_TEMPERATURE:
                        panel.fault = True
                        panel.fault_message = "Wire break / sensor fault"
                        panel.heater_on = False
                        panel.pid.reset()
                        if not was_fault:
                            log.warning("Panel %d sensor fault: %.1f°C", i + 1, panel.temperature)
                        continue

                    panel.fault = False
                    panel.fault_message = ""

                    if not panel.enabled or not self._contactor_on:
                        panel.pid_output = 0.0
                        panel.heater_on = False
                        panel.pid.reset()
                        continue

                    # Run PID
                    panel.pid_output = panel.pid.update(panel.temperature)

                    # Time-proportional output
                    panel.tpo.set_duty(panel.pid_output)
                    panel.heater_on = panel.tpo.should_be_on()
                    ssrs[i] = panel.heater_on

                # Write outputs
                self._controller.write_outputs(
                    contactor=self._contactor_on,
                    ssrs=ssrs,
                )

                self._logger.log_tick(self._panels)
                self.state_updated.emit()

            except Exception as e:
                log.error("Control loop error: %s", e)

            time.sleep(0.1)  # 10 Hz
