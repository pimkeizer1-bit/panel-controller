"""CSV data logger for PID tuning analysis.

Logs temperature, setpoint, PID output, P/I/D terms, and heater state
for all 4 panels at each control loop tick. Output goes to a timestamped
CSV file in the 'logs' directory.
"""

import csv
import logging
import os
import time
from datetime import datetime

log = logging.getLogger(__name__)


class DataLogger:
    """Writes panel data to CSV for offline PID tuning analysis."""

    def __init__(self, log_dir: str = "logs"):
        self._log_dir = log_dir
        self._file = None
        self._writer = None
        self._start_time = None

    def start(self):
        os.makedirs(self._log_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self._log_dir, f"pid_log_{timestamp}.csv")

        self._file = open(path, "w", newline="")
        self._writer = csv.writer(self._file)
        self._start_time = time.monotonic()

        # Header row
        header = ["time_s"]
        for i in range(1, 5):
            header += [
                f"p{i}_temp", f"p{i}_setpoint", f"p{i}_error",
                f"p{i}_pid_out", f"p{i}_p", f"p{i}_i", f"p{i}_d",
                f"p{i}_heater",
            ]
        self._writer.writerow(header)
        log.info("Data logging started: %s", path)

    def log_tick(self, panels):
        if self._writer is None:
            return

        t = time.monotonic() - self._start_time
        row = [f"{t:.3f}"]

        for panel in panels:
            error = panel.setpoint - panel.temperature
            row += [
                f"{panel.temperature:.2f}",
                f"{panel.setpoint:.1f}",
                f"{error:.2f}",
                f"{panel.pid_output:.2f}",
                f"{panel.pid.last_p:.2f}",
                f"{panel.pid.last_i:.2f}",
                f"{panel.pid.last_d:.2f}",
                "1" if panel.heater_on else "0",
            ]

        self._writer.writerow(row)

    def stop(self):
        if self._file:
            self._file.close()
            self._file = None
            self._writer = None
            log.info("Data logging stopped")
