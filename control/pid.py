import time


class PIDController:
    """PID controller with anti-windup for temperature control."""

    def __init__(self, kp=5.0, ki=0.02, kd=1.0, setpoint=120.0,
                 output_min=0.0, output_max=100.0):
        self.kp = kp
        self.ki = ki
        self.kd = kd
        self.setpoint = setpoint
        self.output_min = output_min
        self.output_max = output_max

        self._integral = 0.0
        self._prev_error = None
        self._last_time = None
        self._prev_measurement = None

        # Last computed terms (for logging/tuning)
        self.last_p = 0.0
        self.last_i = 0.0
        self.last_d = 0.0

    def reset(self):
        self._integral = 0.0
        self._prev_error = None
        self._last_time = None
        self._prev_measurement = None

    def update(self, current_value: float) -> float:
        """Compute PID output (0-100%) based on current temperature."""
        now = time.monotonic()
        if self._last_time is None:
            self._last_time = now
            self._prev_error = self.setpoint - current_value
            self._prev_measurement = current_value
            return 0.0

        dt = now - self._last_time
        if dt <= 0:
            return 0.0
        self._last_time = now

        error = self.setpoint - current_value

        # Proportional
        p_term = self.kp * error

        # Integral with anti-windup: clamp I contribution to 50% of output range
        # This prevents massive windup during the long ramp (43 min at 100%)
        # while still allowing I to eliminate steady-state error
        candidate_integral = self._integral + error * dt
        i_clamp = self.output_max * 0.5
        max_i = i_clamp / self.ki if self.ki > 0 else float('inf')
        min_i = -i_clamp / self.ki if self.ki > 0 else float('-inf')
        self._integral = max(min_i, min(max_i, candidate_integral))
        i_term = self.ki * self._integral

        # Derivative on measurement (not error) to avoid derivative kick
        d_term = -self.kd * (current_value - self._prev_measurement) / dt
        self._prev_measurement = current_value
        self._prev_error = error

        self.last_p = p_term
        self.last_i = i_term
        self.last_d = d_term

        output = p_term + i_term + d_term

        # Clamp output
        output = max(self.output_min, min(self.output_max, output))

        return output


class TimeProportionalOutput:
    """Converts continuous PID output (0-100%) to on/off duty cycle.

    For SSR control: SSR is on for (duty% * window) seconds,
    then off for the remainder of the window.
    """

    def __init__(self, window_seconds=2.0):
        self.window_seconds = window_seconds
        self._window_start = None
        self._duty_percent = 0.0

    def set_duty(self, percent: float):
        """Set duty cycle (0-100%)."""
        self._duty_percent = max(0.0, min(100.0, percent))

    def should_be_on(self) -> bool:
        """Return True if the SSR should currently be ON."""
        now = time.monotonic()
        if self._window_start is None:
            self._window_start = now

        elapsed = now - self._window_start
        if elapsed >= self.window_seconds:
            self._window_start = now
            elapsed = 0.0

        on_time = self._duty_percent / 100.0 * self.window_seconds
        return elapsed < on_time
