"""Environment for Festival App processes that verification starts."""

TELEMETRY_OFF = {"FESTIVAL_APP_TELEMETRY": "0"}


def without_app_telemetry(environment):
    """Verification runs never send Festival App usage reports."""
    return {**environment, **TELEMETRY_OFF}
