import time

# For backwards compatibility
from rain_api_core.logging import get_log, log_context


def return_timing_object(**timing):
    timing_object = {
        "service": "Unknown",
        "endpoint": "Unknown",
        "method": "GET",
        "duration": 0,
        "unit": "milliseconds"
    }
    timing_object.update({k.lower(): v for k, v in timing.items()})
    return {"timing": timing_object}


def duration(time_in):
    # Return the time duration in milliseconds
    delta = time.time() - time_in
    return round(delta * 1000, ndigits=2)


__all__ = (
    "duration",
    "get_log",
    "log_context",
    "return_timing_object",
)
