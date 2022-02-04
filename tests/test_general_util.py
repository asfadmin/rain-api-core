from unittest import mock

from rain_api_core.general_util import duration, return_timing_object

MODULE = "rain_api_core.general_util"


def test_return_timing_object():
    assert return_timing_object() == {
        "timing": {
            "service": "Unknown",
            "endpoint": "Unknown",
            "method": "GET",
            "duration": 0,
            "unit": "milliseconds"
        }
    }
    assert return_timing_object(Service="some_service", OTHER_KEY="OTHER_VALUE") == {
        "timing": {
            "service": "some_service",
            "endpoint": "Unknown",
            "method": "GET",
            "duration": 0,
            "unit": "milliseconds",
            "other_key": "OTHER_VALUE"
        }
    }


@mock.patch(f"{MODULE}.time.time")
def test_duration(mock_time):
    mock_time.return_value = 200.1111111
    assert duration(100) == 100111.11
