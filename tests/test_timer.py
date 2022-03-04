import logging
from unittest import mock

import pytest

from rain_api_core.timer import Interval, Timer


@pytest.fixture
def caplog(caplog):
    caplog.handler.setFormatter(logging.Formatter())
    return caplog


def test_timer(caplog):
    log = logging.getLogger("test_logger")
    time = mock.Mock(side_effect=(0, 1, 3, 6, 10))

    timer = Timer(time)
    timer.mark("foo")
    timer.mark("bar")
    timer.mark()
    timer.mark("baz")
    timer.mark()

    with caplog.at_level(logging.DEBUG, log.name):
        timer.log_all(log)

    assert caplog.text == (
        "ET for foo: 1.0000s\n"
        "ET for bar: 2.0000s\n"
        "ET for baz: 4.0000s\n"
        "ET for total: 10.0000s\n"
    )

    assert timer.total.duration() == 10


def test_log_all_incomplete(caplog):
    log = logging.getLogger("test_logger")

    with caplog.at_level(logging.DEBUG, log.name):
        Timer().log_all(log)
    assert caplog.text == ""

    caplog.clear()

    timer = Timer()
    timer.mark()

    with caplog.at_level(logging.DEBUG, log.name):
        Timer().log_all(log)
    assert caplog.text == ""


def test_interval_duration():
    interval = Interval(start=0, end=10)

    assert interval.duration() == 10


def test_interval_error():
    with pytest.raises(ValueError):
        Interval().duration()

    with pytest.raises(ValueError):
        Interval(start=0).duration()

    with pytest.raises(ValueError):
        Interval(end=10).duration()
