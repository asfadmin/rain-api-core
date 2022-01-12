import logging
import sys

import pytest
from rain_api_core.general_util import CustomLogFilter


@pytest.fixture
def logger(custom_log_handler):
    log = logging.getLogger("test_logger")
    log.addHandler(custom_log_handler)
    return log


@pytest.fixture
def custom_log_handler(custom_log_filter):
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(custom_log_filter)
    return handler


@pytest.fixture
def custom_log_filter():
    return CustomLogFilter()


def test_json_logging_exception(caplog, logger):
    with caplog.at_level(logging.INFO):
        logger.info(Exception("test_exception"))

    assert caplog.records[0].msg == "test_exception"
