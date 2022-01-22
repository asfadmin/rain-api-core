import base64
import json
import logging
import re
from collections import defaultdict
from unittest import mock

import _pytest
import jwt
import pytest
from hypothesis import given
from hypothesis import strategies as st

from rain_api_core.general_util import (
    CustomLogFilter,
    duration,
    filter_log_credentials,
    get_log,
    reformat_for_json,
    return_timing_object
)

MODULE = "rain_api_core.general_util"


def is_subseq(x, y):
    it = iter(y)
    return all(c in it for c in x)


@pytest.fixture
def logger(custom_log_filter, caplog, request):
    # We want to keep this isolated from the root logger because `rain_api_core` messes with the
    # root logger config
    log = logging.getLogger(f"test_logger.{request.function}")
    log.propagate = False
    log.setLevel(logging.DEBUG)

    caplog.handler.addFilter(custom_log_filter)
    log.addHandler(caplog.handler)
    return log


@pytest.fixture
def custom_log_filter():
    return CustomLogFilter()


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


def test_filter_log_credentials():
    JWT_TOKEN = (
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
        "e30."
        "yhO34_o49hGy3yoSYmg_nLrR-WHRD7y5QucjyS5Jya2hw49FhXhe-YCktYmnTC1iJH87ICkBBK2MuexWU3mqgA"
    )
    EDL_TOKEN = "EDL-ABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCC"
    BASIC_AUTH_TOKEN = "Basic AAAAABBBBB"
    AWS_TOKEN = ":AAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCC:"
    assert filter_log_credentials(JWT_TOKEN) == "eyJ0eXAiOiJKV1QXXX<JWTTOKEN>XXXuexWU3mqgA"
    assert filter_log_credentials(EDL_TOKEN) == "EDL-AXXX<EDLTOKEN>XXXCCCCCCCCCC"
    assert filter_log_credentials(BASIC_AUTH_TOKEN) == "Basic XXX<BASICAUTH>XXX"
    assert filter_log_credentials(AWS_TOKEN) == ":AAAAAXXX<AWSSECRET>XXXCCCCC:"
    assert filter_log_credentials("foo") == "foo"
    assert filter_log_credentials("") == ""


@mock.patch(f"{MODULE}.UNCENSORED_LOGGING", "1")
def test_filter_log_credentials_uncensored():
    BASIC_AUTH_TOKEN = "Basic AAAAABBBBB"
    assert filter_log_credentials(BASIC_AUTH_TOKEN) == BASIC_AUTH_TOKEN


@given(payload=st.dictionaries(st.text(), st.text()))
def test_filter_log_credentials_jwt(payload, jwt_priv_key):
    cred = jwt.encode(payload, jwt_priv_key, algorithm="RS256")

    filtered = filter_log_credentials(cred)
    assert not is_subseq(cred, filtered)


@given(user=st.text(), passwd=st.text())
def test_filter_log_credentials_basic_auth(user, passwd):
    cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
    header = f"Basic {cred}"

    filtered = filter_log_credentials(header)
    assert not is_subseq(header, filtered.replace("XXX<BASICAUTH>XXX", ""))


@given(data=st.binary(min_size=1))
def test_filter_log_credentials_basic_auth_malformed(data):
    # Theoretically we shouldn't see this data, but better to be able to handle it anyways
    cred = base64.b64encode(data).decode()
    header = f"Basic {cred}"

    filtered = filter_log_credentials(header)
    assert not is_subseq(header, filtered.replace("XXX<BASICAUTH>XXX", ""))


def test_reformat_for_json_dict():
    assert reformat_for_json({"foo": "bar"}) == '{"foo": "bar"}'
    assert reformat_for_json(defaultdict(foo="bar")) == '{"foo": "bar"}'

    class CustomDict(dict):
        pass

    assert reformat_for_json(CustomDict(foo="bar")) == '{"foo": "bar"}'


def test_reformat_for_json_str():
    data = "foobar"
    data2 = "{ asdf"
    # Check for exact object equality to ensure the data was not copied
    assert reformat_for_json(data) is data
    assert reformat_for_json(data2) is data2
    assert reformat_for_json('{  "foo":  \n "bar"  }') == '{"foo": "bar"}'


def test_get_log(capsys, monkeypatch):
    # Reset the root logger
    monkeypatch.setattr(logging, "root", logging.RootLogger(logging.WARNING))
    log = get_log()
    log.info("test message: %s", 100)

    # NOTE: Adding any logging or print statements into custom logging internals may cause this test to fail
    stdout, _ = capsys.readouterr()
    msg = json.loads(stdout.strip())
    # To avoid having to update the test everytime the file changes...
    del msg["lineno"]
    del msg["filename"]

    assert msg == {
        "level": "INFO",
        "RequestId": "None",
        "OriginRequestId": "None",
        "message": "test message: 100",
        "maturity": "DEV",
        "user_id": "None",
        "route": "None",
        "build": "NOBUILD"
    }


def test_get_log_flat(capsys, monkeypatch):
    # Reset the root logger
    monkeypatch.setattr(logging, "root", logging.RootLogger(logging.WARNING))
    monkeypatch.setenv("LOGTYPE", "flat")

    log = get_log()
    log.info("test message: %s", 100)

    # NOTE: Adding any logging or print statements into custom logging internals may cause this test to fail
    stdout, _ = capsys.readouterr()
    assert re.match(
        r"INFO: test message: 100 \([a-z_]+.py line [0-9]+/NOBUILD/DEV\) - "
        "RequestId: None; OriginRequestId: None; user_id: None; route: None\n",
        stdout
    )


def test_log_filter_update(logger, custom_log_filter, caplog):
    custom_log_filter.update(maturity="PROD", request_id="new_request_id")

    logger.info("test")

    record = caplog.records[0]
    assert record.maturity == "PROD"
    assert record.request_id == "new_request_id"
    assert record.getMessage() == "test"


def test_json_logging_exception(logger, caplog):
    logger.info(Exception("test_exception"))

    assert caplog.records[0].getMessage() == "test_exception"


def test_json_logging_quotes(logger, caplog):
    obj = {
        "foo': 'baz', 'qux": "bar"
    }
    logger.info(obj)

    msg = caplog.records[0].getMessage()
    assert msg == '{"foo\': \'baz\', \'qux": "bar"}'
    assert json.loads(msg) == obj


def test_json_logging_quotes_malformed(logger, caplog):
    obj = {
        "foo'": "bar"
    }
    logger.info(obj)

    msg = caplog.records[0].getMessage()
    assert msg == '{"foo\'": "bar"}'
    assert json.loads(msg) == obj
