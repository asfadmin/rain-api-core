import base64
import io
import json
import logging
import re
from unittest import mock

import jwt
import pytest
from hypothesis import given
from hypothesis import strategies as st

from rain_api_core.logging import JSONFormatter, PercentPlaceholder, TaggingFilter, filter_log_credentials, get_log

MODULE = "rain_api_core.logging"


def is_subseq(x, y):
    it = iter(y)
    return all(c in it for c in x)


@pytest.fixture
def log_io():
    return io.StringIO()


@pytest.fixture
def logger(custom_log_filter, custom_log_handler, caplog, request):
    # We want to keep this isolated from the root logger because `rain_api_core` messes with the
    # root logger config
    log = logging.getLogger(f"test_logger.{request.function}")
    log.propagate = False
    log.setLevel(logging.DEBUG)

    log.addHandler(custom_log_handler)

    caplog.handler.addFilter(custom_log_filter)
    log.addHandler(caplog.handler)
    yield log
    caplog.handler.removeFilter(custom_log_filter)


@pytest.fixture
def custom_log_filter():
    log_filter = TaggingFilter()
    log_filter.update(
        request_id="the_request_id",
        origin_request_id="the_origin_request_id",
        user_id="the_user_id",
    )
    return log_filter


@pytest.fixture
def custom_log_formatter():
    return JSONFormatter()


@pytest.fixture
def custom_log_handler(custom_log_formatter, custom_log_filter, log_io):
    handler = logging.StreamHandler(log_io)
    handler.setFormatter(custom_log_formatter)
    handler.addFilter(custom_log_filter)
    return handler


def test_get_log(capsys, monkeypatch):
    # Reset the root logger
    monkeypatch.setattr(logging, "root", logging.RootLogger(logging.WARNING))
    log = get_log()
    log.info("test message: %s, Creds: %s", 100, "Basic ABCD")

    # NOTE: Adding any logging or print statements into custom logging internals may cause this test to fail
    stdout, _ = capsys.readouterr()
    msg = json.loads(stdout.strip())
    # To avoid having to update the test everytime the file changes...
    del msg["lineno"]
    del msg["filename"]

    assert msg == {
        "level": "INFO",
        "RequestId": None,
        "OriginRequestId": None,
        "message": "test message: 100, Creds: Basic XXX<BASICAUTH>XXX",
        "maturity": "DEV",
        "user_id": None,
        "route": None,
        "build": "NOBUILD",
        "exception": None
    }


def test_get_log_json_object(monkeypatch, capsys):
    # Reset the root logger
    monkeypatch.setattr(logging, "root", logging.RootLogger(logging.WARNING))
    log = get_log()
    log.info({"Some": "json", "object": 100})

    # NOTE: Adding any logging or print statements into custom logging internals may cause this test to fail
    stdout, _ = capsys.readouterr()
    msg = json.loads(stdout.strip())
    # To avoid having to update the test everytime the file changes...
    del msg["lineno"]
    del msg["filename"]

    assert msg == {
        "level": "INFO",
        "RequestId": None,
        "OriginRequestId": None,
        "message": {
            "Some": "json",
            "object": 100
        },
        "maturity": "DEV",
        "user_id": None,
        "route": None,
        "build": "NOBUILD",
        "exception": None
    }


def test_get_log_json_object_exception(monkeypatch, capsys):
    # Reset the root logger
    monkeypatch.setattr(logging, "root", logging.RootLogger(logging.WARNING))
    log = get_log()
    try:
        raise Exception("Test Exception")
    except Exception:
        log.info({"Some": "json", "object": 100}, exc_info=True)

    # NOTE: Adding any logging or print statements into custom logging internals may cause this test to fail
    stdout, _ = capsys.readouterr()
    msg = json.loads(stdout.strip())
    # To avoid having to update the test everytime the file changes...
    del msg["lineno"]
    del msg["filename"]

    assert msg == {
        "level": "INFO",
        "RequestId": None,
        "OriginRequestId": None,
        "message": {
            "Some": "json",
            "object": 100
        },
        "maturity": "DEV",
        "user_id": None,
        "route": None,
        "build": "NOBUILD",
        "exception": [
            "Traceback (most recent call last):",
            mock.ANY,
            '    raise Exception("Test Exception")',
            "Exception: Test Exception"
        ]
    }


def test_get_log_flat(capsys, monkeypatch):
    # Reset the root logger
    monkeypatch.setattr(logging, "root", logging.RootLogger(logging.WARNING))
    monkeypatch.setenv("LOGTYPE", "flat")

    log = get_log()
    log.info("test message: %s, Creds: %s", 100, "Basic ABCD")

    # NOTE: Adding any logging or print statements into custom logging internals may cause this test to fail
    stdout, _ = capsys.readouterr()
    assert re.match(
        r"INFO: test message: 100, Creds: Basic XXX<BASICAUTH>XXX \([a-z_]+.py line [0-9]+/NOBUILD/DEV\) - "
        "RequestId: None; OriginRequestId: None; user_id: None; route: None\n",
        stdout
    )


def test_percent_placeholder():
    placeholder = PercentPlaceholder("foo")
    assert placeholder % {"foo": "bar"} == "bar"
    assert placeholder % ("bar",) is None


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


def test_json_logging_quotes(logger, log_io):
    obj = {
        "foo': 'baz', 'qux": "bar"
    }
    logger.info(obj)

    msg = log_io.getvalue()
    assert msg == '{"message": {"foo\': \'baz\', \'qux": "bar"}}\n'
    assert json.loads(msg) == {"message": obj}


def test_json_logging_quotes_malformed(logger, log_io):
    obj = {
        "foo'": "bar"
    }
    logger.info(obj)

    msg = log_io.getvalue()
    assert msg == '{"message": {"foo\'": "bar"}}\n'
    assert json.loads(msg) == {"message": obj}


def test_json_logging_not_serializable(logger, log_io):
    class SomeClass():
        def __repr__(self) -> str:
            return "SomeClass()"

    logger.info(SomeClass())

    msg = log_io.getvalue()
    assert msg == '{"message": "SomeClass()"}\n'
    assert json.loads(msg) == {"message": "SomeClass()"}


def test_json_logging_missing_key(logger, custom_log_handler, log_io):
    custom_log_handler.setFormatter(JSONFormatter("%(does_not_exist)s"))
    logger.info("hello")

    assert log_io.getvalue() == ""


def test_json_logging_time_as_field(logger, custom_log_handler, log_io):
    custom_log_handler.setFormatter(JSONFormatter("%(asctime)s", datefmt="the_date"))
    logger.info("hello")

    assert log_io.getvalue() == '"the_date"\n'


def test_json_logging_time_in_field(logger, custom_log_handler, log_io):
    custom_log_handler.setFormatter(JSONFormatter("the time is %(asctime)s", datefmt="the_date"))
    logger.info("hello")

    assert log_io.getvalue() == '"the time is the_date"\n'


def test_json_logging_deep_format(logger, custom_log_handler, log_io):
    custom_log_handler.setFormatter(JSONFormatter({
        "key1": {
            "route": "%(route)s",
            "key2": [
                {"message": "%(message)s"},
                {"message": "%(message)s", "maturity": "%(maturity)s"},
                {
                    "key3": ["%(build_vers)s"]
                }
            ]
        },
        "constant": 100,
        "string_constant": "FOO",
        "format_string": "%(request_id)s from %(origin_request_id)s"
    }))
    obj = {"foo": "bar"}
    logger.info(obj)

    msg = log_io.getvalue()
    assert json.loads(msg) == {
        "key1": {
            "route": None,
            "key2": [
                {"message": obj},
                {"message": obj, "maturity": "DEV"},
                {
                    "key3": ["NOBUILD"]
                }
            ]
        },
        "constant": 100,
        "string_constant": "FOO",
        "format_string": "the_request_id from the_origin_request_id"
    }
