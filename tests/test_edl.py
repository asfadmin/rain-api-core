import io
import json
import urllib.error
from unittest import mock

import pytest

from rain_api_core.edl import EdlClient, EdlException, EulaException

MODULE = "rain_api_core.edl"


@pytest.fixture
def edl_client():
    return EdlClient()


@mock.patch(f"{MODULE}.urllib.request.urlopen", autospec=True)
def test_client_request(mock_urlopen, edl_client):
    mock_urlopen(mock.ANY).__enter__().read.return_value = b'{"foo": "bar"}'

    response = edl_client.request(
        "POST",
        "/foo/bar",
        params={
            "param_1": "value_1",
            "param_2": "value_2",
        },
        data={
            "data_1": "value_1",
            "data_2": "value_2",
        },
        headers={"header_1": "value_1"},
    )

    request_obj = mock_urlopen.mock_calls[2].args[0]

    assert response == {"foo": "bar"}
    assert request_obj.method == "POST"
    assert request_obj.full_url == (
        "https://urs.earthdata.nasa.gov/foo/bar?param_1=value_1&param_2=value_2"
    )
    assert request_obj.data == b"data_1=value_1&data_2=value_2"
    assert request_obj.headers == {"Header_1": "value_1"}


@mock.patch(f"{MODULE}.urllib.request.urlopen", autospec=True)
def test_client_request_urlerror(mock_urlopen, edl_client):
    test_error = urllib.error.URLError("test error")
    mock_urlopen.side_effect = test_error

    with pytest.raises(EdlException) as ex_info:
        edl_client.request("GET", "/foo/bar")

    assert ex_info.value.inner is test_error
    assert ex_info.value.msg == {}
    assert ex_info.value.payload is None


@mock.patch(f"{MODULE}.urllib.request.urlopen", autospec=True)
def test_client_request_httperror(mock_urlopen, edl_client):
    test_error = urllib.error.HTTPError(
        url="/foo/bar",
        code=500,
        msg="Internal Server Error",
        hdrs={},
        fp=io.BytesIO(b'{"foo": "bar"}'),
    )
    mock_urlopen.side_effect = test_error

    with pytest.raises(EdlException) as ex_info:
        edl_client.request("GET", "/foo/bar")

    assert ex_info.value.inner is test_error
    assert ex_info.value.msg == {"foo": "bar"}
    assert ex_info.value.payload == b'{"foo": "bar"}'


@mock.patch(f"{MODULE}.urllib.request.urlopen", autospec=True)
def test_client_request_httperror_eula(mock_urlopen, edl_client):
    error_response = {
        "error": "invalid_token",
        "status_code": 401,
        "error_description": "EULA Acceptance Failure",
        "resolution_url": "https://uat.urs.earthdata.nasa.gov/approve_app",
    }
    error_response_encoded = json.dumps(error_response).encode()
    test_error = urllib.error.HTTPError(
        url="/foo/bar",
        code=401,
        msg="Unauthorized",
        hdrs={},
        fp=io.BytesIO(error_response_encoded),
    )
    mock_urlopen.side_effect = test_error

    with pytest.raises(EulaException) as ex_info:
        edl_client.request("GET", "/foo/bar")

    assert ex_info.value.inner is test_error
    assert ex_info.value.msg == {
        "error": "invalid_token",
        "status_code": 401,
        "error_description": "EULA Acceptance Failure",
        "resolution_url": "https://uat.urs.earthdata.nasa.gov/approve_app",
    }
    assert ex_info.value.payload == error_response_encoded
