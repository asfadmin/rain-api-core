import string
from base64 import urlsafe_b64decode
from http.cookies import CookieError, SimpleCookie
from unittest import mock

import boto3
import jwt
import moto
import pytest
from hypothesis import assume, given, note
from hypothesis import strategies as st

from rain_api_core.view_util import (
    TemplateManager,
    decode_jwt_payload,
    get_cookie_expiration_date_str,
    get_cookie_vars,
    get_cookies,
    get_exp_time,
    get_jwt_keys,
    is_jwt_blacklisted,
    make_jwt_payload,
    make_set_cookie_headers_jwt,
    set_jwt_blacklist,
)

MODULE = "rain_api_core.view_util"


@pytest.fixture
def local_cachedir(tmp_path, mocker):
    cachedir = tmp_path / "cache"
    mocker.patch(f"{MODULE}.HTML_TEMPLATE_LOCAL_CACHEDIR", str(cachedir))
    return cachedir


@pytest.fixture
def template_dir(data, mocker):
    path = data / "templates"
    mocker.patch(f"{MODULE}.HTML_TEMPLATE_LOCAL_CACHEDIR", path)
    mocker.patch(f"{MODULE}.HTML_TEMPLATE_STATUS", "ERROR")
    return path


cookie_key_characters = st.sampled_from(string.ascii_letters + string.digits + "!#%&'*+-.^_`|~")
cookie_value_characters = st.sampled_from(string.ascii_letters + string.digits + "!#$%&'()*+-./:<=>?@[]^_`{|}~")


@mock.patch(f"{MODULE}.retrieve_secret", autospec=True)
def test_get_jwt_keys(mock_retrieve_secret):
    mock_retrieve_secret.return_value = {
        "foo": "YmFy",
        "baz": "cXV4"
    }
    get_jwt_keys.cache_clear()

    assert get_jwt_keys() == {
        "foo": b"bar",
        "baz": b"qux"
    }


@mock.patch(f"{MODULE}.retrieve_secret", autospec=True)
def test_get_jwt_keys_error(mock_retrieve_secret):
    mock_retrieve_secret.return_value = {
        "foo": "bar"
    }
    get_jwt_keys.cache_clear()

    with pytest.raises(ValueError):
        _ = get_jwt_keys()


@moto.mock_s3
def test_download_templates(local_cachedir):
    bucket = "test_bucket"
    template_dir = "templates/"
    filenames = ["template1.html", "template2.html"]
    contents = b"<html></html>"
    client = boto3.client("s3")
    client.create_bucket(Bucket=bucket)
    for filename in filenames:
        client.put_object(Bucket=bucket, Key=f"{template_dir}{filename}", Body=contents)

    manager = TemplateManager(bucket, template_dir, cache_dir=str(local_cachedir))
    manager.download_templates()

    for filename in filenames:
        with open(local_cachedir / filename, "rb") as f:
            assert f.read() == contents


@moto.mock_s3
def test_download_templates_none_available(local_cachedir):
    bucket = "test_bucket"
    client = boto3.client("s3")
    client.create_bucket(Bucket=bucket)

    manager = TemplateManager(bucket, "templates", cache_dir=str(local_cachedir))
    manager.download_templates()

    assert list(local_cachedir.iterdir()) == []


@moto.mock_s3
def test_download_templates_missing_bucket(local_cachedir):
    manager = TemplateManager("does_not_exist", "templates", cache_dir=local_cachedir)
    manager.download_templates()

    assert list(local_cachedir.iterdir()) == []


@moto.mock_s3
def test_download_templates_missing_template_dir(local_cachedir):
    manager = TemplateManager("does_not_exist", "", cache_dir=local_cachedir)
    manager.download_templates()

    assert list(local_cachedir.iterdir()) == []


def test_render(template_dir):
    manager = TemplateManager("", "", cache_dir=template_dir)

    rendered = manager.render("test.html", {"body": "Hello World!"})
    assert "Hello World!" in rendered


def test_render_missing_template(template_dir):
    manager = TemplateManager("", "", cache_dir=template_dir)

    rendered = manager.render("does_not_exist.html", {"body": "Hello World!"})
    assert rendered == "Cannot find the HTML template directory"


@moto.mock_s3
def test_render_wait_for_templates(local_cachedir):
    bucket = "test_bucket"
    template_dir = "templates/"
    filenames = ["template1.html", "template2.html"]
    contents = b"<html>{{ body }}</html>"
    client = boto3.client("s3")
    client.create_bucket(Bucket=bucket)
    for filename in filenames:
        client.put_object(Bucket=bucket, Key=f"{template_dir}{filename}", Body=contents)

    manager = TemplateManager(bucket, template_dir, cache_dir=local_cachedir)

    rendered = manager.render("template1.html", {"body": "Hello World!"})
    assert "Hello World!" in rendered


@mock.patch(f"{MODULE}.get_cookies", autospec=True)
@mock.patch(f"{MODULE}.decode_jwt_payload", autospec=True)
def test_get_cookie_vars(mock_decode_jwt_payload, mock_get_cookies):
    mock_get_cookies.return_value = {"asf-urs": "JWT_ENCODED_PAYLOAD"}
    mock_decode_jwt_payload.return_value = {"decoded": "payload"}

    headers = {"some": "headers"}
    assert get_cookie_vars(headers) == {"asf-urs": {"decoded": "payload"}}

    mock_get_cookies.assert_called_once_with(headers)
    mock_decode_jwt_payload.assert_called_once_with("JWT_ENCODED_PAYLOAD", "RS256")


@mock.patch(f"{MODULE}.get_cookies", autospec=True)
@mock.patch(f"{MODULE}.decode_jwt_payload", autospec=True)
def test_get_cookie_vars_error(mock_decode_jwt_payload, mock_get_cookies):
    mock_get_cookies.return_value = {}

    headers = {"some": "headers"}
    assert get_cookie_vars(headers) == {}
    mock_decode_jwt_payload.assert_not_called()


@mock.patch(f"{MODULE}.time", autospec=True)
def test_get_exp_time(mock_time):
    mock_time.return_value = 100

    assert get_exp_time() == 100 + (168 * 60 * 60)


@mock.patch(f"{MODULE}.time", autospec=True)
def test_get_cookie_expiration_date_str(mock_time):
    mock_time.return_value = 0
    assert get_cookie_expiration_date_str() == "Thu, 08 Jan 1970 00:00:00 GMT"

    mock_time.return_value = 1
    assert get_cookie_expiration_date_str() == "Thu, 08 Jan 1970 00:00:01 GMT"

    mock_time.return_value = 1_000_000
    assert get_cookie_expiration_date_str() == "Mon, 19 Jan 1970 13:46:40 GMT"

    mock_time.return_value = 1_000_000_000
    assert get_cookie_expiration_date_str() == "Sun, 16 Sep 2001 01:46:40 GMT"


@given(
    name=st.text(cookie_key_characters, min_size=1),
    value=st.text(cookie_value_characters)
)
def test_get_cookies_valid(name, value):
    cookie = SimpleCookie()
    try:
        cookie[name] = value
    except CookieError:
        note(f"Filtered: {name}")
        assume(False)

    cookie_str = cookie.output(header="")
    note(f"Cookie: {cookie_str}")
    assert get_cookies({"Cookie": cookie_str}) == {name: value}


@given(data=st.text())
def test_get_cookies_error(data):
    # Should not raise
    get_cookies({"Cookie": data})


def test_get_cookies_key_precedence():
    assert get_cookies({"cookie": "key=value"}) == {"key": "value"}
    assert get_cookies({"cookie": "key=value", "Cookie": "foo=bar"}) == {"key": "value"}
    assert get_cookies({"cookie": "key=value", "COOKIE": "bax=qux"}) == {"key": "value"}
    assert get_cookies({"Cookie": "key=value", "COOKIE": "bax=qux"}) == {"key": "value"}


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_make_jwt_payload(mock_get_jwt_keys, jwt_priv_key):
    mock_get_jwt_keys.return_value = {"rsa_priv_key": jwt_priv_key}
    encoded = make_jwt_payload({"foo": "bar"})

    header, payload, signature = encoded.split(".")
    assert urlsafe_b64decode(header + "==") == b'{"alg":"RS256","typ":"JWT"}'
    assert urlsafe_b64decode(payload + "==") == b'{"foo":"bar"}'


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_make_jwt_payload_type_error(mock_get_jwt_keys, jwt_priv_key):
    mock_get_jwt_keys.return_value = {"rsa_priv_key": jwt_priv_key}
    with pytest.raises(TypeError):
        make_jwt_payload("not a dict") == ""


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_make_jwt_payload_error(mock_get_jwt_keys):
    mock_get_jwt_keys.side_effect = Exception("test exception")
    with pytest.raises(Exception):
        make_jwt_payload({"foo": "bar"})


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_decode_jwt_payload(mock_get_jwt_keys, jwt_pub_key, jwt_priv_key):
    mock_get_jwt_keys.return_value = {"rsa_pub_key": jwt_pub_key}
    payload = {"foo": "bar"}

    encoded = jwt.encode(payload, jwt_priv_key, algorithm="RS256")
    assert decode_jwt_payload(encoded) == payload


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_decode_jwt_payload_expired_token(mock_get_jwt_keys, jwt_pub_key, jwt_priv_key):
    mock_get_jwt_keys.return_value = {"rsa_pub_key": jwt_pub_key}
    payload = {"exp": 0, "foo": "bar"}

    encoded = jwt.encode(payload, jwt_priv_key, algorithm="RS256")
    assert decode_jwt_payload(encoded) == {}


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_decode_jwt_payload_invalid_signature(mock_get_jwt_keys, jwt_pub_key):
    mock_get_jwt_keys.return_value = {"rsa_pub_key": jwt_pub_key}

    encoded = b".".join((
        jwt.utils.base64url_encode(b'{"alg": "RS256"}'),
        jwt.utils.base64url_encode(b'{"not valid'),
        jwt.utils.base64url_encode(b"some bytes"),
    ))
    assert decode_jwt_payload(encoded) == {}


@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_decode_jwt_payload_invalid_token(mock_get_jwt_keys, jwt_pub_key, jwt_priv_key):
    mock_get_jwt_keys.return_value = {"rsa_pub_key": jwt_pub_key}

    encoded = jwt.api_jws.encode(b'{"not valid', jwt_priv_key, algorithm="RS256")
    # Can only happen if:
    # 1. An app developer mucked about with JWT (as above) and signed invalid token, or
    # 2. The private key was leaked and a malicious entity singned an invalid token, or
    # 3. RSA was broken by quantum computing and a malicious entity signed an invalid token
    with pytest.raises(jwt.DecodeError):
        decode_jwt_payload(encoded)


@mock.patch(f"{MODULE}.is_jwt_blacklisted", autospec=True)
@mock.patch(f"{MODULE}.get_jwt_keys", autospec=True)
def test_decode_jwt_payload_blacklist(
    mock_get_jwt_keys,
    mock_is_jwt_blacklisted,
    jwt_pub_key,
    jwt_priv_key,
    monkeypatch
):
    mock_get_jwt_keys.return_value = {"rsa_pub_key": jwt_pub_key}
    mock_is_jwt_blacklisted.return_value = True
    monkeypatch.setenv("BLACKLIST_ENDPOINT", "true")
    payload = {"foo": "bar"}

    encoded = jwt.encode(payload, jwt_priv_key, algorithm="RS256")
    assert decode_jwt_payload(encoded) == {}

    mock_is_jwt_blacklisted.return_value = False
    assert decode_jwt_payload(encoded) == payload


@mock.patch(f"{MODULE}.make_jwt_payload", autospec=True)
@mock.patch(f"{MODULE}.get_cookie_expiration_date_str", autospec=True)
def test_make_set_cookie_headers_jwt(mock_get_cookie_expiration_date_str, mock_make_jwt_payload):
    mock_get_cookie_expiration_date_str.return_value = "THE_EXPDATE"
    mock_make_jwt_payload.return_value = "THE_JWT_PAYLOAD"

    assert make_set_cookie_headers_jwt("") == {
        "SET-COOKIE": "asf-urs=THE_JWT_PAYLOAD; Expires=THE_EXPDATE; Path=/"
    }
    assert make_set_cookie_headers_jwt("", expdate="EXPLICIT_EXPDATE") == {
        "SET-COOKIE": "asf-urs=THE_JWT_PAYLOAD; Expires=EXPLICIT_EXPDATE; Path=/"
    }
    assert make_set_cookie_headers_jwt("", expdate="EXPLICIT_EXPDATE", cookie_domain="THE_DOMAIN") == {
        "SET-COOKIE": "asf-urs=THE_JWT_PAYLOAD; Expires=EXPLICIT_EXPDATE; Path=/; Domain=THE_DOMAIN"
    }


@mock.patch(f"{MODULE}.set_jwt_blacklist", autospec=True)
@mock.patch(f"{MODULE}.JWT_BLACKLIST", new_callable=dict)
def test_is_jwt_blacklisted(jwt_blacklist, mock_set_jwt_blacklist):
    jwt_blacklist.update({
        "blacklist": {
            "user_id": 1000
        },
        "timestamp": 0
    })

    assert is_jwt_blacklisted({"urs-user-id": "user_id", "iat": 10}) is True
    mock_set_jwt_blacklist.assert_called_once()

    assert is_jwt_blacklisted({"urs-user-id": "user_id", "iat": 2000}) is False
    assert is_jwt_blacklisted({"urs-user-id": "other_user", "iat": 10}) is False


@mock.patch(f"{MODULE}.set_jwt_blacklist", autospec=True)
def test_is_jwt_blacklisted_error(mock_set_jwt_blacklist):
    mock_set_jwt_blacklist.side_effect = Exception("Test exception")

    assert is_jwt_blacklisted({"urs-user-id": "user_id", "iat": 10}) is False


@mock.patch(f"{MODULE}.time", autospec=True)
@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.JWT_BLACKLIST", new_callable=dict)
def test_set_jwt_blacklist(jwt_blacklist, mock_request, mock_time, monkeypatch):
    endpoint = "https://blacklist_endpoint"
    monkeypatch.setenv("BLACKLIST_ENDPOINT", endpoint)
    mock_request.urlopen(endpoint).read.return_value = b'{"blacklist": {"foo": "bar"}}'
    mock_time.return_value = 0

    set_jwt_blacklist()
    # If this is imported before calling `set_jwt_blacklist` it will still be referencing the initial value
    from rain_api_core.view_util import JWT_BLACKLIST

    assert JWT_BLACKLIST == {
        "blacklist": {"foo": "bar"},
        "timestamp": 0
    }
    # The object itself is not touched, only the reference that JWT_BLACKLIST points to is changed
    assert jwt_blacklist == {}


@mock.patch(f"{MODULE}.time", autospec=True)
@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.JWT_BLACKLIST", new_callable=dict)
def test_set_jwt_blacklist_cached(jwt_blacklist, mock_request, mock_time, monkeypatch):
    endpoint = "https://blacklist_endpoint"
    monkeypatch.setenv("BLACKLIST_ENDPOINT", endpoint)
    mock_urlopen = mock_request.urlopen(endpoint)
    mock_urlopen.read.return_value = b'{"blacklist": {"foo": "bar"}}'
    mock_time.return_value = 0

    set_jwt_blacklist()
    # If this is imported before calling `set_jwt_blacklist` it will still be referencing the initial value
    from rain_api_core.view_util import JWT_BLACKLIST

    assert mock_request.urlopen.call_count == 2
    assert JWT_BLACKLIST == {
        "blacklist": {"foo": "bar"},
        "timestamp": 0
    }
    # The object itself is not touched, only the reference that JWT_BLACKLIST points to is changed
    assert jwt_blacklist == {}

    # Second call, cached version is used
    set_jwt_blacklist()
    from rain_api_core.view_util import JWT_BLACKLIST

    assert mock_request.urlopen.call_count == 2
    assert JWT_BLACKLIST == {
        "blacklist": {"foo": "bar"},
        "timestamp": 0
    }

    # Third call, after some time has passed the data is re-fetched
    mock_time.return_value = 1000
    mock_urlopen.read.return_value = b'{"blacklist": {"baz": "qux"}}'
    set_jwt_blacklist()
    from rain_api_core.view_util import JWT_BLACKLIST

    # Call count increased
    assert mock_request.urlopen.call_count == 3
    # Variable updated
    assert JWT_BLACKLIST == {
        "blacklist": {"baz": "qux"},
        "timestamp": 1000
    }
