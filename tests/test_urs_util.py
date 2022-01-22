import urllib
from unittest import mock

import pytest

from rain_api_core.urs_util import (
    do_auth,
    do_login,
    get_base_url,
    get_new_token_and_profile,
    get_profile,
    get_redirect_url,
    get_urs_creds,
    get_urs_url,
    user_in_group,
    user_in_group_list,
    user_in_group_urs,
    user_profile_2_jwt_payload
)

MODULE = "rain_api_core.urs_util"


@pytest.fixture
def context():
    return {
        "apiId": "test_apiId",
        "identity": {
            "userAgent": "Mozilla ..."
        },
        "domainName": "example.com",
        "stage": "DEV"
    }


def test_get_base_url(monkeypatch):
    monkeypatch.setenv("DOMAIN_NAME", "example.com")
    assert get_base_url() == "https://example.com/"


def test_get_base_url_no_env(context):
    assert get_base_url(context) == "https://example.com/DEV/"


def test_get_base_url_error():
    with pytest.raises(TypeError):
        get_base_url()


def test_get_redirect_url(context):
    assert get_redirect_url(context) == "https://example.com/DEV/login"


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_do_auth(mock_get_urs_creds, mock_request):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_response = mock.NonCallableMock()
    mock_response.read.return_value = '{"foo": "bar"}'
    mock_request.urlopen.return_value = mock_response

    assert do_auth("code", "redir_url") == {"foo": "bar"}


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_do_auth_error(mock_get_urs_creds, mock_request):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_request.urlopen.side_effect = urllib.error.URLError("test error")

    assert do_auth("code", "redir_url") == {}


@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_get_urs_url(mock_get_urs_creds, context):
    mock_get_urs_creds.return_value = {"UrsId": "URS_ID"}

    assert get_urs_url(context) == (
        "https://urs.earthdata.nasa.gov/oauth/authorize"
        "?client_id=URS_ID"
        "&response_type=code"
        "&redirect_uri=https://example.com/DEV/login"
    )
    assert get_urs_url(context, to="foo") == (
        "https://urs.earthdata.nasa.gov/oauth/authorize"
        "?client_id=URS_ID"
        "&response_type=code"
        "&redirect_uri=https://example.com/DEV/login"
        "&state=foo"
    )

    del context["identity"]["userAgent"]
    assert get_urs_url(context) == (
        "https://urs.earthdata.nasa.gov/oauth/authorize"
        "?client_id=URS_ID"
        "&response_type=code"
        "&redirect_uri=https://example.com/DEV/login"
    )

    context["identity"]["userAgent"] = ""
    assert get_urs_url(context) == (
        "https://urs.earthdata.nasa.gov/oauth/authorize"
        "?client_id=URS_ID"
        "&response_type=code"
        "&redirect_uri=https://example.com/DEV/login"
        "&app_type=401"
    )


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
def test_get_profile(mock_request):
    mock_response = mock.NonCallableMock()
    mock_response.read.return_value = '{"foo": "bar"}'
    mock_request.urlopen.return_value = mock_response

    assert get_profile("user_id", "token") == {"foo": "bar"}
    assert get_profile("user_id", "token", "temptoken") == {"foo": "bar"}
    assert get_profile(None, "token") == {}
    assert get_profile("user_id", None) == {}


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.get_new_token_and_profile", autospec=True)
def test_get_profile_error(mock_get_new_token_and_profile, mock_request):
    mock_get_new_token_and_profile.return_value = {"foo": "bar"}
    mock_request.urlopen.side_effect = urllib.error.URLError("test error")

    assert get_profile("user_id", "token", "temptoken") == {}
    mock_get_new_token_and_profile.assert_not_called()

    assert get_profile("user_id", "token") == {"foo": "bar"}
    mock_get_new_token_and_profile.assert_called_once_with("user_id", "token", {})


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_get_new_token_and_profile(mock_get_urs_creds, mock_get_profile, mock_request):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_get_profile.return_value = {"foo": "bar"}
    mock_response = mock.NonCallableMock()
    mock_response.read.return_value = '{"access_token": "token"}'
    mock_request.urlopen.return_value = mock_response

    assert get_new_token_and_profile("user_id", "cookietoken") == {"foo": "bar"}
    mock_get_profile.assert_called_once_with("user_id", "cookietoken", "token", aux_headers={})


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_get_new_token_and_profile_error(mock_get_urs_creds, mock_get_profile, mock_request):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_request.urlopen.side_effect = urllib.error.URLError("test error")

    assert get_new_token_and_profile("user_id", "cookietoken") is False
    mock_get_profile.assert_not_called()


@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_user_in_group_list(mock_get_urs_creds):
    mock_get_urs_creds.return_value = {"UrsId": "CLIENT_ID_1"}

    user_groups = [
        {"client_id": "CLIENT_ID_1", "name": "GROUP_1"},
        {"client_id": "CLIENT_ID_2", "name": "GROUP_1"},
        {"client_id": "CLIENT_ID_3", "name": "GROUP_1"},
        {"client_id": "CLIENT_ID_3", "name": "GROUP_2"}
    ]
    mock_get_urs_creds.return_value = {"UrsId": "CLIENT_ID_1"}
    assert user_in_group_list([], user_groups) is False
    assert user_in_group_list(["GROUP_1", "GROUP_2"], user_groups) is True
    assert user_in_group_list(["GROUP_2", "GROUP_1"], user_groups) is True
    mock_get_urs_creds.return_value = {"UrsId": "CLIENT_ID_2"}
    assert user_in_group_list(["GROUP_1", "GROUP_2"], user_groups) is True
    mock_get_urs_creds.return_value = {"UrsId": "CLIENT_ID_3"}
    assert user_in_group_list(["GROUP_1", "GROUP_2"], user_groups) is True
    mock_get_urs_creds.return_value = {"UrsId": "CLIENT_ID_4"}
    assert user_in_group_list(["GROUP_1", "GROUP_2"], user_groups) is False


@mock.patch(f"{MODULE}.user_in_group_list", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
def test_user_in_group_urs(mock_get_profile, mock_user_in_group_list):
    private_groups = []
    user_profile = {"user_groups": []}
    mock_get_profile.return_value = {"user_groups": [], "new_profile": True}

    mock_user_in_group_list.return_value = True
    assert user_in_group_urs(private_groups, "user_id", "token", user_profile) == (True, {})
    mock_user_in_group_list.assert_called_once()

    mock_user_in_group_list.return_value = False
    assert user_in_group_urs(private_groups, "user_id", "token", user_profile) == (
        False,
        {"user_groups": [], "new_profile": True}
    )
    mock_get_profile.assert_called_once()


@mock.patch(f"{MODULE}.user_in_group_list", autospec=True)
def test_user_in_group(mock_user_in_group_list):
    mock_user_in_group_list.return_value = True

    assert user_in_group([], {}) == (False, {})
    mock_user_in_group_list.assert_not_called()
    assert user_in_group(["GROUP_1"], {"asf-urs": {}}) == (False, {})
    mock_user_in_group_list.assert_not_called()
    assert user_in_group(["GROUP_1"], {"asf-urs": {"urs-groups": []}}) == (True, {})
    mock_user_in_group_list.assert_called_once()


@mock.patch(f"{MODULE}.user_in_group_list", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
def test_user_in_group_refresh(mock_get_profile, mock_user_in_group_list):
    mock_user_in_group_list.return_value = True
    mock_get_profile.return_value = {"user_groups": []}
    cookievars = {
        "asf-urs": {
            "urs-user-id": "user_id",
            "urs-access-token": "access_token",
            "urs-groups": []
        }
    }

    assert user_in_group(["GROUP_1"], cookievars, refresh_first=True) == (True, {"user_groups": []})
    mock_user_in_group_list.assert_called_once()

    mock_user_in_group_list.return_value = False
    assert user_in_group(["GROUP_1"], cookievars, refresh_first=False) == (False, {"user_groups": []})


@mock.patch(f"{MODULE}.retrieve_secret", autospec=True)
def test_get_urs_creds(mock_retrieve_secret, monkeypatch):
    assert get_urs_creds() == {}

    monkeypatch.setenv("URS_CREDS_SECRET_NAME", "secret_name")
    mock_retrieve_secret.return_value = {}
    assert get_urs_creds() == {}
    mock_retrieve_secret.assert_called_once_with("secret_name")

    secret = {
        "UrsId": "URS_ID",
        "UrsAuth": "URS_AUTH"
    }
    mock_retrieve_secret.return_value = secret
    assert get_urs_creds() == secret


@mock.patch(f"{MODULE}.time", autospec=True)
@mock.patch(f"{MODULE}.get_exp_time", autospec=True)
def test_user_profile_2_jwt_payload(mock_get_exp_time, mock_time):
    mock_time.return_value = 0
    mock_get_exp_time.return_value = 1000

    user_profile = {
        "first_name": "First",
        "last_name": "Last",
        "email_address": "email@domain.com",
        "user_groups": []
    }

    assert user_profile_2_jwt_payload("user_id", "access_token", user_profile) == {
        # Do we want more items in here?
        "first_name": "First",
        "last_name": "Last",
        "email": "email@domain.com",
        "urs-user-id": "user_id",
        "urs-access-token": "access_token",
        "urs-groups": [],
        "iat": 0,
        "exp": 1000,
    }


@mock.patch(f"{MODULE}.do_auth", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
@mock.patch(f"{MODULE}.user_profile_2_jwt_payload", autospec=True)
@mock.patch(f"{MODULE}.make_set_cookie_headers_jwt", autospec=True)
def test_do_login(
    mock_make_set_cookie_headers_jwt,
    mock_user_profile_2_jwt_payload,
    mock_get_profile,
    mock_do_auth,
    context
):
    mock_do_auth.return_value = {
        "endpoint": "ENDPOINT",
        "access_token": "ACCESS_TOKEN"
    }
    mock_get_profile.return_value = {
        "user_groups": ["GROUP_1"]
    }
    mock_make_set_cookie_headers_jwt.return_value = {
        "SET-COOKIE": "foo=bar"
    }

    args = {
        "code": "URS_CODE"
    }
    assert do_login(args, context) == (
        301,
        {},
        {
            "Location": "https://example.com/DEV/",
            "SET-COOKIE": "foo=bar"
        }
    )

    args = {
        "code": "URS_CODE",
        "state": "https://somewhere-else.com"
    }
    assert do_login(args, context) == (
        301,
        {},
        {
            "Location": "https://somewhere-else.com",
            "SET-COOKIE": "foo=bar"
        }
    )

    mock_get_profile.return_value = {
        "foo": "bar"
    }
    assert do_login(args, context) == (
        301,
        {},
        {
            "Location": "https://somewhere-else.com",
            "SET-COOKIE": "foo=bar"
        }
    )


@mock.patch(f"{MODULE}.do_auth", autospec=True)
def test_do_login_failed_auth(mock_do_auth, context):
    mock_do_auth.return_value = {}

    assert do_login({"code": "URS_CODE"}, context) == (
        400,
        {
            "contentstring": "There was a problem talking to URS Login",
            "title": "Could Not Login"
        },
        {}
    )


@mock.patch(f"{MODULE}.do_auth", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
def test_do_login_failed_profile(mock_get_profile, mock_do_auth, context):
    mock_do_auth.return_value = {
        "endpoint": "ENDPOINT",
        "access_token": "ACCESS_TOKEN"
    }
    mock_get_profile.return_value = {}

    assert do_login({"code": "URS_CODE"}, context) == (
        400,
        {
            "contentstring": "Could not get user profile from URS",
            "title": "Could Not Login"
        },
        {}
    )


def test_do_login_error():
    assert do_login({}, {}) == (
        400,
        {
            "contentstring": "No params",
            "title": "Could Not Login"
        },
        {}
    )
    assert do_login({"error": "URS_ERROR"}, {}) == (
        400,
        {
            "contentstring": 'An error occurred while trying to log into URS. URS says: "URS_ERROR". ',
            "title": "Could Not Login"
        },
        {}
    )
    assert do_login({"error": "access_denied"}, {}) == (
        401,
        {
            "contentstring": "Be sure to agree to the EULA.",
            "title": "Could Not Login",
            "error_code": "EULA_failure"
        },
        {}
    )
    assert do_login({"foo": "bar"}, {}) == (
        400,
        {
            "contentstring": "Did not get the required CODE from URS",
            "title": "Could Not Login",
        },
        {}
    )
