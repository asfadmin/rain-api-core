import urllib
from unittest import mock

import pytest

from rain_api_core.auth import JwtManager, UserProfile
from rain_api_core.edl import EdlException
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


@pytest.fixture
def user_profile():
    return UserProfile(
        user_id='test_user',
        first_name='John',
        last_name='Smith',
        email='j.smith@email.com',
        groups=[],
        token='test_token',
        iat=0,
        exp=0
    )


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


@mock.patch(f"{MODULE}.EdlClient", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_do_auth(mock_get_urs_creds, mock_client):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_client().request.return_value = {"foo": "bar"}

    assert do_auth("code", "redir_url") == {"foo": "bar"}


@mock.patch(f"{MODULE}.EdlClient", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_do_auth_error(mock_get_urs_creds, mock_client):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_client().request.side_effect = EdlException(
        urllib.error.URLError("test error"),
        msg={},
        payload=None,
    )

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


@mock.patch(f"{MODULE}.EdlClient", autospec=True)
def test_get_profile(mock_client):
    mock_client().request.return_value = {
        "uid": "user_id",
        "first_name": "John",
        "last_name": "Smith",
        "email_address": "peter.l.smith@nasa.gov",
        "user_groups": [],
    }

    profile = get_profile("user_id", "token")
    assert profile.user_id == "user_id"
    assert profile.first_name == "John"

    profile = get_profile("user_id", "token", "temptoken")
    assert profile.user_id == "user_id"
    assert get_profile(None, "token") is None
    assert get_profile("user_id", None) is None


@mock.patch(f"{MODULE}.EdlClient", autospec=True)
@mock.patch(f"{MODULE}.get_new_token_and_profile", autospec=True)
def test_get_profile_error(mock_get_new_token_and_profile, mock_client):
    mock_get_new_token_and_profile.return_value = {"foo": "bar"}
    mock_client().request.side_effect = EdlException(
        urllib.error.URLError("test error"),
        msg={},
        payload=None,
    )

    assert get_profile("user_id", "token", "temptoken") is None
    mock_get_new_token_and_profile.assert_not_called()

    assert get_profile("user_id", "token") == {"foo": "bar"}
    mock_get_new_token_and_profile.assert_called_once_with("user_id", "token", {})


@mock.patch(f"{MODULE}.EdlClient", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_get_new_token_and_profile(mock_get_urs_creds, mock_get_profile, mock_client):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_get_profile.return_value = {"foo": "bar"}

    mock_client().request.return_value = {"access_token": "token"}

    assert get_new_token_and_profile("user_id", "cookietoken") == {"foo": "bar"}
    mock_get_profile.assert_called_once_with("user_id", "cookietoken", "token", aux_headers={})


@mock.patch(f"{MODULE}.EdlClient", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
@mock.patch(f"{MODULE}.get_urs_creds", autospec=True)
def test_get_new_token_and_profile_error(mock_get_urs_creds, mock_get_profile, mock_client):
    mock_get_urs_creds.return_value = {"UrsAuth": "URS_AUTH"}
    mock_client().request.side_effect = EdlException(
        urllib.error.URLError("test error"),
        msg={},
        payload=None,
    )

    assert get_new_token_and_profile("user_id", "cookietoken") is None
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

    user = UserProfile(
        user_id='test_user_id',
        token='test_token',
        groups=[],
        first_name='test_first_name',
        last_name='test_last_name',
        email='test_email',
    )

    assert user_in_group([], {}) == (False, None)
    mock_user_in_group_list.assert_not_called()
    assert user_in_group(["GROUP_1"], None) == (False, None)
    mock_user_in_group_list.assert_not_called()
    assert user_in_group(["GROUP_1"], user) == (True, None)
    mock_user_in_group_list.assert_called_once()


@mock.patch(f"{MODULE}.user_in_group_list", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
def test_user_in_group_refresh(mock_get_profile, mock_user_in_group_list):
    mock_user_in_group_list.return_value = True
    user = UserProfile(
        user_id='test_user_id',
        token='test_token',
        groups=[],
        first_name='test_first_name',
        last_name='test_last_name',
        email='test_email',
    )
    mock_get_profile.return_value = user

    assert user_in_group(["GROUP_1"], user, refresh_first=True) == (True, user)
    mock_user_in_group_list.assert_called_once()

    mock_user_in_group_list.return_value = False
    assert user_in_group(["GROUP_1"], user, refresh_first=False) == (False, user)


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


@mock.patch(f"{MODULE}.do_auth", autospec=True)
@mock.patch(f"{MODULE}.get_profile", autospec=True)
@mock.patch(f"{MODULE}.JwtManager.get_header_to_set_auth_cookie", autospec=True)
def test_do_login(
        mock_get_header_to_set_auth_cookie,
        mock_get_profile,
        mock_do_auth,
        context,
        user_profile
):
    mock_do_auth.return_value = {
        "endpoint": "ENDPOINT",
        "access_token": "ACCESS_TOKEN"
    }
    user_profile.groups = ['GROUP_1']
    mock_get_profile.return_value = user_profile
    mock_get_header_to_set_auth_cookie.return_value = {
        "SET-COOKIE": "foo=bar"
    }

    args = {
        "code": "URS_CODE"
    }
    jwt_manager = JwtManager('algorithm', 'pub_key', 'priv_key', 'cookie-name')
    assert do_login(args, context, jwt_manager) == (
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
    assert do_login(args, context, jwt_manager) == (
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
    jwt_manager = JwtManager('algorithm', 'pub_key', 'priv_key', 'cookie-name')

    assert do_login({"code": "URS_CODE"}, context, jwt_manager) == (
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
    mock_get_profile.return_value = None
    jwt_manager = JwtManager('algorithm', 'pub_key', 'priv_key', 'cookie-name')

    assert do_login({"code": "URS_CODE"}, context, jwt_manager) == (
        400,
        {
            "contentstring": "Could not get user profile from URS",
            "title": "Could Not Login"
        },
        {}
    )


def test_do_login_error():
    jwt_manager = JwtManager('algorithm', 'pub_key', 'priv_key', 'cookie-name')
    assert do_login({}, {}, jwt_manager) == (
        400,
        {
            "contentstring": "No params",
            "title": "Could Not Login"
        },
        {}
    )

    assert do_login({"error": "URS_ERROR"}, {}, jwt_manager) == (
        400,
        {
            "contentstring": 'An error occurred while trying to log into URS. URS says: "URS_ERROR". ',
            "title": "Could Not Login"
        },
        {}
    )
    assert do_login({"error": "access_denied"}, {}, jwt_manager) == (
        401,
        {
            "contentstring": "Be sure to agree to the EULA.",
            "title": "Could Not Login",
            "error_code": "EULA_failure"
        },
        {}
    )
    assert do_login({"foo": "bar"}, {}, jwt_manager) == (
        400,
        {
            "contentstring": "Did not get the required CODE from URS",
            "title": "Could Not Login",
        },
        {}
    )
