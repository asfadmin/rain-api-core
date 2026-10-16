import dataclasses
from time import time
from unittest import mock

import boto3
import jwt
import jwt.utils
import pytest
from moto import mock_aws

from rain_api_core.auth import JwtManager, SessionManager, UserProfile

MODULE = "rain_api_core.auth"


@pytest.fixture
def client_dynamodb():
    with mock_aws():
        yield boto3.client("dynamodb")


@pytest.fixture
def jwt_manager(jwt_priv_key, jwt_pub_key):
    return JwtManager(
        algorithm="RS256",
        public_key=jwt_pub_key,
        private_key=jwt_priv_key,
        cookie_name="auth-cookie",
    )


@pytest.fixture
def revoked_session_table(client_dynamodb):
    table_name = "UnitTestRevokedSessions"
    client_dynamodb.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {
                "AttributeName": "SessionId",
                "AttributeType": "S",
            },
        ],
        KeySchema=[
            {
                "AttributeName": "SessionId",
                "KeyType": "HASH",
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    client_dynamodb.update_time_to_live(
        TableName=table_name,
        TimeToLiveSpecification={
            "Enabled": True,
            "AttributeName": "ExpiresAt",
        },
    )

    return boto3.resource("dynamodb").Table(table_name)


def test_decode_jwt(jwt_manager, jwt_priv_key):
    payload = {"foo": "bar"}
    encoded = jwt.encode(payload, jwt_priv_key, "RS256")
    assert jwt_manager._decode_jwt(encoded) == payload


def test_decode_jwt_expired(jwt_manager, jwt_priv_key):
    payload = {"foo": "bar", "exp": 0}
    encoded = jwt.encode(payload, jwt_priv_key, "RS256")
    assert jwt_manager._decode_jwt(encoded) is None


def test_decode_jwt_invalid(jwt_manager):
    encoded = b".".join(
        (
            jwt.utils.base64url_encode(b'{"alg": "RS256"}'),
            jwt.utils.base64url_encode(b'{"not valid'),
            jwt.utils.base64url_encode(b"some bytes"),
        )
    ).decode()
    assert jwt_manager._decode_jwt(encoded) is None


def test_get_auth_cookie(jwt_manager):
    jwt_manager.cookie_name = "auth-cookie"

    headers = {"Cookie": "auth-cookie=foo"}
    assert jwt_manager._get_auth_cookie(headers).value == "foo"
    headers = {"Cookie": "auth-cookie=foo; not-auth-cookie=bar"}
    assert jwt_manager._get_auth_cookie(headers).value == "foo"
    headers = {"Cookie": "not-auth-cookie=foo"}
    assert jwt_manager._get_auth_cookie(headers) is None


def test_in_blacklist(jwt_manager):
    jwt_manager.black_list = {
        "blacklisted_user": 100,
    }

    profile = UserProfile(
        user_id="blacklisted_user",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
        iat=75,
    )
    assert jwt_manager._in_blacklist(profile) is True
    profile.iat = 115
    assert jwt_manager._in_blacklist(profile) is False


@mock.patch(f"{MODULE}.time", autospec=True)
def test_jwt_payload_from_user_profile(mock_time, jwt_manager):
    profile = UserProfile(
        user_id="test_user_id",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
    )
    mock_time.return_value = 1

    jwt_manager.session_ttl = 5
    payload = jwt_manager._jwt_payload_from_user_profile(profile)

    assert payload == {
        "urs-user-id": "test_user_id",
        "first_name": "test_first_name",
        "last_name": "test_last_name",
        "email": "test_email",
        "urs-access-token": "test_token",
        "urs-groups": ["test_group1", "test_group2"],
        "iat": 1,
        "exp": 6,
    }


@mock.patch(f"{MODULE}.JwtManager._in_blacklist", autospec=True)
def test_get_profile_from_header(mock_in_blacklist, jwt_manager, jwt_priv_key):
    mock_in_blacklist.return_value = False
    payload = {
        "urs-user-id": "test_user",
        "first_name": "test",
        "last_name": "user",
        "email": "user@emailwebsite.com",
        "urs-access-token": "foo",
        "urs-groups": [],
    }

    headers = {
        "Cookie": f"auth-cookie={jwt.encode(payload, jwt_priv_key, 'RS256')}",
    }
    user_profile = jwt_manager.get_profile_from_headers(headers)
    assert user_profile.user_id == "test_user"

    headers = {}
    assert jwt_manager.get_profile_from_headers(headers) is None


@mock.patch(f"{MODULE}.JwtManager._in_blacklist", autospec=True)
def test_get_profile_from_header_jwt_blacklisted(
    mock_in_blacklist,
    jwt_manager,
    jwt_priv_key,
):
    mock_in_blacklist.return_value = True
    payload = {
        "urs-user-id": "test_user",
        "first_name": "test",
        "last_name": "user",
        "email": "user@emailwebsite.com",
        "urs-access-token": "foo",
        "urs-groups": [],
    }

    headers = {
        "Cookie": f"auth-cookie={jwt.encode(payload, jwt_priv_key, 'RS256')}",
    }
    user_profile = jwt_manager.get_profile_from_headers(headers)
    assert user_profile is None


@mock.patch(f"{MODULE}.JwtManager._encode_jwt", autospec=True)
@mock.patch(f"{MODULE}.time", autospec=True)
def test_get_header_to_set_auth_cookie(
    mock_time,
    mock_encode_jwt,
    jwt_manager,
):
    jwt_manager.cookie_name = "auth-cookie"
    jwt_manager.session_ttl = 1

    mock_encode_jwt.return_value = "COOKIE_VALUE"
    mock_time.return_value = 0

    profile = UserProfile(
        user_id="test_user_id",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
        iat=0,
        exp=0,
    )

    header = jwt_manager.get_header_to_set_auth_cookie(profile, "")
    assert header == {
        "SET-COOKIE": (
            "auth-cookie=COOKIE_VALUE; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path=/; Secure; HttpOnly; SameSite=Lax"
        )
    }

    header = jwt_manager.get_header_to_set_auth_cookie(profile, "DOMAIN")
    assert header == {
        "SET-COOKIE": (
            "auth-cookie=COOKIE_VALUE; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path=/; Domain=DOMAIN; Secure; HttpOnly; "
            "SameSite=Lax"
        )
    }


def test_get_header_to_set_auth_cookie_logout(jwt_manager):
    header = jwt_manager.get_header_to_set_auth_cookie(None, "DOMAIN")
    assert header == {
        "SET-COOKIE": (
            "auth-cookie=expired; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Domain=DOMAIN; Secure; HttpOnly; "
            "SameSite=Lax"
        )
    }


@mock.patch(f"{MODULE}.time", autospec=True)
def test_jwt_manager_session_ttl_sub_hour(mock_time):
    jwt_manager = JwtManager(
        "RSA256",
        "",
        "private_key",
        "cookie_name",
        session_ttl_in_hours=0.5,
    )
    profile = UserProfile(
        user_id="test_user_id",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
    )
    mock_time.return_value = 1

    payload = jwt_manager._jwt_payload_from_user_profile(profile)
    assert payload == {
        "urs-user-id": "test_user_id",
        "first_name": "test_first_name",
        "last_name": "test_last_name",
        "email": "test_email",
        "urs-access-token": "test_token",
        "urs-groups": ["test_group1", "test_group2"],
        "iat": 1,
        "exp": 1801,
    }


def test_session_manager(revoked_session_table):
    session_manager = SessionManager(revoked_session_table.name)

    profile = UserProfile(
        user_id="test_user",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
        iat=int(time()),
        exp=int(time()) + 1000,
    )

    assert session_manager.is_session_revoked(profile) is False
    session_manager.revoke_session(profile)
    assert session_manager.is_session_revoked(profile) is True


def test_session_manager_revoke_session(revoked_session_table):
    session_manager = SessionManager(revoked_session_table.name)

    profile = UserProfile(
        user_id="test_user",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
        iat=0,
        exp=1000,
    )

    session_manager.revoke_session(profile)
    items = revoked_session_table.scan()["Items"]

    session_id = items[0]["SessionId"]
    assert items == [
        {
            "SessionId": session_id,
            "CreatedAt": mock.ANY,
            "ExpiresAt": 1000,
        },
    ]

    # Calling it twice does not create new items. The creation time may change.
    session_manager.revoke_session(profile)
    items = revoked_session_table.scan()["Items"]
    assert items == [
        {
            "SessionId": session_id,
            "CreatedAt": mock.ANY,
            "ExpiresAt": 1000,
        },
    ]


def test_session_manager_is_session_revoked(revoked_session_table):
    session_manager = SessionManager(revoked_session_table.name)

    profile = UserProfile(
        user_id="test_user",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
        iat=int(time()) - 1000,
        exp=int(time()) + 1000,
    )

    session_id = session_manager._get_session_id(profile)

    revoked_session_table.put_item(
        Item={
            "SessionId": session_id,
            "CreatedAt": int(time()),
            "ExpiresAt": int(time()) + 1000,
        },
    )
    assert session_manager.is_session_revoked(profile) is True

    # Created at time is before token minting time
    revoked_session_table.put_item(
        Item={
            "SessionId": session_id,
            "CreatedAt": int(time()) - 2000,
            "ExpiresAt": int(time()) + 1000,
        },
    )
    assert session_manager.is_session_revoked(profile) is False

    # Revocation has expired
    revoked_session_table.put_item(
        Item={
            "SessionId": session_id,
            "CreatedAt": int(time()),
            "ExpiresAt": int(time()) - 1000,
        },
    )
    assert session_manager.is_session_revoked(profile) is False


def test_session_manager_get_session_id(revoked_session_table):
    session_manager = SessionManager(revoked_session_table.name)

    profile = UserProfile(
        user_id="test_user",
        token="test_token",
        groups=["test_group1", "test_group2"],
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_email",
        iat=0,
        exp=1000,
    )

    original_session_id = session_manager._get_session_id(profile)

    # Changing an attribute changes the ID
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, user_id="replaced"),
        )
        != original_session_id
    )
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, token="replaced"),
        )
        != original_session_id
    )
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, groups=["replaced"]),
        )
        != original_session_id
    )
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, first_name="replaced"),
        )
        != original_session_id
    )
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, last_name="replaced"),
        )
        != original_session_id
    )
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, email="replaced"),
        )
        != original_session_id
    )
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, iat=50),
        )
        != original_session_id
    )
    assert (
        session_manager._get_session_id(
            dataclasses.replace(profile, exp=5000),
        )
        != original_session_id
    )
