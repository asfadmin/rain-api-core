from unittest import mock

import jwt
import jwt.utils
import pytest

from rain_api_core.auth import JwtManager, UserProfile

MODULE = 'rain_api_core.auth'


@pytest.fixture
def jwt_manager(jwt_priv_key, jwt_pub_key):
    return JwtManager(
        algorithm='RS256',
        public_key=jwt_pub_key,
        private_key=jwt_priv_key,
        cookie_name='auth-cookie',
    )


def test_decode_jwt(jwt_manager, jwt_priv_key):
    payload = {'foo': 'bar'}
    encoded = jwt.encode(payload, jwt_priv_key, 'RS256')
    assert jwt_manager._decode_jwt(encoded) == payload


def test_decode_jwt_expired(jwt_manager, jwt_priv_key):
    payload = {'foo': 'bar', 'exp': 0}
    encoded = jwt.encode(payload, jwt_priv_key, 'RS256')
    assert jwt_manager._decode_jwt(encoded) is None


def test_decode_jwt_invalid(jwt_manager, jwt_priv_key):
    encoded = b".".join((
        jwt.utils.base64url_encode(b'{"alg": "RS256"}'),
        jwt.utils.base64url_encode(b'{"not valid'),
        jwt.utils.base64url_encode(b"some bytes"),
    )).decode()
    assert jwt_manager._decode_jwt(encoded) is None


def test_get_auth_cookie(jwt_manager):
    jwt_manager.cookie_name = 'auth-cookie'

    headers = {'Cookie': 'auth-cookie=foo'}
    assert jwt_manager._get_auth_cookie(headers).value == 'foo'
    headers = {'Cookie': 'auth-cookie=foo; not-auth-cookie=bar'}
    assert jwt_manager._get_auth_cookie(headers).value == 'foo'
    headers = {'Cookie': 'not-auth-cookie=foo'}
    assert jwt_manager._get_auth_cookie(headers) is None


def test_in_blacklist(jwt_manager):
    jwt_manager.black_list = {
        'blacklisted_user': 100,
    }

    profile = UserProfile(
        user_id='blacklisted_user',
        token='test_token',
        groups=['test_group1', 'test_group2'],
        first_name='test_first_name',
        last_name='test_last_name',
        email='test_email',
        iat=75
    )
    assert jwt_manager._in_blacklist(profile) is True
    profile.iat = 115
    assert jwt_manager._in_blacklist(profile) is False


@mock.patch(f'{MODULE}.time', autospec=True)
def test_jwt_payload_from_user_profile(mock_time, jwt_manager):
    profile = UserProfile(
        user_id='test_user_id',
        token='test_token',
        groups=['test_group1', 'test_group2'],
        first_name='test_first_name',
        last_name='test_last_name',
        email='test_email',
    )
    mock_time.return_value = 1

    jwt_manager.session_ttl = 5
    payload = jwt_manager._jwt_payload_from_user_profile(profile)

    assert payload == {
        'urs-user-id': 'test_user_id',
        'first_name': 'test_first_name',
        'last_name': 'test_last_name',
        'email': 'test_email',
        'urs-access-token': 'test_token',
        'urs-groups': ['test_group1', 'test_group2'],
        'iat': 1,
        'exp': 6
    }


@mock.patch(f'{MODULE}.JwtManager._in_blacklist', autospec=True)
def test_get_profile_from_header(mock_in_blacklist, jwt_manager, jwt_priv_key):
    mock_in_blacklist.return_value = False
    payload = {
        'urs-user-id': 'test_user',
        'first_name': 'test',
        'last_name': 'user',
        'email': 'user@emailwebsite.com',
        'urs-access-token': 'foo',
        'urs-groups': []
    }

    headers = {
        'Cookie': f'auth-cookie={jwt.encode(payload, jwt_priv_key, "RS256")}'
    }
    user_profile = jwt_manager.get_profile_from_headers(headers)
    assert user_profile.user_id == 'test_user'

    headers = {}
    assert jwt_manager.get_profile_from_headers(headers) is None


@mock.patch(f'{MODULE}.JwtManager._in_blacklist', autospec=True)
def test_get_profile_from_header_jwt_blacklisted(mock_in_blacklist, jwt_manager, jwt_priv_key):
    mock_in_blacklist.return_value = True
    payload = {
        'urs-user-id': 'test_user',
        'first_name': 'test',
        'last_name': 'user',
        'email': 'user@emailwebsite.com',
        'urs-access-token': 'foo',
        'urs-groups': []
    }

    headers = {
        'Cookie': f'auth-cookie={jwt.encode(payload, jwt_priv_key, "RS256")}'
    }
    user_profile = jwt_manager.get_profile_from_headers(headers)
    assert user_profile is None


@mock.patch(f'{MODULE}.JwtManager._encode_jwt', autospec=True)
@mock.patch(f'{MODULE}.time', autospec=True)
def test_get_header_to_set_auth_cookie(
    mock_time,
    mock_encode_jwt,
    jwt_manager,
    jwt_priv_key,
):
    jwt_manager.cookie_name = 'auth-cookie'
    jwt_manager.session_ttl = 1

    mock_encode_jwt.return_value = 'COOKIE_VALUE'
    mock_time.return_value = 0

    profile = UserProfile(
        user_id='test_user_id',
        token='test_token',
        groups=['test_group1', 'test_group2'],
        first_name='test_first_name',
        last_name='test_last_name',
        email='test_email',
        iat=0,
        exp=0
    )

    header = jwt_manager.get_header_to_set_auth_cookie(profile, '')
    assert header == {'SET-COOKIE': 'auth-cookie=COOKIE_VALUE; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path=/'}

    header = jwt_manager.get_header_to_set_auth_cookie(profile, 'DOMAIN')
    assert header == {
        'SET-COOKIE': 'auth-cookie=COOKIE_VALUE; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path=/; Domain=DOMAIN'
    }


def test_get_header_to_set_auth_cookie_logout(jwt_manager):
    header = jwt_manager.get_header_to_set_auth_cookie(None, 'DOMAIN')
    assert header == {'SET-COOKIE': 'auth-cookie=expired; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Domain=DOMAIN'}


@mock.patch(f'{MODULE}.time', autospec=True)
def test_jwt_manager_session_ttl_sub_hour(mock_time):
    jwt_manager = JwtManager(
        "RSA256",
        "",
        "private_key",
        "cookie_name",
        session_ttl_in_hours=0.5
    )
    profile = UserProfile(
        user_id='test_user_id',
        token='test_token',
        groups=['test_group1', 'test_group2'],
        first_name='test_first_name',
        last_name='test_last_name',
        email='test_email',
    )
    mock_time.return_value = 1

    payload = jwt_manager._jwt_payload_from_user_profile(profile)
    assert payload == {
        'urs-user-id': 'test_user_id',
        'first_name': 'test_first_name',
        'last_name': 'test_last_name',
        'email': 'test_email',
        'urs-access-token': 'test_token',
        'urs-groups': ['test_group1', 'test_group2'],
        'iat': 1,
        'exp': 1801,
    }
