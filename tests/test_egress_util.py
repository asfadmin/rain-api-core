from datetime import datetime
from unittest import mock

from rain_api_core.egress_util import get_presigned_url, hmacsha256, prepend_bucketname

MODULE = "rain_api_core.egress_util"


def test_prepend_bucketname(monkeypatch):
    assert prepend_bucketname("foo") == "gsfc-ngap-d-foo"

    monkeypatch.setenv("MATURITY", "PROD")
    assert prepend_bucketname("bar") == "gsfc-ngap-p-bar"

    monkeypatch.setenv("BUCKETNAME_PREFIX", "prefix-")
    assert prepend_bucketname("baz") == "prefix-baz"


def test_hmacsha256():
    assert hmacsha256(b"foo", "the_data").hexdigest() == (
        "0f926bf441414ac369f8c5235acc1b5de4b2e56b5447e421eee47cfdd6202e54"
    )


@mock.patch(f"{MODULE}.datetime", autospec=True)
def test_get_presigned_url(mock_datetime):
    mock_datetime.utcnow.return_value = datetime(2015, 1, 1)
    session = {
        "Credentials": {
            "AccessKeyId": "access_key_id",
            "SecretAccessKey": "secret_access_key",
            "SessionToken": "session_token"
        }
    }
    presigned_url = get_presigned_url(session, "bucket_name", "object_name", "region_name", 1000, "user_id")
    assert presigned_url == (
        "https://bucket_name.s3.region_name.amazonaws.com/object_name"
        "?A-userid=user_id"
        "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=access_key_id%2F20150101%2Fregion_name%2Fs3%2Faws4_request"
        "&X-Amz-Date=20150101T000000Z"
        "&X-Amz-Expires=1000"
        "&X-Amz-Security-Token=session_token"
        "&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=766aa9d15ec05d33bb6de720b02e8b9cf7d96def24a94cba3e0b39f19b302834"
    )


@mock.patch(f"{MODULE}.datetime", autospec=True)
def test_get_presigned_url_with_spaces(mock_datetime):
    mock_datetime.utcnow.return_value = datetime(2015, 1, 1)
    session = {
        "Credentials": {
            "AccessKeyId": "access_key_id",
            "SecretAccessKey": "secret_access_key",
            "SessionToken": "session_token"
        }
    }
    presigned_url = get_presigned_url(session, "bucket_name", "has spaces ", "region_name", 1000, "user_id")
    assert presigned_url == (
        "https://bucket_name.s3.region_name.amazonaws.com/has%20spaces%20"
        "?A-userid=user_id"
        "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=access_key_id%2F20150101%2Fregion_name%2Fs3%2Faws4_request"
        "&X-Amz-Date=20150101T000000Z"
        "&X-Amz-Expires=1000"
        "&X-Amz-Security-Token=session_token"
        "&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=99787202e2729ab15cea657f8a1a78716e570fc65a07c5fb60128ab205753ace"
    )


@mock.patch(f"{MODULE}.datetime", autospec=True)
def test_get_presigned_url_with_colons(mock_datetime):
    mock_datetime.utcnow.return_value = datetime(2015, 1, 1)
    session = {
        "Credentials": {
            "AccessKeyId": "access_key_id",
            "SecretAccessKey": "secret_access_key",
            "SessionToken": "session_token"
        }
    }
    presigned_url = get_presigned_url(session, "bucket_name", "has_:colons:", "region_name", 1000, "user_id")
    assert presigned_url == (
        "https://bucket_name.s3.region_name.amazonaws.com/has_%3Acolons%3A"
        "?A-userid=user_id"
        "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=access_key_id%2F20150101%2Fregion_name%2Fs3%2Faws4_request"
        "&X-Amz-Date=20150101T000000Z"
        "&X-Amz-Expires=1000"
        "&X-Amz-Security-Token=session_token"
        "&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=f664672404aa1f98d2017c386011b3cb20625ca21cf082420c67b4bca3891489"
    )


@mock.patch(f"{MODULE}.datetime", autospec=True)
def test_get_presigned_url_with_newlines(mock_datetime):
    mock_datetime.utcnow.return_value = datetime(2015, 1, 1)
    session = {
        "Credentials": {
            "AccessKeyId": "access_key_id",
            "SecretAccessKey": "secret_access_key",
            "SessionToken": "session_token"
        }
    }
    presigned_url = get_presigned_url(session, "bucket_name", "has\nnewlines\n", "region_name", 1000, "user_id")
    assert presigned_url == (
        "https://bucket_name.s3.region_name.amazonaws.com/has%0Anewlines%0A"
        "?A-userid=user_id"
        "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=access_key_id%2F20150101%2Fregion_name%2Fs3%2Faws4_request"
        "&X-Amz-Date=20150101T000000Z"
        "&X-Amz-Expires=1000"
        "&X-Amz-Security-Token=session_token"
        "&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=b5f7dab0ba1af2a1a5c625f526de6ab8047a20f165675890cfa8caf70cfed730"
    )

@mock.patch(f"{MODULE}.datetime", autospec=True)
def test_get_presigned_url_with_api_request_uuid(mock_datetime):
    mock_datetime.utcnow.return_value = datetime(2024, 1, 1)
    session = {
        "Credentials": {
            "AccessKeyId": "access_key_id",
            "SecretAccessKey": "secret_access_key",
            "SessionToken": "session_token"
        }
    }
    presigned_url = get_presigned_url(session, "bucket_name", "object_name", "region_name", 500, "user_id", api_request_uuid="uuid_value")
    assert presigned_url == (
        "https://bucket_name.s3.region_name.amazonaws.com/object_name"
        "?A-api-request-uuid=uuid_value"
        "&A-userid=user_id"
        "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=access_key_id%2F20240101%2Fregion_name%2Fs3%2Faws4_request"
        "&X-Amz-Date=20240101T000000Z"
        "&X-Amz-Expires=500"
        "&X-Amz-Security-Token=session_token"
        "&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=3010924b3725f8b47a3486ea4005f658128ddc5dde5ca405dfe1bd69bd2ae7a8"
    )