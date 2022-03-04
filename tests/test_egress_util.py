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
