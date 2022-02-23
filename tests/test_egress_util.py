import copy
from datetime import datetime
from unittest import mock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from rain_api_core.egress_util import (
    bucket_prefix_match,
    check_private_bucket,
    check_public_bucket,
    get_bucket_dynamic_path,
    get_presigned_url,
    get_sorted_bucket_list,
    hmacsha256,
    prepend_bucketname,
    process_request,
    process_varargs
)

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


@pytest.mark.parametrize(
    "bucket_map",
    (
        {"foo": "bucket1"},
        {"foo": {"bucket": "bucket1"}},
        {"MAP": {"foo": {"bucket": "bucket1"}}}
    )
)
def test_get_bucket_dynamic_path(bucket_map):
    # Using a tuple instead of a list to ensure the input is not modified
    path_list = ["foo", "bar", "baz"]
    original_path_list = list(path_list)
    original_bucket_map = copy.deepcopy(bucket_map)

    path, bucket, object, headers = get_bucket_dynamic_path(path_list, bucket_map)
    assert path == "gsfc-ngap-d-bucket1"
    assert bucket == "foo"
    assert object == "bar/baz"
    assert headers == {}
    # The input should not have been modified
    assert path_list == original_path_list
    assert bucket_map == original_bucket_map


def test_get_bucket_dynamic_path_headers():
    path_list = ["foo", "bar"]
    bucket_map = {
        "foo": {
            "bucket": "bucket1",
            "headers": {
                "header1": "baz",
                "header2": "qux"
            }
        }
    }

    path, bucket, object, headers = get_bucket_dynamic_path(path_list, bucket_map)
    assert path == "gsfc-ngap-d-bucket1"
    assert bucket == "foo"
    assert object == "bar"
    assert headers == {
        "header1": "baz",
        "header2": "qux"
    }


def test_get_bucket_dynamic_path_nested():
    path_list = ["foo", "bar", "baz", "qux"]
    bucket_map = {
        "foo": {
            "bar": {
                "baz": "bucket1"
            }
        }
    }

    path, bucket, object, headers = get_bucket_dynamic_path(path_list, bucket_map)
    assert path == "gsfc-ngap-d-bucket1"
    assert bucket == "foo/bar/baz"
    assert object == "qux"
    assert headers == {}


def test_get_bucket_dynamic_path_nonexistent():
    assert get_bucket_dynamic_path([], {}) == (None, None, None, {})
    assert get_bucket_dynamic_path(["foo"], {"bar": "bucket1"}) == (None, None, None, {})
    assert get_bucket_dynamic_path(["foo"], {"foo": {}}) == (None, None, None, {})
    assert get_bucket_dynamic_path(["foo", "bar"], {"foo": {"qux":  "bucket1"}}) == (None, None, None, {})


@mock.patch(f"{MODULE}.process_request", autospec=True)
def test_process_varargs(mock_process_request):
    mock_process_request.return_value = (1, 2, 3, 4)

    assert process_varargs("", {}) == (1, 2, 3)


@pytest.mark.parametrize(
    "bucket_map",
    (
        {"foo": "bucket1"},
        {"foo": {"bucket": "bucket1"}},
        {"MAP": {"foo": {"bucket": "bucket1"}}}
    )
)
def test_process_request(bucket_map):
    assert process_request("foo/bar", bucket_map) == (
        "foo",
        "gsfc-ngap-d-bucket1",
        "bar",
        {}
    )


def test_process_request_invalid():
    bucket_map = {
        "MAP": {
            "foo": {
                "bucket": "bucket1"
            }
        }
    }
    assert process_request("foo", bucket_map) == ("foo", None, None, {})
    assert process_request("bar/baz", bucket_map) == ("bar", None, "baz", {})


def test_process_request_reverse_url(monkeypatch):
    bucket_map = {
        "MAP": {
            "foo": {
                "bucket": "bucket1"
            }
        }
    }
    assert process_request("bar/foo/baz", bucket_map) == ("bar/foo", None, "baz", {})

    monkeypatch.setenv("USE_REVERSE_BUCKET_MAP", "TRUE")
    assert process_request("bar/foo/baz", bucket_map) == ("foo", "gsfc-ngap-d-bucket1", "bar/baz", {})


def test_bucket_prefix_match():
    # Copied from: https://github.com/asfadmin/thin-egress-app/issues/188

    # No Object Specified Bucket Match
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket1"
    ) is True

    # Deep match      https://<TEA>/bucket1/prefix1/prefix2/path/object
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket1/prefix1/prefix2",
        object_name="prefix1/prefix2/path/object"
    ) is True

    # Shallow Match https://<TEA>/bucket1/prefix1/path/object
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket1/prefix1",
        object_name="prefix1/path/object"
    ) is True

    # Shallow Match, unnecessary trailing slash    https://<TEA>/bucket1/prefix1/path/object
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket1/prefix1/",
        object_name="prefix1/path/object"
    ) is True

    # Simple match  https://<TEA>/bucket1/object
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket1",
        object_name="object"
    ) is True

    # Bucket Mismatch https://<TEA>/bucket2/prefix1/path/object
    assert bucket_prefix_match(
        bucket_check="bucket2",
        bucket_map="bucket1/prefix1",
        object_name="prefix1/path/object"
    ) is False

    # Bucket Match, Prefix Mismatch    https://<TEA>/bucket1/prefix2/path/object
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket1/prefix1",
        object_name="prefix2/path/object"
    ) is False

    # No Object Specified Bucket Mis-Match
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket2/prefix1/prefix2"
    ) is False

    # No Object Specified Prefix mis-Match
    assert bucket_prefix_match(
        bucket_check="bucket1",
        bucket_map="bucket1/prefix1/prefix2"
    ) is False


def test_bucket_prefix_match_extra():
    assert bucket_prefix_match("", "") is True
    assert bucket_prefix_match("foo", "foo") is True
    assert bucket_prefix_match("foo", "foo", object_name="") is True
    assert bucket_prefix_match("foo", "foo", object_name="bar") is True
    assert bucket_prefix_match("foo", "foo/bar", object_name="bar") is True
    assert bucket_prefix_match("foo", "foo/bar", object_name="bar/baz") is True
    assert bucket_prefix_match("foo", "foo/bar/baz", object_name="bar/baz") is True
    assert bucket_prefix_match("foo", "foo/bar/baz/qux", object_name="bar/baz/qux") is True
    assert bucket_prefix_match("foo", "foo/bar/baz") is False
    assert bucket_prefix_match("qux", "foo/bar/baz", object_name="bar/baz") is False
    assert bucket_prefix_match("foo/bar/baz", "foo/bar/baz") is False


@given(bucket_check=st.text(), bucket_map=st.text(), object_name=st.text())
def test_bucket_prefix_match_no_error(bucket_check, bucket_map, object_name):
    ans = bucket_prefix_match(bucket_check, bucket_map, object_name)
    assert ans in (True, False)
    if ans:
        assert bucket_map.startswith(bucket_check)


def test_get_sorted_bucket_list():
    bucket_map = {
        "GROUP_1": {
            "a/b/c": 0,
            "a": 0,
            "d/f": 0,
            "c": 0,
            "b": 0,
            "z/y/x": 0,
        },
        "GROUP_2": [
            "a/b/c",
            "a",
            "d/f",
            "c",
            "b",
            "z/y/x",
        ],
        "GROUP_3": 0
    }
    expected = ["a/b/c", "z/y/x", "d/f", "a", "c", "b"]
    assert get_sorted_bucket_list(bucket_map, "GROUP_1") == expected
    assert get_sorted_bucket_list(bucket_map, "GROUP_2") == expected
    assert get_sorted_bucket_list(bucket_map, "GROUP_3") == []
    assert get_sorted_bucket_list(bucket_map, "GROUP_4") == []


def test_check_private_bucket(monkeypatch):
    monkeypatch.setenv("BUCKETNAME_PREFIX", "")
    # Copied from: https://github.com/asfadmin/thin-egress-app/issues/188
    bucket_map = {
        "MAP": {
            "general-browse": "browse-bucket",
            "productX": "bucket"
        },
        "PUBLIC_BUCKETS": {
            "browse-bucket": "General browse Imagery",
            "bucket/browse": "ProductX Browse Imagery"
        },
        "PRIVATE_BUCKETS": {
            "bucket/2020/12": ["science_team"]
        }
    }

    assert check_private_bucket("bucket", {}) is False
    assert check_private_bucket("bucket", bucket_map) is False
    assert check_private_bucket("browse-bucket", bucket_map) is False
    assert check_private_bucket("bucket", bucket_map, "browse/obj1") is False
    assert check_private_bucket("bucket", bucket_map, "2020/12/obj1") == ["science_team"]


def test_check_public_bucket(monkeypatch):
    monkeypatch.setenv("BUCKETNAME_PREFIX", "")
    # Modified from: https://github.com/asfadmin/thin-egress-app/issues/188
    bucket_map = {
        "MAP": {
            "general-browse": "browse-bucket",
            "productX": "bucket"
        },
        "PUBLIC_BUCKETS": {
            "browse-bucket": "General browse Imagery",
            "bucket/browse": "ProductX Browse Imagery"
        },
        "PRIVATE_BUCKETS": {
            "bucket/2020/12": ["science_team"]
        }
    }

    assert check_public_bucket("browse-bucket", {}) is False
    assert check_public_bucket("browse-bucket", bucket_map) is True
    assert check_public_bucket("bucket", bucket_map) is False
    assert check_public_bucket("bucket", bucket_map, "browse/obj1") is True


def test_check_public_sub_directory(monkeypatch):
    monkeypatch.setenv("BUCKETNAME_PREFIX", "")
    bucket_map = {
        "MAP": {
            "productX": "bucket"
        },
        "PUBLIC_BUCKETS": [
            "bucket/foo/browse"
        ],
        "PRIVATE_BUCKETS": {
            "bucket/foo": ["some_permission"]
        }
    }

    assert check_public_bucket("bucket", {}) is False
    assert check_public_bucket("bucket", bucket_map) is False
    assert check_public_bucket("bucket", bucket_map, "foo/object1") is False
    assert check_public_bucket("bucket", bucket_map, "foo/browse/object1") is True

    assert check_private_bucket("bucket", bucket_map, "foo/object1") == ["some_permission"]
