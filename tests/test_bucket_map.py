import copy

import pytest

from rain_api_core.bucket_map import _PUBLIC, BucketMap, BucketMapEntry


@pytest.fixture
def sample_bucket_map():
    # Modified from: https://github.com/asfadmin/thin-egress-app/issues/188
    return {
        "MAP": {
            "ANY_AUTHED": "authed-bucket",
            "general-browse": "browse-bucket",
            "productX": "bucket",
            "nested": {
                "nested2a": {
                    "nested3": "nested-bucket-public"
                },
                "nested2b": "nested-bucket-private"
            }
        },
        "PUBLIC_BUCKETS": {
            "browse-bucket": "General browse Imagery",
            "bucket/browse": "ProductX Browse Imagery"
        },
        "PRIVATE_BUCKETS": {
            "bucket/2020/12": ["science_team"],
            "nested-bucket-private": []
        }
    }


def test_get_simple():
    bucket_map = {
        "PATH": "bucket-name",
    }
    b_map = BucketMap(bucket_map, bucket_name_prefix="pre-")

    entry = b_map.get("PATH/obj1")
    assert entry.bucket == "pre-bucket-name"
    assert entry.bucket_path == "PATH"
    assert entry.object_key == "obj1"
    assert entry.headers == {}

    dir_entry = b_map.get("PATH/")
    assert dir_entry.bucket == "pre-bucket-name"
    assert dir_entry.bucket_path == "PATH"
    assert dir_entry.object_key == ""
    assert dir_entry.headers == {}

    assert b_map.get("PATH") is None
    assert b_map.get("NOT/VALID") is None


@pytest.mark.parametrize(
    "bucket_map",
    (
        {"foo": "bucket1"},
        {"foo": {"bucket": "bucket1"}},
        {"MAP": {"foo": {"bucket": "bucket1"}}}
    )
)
def test_get_compatibility(bucket_map):
    b_map = BucketMap(bucket_map)
    entry = b_map.get("foo/bar")

    assert entry.bucket == "bucket1"
    assert entry.bucket_path == "foo"
    assert entry.object_key == "bar"
    assert entry.headers == {}


def test_get_nested():
    bucket_map = {
        "PATH": {
            "LEVEL1": {
                "LEVEL2": "bucket-name"
            }
        },
    }

    b_map = BucketMap(bucket_map)

    entry = b_map.get("PATH/LEVEL1/LEVEL2/obj1")
    assert entry.bucket == "bucket-name"
    assert entry.bucket_path == "PATH/LEVEL1/LEVEL2"
    assert entry.object_key == "obj1"
    assert entry.headers == {}

    dir_entry = b_map.get("PATH/LEVEL1/LEVEL2/")
    assert dir_entry.bucket == "bucket-name"
    assert dir_entry.bucket_path == "PATH/LEVEL1/LEVEL2"
    assert dir_entry.object_key == ""
    assert dir_entry.headers == {}

    assert b_map.get("PATH/LEVEL1/LEVEL2") is None


def test_get_with_headers():
    bucket_map = {
        "PATH": {
            "bucket": "bucket-name",
            "headers": {
                "Header1": "Value1"
            }
        }
    }
    b_map = BucketMap(bucket_map)

    entry = b_map.get("PATH/obj1")
    assert entry.bucket == "bucket-name"
    assert entry.bucket_path == "PATH"
    assert entry.object_key == "obj1"
    assert entry.headers == {"Header1": "Value1"}

    dir_entry = b_map.get("PATH/")
    assert dir_entry.bucket == "bucket-name"
    assert dir_entry.bucket_path == "PATH"
    assert dir_entry.object_key == ""
    assert dir_entry.headers == {"Header1": "Value1"}

    assert b_map.get("PATH") is None


def test_get_reverse():
    bucket_map = {
        "PATH": {
            "STAGE": "bucket-name"
        }
    }
    b_map = BucketMap(bucket_map, reverse=True)

    entry = b_map.get("STAGE/PATH/obj1")
    assert entry.bucket == "bucket-name"
    assert entry.bucket_path == "PATH/STAGE"
    assert entry.object_key == "obj1"

    dir_entry = b_map.get("STAGE/PATH/")
    assert dir_entry.bucket == "bucket-name"
    assert entry.bucket_path == "PATH/STAGE"
    assert dir_entry.object_key == ""

    assert b_map.get("STAGE/PATH") is None


@pytest.mark.parametrize(
    "bucket_map",
    (
        {"foo": "bucket1"},
        {"foo": {"bucket": "bucket1"}},
        {"MAP": {"foo": {"bucket": "bucket1"}}}
    )
)
def test_get_path_compatibility(bucket_map):
    # Using a tuple instead of a list to ensure the input is not modified
    path_list = ["foo", "bar", "baz"]
    original_path_list = list(path_list)
    original_bucket_map = copy.deepcopy(bucket_map)

    b_map = BucketMap(bucket_map)
    entry = b_map.get_path(path_list)

    assert entry.bucket == "bucket1"
    assert entry.bucket_path == "foo"
    assert entry.object_key == "bar/baz"
    assert entry.headers == {}
    # The input should not have been modified
    assert path_list == original_path_list
    assert bucket_map == original_bucket_map


def test_get_path_nonexistent():
    assert BucketMap({}).get_path([]) is None
    assert BucketMap({"bar": "bucket1"}).get_path(["foo"]) is None
    assert BucketMap({"foo": {}}).get_path(["foo"]) is None
    assert BucketMap({"foo": {"qux":  "bucket1"}}).get_path(["foo", "bar"]) is None


def test_entries_empty():
    b_map = BucketMap({})

    assert list(b_map.entries()) == []


def test_entries_simple():
    bucket_map = {
        "PATH": "bucket-name",
    }
    b_map = BucketMap(bucket_map, bucket_name_prefix="pre-")

    assert list(b_map.entries()) == [
        BucketMapEntry(
            bucket="pre-bucket-name",
            bucket_path="PATH",
            object_key="",
        )
    ]


def test_entries_multiple():
    bucket_map = {
        "PATH": "bucket1",
        "PATH2": "bucket2"
    }
    b_map = BucketMap(bucket_map, bucket_name_prefix="pre-")

    assert list(b_map.entries()) == [
        BucketMapEntry(
            bucket="pre-bucket1",
            bucket_path="PATH",
            object_key="",
        ),
        BucketMapEntry(
            bucket="pre-bucket2",
            bucket_path="PATH2",
            object_key="",
        )
    ]


@pytest.mark.parametrize(
    "bucket_map",
    (
        {"foo": "bucket1"},
        {"foo": {"bucket": "bucket1"}},
        {"MAP": {"foo": {"bucket": "bucket1"}}}
    )
)
def test_entries_compatibility(bucket_map):
    b_map = BucketMap(bucket_map)

    assert list(b_map.entries()) == [
        BucketMapEntry(
            bucket="bucket1",
            bucket_path="foo",
            object_key="",
        )
    ]


def test_entries_nested():
    bucket_map = {
        "PATH": {
            "LEVEL1": {
                "LEVEL2": "bucket-name"
            }
        },
    }

    b_map = BucketMap(bucket_map)

    assert list(b_map.entries()) == [
        BucketMapEntry(
            bucket="bucket-name",
            bucket_path="PATH/LEVEL1/LEVEL2",
            object_key="",
        )
    ]


def test_entries(sample_bucket_map):
    b_map = BucketMap(sample_bucket_map)

    assert list(b_map.entries()) == [
        BucketMapEntry(
            bucket="authed-bucket",
            bucket_path="ANY_AUTHED",
            object_key="",
        ),
        BucketMapEntry(
            bucket="browse-bucket",
            bucket_path="general-browse",
            object_key="",
            _access_control={"": _PUBLIC}
        ),
        BucketMapEntry(
            bucket="bucket",
            bucket_path="productX",
            object_key="",
            _access_control={
                "2020/12": {"science_team"},
                "browse": _PUBLIC
            }
        ),
        BucketMapEntry(
            bucket="nested-bucket-public",
            bucket_path="nested/nested2a/nested3",
            object_key="",
        ),
        BucketMapEntry(
            bucket="nested-bucket-private",
            bucket_path="nested/nested2b",
            object_key="",
            _access_control={"": set()}
        ),
    ]


def test_entries_with_headers():
    bucket_map = {
        "PATH": {
            "bucket": "bucket-name",
            "headers": {
                "Header1": "Value1"
            }
        }
    }
    b_map = BucketMap(bucket_map)

    assert list(b_map.entries()) == [
        BucketMapEntry(
            bucket="bucket-name",
            bucket_path="PATH",
            object_key="",
            headers={"Header1": "Value1"}
        )
    ]


def test_check_bucket_access(sample_bucket_map):
    b_map = BucketMap(sample_bucket_map)

    assert BucketMap({}).get("productX") is None
    assert b_map.get("productX") is None

    assert b_map.get("productX/obj1").is_accessible() is False
    assert b_map.get("ANY_AUTHED/obj1").is_accessible() is False
    assert b_map.get("ANY_AUTHED/obj1").is_accessible(groups=[]) is True
    assert b_map.get("general-browse/obj1").is_accessible() is True
    assert b_map.get("general-browse/obj1").is_accessible(groups=["science_team"]) is True
    assert b_map.get("productX/browse/obj1").is_accessible() is True
    assert b_map.get("productX/2020/12/obj1").is_accessible(groups=["science_team"]) is True
    assert b_map.get("productX/2020/23/obj2").is_accessible(groups=["science_team"]) is True
    assert b_map.get("productX/2020/12/obj1").is_accessible() is False
    assert b_map.get("nested/nested2b/obj1").is_accessible() is False
    assert b_map.get("nested/nested2b/obj1").is_accessible(groups=[]) is True


def test_check_bucket_access_conflicting():
    # When a bucket is configured to be both public and private
    bucket_map = {
        "MAP": {
            "PATH": "bucket"
        },
        "PUBLIC_BUCKETS": [
            "bucket"
        ],
        "PRIVATE_BUCKETS": {
            "bucket": ["some_permission"]
        }
    }
    b_map = BucketMap(bucket_map)

    assert b_map.get("PATH/obj1").is_accessible() is False
    assert b_map.get("PATH/obj1").is_accessible(groups=["some_permission"]) is True


def test_check_bucket_access_nested_paths():
    bucket_map = {
        "MAP": {
            "nested": {
                "nested2a": {
                    "nested3": "nested-bucket-public"
                },
                "nested2b": "nested-bucket-private"
            }
        },
        "PUBLIC_BUCKETS": {
            "nested-bucket-public": "Public bucket in 'nested'"
        },
        "PRIVATE_BUCKETS": {
            "nested-bucket-private": ["science_team"]
        }
    }
    b_map = BucketMap(bucket_map)

    assert b_map.get("nested/obj1") is None
    assert b_map.get("nested/nested2a/obj1") is None
    assert b_map.get("nested/nested2a/nested3") is None

    assert b_map.get("nested/nested2b/obj1").is_accessible() is False
    assert b_map.get("nested/nested2b/obj1").is_accessible(groups=["wrong_group"]) is False
    assert b_map.get("nested/nested2b/obj1").is_accessible(groups=["science_team"]) is True
    assert b_map.get("nested/nested2a/nested3/obj1").is_accessible() is True


def test_check_bucket_access_nested_prefixes():
    bucket_map = {
        "MAP": {
            "PATH": "bucket"
        },
        "PUBLIC_BUCKETS": [
            "bucket/foo/browse"
        ],
        "PRIVATE_BUCKETS": {
            "bucket/foo": ["some_permission"]
        }
    }
    b_map = BucketMap(bucket_map)

    assert b_map.get("PATH/obj1").is_accessible() is False
    assert b_map.get("PATH/foo/obj1").is_accessible() is False
    assert b_map.get("PATH/foo/obj1").is_accessible(groups=["some_permission"]) is True
    assert b_map.get("PATH/foo/browse/obj1").is_accessible(groups=["some_permission"]) is True
    assert b_map.get("PATH/foo/browse/obj1").is_accessible() is True


def test_check_bucket_access_depth():
    bucket_map = {
        "MAP": {
            "PATH": "bucket"
        },
        "PUBLIC_BUCKETS": [
            "bucket/browse"
        ],
        "PRIVATE_BUCKETS": {
            "bucket/browse/foo": ["some_permission"]
        }
    }
    b_map = BucketMap(bucket_map)

    assert b_map.get("PATH/obj1").is_accessible() is False
    assert b_map.get("PATH/browse/foo/obj1").is_accessible() is False
    assert b_map.get("PATH/browse/foo/obj1").is_accessible(groups=["some_permission"]) is True
    assert b_map.get("PATH/browse/obj1").is_accessible(groups=["some_permission"]) is True
    assert b_map.get("PATH/browse/obj1").is_accessible() is True


def test_check_bucket_access_malformed():
    bucket_map = {
        "MAP": {
            "PATH": "bucket"
        },
        "PUBLIC_BUCKETS": 10
    }
    b_map = BucketMap(bucket_map)

    assert b_map.get("PATH/obj1").is_accessible() is False


def test_get_required_groups(sample_bucket_map):
    b_map = BucketMap(sample_bucket_map)

    assert b_map.get("productX/obj1").get_required_groups() == set()
    assert b_map.get("ANY_AUTHED/obj1").get_required_groups() == set()
    assert b_map.get("general-browse/obj1").get_required_groups() is None
    assert b_map.get("productX/browse/obj1").get_required_groups() is None
    assert b_map.get("productX/2020/12/obj1").get_required_groups() == {"science_team"}
    assert b_map.get("productX/2020/23/obj2").get_required_groups() == set()
