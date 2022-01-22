import json
from unittest import mock

import boto3
import botocore
import moto
import pytest
from netaddr import IPNetwork

from rain_api_core.aws_util import (
    check_in_region_request,
    get_region,
    get_region_cidr_ranges,
    get_role_creds,
    get_role_session,
    get_s3_resource,
    get_yaml,
    get_yaml_file,
    read_s3,
    retrieve_secret,
    role_creds_cache
)

MODULE = "rain_api_core.aws_util"


def test_get_region():
    assert get_region() == "us-east-1"


@mock.patch(f"{MODULE}.boto_Session.region_name", new_callable=mock.PropertyMock)
@mock.patch(f"{MODULE}.region", "")
def test_get_region_cache(mock_region_name):
    mock_region_name.return_value = "us-east-1"

    assert get_region() == "us-east-1"
    assert get_region() == "us-east-1"
    mock_region_name.assert_called_once()


@moto.mock_secretsmanager
def test_retrieve_secret():
    client = boto3.client("secretsmanager")
    client.create_secret(Name="secret_name", SecretString='{"foo": "bar"}')

    assert retrieve_secret("secret_name") == {"foo": "bar"}


@moto.mock_secretsmanager
def test_retrieve_secret_binary():
    client = boto3.client("secretsmanager")
    client.create_secret(Name="binary_secret_name", SecretBinary=b"foobar")

    assert retrieve_secret("binary_secret_name") == {}


@mock.patch(f"{MODULE}.botosess", autospec=True)
def test_retrieve_secret_cached(mock_botosess):
    client = mock_botosess.client()
    client.get_secret_value.return_value = {"SecretString": '{"foo": "bar"}'}

    assert retrieve_secret("cached_secret_name") == {"foo": "bar"}
    # Now change the secret value
    client.get_secret_value.return_value = {"SecretString": '{"baz": "qux"}'}
    assert retrieve_secret("cached_secret_name") == {"foo": "bar"}
    client.get_secret_value.assert_called_once()


@moto.mock_secretsmanager
def test_retrieve_secret_nonexistent():
    with pytest.raises(botocore.exceptions.ClientError):
        assert retrieve_secret("does_not_exist") == {"foo": "bar"}


@moto.mock_s3
def test_get_s3_resource_cached(monkeypatch):
    monkeypatch.setenv("S3_SIGNATURE_VERSION", "v2")

    assert get_s3_resource() is get_s3_resource()


@moto.mock_s3
def test_read_s3():
    resource = boto3.resource("s3")
    bucket = resource.Bucket("test_bucket")
    bucket.create()
    bucket.put_object(Key="test_file", Body=b"foobar")

    assert read_s3("test_bucket", "test_file", resource) == "foobar"
    assert read_s3("test_bucket", "test_file") == "foobar"


@moto.mock_s3
def test_read_s3_nonexistent():
    resource = boto3.resource("s3")

    with pytest.raises(botocore.exceptions.ClientError):
        assert read_s3("nonexistent", "test_file", resource)


@moto.mock_s3
def test_get_yaml(data):
    resource = boto3.resource("s3")
    bucket = resource.Bucket("test_bucket")
    bucket.create()
    with open(data / "sample.yaml") as f:
        bucket.put_object(Key="sample.yaml", Body=f.read())

    assert get_yaml("test_bucket", "sample.yaml") == {"key": ["value1", "value2"]}


@moto.mock_s3
def test_get_yaml_nonexistent():
    with pytest.raises(botocore.exceptions.ClientError):
        assert get_yaml("nonexistent", "sample.yaml")


@moto.mock_s3
def test_get_yaml_file(data):
    resource = boto3.resource("s3")
    bucket = resource.Bucket("test_bucket")
    bucket.create()
    with open(data / "sample.yaml") as f:
        bucket.put_object(Key="sample.yaml", Body=f.read())

    assert get_yaml_file("test_bucket", "sample.yaml") == {"key": ["value1", "value2"]}


@moto.mock_s3
def test_get_yaml_file_nonexistent():
    assert get_yaml_file("nonexistent", "") == {}

    # TODO(reweeden): a library function like this should NEVER be raising a SystemExit
    with pytest.raises(SystemExit):
        assert get_yaml_file("nonexistent", "sample.yaml")


@moto.mock_sts
def test_get_role_creds(monkeypatch):
    monkeypatch.setenv("EGRESS_APP_DOWNLOAD_ROLE_ARN", "egress_app_download_role_arn")
    monkeypatch.setitem(role_creds_cache, "egress_app_download_role_arn", {})

    session, session_offset = get_role_creds("user_id")
    assert session == {
        "AssumedRoleUser": {
            "Arn": mock.ANY,
            "AssumedRoleId": mock.ANY
        },
        "Credentials": {
            "AccessKeyId": mock.ANY,
            "Expiration": mock.ANY,
            "SecretAccessKey": mock.ANY,
            "SessionToken": mock.ANY
        },
        "PackedPolicySize": 6,
        "ResponseMetadata": {
            "HTTPHeaders": {
                "server": "amazon.com"
            },
            "HTTPStatusCode": 200,
            "RequestId": "c6104cbe-af31-11e0-8154-cbc7ccf896c7",
            "RetryAttempts": 0
        }
    }
    assert session_offset == 0


@moto.mock_sts
@mock.patch(f"{MODULE}.time", autospec=True)
def test_get_role_creds_cached(mock_time, monkeypatch):
    monkeypatch.setenv("EGRESS_APP_DOWNLOAD_ROLE_ARN", "egress_app_download_role_arn")
    monkeypatch.setitem(role_creds_cache, "egress_app_download_role_arn", {})
    mock_time.return_value = 0

    session1, _ = get_role_creds("user_id2")
    session2, _ = get_role_creds("user_id2")

    assert session1 is session2

    mock_time.return_value = 1000
    session3, _ = get_role_creds("user_id2")

    assert session1 is not session3
    assert session1 != session3


@moto.mock_sts
def test_get_role_session_cached(monkeypatch):
    monkeypatch.setenv("EGRESS_APP_DOWNLOAD_ROLE_ARN", "egress_app_download_role_arn")
    monkeypatch.setitem(role_creds_cache, "egress_app_download_role_arn", {})

    session1 = get_role_session(user_id="user_id3")
    session2 = get_role_session(user_id="user_id3")
    session3 = get_role_session(user_id="user_id4")

    assert session1 is session2
    assert session1 is not session3


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
def test_get_region_cidr_ranges(mock_request, data):
    with open(data / "ip-ranges.json", "rb") as f:
        content = f.read()

    mock_request.urlopen("").read.return_value = content

    assert get_region_cidr_ranges() == [
        IPNetwork("43.224.79.212/31"),
        IPNetwork("52.94.152.9/32"),
        IPNetwork("13.34.43.192/27"),
        IPNetwork("15.181.232.0/21"),
        IPNetwork("52.93.127.163/32"),
        IPNetwork("3.2.0.0/24")
    ]


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.region_list_cache", [])
def test_get_region_cidr_ranges_cached(mock_request):
    mock_request.urlopen("").read.return_value = b'{"prefixes": [{"ip_prefix": "10.0.0.1/24", "region": "us-east-1"}]}'

    get_region_cidr_ranges()
    assert mock_request.urlopen.call_count == 2
    get_region_cidr_ranges()
    assert mock_request.urlopen.call_count == 2


@mock.patch(f"{MODULE}.urllib.request", autospec=True)
@mock.patch(f"{MODULE}.region_list_cache", [])
def test_get_region_cidr_ranges_bad_data(mock_request):
    mock_request.urlopen("").read.return_value = json.dumps({
        "prefixes": [
            {},
            {
                "ip_prefix": "10.0.0.1/24",
                "region": "us-east-1"
            }
        ]
    }).encode()

    assert get_region_cidr_ranges() == [
        IPNetwork("10.0.0.1/24"),
    ]


@mock.patch(f"{MODULE}.get_region_cidr_ranges", autospec=True)
def test_check_in_region_request(mock_get_region_cidr_ranges):
    mock_get_region_cidr_ranges.return_value = [IPNetwork("10.0.0.0/24")]

    assert check_in_region_request("10.0.0.1") is True
    assert check_in_region_request("10.0.0.255") is True
    assert check_in_region_request("10.0.1.1") is False
