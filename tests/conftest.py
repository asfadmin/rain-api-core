import logging
import os
from pathlib import Path

import boto3
import pytest
from moto.core import patch_client, patch_resource

logging.getLogger("rain_api_core").setLevel(logging.DEBUG)


class MockBoto3Session(boto3.Session):
    def client(self, *args, **kwargs):
        client = super().client(*args, **kwargs)
        patch_client(client)
        return client

    def resource(self, *args, **kwargs):
        resource = super().resource(*args, **kwargs)
        patch_resource(resource)
        return resource


# TODO(reweeden): Do we need both?
# boto3.Session = MockBoto3Session
boto3.session.Session = MockBoto3Session


@pytest.fixture(scope="session", autouse=True)
def aws_config():
    """Set up aws cli/boto configuration

    This makes sure we don't accidentally touch real resources.
    """
    # NOTE: This will persist beyond the pytest session,
    # however, the process should terminate immediately afterwards.
    os.environ["AWS_ACCESS_KEY_ID"] = "TEST_ACCESS_KEY_ID"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "TEST_SECRET_ACCESS_KEY"
    os.environ["AWS_SECURITY_TOKEN"] = "TEST_SECURITY_TOKEN"
    os.environ["AWS_SESSION_TOKEN"] = "TEST_SESSION_TOKEN"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="module")
def data(request):
    return Path(request.fspath).parent / "data"


@pytest.fixture(scope="session")
def jwt_priv_key():
    return """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBANagXeaHD8qqP3u/R5ozLClxNxlgCdvKYkETk/VU1gjLZjQF8ngc
GaNPVM9ndQ3JX8Ot24aeZEDk6bZcwD/YZtMCAwEAAQJARaCe9eOJFvlmQPIL+5Vw
VT16X4wNhrVAbNY6INPV3+HsbJPrUjc72dY/PQf6cMBXgKl9ykq75WsKW5ZghEhA
wQIhAPGjMI+zlKAvvq2DnW5D1gEzuFhsiLt/tmAgTW9xSnThAiEA42Ir0/98h0wq
kgpnpbT6aQOD0TOIWIZWyumBhYmo3jMCIQC1HGyMeLxAaCjR4uE/wUaIthxI4miF
qI6oc+22RsLY4QIgbb+kh954rJUGtxZukHyZoLYhmYfV92Rf3/B0o4+eAiECIBR2
xOewMazHL1H31fI4/iUYYU6x5I1DTMh4XiAA2ffi
-----END RSA PRIVATE KEY-----"""


@pytest.fixture(scope="session")
def jwt_pub_key():
    return """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANagXeaHD8qqP3u/R5ozLClxNxlgCdvK
YkETk/VU1gjLZjQF8ngcGaNPVM9ndQ3JX8Ot24aeZEDk6bZcwD/YZtMCAwEAAQ==
-----END PUBLIC KEY-----
    """
