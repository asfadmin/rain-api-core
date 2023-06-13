import hmac
import os
import urllib.parse
from datetime import datetime
from hashlib import sha256


def prepend_bucketname(name: str) -> str:
    prefix = get_bucket_name_prefix()
    return f"{prefix}{name}"


def get_bucket_name_prefix() -> str:
    prefix = os.getenv("BUCKETNAME_PREFIX")
    if prefix is None:
        maturity = os.getenv("MATURITY", "DEV")[0].lower()
        prefix = f"gsfc-ngap-{maturity}-"

    return prefix


def hmacsha256(key: bytes, string: str) -> hmac.HMAC:
    return hmac.new(key, string.encode(), sha256)


def get_presigned_url(session, bucket_name, object_name, region_name, expire_seconds, user_id, method='GET') -> str:
    timez = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    datez = timez[:8]
    region_id = "." + region_name if region_name != "us-east-1" else ""
    hostname = f"{bucket_name}.s3{region_id}.amazonaws.com"

    cred = session['Credentials']['AccessKeyId']
    secret = session['Credentials']['SecretAccessKey']
    token = session['Credentials']['SessionToken']

    aws4_request = "/".join([datez, region_name, "s3", "aws4_request"])
    cred_string = f"{cred}/{aws4_request}"

    can_query_string = "&".join([
        f"A-userid={user_id}",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "X-Amz-Credential=" + urllib.parse.quote_plus(cred_string),
        "X-Amz-Date=" + timez,
        f"X-Amz-Expires={expire_seconds}",
        "X-Amz-Security-Token=" + urllib.parse.quote_plus(token),
        "X-Amz-SignedHeaders=host"
    ])

    can_request = (
        f"{method}\n"
        f"/{object_name}\n"
        f"{can_query_string}\n"
        f"host:{hostname}\n\n"
        "host\n"
        "UNSIGNED-PAYLOAD"
    )
    can_request_hash = sha256(can_request.encode()).hexdigest()

    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        timez,
        aws4_request,
        can_request_hash
    ])

    step_one = hmacsha256(f"AWS4{secret}".encode(), datez).digest()
    step_two = hmacsha256(step_one, region_name).digest()
    step_three = hmacsha256(step_two, "s3").digest()
    signing_key = hmacsha256(step_three, "aws4_request").digest()

    signature = hmacsha256(signing_key, string_to_sign).hexdigest()

    return f"https://{hostname}/{object_name}?{can_query_string}&X-Amz-Signature={signature}"
