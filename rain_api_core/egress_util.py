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
    return hmac.new(key, string.encode('utf-8'), sha256)


def get_presigned_url(session, bucket_name, object_name, region_name, expire_seconds, user_id, method='GET') -> str:
    timez = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    datez = timez[:8]
    hostname = "{0}.s3{1}.amazonaws.com".format(bucket_name, "." + region_name if region_name != "us-east-1" else "")

    cred = session['Credentials']['AccessKeyId']
    secret = session['Credentials']['SecretAccessKey']
    token = session['Credentials']['SessionToken']

    aws4_request = "/".join([datez, region_name, "s3", "aws4_request"])
    cred_string = "{0}/{1}".format(cred, aws4_request)

    # Canonical Query String Parts
    parts = ["A-userid={0}".format(user_id),
             "X-Amz-Algorithm=AWS4-HMAC-SHA256",
             "X-Amz-Credential="+urllib.parse.quote_plus(cred_string),
             "X-Amz-Date="+timez,
             "X-Amz-Expires={0}".format(expire_seconds),
             "X-Amz-Security-Token="+urllib.parse.quote_plus(token),
             "X-Amz-SignedHeaders=host"]

    can_query_string = "&".join(parts)

    # Canonical Requst
    can_req = (
        f"{method}\n"
        f"/{object_name}\n"
        f"{can_query_string}\n"
        f"host:{hostname}\n\n"
        "host\n"
        "UNSIGNED-PAYLOAD"
    )
    can_req_hash = sha256(can_req.encode('utf-8')).hexdigest()

    # String to Sign
    stringtosign = "\n".join(["AWS4-HMAC-SHA256", timez, aws4_request, can_req_hash])

    # Signing Key
    StepOne = hmacsha256("AWS4{0}".format(secret).encode('utf-8'), datez).digest()
    StepTwo = hmacsha256(StepOne, region_name).digest()
    StepThree = hmacsha256(StepTwo, "s3").digest()
    SigningKey = hmacsha256(StepThree, "aws4_request").digest()

    # Final Signature
    Signature = hmacsha256(SigningKey, stringtosign).hexdigest()

    # Dump URL
    url = "https://" + hostname + "/" + object_name + "?" + can_query_string + "&X-Amz-Signature=" + Signature
    return url
