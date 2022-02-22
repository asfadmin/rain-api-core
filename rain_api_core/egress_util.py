import hmac
import logging
import os
import urllib.parse
from datetime import datetime
from hashlib import sha256

from rain_api_core.bucket_map import BucketMap

log = logging.getLogger(__name__)

# This warning is stupid
# pylint: disable=logging-fstring-interpolation


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


def get_bucket_dynamic_path(path_list: list, b_map: dict):
    # Old and REVERSE format has no 'MAP'.
    node = b_map.get("MAP", b_map)

    log.debug("Pathparts is {}".format(path_list))
    # Walk the bucket map to see if this path is valid
    for i, path_part in enumerate(path_list):
        # Check if we hit a leaf of the YAML tree
        if isinstance(node, str):
            bucket = node
            headers = {}
        elif "bucket" in node:
            bucket = node["bucket"]
            headers = node.get("headers") or {}

        elif path_part in node:
            node = node[path_part]
            continue
        else:
            log.warning("Could not find {} in bucketmap".format(path_part))
            log.debug("bucketmap: {}".format(node))
            break

        assert bucket is not None
        # Split the path into bucket_name and object_name
        head, tail = path_list[:i], path_list[i:]
        bucket_path = "/".join(head)
        object_name = "/".join(tail)

        log.info("Bucket mapping was {0}, object was {1}".format(bucket_path, object_name))
        return prepend_bucketname(bucket), bucket_path, object_name, headers

    return None, None, None, {}


def process_varargs(varargs: str, b_map: dict):
    """
    wrapper around process_request that returns legacy values to preserve backward compatibility
    :param varargs: a list with the path to the file requested.
    :param b_map: bucket map
    :return: path, bucket, object_name
    """
    log.warning('Deprecated process_varargs() called.')
    path, bucket, object_name, _ = process_request(varargs, b_map)
    return path, bucket, object_name


def process_request(varargs: str, b_map: dict):
    split_args = varargs.split("/")

    # Make sure we got at least 1 path, and 1 file name:
    if len(split_args) < 2:
        return varargs, None, None, {}

    # Watch for ASF-ish reverse URL mapping formats:
    reverse = os.getenv('USE_REVERSE_BUCKET_MAP', 'FALSE').lower() == 'true'
    if len(split_args) == 3:
        if reverse:
            split_args[0], split_args[1] = split_args[1], split_args[0]

    # Look up the bucket from path parts
    bucket_map = BucketMap(b_map, get_bucket_name_prefix(), reverse=reverse)
    entry = bucket_map.get_path(split_args)

    # If we didn't figure out the bucket, we don't know the path/object_name
    if entry is None:
        object_name = split_args.pop(-1)
        return "/".join(split_args), None, object_name, {}

    return entry.bucket_path, entry.bucket, entry.object_key, entry.headers


def bucket_prefix_match(bucket_check: str, bucket_map: str, object_name: str = "") -> bool:
    # NOTE: https://github.com/asfadmin/thin-egress-app/issues/188
    log.debug(f"bucket_prefix_match(): checking if {bucket_check} matches {bucket_map} w/ optional obj '{object_name}'")
    prefix, *tail = bucket_map.split("/", 1)
    if bucket_check == prefix and object_name.startswith("/".join(tail)):
        log.debug(f"Prefixed Bucket Map matched: s3://{bucket_check}/{object_name} => {bucket_map}")
        return True
    return False


# Sort public/private buckets such that object-prefixes are processed FIRST
def get_sorted_bucket_list(b_map: dict, bucket_group: str) -> list:
    if bucket_group not in b_map:
        # But why?!
        log.warning(f"Bucket map does not contain bucket group '{bucket_group}'")
        return []

    # b_map[bucket_group] SHOULD be a dict, but list actually works too.
    if isinstance(b_map[bucket_group], dict):
        return sorted(list(b_map[bucket_group].keys()), key=lambda e: e.count("/"), reverse=True)
    if isinstance(b_map[bucket_group], list):
        return sorted(list(b_map[bucket_group]), key=lambda e: e.count("/"), reverse=True)

    # Something went wrong.
    return []


def check_private_bucket(bucket: str, b_map: dict, object_name: str = ""):
    log.debug('check_private_buckets(): bucket: {}'.format(bucket))

    # Check public bucket file:
    if 'PRIVATE_BUCKETS' in b_map:
        # Prioritize prefixed buckets first, the deeper the better!
        # TODO(reweeden): cache the sorted list (refactoring to object would be easiest)
        sorted_buckets = get_sorted_bucket_list(b_map, 'PRIVATE_BUCKETS')
        log.debug(f"Sorted PRIVATE buckets are {sorted_buckets}")
        for priv_bucket in sorted_buckets:
            if bucket_prefix_match(bucket, prepend_bucketname(priv_bucket), object_name):
                # This bucket is PRIVATE, return group!
                return b_map['PRIVATE_BUCKETS'][priv_bucket]

    return False


def check_public_bucket(bucket: str, b_map: dict, object_name: str = ""):
    # Check for PUBLIC_BUCKETS in bucket map file
    if 'PUBLIC_BUCKETS' in b_map:
        # TODO(reweeden): cache the sorted list (refactoring to object would be easiest)
        sorted_buckets = get_sorted_bucket_list(b_map, 'PUBLIC_BUCKETS')
        log.debug(f"Sorted PUBLIC buckets are {sorted_buckets}")
        for pub_bucket in sorted_buckets:
            if bucket_prefix_match(bucket, prepend_bucketname(pub_bucket), object_name):
                # This bucket is public!
                log.debug("found a public, we'll take it")
                return True

    # Did not find this in public bucket list
    log.debug('we did not find a public bucket for {}'.format(bucket))
    return False
