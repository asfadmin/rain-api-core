import logging
import hmac
from hashlib import sha256
import os
import urllib
from datetime import datetime

log = logging.getLogger(__name__)


def prepend_bucketname(name):

    prefix = os.getenv('BUCKETNAME_PREFIX', "gsfc-ngap-{}-".format(os.getenv('MATURITY', 'DEV')[0:1].lower()))
    return "{}{}".format(prefix, name)


def hmacsha256(key, string):

    return hmac.new(key, string.encode('utf-8'), sha256)


def get_presigned_url(session, bucket_name, object_name, region_name, expire_seconds, user_id, method='GET'):

    timez = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    datez = timez[:8]
    hostname = "{0}.s3{1}.amazonaws.com".format(bucket_name, "."+region_name if region_name != "us-east-1" else "")

    cred   = session['Credentials']['AccessKeyId']
    secret = session['Credentials']['SecretAccessKey']
    token  = session['Credentials']['SessionToken']

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
    can_req = method + "\n/" + object_name + "\n" + can_query_string + "\nhost:" + hostname + "\n\nhost\nUNSIGNED-PAYLOAD"
    can_req_hash = sha256(can_req.encode('utf-8')).hexdigest()

    # String to Sign
    stringtosign = "\n".join(["AWS4-HMAC-SHA256", timez, aws4_request, can_req_hash])

    # Signing Key
    StepOne =    hmacsha256( "AWS4{0}".format(secret).encode('utf-8'), datez).digest()
    StepTwo =    hmacsha256( StepOne, region_name ).digest()
    StepThree =  hmacsha256( StepTwo, "s3").digest()
    SigningKey = hmacsha256( StepThree, "aws4_request").digest()


    # Final Signature
    Signature = hmacsha256(SigningKey, stringtosign).hexdigest()

    # Dump URL
    url = "https://" + hostname + "/" + object_name + "?" + can_query_string + "&X-Amz-Signature=" + Signature
    return url


def get_bucket_dynamic_path(path_list, b_map):

    # Old and REVERSE format has no 'MAP'. In either case, we don't want it fouling our dict.
    if 'MAP' in b_map:
        map_dict = b_map['MAP']
    else:
        map_dict = b_map

    mapping = []

    log.debug("Pathparts is {0}".format(", ".join(path_list)))
    # walk the bucket map to see if this path is valid
    for path_part in path_list:
        # Check if we hit a leaf of the YAML tree
        if (mapping and isinstance(map_dict, str)) or 'bucket' in map_dict: #
            customheaders = {}
            if isinstance(map_dict, dict) and 'bucket' in map_dict:
                bucketname = map_dict['bucket']
                if 'headers' in map_dict:
                    customheaders = map_dict['headers']
            else:
                bucketname = map_dict

            log.debug(f'mapping: {mapping}')
            # Pop mapping off path_list
            for _ in mapping:
                path_list.pop(0)

            # Join the remaining bits together to form object_name
            object_name = "/".join(path_list)
            bucket_path = "/".join(mapping)

            log.info("Bucket mapping was {0}, object was {1}".format(bucket_path, object_name))
            return prepend_bucketname(bucketname), bucket_path, object_name, customheaders

        if path_part in map_dict:
            map_dict = map_dict[path_part]
            mapping.append(path_part)
            log.debug("Found {0}, Mapping is now {1}".format(path_part, "/".join(mapping)))

        else:
            log.warning("Could not find {0} in bucketmap".format(path_part))
            log.debug('said bucketmap: {}'.format(map_dict))
            return False, False, False, {}

    # what? No path?
    return False, False, False, {}


def process_varargs(varargs: list, b_map: dict):
    """
    wrapper around process_request that returns legacy values to preserve backward compatibility
    :param varargs: a list with the path to the file requested.
    :param b_map: bucket map
    :return: path, bucket, object_name
    """
    log.warning('Deprecated process_varargs() called.')
    path, bucket, object_name, headers = process_request(varargs, b_map)
    return path, bucket, object_name


def process_request(varargs, b_map):

    varargs = varargs.split("/")

    # Make sure we got at least 1 path, and 1 file name:
    if len(varargs) < 2:
        return "/".join(varargs), None, None, []

    # Watch for ASF-ish reverse URL mapping formats:
    if len(varargs) == 3:
        if os.getenv('USE_REVERSE_BUCKET_MAP', 'FALSE').lower() == 'true':
            varargs[0], varargs[1] = varargs[1], varargs[0]

    # Look up the bucket from path parts
    bucket, path, object_name, headers = get_bucket_dynamic_path(varargs, b_map)

    # If we didn't figure out the bucket, we don't know the path/object_name
    if not bucket:
        object_name = varargs.pop(-1)
        path = "/".join(varargs)

    return path, bucket, object_name, headers

def bucket_prefix_match(bucket_check, bucket_map, object_name=""):
    log.debug(f"bucket_prefix_match(): checking if {bucket_check} matches {bucket_map} w/ optional obj '{object_name}'")
    if bucket_check == bucket_map.split('/')[0] and object_name.startswith("/".join(bucket_map.split('/')[1:])):
        log.debug(f"Prefixed Bucket Map matched: s3://{bucket_check}/{object_name} => {bucket_map}")
        return True
    return False


# Sort public/private buckets such that object-prefixes are processed FIRST
def get_sorted_bucket_list(b_map, bucket_group):
    if bucket_group not in b_map:
        # But why?!
        log.warning(f"Bucket map does not contain bucket group '{bucket_group}'")
        return []
    
    # b_map[bucket_group] SHOULD be a dict, but list actually works too.
    if  isinstance(b_map[bucket_group], dict):
        return sorted(list(b_map[bucket_group].keys()), key=lambda e: e.count("/"), reverse=True )
    elif isinstance(b_map[bucket_group], list):
        return sorted(list(b_map[bucket_group]), key=lambda e: e.count("/"), reverse=True )
    
    # Something went wrong.
    return []

def check_private_bucket(bucket, b_map, object_name=""):

    log.debug('check_private_buckets(): bucket: {}'.format(bucket))

    # Check public bucket file:
    if 'PRIVATE_BUCKETS' in b_map:
        # Prioritize prefixed buckets first, the deeper the better!
        sorted_buckets = get_sorted_bucket_list(b_map, 'PRIVATE_BUCKETS')
        log.debug(f"Sorted PRIVATE buckets are {sorted_buckets}")
        for priv_bucket in sorted_buckets:
            if bucket_prefix_match(bucket, prepend_bucketname(priv_bucket), object_name):
                # This bucket is PRIVATE, return group!
                return b_map['PRIVATE_BUCKETS'][priv_bucket]

    return False

def check_public_bucket(bucket, b_map, object_name=""):

    # Check for PUBLIC_BUCKETS in bucket map file
    if 'PUBLIC_BUCKETS' in b_map:
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
