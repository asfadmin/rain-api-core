
import logging
import os
import sys
import urllib
from netaddr import IPAddress, IPNetwork
from json import loads
from time import time
from yaml import safe_load
from boto3 import client as botoclient, resource as botoresource, session as botosession, Session as boto_Session
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)
secret_cache = {}
region_list_cache = []

def get_region():
    url = 'http://169.254.169.254/latest/dynamic/instance-identity/document'
    try:
        req = urllib.request.Request(url)
        log.debug("Downloading region data from inside AWS")
        r = urllib.request.urlopen(req, timeout=1.5).read()
        return loads(r.decode('utf-8'))["region"]
    except Exception as e:                                                                 #pylint: disable=broad-except
        log.warning("Could not download region metadata, using us-east-1: {0}".format(e))
        return "us-east-1"


aws_region = get_region()

def retrieve_secret(secret_name):

    global secret_cache                                                               # pylint: disable=global-statement
    t0 = time()

    if secret_name in secret_cache:
        log.debug('ET for retrieving secret {} from cache: {} sec'.format(secret_name, round(time() - t0, 4)))
        return secret_cache[secret_name]

    region_name = os.getenv('AWS_DEFAULT_REGION')
    # Create a Secrets Manager client
    session = botosession.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        log.error("Encountered fatal error trying to reading URS Secret: {0}".format(e))
        raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:

            secret = loads(get_secret_value_response['SecretString'])
            secret_cache[secret_name] = secret
            log.debug('ET for retrieving secret {} from secret store: {} sec'.format(secret_name, round(time() - t0, 4)))
            return secret

    return {}


def get_s3_resource():

    params = {}
    # Swift signature compatability
    if os.getenv('S3_SIGNATURE_VERSION'):
        params['config'] = bc_Config(signature_version=os.getenv('S3_SIGNATURE_VERSION'))
    s3 = botoresource('s3', **params)
    return s3


def write_s3(bucket, key, data):

    t0 = time()
    log.debug("Writing data to s3://{1}/{0}".format(key, bucket))
    params = {}
    # Swift signature compatability
    if os.getenv('S3_SIGNATURE_VERSION'):
        params['config'] = bc_Config(signature_version=os.getenv('S3_SIGNATURE_VERSION'))
    s3 = botoresource('s3', **params)
    s3object = s3.Object(bucket, key)
    s3object.put(Body=data)
    log.debug('ET for writing {} to S3: {} sec'.format(key, round(time() - t0, 4)))
    return True


def read_s3(bucket, key):

    t0 = time()
    log.info("Downloading config file {0} from s3://{1}...".format(key, bucket))
    s3 = get_s3_resource()
    obj = s3.Object(bucket, key)
    log.debug('ET for reading {} from S3: {} sec'.format(key, round(time() - t0, 4)))
    return obj.get()['Body'].read().decode('utf-8')



def get_yaml(bucket, file_name):

    try:
        cfg_yaml = read_s3(bucket, file_name)
        return safe_load(cfg_yaml)
    except ClientError as e:
        log.error('Had trouble getting yaml file s3://{}/{}, {}'.format(bucket, file_name, e))
        raise

def get_yaml_file(bucket, key):

    if not key:
        # No file was provided, send empty dict
        return {}
    try:
        log.info("Attempting to download yaml s3://{0}/{1}".format(bucket, key))
        optional_file = get_yaml( bucket, key )
        return optional_file
    except ClientError as e:
        # The specified file did not exist
        log.error("Could not download yaml @ s3://{0}/{1}: {2}".format(bucket, key, e))
        sys.exit()

def get_role_creds(user_id=None):

    sts = botoclient('sts')
    if not user_id:
        user_id = 'unauthenticated'
    download_role_arn = os.getenv('EGRESS_APP_DOWNLOAD_ROLE_ARN')
    log.debug('assuming role: {}, role session username: {}'.format(download_role_arn, user_id))
    return sts.assume_role(RoleArn=download_role_arn, RoleSessionName=user_id)

def get_role_session(creds=None, user_id=None):

    sts_resp = creds if creds else get_role_creds(user_id)
    log.debug('sts_resp: {}'.format(sts_resp))
    session = boto_Session(
        aws_access_key_id=sts_resp['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_resp['Credentials']['SecretAccessKey'],
        aws_session_token=sts_resp['Credentials']['SessionToken'])

    return session


def get_region_cidr_ranges():
    # Utility function to download AWS regions

    global region_list_cache                                                                 #pylint: disable=global-statement

    if not region_list_cache:                                                          #pylint: disable=used-before-assignment
        url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
        req = urllib.request.Request(url)
        r = urllib.request.urlopen(req).read()

        region_list_json = loads(r.decode('utf-8'))
        region_list_cache = []

        # Sort out ONLY values from this AWS region
        for pre in region_list_json["prefixes"]:
            if "ip_prefix" in pre and "region" in pre:
                if pre["region"] == aws_region:
                    region_list_cache.append(IPNetwork(pre["ip_prefix"]))

    return region_list_cache


def check_in_region_request(ip_addr:str):

    for cidr in get_region_cidr_ranges(): # TODO: use cached value for this
        #log.debug("Checking ip {0} vs cidr {1}".format(user_ip, cidr))
        if IPAddress(ip_addr) in cidr:
            log.info("IP {0} matched in-region CIDR {1}".format(ip_addr, cidr))
            return True

    return False
