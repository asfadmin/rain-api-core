
import logging
import os
import sys
import urllib
from netaddr import IPAddress, IPNetwork
from json import loads
from time import time
from yaml import safe_load
from boto3 import client as botoclient, resource as botoresource, session as botosession, Session as boto_Session
from boto3.resources.base import ServiceResource
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)
secret_cache = {}
region_list_cache = []
region = ''
botosess = botosession.Session()
role_creds_cache = {}

def get_region():
    """
    Will determine and return current AWS region.
    :return: string describing AWS region
    :type: string
    """
    global region                                                                      #pylint: disable=global-statement
    if not region:
        region = botosession.Session().region_name
    return region


def retrieve_secret(secret_name):

    global secret_cache                                                               # pylint: disable=global-statement
    global botosess                                                                   # pylint: disable=global-statement
    t0 = time()

    if secret_name in secret_cache:
        log.debug('ET for retrieving secret {} from cache: {} sec'.format(secret_name, round(time() - t0, 4)))
        return secret_cache[secret_name]

    region_name = os.getenv('AWS_DEFAULT_REGION')

    # Create a Secrets Manager client
    client = botosess.client(
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
    """

    :return: subclass of boto3.resources.base.ServiceResource
    """
    params = {}
    # Swift signature compatability
    if os.getenv('S3_SIGNATURE_VERSION'):
        params['config'] = bc_Config(signature_version=os.getenv('S3_SIGNATURE_VERSION'))
    s3 = botoresource('s3', **params)
    return s3


def read_s3(bucket: str, key: str, s3: ServiceResource=None):
    """
    returns file
    :type bucket: str
    :param bucket:

    :type key: str
    :param key:
    :param s3: S3 resource

    :return: str
    """
    if not s3:
        log.warning('creating a S3 resource in read_s3() function')
        s3 = get_s3_resource()
    t0 = time()
    log.info("Downloading config file {0} from s3://{1}...".format(key, bucket))
    obj = s3.Object(bucket, key)
    log.debug('ET for reading {} from S3: {} sec'.format(key, round(time() - t0, 4)))
    return obj.get()['Body'].read().decode('utf-8')


def get_yaml(bucket: str, file_name: str, s3: ServiceResource=None):
    """
    Loads the YAML from a given bucket/filename
    :param bucket: bucket name
    :param file_name: file path/name
    :return:
    """
    try:
        cfg_yaml = read_s3(bucket, file_name)
        return safe_load(cfg_yaml)
    except ClientError as e:
        log.error('Had trouble getting yaml file s3://{}/{}, {}'.format(bucket, file_name, e))
        raise


def get_yaml_file(bucket, key, s3: ServiceResource=None):

    if not key:
        # No file was provided, send empty dict
        return {}
    try:
        log.info("Attempting to download yaml s3://{0}/{1}".format(bucket, key))
        optional_file = get_yaml(bucket, key, s3)
        return optional_file
    except ClientError as e:
        # The specified file did not exist
        log.error("Could not download yaml @ s3://{0}/{1}: {2}".format(bucket, key, e))
        sys.exit()


def get_role_creds(user_id: str='', in_region: bool=False):
    """
    :param user_id: string with URS username
    :param in_region: boolean If True a download role that works only in region will be returned
    :return: Returns a set of temporary security credentials (consisting of an access key ID, a secret access key, and a security token)
    """
    sts = botoclient('sts')
    if not user_id:
        user_id = 'unauthenticated'

    if user_id not in role_creds_cache:
        if in_region:
            download_role_arn = os.getenv('EGRESS_APP_DOWNLOAD_ROLE_INREGION_ARN')
        else:
            download_role_arn = os.getenv('EGRESS_APP_DOWNLOAD_ROLE_ARN')

        log.debug('assuming role: {}, role session username: {}'.format(download_role_arn, user_id))
        role_creds_cache[user_id] = sts.assume_role(RoleArn=download_role_arn, RoleSessionName=user_id)

    return role_creds_cache[user_id]


def get_role_session(creds=None, user_id=None):

    sts_resp = creds if creds else get_role_creds(user_id)
    log.debug('sts_resp: {}'.format(sts_resp))
    session = boto_Session(
        aws_access_key_id=sts_resp['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_resp['Credentials']['SecretAccessKey'],
        aws_session_token=sts_resp['Credentials']['SessionToken'])

    return session


def get_region_cidr_ranges():
    """
    :return: Utility function to download AWS regions
    """

    global region_list_cache                                                           #pylint: disable=global-statement

    if not region_list_cache:                                                    #pylint: disable=used-before-assignment
        url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
        req = urllib.request.Request(url)
        r = urllib.request.urlopen(req).read()                               #nosec URL is *always* https://ip-ranges...

        region_list_json = loads(r.decode('utf-8'))
        region_list_cache = []

        # Sort out ONLY values from this AWS region
        for pre in region_list_json["prefixes"]:
            if "ip_prefix" in pre and "region" in pre:
                if pre["region"] == get_region():
                    region_list_cache.append(IPNetwork(pre["ip_prefix"]))

    return region_list_cache


def check_in_region_request(ip_addr: str):
    """
    :param ip_addr: string with ip address to be checked for in-regionness
    :return: boolean True if ip_addr is in_region, False otherwise
    :type: Boolean
    """

    for cidr in get_region_cidr_ranges():
        #log.debug("Checking ip {0} vs cidr {1}".format(user_ip, cidr))
        if IPAddress(ip_addr) in cidr:
            log.info("IP {0} matched in-region CIDR {1}".format(ip_addr, cidr))
            return True

    return False
