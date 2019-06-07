
import logging
import os
import sys
from json import loads
from yaml import safe_load
from boto3 import client as botoclient, resource as botoresource, session as botosession, Session as boto_Session
from botocore.config import Config as bc_Config
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


def retrieve_secret(secret_name):

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
            return loads(get_secret_value_response['SecretString'])

    return {}


def get_s3_resource():

    params = {}
    # Swift signature compatability
    if os.getenv('S3_SIGNATURE_VERSION'):
        params['config'] = bc_Config(signature_version=os.getenv('S3_SIGNATURE_VERSION'))
    s3 = botoresource('s3', **params)
    return s3


def write_s3(bucket, key, data):

    log.debug("Writing data to s3://{1}/{0}".format(key, bucket))
    params = {}
    # Swift signature compatability
    if os.getenv('S3_SIGNATURE_VERSION'):
        params['config'] = bc_Config(signature_version=os.getenv('S3_SIGNATURE_VERSION'))
    s3 = botoresource('s3', **params)
    s3object = s3.Object(bucket, key)
    s3object.put(Body=data)
    return True


def read_s3(bucket, key):

    log.info("Downloading config file {0} from s3://{1}...".format(key, bucket))
    s3 = get_s3_resource()
    obj = s3.Object(bucket, key)
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