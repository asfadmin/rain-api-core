import json
import logging
import os

from boto3 import client as botoclient
from botocore.exceptions import ClientError
from time import time

from .aws_util import write_s3, read_s3, get_s3_resource

log = logging.getLogger(__name__)

active_sessions = {}
session_store = os.getenv('SESSION_STORE', 'DB')
sessttl = int(os.getenv('SESSION_TTL', '168')) * 60 * 60
if session_store == 'DB':
    ddb = botoclient('dynamodb')
    sesstable = os.getenv('SESSION_TABLE')
else:
    ddb = sesstable = None


def cache_session(user_id, token, session):

    global active_sessions                                                            # pylint: disable=global-statement

    session_path = craft_profile_path(user_id, token)
    active_sessions[session_path] = {'profile': session, 'timestamp': round(time())}


def uncache_session(user_id, token):

    global active_sessions                                                            # pylint: disable=global-statement

    session_path = craft_profile_path(user_id, token)
    try:
        active_sessions.pop(session_path)
    except KeyError:
        # If it's not there, it's not there.
        pass


def prune_cached_sessions():

    # Expire and re-fetch session after 3600 minutes
    pruneable = []
    for pp in active_sessions:
        if active_sessions[pp]['timestamp'] < round(time()) - 3600:
            log.debug("Found memory cached profile {0} to be {1} seconds old".format(pp, round(time()) -
                                                                                     active_sessions[pp]['timestamp']))
            pruneable.append(pp)
    for pp in pruneable:
        log.debug("Pruning old session: {0}".format(pp))
        active_sessions.pop(pp)


def get_cached_session(user_id, token):

    global active_sessions                                                            # pylint: disable=global-statement

    prune_cached_sessions()

    key = craft_profile_path(user_id, token)
    if key in active_sessions:

        log.debug('wow, returning cached session: {}'.format(key))
        #log.debug('this is it: {}'.format(active_sessions[key]))
        return active_sessions[key]['profile']

    return {}


def get_session(user_id, token):
    t0 = time()
    sess = get_cached_session(user_id, token)
    if sess:
        log.debug('ET session retrieval (cached): {} sec'.format(round(time() - t0, 4)))
        return sess

    if session_store == 'DB':
        return get_session_from_db(user_id, token)

    if session_store == 'S3':
        return get_session_from_s3(user_id, token)


def get_session_from_db(user_id, token):
    t0 = time()
    session_path = craft_profile_path(user_id, token)
    keydict = {'id': {'S': session_path}}
    resp = ddb.get_item(TableName=sesstable, Key=keydict)
    try:
        session = json.loads(resp['Item']['session']['S'])
        cache_session(user_id, token, session)
        log.debug('ET session retrieval (from DB): {} sec'.format(round(time() - t0, 4)))
        return session
    except KeyError as e:
        log.error('trouble getting session out of table for {} because {}. This is what they gave us: {}'.format(user_id, e, resp))
        return {}


def craft_profile_path(user_id, token):
    return "{0}/{1}".format(user_id, token)


def get_session_from_s3(user_id, token):
    t0 = time()
    profile_path = craft_profile_path(user_id, token)
    try:
        profile = json.loads(read_s3(os.getenv('SESSION_BUCKET', "rain-t-config"), profile_path))
        log.debug('ET session retrieval (from S3): {} sec'.format(round(time() - t0, 4)))
    except ClientError as e:
        log.warning('error loading profile: ')
        log.warning(e)
        return {}
    log.debug("Saving memory cached profile @ {0}".format(profile_path))
    cache_session(user_id, token, profile)
    return profile


def store_session(user_id, token, sess):
    log.debug('storing session into {} for {}: {}'.format(session_store, user_id, sess))
    cache_session(user_id, token, sess)
    log.debug('{}/{} session cached in lambda memory'.format(user_id, token))
    if session_store == 'DB':
        return store_session_in_db(user_id, token, sess)
    if session_store == 'S3':
        return store_session_in_s3(user_id, token, sess)


def store_session_in_db(user_id, token, sess):
    t0 = time()
    item = {'id': {'S': '{}/{}'.format(user_id, token)},
            'expires': {'N': str(int(time()) + sessttl)},
            'session': {'S': json.dumps(sess)}}
    log.debug('putting {} into table {}'.format(item, sess))
    ddb.put_item(TableName=sesstable, Item=item)
    log.debug('ET session store (to DB): {} sec'.format(round(time() - t0, 4)))
    return True


def store_session_in_s3(user_id, token, user_profile):
    t0 = time()
    profile_path = craft_profile_path(user_id, token)
    write_s3(os.getenv('SESSION_BUCKET', None), profile_path, json.dumps(user_profile))
    log.debug('ET session store (to s3): {} sec'.format(round(time() - t0, 4)))
    return True


def extend_session_ttl(user_id, token):
    if session_store == 'DB':
        return extend_session_ttl_db(user_id, token)
    if session_store == 'S3':
        return extend_session_ttl_s3(user_id, token)


def extend_session_ttl_db(user_id, token):
    keydict = {'id': {'S': '{}/{}'.format(user_id, token)}}
    updexpr = 'set expires = :e'
    exprattrval = {':e': str(int(time()) + sessttl)}
    ddb.update_item(TableName=sesstable, Key=keydict, UpdateExpression=updexpr, ExpressionAttributeValues=exprattrval)


def extend_session_ttl_s3(user_id, token):
    raise NotImplementedError


def delete_session(user_id, token):
    uncache_session(user_id, token)
    if session_store == 'DB':
        return delete_session_db(user_id, token)
    if session_store == 'S3':
        return delete_session_s3(user_id, token)


def delete_session_db(user_id, token):
    keydict = {'id': {'S': '{}/{}'.format(user_id, token)}}
    resp = ddb.delete_item(TableName=sesstable, Key=keydict)
    log.debug('result from delete: {}'.format(resp))
    return True


def delete_session_s3(user_id, token):
    s3 = get_s3_resource()
    key = craft_profile_path(user_id, token)
    try:
        log.info("Attempting to delete s3 object {0} from s3://{1}...".format(key, os.getenv('SESSION_BUCKET', None)))
        s3.Object(os.getenv('SESSION_BUCKET', None), key).delete()
    except ClientError as e:
        if e.response['Error']['Code'] == "404":
            log.debug("File to delete was not found. Good enough.")
            return True

        return False
    return True


