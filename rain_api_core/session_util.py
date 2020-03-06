import json
import logging
import os

from boto3 import client as botoclient
from botocore.exceptions import ClientError
from time import time

log = logging.getLogger(__name__)

active_sessions = {}

sessttl = int(os.getenv('SESSION_TTL', '168')) * 60 * 60


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


def craft_profile_path(user_id, token):
    return "{0}/{1}".format(user_id, token)






