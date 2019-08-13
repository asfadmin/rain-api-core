
import logging
import os
import re
import urllib
from time import time
from json import loads

from .view_util import make_set_cookie_headers, make_set_cookie_headers_jwt, get_exp_time, decode_jwt_payload
from .aws_util import retrieve_secret
from .session_util import store_session

log = logging.getLogger(__name__)




def get_base_url(ctxt=False):
    # Make a redirect url using optional custom domain_name, otherwise use raw domain/stage provided by API Gateway.
    try:
        return 'https://{}/'.format(
            os.getenv('DOMAIN_NAME', '{}/{}'.format(ctxt['domainName'], ctxt['stage'])))
    except (TypeError, IndexError) as e:
        log.error('could not create a redirect_url, because {}'.format(e))
        raise


def get_redirect_url(ctxt=False):
    return '{}login'.format(get_base_url(ctxt))


def do_auth(code, redirect_url):

    url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + "/oauth/token"

    # App U:P from URS Application
    auth = get_urs_creds()['UrsAuth']

    post_data = {"grant_type": "authorization_code",
                 "code": code,
                 "redirect_uri": redirect_url}

    headers = {"Authorization": "BASIC " + auth}
    post_data_encoded = urllib.parse.urlencode(post_data).encode("utf-8")
    post_request = urllib.request.Request(url, post_data_encoded, headers)

    t0 = time()
    try:
        log.debug('headers: {}'.format(headers))
        log.debug('url: {}'.format(url))
        log.debug('post_data: {}'.format(post_data))

        response = urllib.request.urlopen(post_request)                               #nosec URL is *always* URS.
        t1 = time()
        packet = response.read()
        log.debug('ET to do_auth() urlopen(): {} sec'.format(t1 - t0))
        log.debug('ET to do_auth() request to URS: {} sec'.format(time() - t0))
        return loads(packet)

    except urllib.error.URLError as e:
        log.error("Error fetching auth: {0}".format(e))
        log.debug('ET for the attempt: {}'.format(format(round(time() - t0, 4))))
        return {}


def get_urs_url(ctxt, to=False):

    base_url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + '/oauth/authorize'

    # From URS Application
    client_id = get_urs_creds()['UrsId']

    log.debug('domain name: %s' % os.getenv('DOMAIN_NAME', 'no domainname set'))
    log.debug('if no domain name set: {}/{}'.format(ctxt['domainName'], ctxt['stage']))

    urs_url = '{0}?client_id={1}&response_type=code&redirect_uri={2}'.format(base_url, client_id, get_redirect_url(ctxt))
    if to:
        urs_url += "&state={0}".format(to)

    # Try to handle scripts
    agent_pattern = re.compile('^(curl|wget|aria2|python)', re.IGNORECASE)

    try:
        download_agent = ctxt['identity']['userAgent']
    except IndexError:
        log.debug("No User Agent!")
        return urs_url

    if agent_pattern.match(download_agent):
        urs_url += "&app_type=401"

    return urs_url


def get_profile(user_id, token, temptoken=False):
    if not user_id or not token:
        return {}

    # get_new_token_and_profile() will pass this function a temporary token with which to fetch the profile info. We
    # don't want to keep it around, just use it here, once:
    if temptoken:
        headertoken = temptoken
    else:
        headertoken = token

    url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + "/api/users/{0}".format(user_id)
    headers = {"Authorization": "Bearer " + headertoken}
    req = urllib.request.Request(url, None, headers)

    t0 = time()
    try:

        response = urllib.request.urlopen(req)  # nosec URL is *always* URS.
        t1 = time()
        packet = response.read()

        user_profile = loads(packet)
        t2 = time()
        store_session(user_id, token, user_profile)
        t3 = time()
        log.debug('ET for get_profile() urlopen() {} sec'.format(t1 - t0))
        log.debug('ET for get_profile() response.read() and loads() {} sec'.format(t2 - t1))
        log.debug('ET for get_profile() store_session() {} sec'.format(t3 - t2))

        return user_profile

    except urllib.error.URLError as e:
        log.warning("Error fetching profile: {0}".format(e))
        log.debug('ET for the attempt: {}'.format(format(round(time() - t0, 4))))
        if not temptoken: # This keeps get_new_token_and_profile() from calling this over and over
            log.debug('because error above, going to get_new_token_and_profile()')
            return get_new_token_and_profile(user_id, token)
        else:
            log.debug('We got that 401 above and we\'re using a temptoken ({}), so giving up and not getting a profile.'.format(temptoken))
            return {}


def check_profile(cookies):
    try:
        token = cookies['urs-access-token']
        user_id = cookies['urs-user-id']
    except(IndexError, KeyError):
        token = False
        user_id = False

    if token and user_id:
        return get_profile(user_id, token)

    log.warning('Did not find token ({0}) or user_id ({1})'.format(token, user_id))
    return False


def get_new_token_and_profile(user_id, cookietoken):

    # get a new token
    url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + "/oauth/token"

    # App U:P from URS Application
    auth = get_urs_creds()['UrsAuth']
    post_data = {"grant_type": "client_credentials" }
    headers = {"Authorization": "BASIC " + auth}

    # Download token
    post_data_encoded = urllib.parse.urlencode(post_data).encode("utf-8")
    post_request = urllib.request.Request(url, post_data_encoded, headers)

    t0 = time()
    try:
        log.info("Attempting to get new Token")

        response = urllib.request.urlopen(post_request)                              #nosec URL is *always* URS.
        t1 = time()
        packet = response.read()
        new_token = loads(packet)['access_token']
        t2 = time()
        log.info("Retrieved new token: {0}".format(new_token))
        log.debug('ET for get_new_token_and_profile() urlopen() {} sec'.format(t1 - t0))
        log.debug('ET for get_new_token_and_profile() response.read() and loads() {} sec'.format(t2- t1))
        # Get user profile with new token
        return get_profile(user_id, cookietoken, new_token)

    except urllib.error.URLError as e:
        log.error("Error fetching auth: {0}".format(e))
        log.debug('ET for the attempt: {}'.format(format(round(time() - t0, 4))))
        return False


def user_in_group_list(private_groups, user_groups):
    client_id = get_urs_creds()['UrsId']
    log.info("Searching for private groups {0} in {1}".format(private_groups, user_groups))
    for u_g in user_groups:
        if u_g['client_id'] == client_id:
            for p_g in private_groups:
                if p_g == u_g['name']:
                    # Found the matching group!
                    log.info("User belongs to private group {}".format(p_g))
                    return True


def user_in_group_urs(private_groups, user_id, user_profile=None, refresh_first=False):

    if user_profile and 'user_groups' in user_profile and user_in_group_list(private_groups, user_profile['user_groups']):
        log.info("User {0} belongs to private group".format(user_id))
        return True

    # User likely isn't in ANY groups
    else:
        log.warning('user_groups block not found in user profile!')

    if not refresh_first:
        # maybe refreshing the user's profile will help
        log.info("Could not validate user {0} belonging to groups {1}, attempting profile refresh".format(user_id,
                                                                                                          private_groups))
        return user_in_group_urs(private_groups, user_id, {}, refresh_first=True)

    log.warning("Even after profile refresh, user {0} does not belong to groups {1}".format(user_id, private_groups))
    return False


def user_in_group(private_groups, cookievars, user_profile=None, refresh_first=False):
    if not private_groups:
        return False

    try:
        jwt = cookievars['asf-urs']

    except (KeyError, IndexError) as e:
        log.warning('JWT cookie not present. Falling back to "urs-user-id" and "urs-access-token"')
        if refresh_first or not user_profile:
            user_profile = get_profile(cookievars['urs-user-id'], cookievars['urs-access-token'])

        return user_in_group_urs(private_groups, cookievars['urs-user-id'], user_profile, refresh_first)
    else:

        jwt_payload = decode_jwt_payload(jwt)

        if refresh_first:
            jwt_payload['user_groups'] = get_profile(jwt_payload['urs-user-id'], jwt_payload['urs-access-token'])['user_groups']
            # TODO: reset fresh group-membership JWT cookie now? Somehow?

        in_group = user_in_group_list(private_groups, jwt_payload['user_groups'])
        if in_group:
            return True
        elif not in_group and not refresh_first:
            # TODO: look at ['iat'] and if cookie is recent enough (how recent?), don't bother doing this.
            # one last ditch effort to see if they were so very recently added to group:
            jwt_payload['user_groups'] = get_profile(jwt_payload['urs-user-id'], jwt_payload['urs-access-token'])['user_groups']
            return user_in_group(private_groups, cookievars, {}, refresh_first=True)
        else:
            return False


# return looks like:
# {
#     "UrsId": "stringofseeminglyrandomcharacters",
#     "UrsAuth": "verymuchlongerstringofseeminglyrandomcharacters"
# }
def get_urs_creds():

    secret_name = os.getenv('URS_CREDS_SECRET_NAME', None)

    if not secret_name:
        log.error('URS_CREDS_SECRET_NAME not set')
        return {}
    secret = retrieve_secret(secret_name)
    if not ('UrsId' in secret and 'UrsAuth' in secret):
        log.error('AWS secret {} does not contain required keys "UrsId" and "UrsAuth"'.format(secret_name))

    return secret


# This do_login() is mainly for chalice clients.
def do_login(args, context, cookie_domain=''):

    log.debug('the query_params: {}'.format(args))

    if not args:
        template_vars = {'contentstring': 'No params', 'title': 'Could Not Login'}
        headers = {}
        return 400, template_vars, headers

    if args.get('error', False):
        contentstring = 'An error occurred while trying to log into URS. URS says: "{}". '.format(args.get('error', ''))
        if args.get('error') == 'access_denied':
            # This happens when user doesn't agree to EULA. Maybe other times too.
            return_status = 401
            contentstring += 'Be sure to agree to the EULA.'
        else:
            return_status = 400

        template_vars = {'contentstring': contentstring, 'title': 'Could Not Login'}

        return return_status, template_vars, {}

    if 'code' not in args:
        contentstring = 'Did not get the required CODE from URS'

        template_vars = {'contentstring': contentstring, 'title': 'Could not login.'}
        headers = {}
        return 400, template_vars, headers

    log.debug('pre-do_auth() query params: {}'.format(args))
    redir_url = get_redirect_url(context)
    auth = do_auth(args.get('code', ''), redir_url)
    log.debug('auth: {}'.format(auth))
    if not auth:
        log.debug('no auth returned from do_auth()')

        template_vars = {'contentstring': 'There was a problem talking to URS Login', 'title': 'Could Not Login'}

        return 400, template_vars, {}

    user_id = auth['endpoint'].split('/')[-1]

    user_profile = get_profile(user_id, auth['access_token'])
    log.debug('Got the user profile: {}'.format(user_profile))
    if user_profile:
        log.debug('urs-access-token: {}'.format(auth['access_token']))
        if 'state' in args:
            redirect_to = args["state"]
        else:
            redirect_to = get_base_url(context)

        if 'user_groups' not in user_profile or not user_profile['user_groups']:
            user_profile['user_groups'] = []

        jwt_cookie_payload = {
            'urs-user-id': user_id,
            'urs-access-token': auth['access_token'],
            'urs-groups': user_profile['user_groups'],
            'iat': int(time()),
            'exp': get_exp_time(),
        }

        headers = {'Location': redirect_to}
        headers.update(make_set_cookie_headers(user_id, auth['access_token'], '', cookie_domain))
        headers.update(make_set_cookie_headers_jwt(jwt_cookie_payload, '', cookie_domain))
        return 301, {}, headers

    template_vars = {'contentstring': 'Could not get user profile from URS', 'title': 'Could Not Login'}
    return 400, template_vars, {}
