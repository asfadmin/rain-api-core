import logging
import os
from typing import Optional

from rain_api_core.auth import JwtManager, UserProfile
from rain_api_core.aws_util import retrieve_secret
from rain_api_core.edl import EdlClient, EdlException
from rain_api_core.logging import log_context

log = logging.getLogger(__name__)


def get_base_url(ctxt: dict = None) -> str:
    # Make a redirect url using optional custom domain_name, otherwise use raw domain/stage provided by API Gateway.
    try:
        domain = os.getenv('DOMAIN_NAME') or f"{ctxt['domainName']}/{ctxt['stage']}"
        return f'https://{domain}/'
    except (TypeError, KeyError) as e:
        log.error('could not create a redirect_url, because {}'.format(e))
        raise


def get_redirect_url(ctxt: dict = None) -> str:
    return f'{get_base_url(ctxt)}login'


def do_auth(code: str, redirect_url: str, aux_headers: dict = {}) -> dict:
    # App U:P from URS Application
    auth = get_urs_creds()['UrsAuth']

    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_url,
    }

    headers = {'Authorization': 'Basic ' + auth}
    headers.update(aux_headers)

    client = EdlClient()
    try:
        return client.request(
            'POST',
            '/oauth/token',
            data=data,
            headers=headers,
        )
    except EdlException:
        return {}


def get_urs_url(ctxt: dict, to: str = None) -> str:
    base_url = os.getenv('AUTH_BASE_URL', 'https://urs.earthdata.nasa.gov') + '/oauth/authorize'

    # From URS Application
    client_id = get_urs_creds()['UrsId']

    log.debug('domain name: {0}'.format(os.getenv('DOMAIN_NAME', 'no domainname set')))
    log.debug('if no domain name set: {}.execute-api.{}.amazonaws.com/{}'.format(
        ctxt['apiId'],
        os.getenv('AWS_DEFAULT_REGION', '<region>'),
        ctxt['stage']
    ))

    urs_url = f'{base_url}?client_id={client_id}&response_type=code&redirect_uri={get_redirect_url(ctxt)}'
    if to:
        urs_url += f"&state={to}"

    # Try to handle scripts
    try:
        download_agent = ctxt['identity']['userAgent']
    except KeyError:
        log.debug("No User Agent!")
        return urs_url

    if not download_agent.startswith('Mozilla'):
        urs_url += "&app_type=401"

    return urs_url


def get_user_profile(urs_user_payload: dict, access_token) -> UserProfile:
    return UserProfile(
        user_id=urs_user_payload['uid'],
        token=access_token,
        groups=urs_user_payload['user_groups'],
        first_name=urs_user_payload['first_name'],
        last_name=urs_user_payload['last_name'],
        email=urs_user_payload['email_address'],
    )


def get_profile(
    user_id: str,
    token: str,
    temptoken: str = None,
    aux_headers: dict = {},
) -> Optional[UserProfile]:
    if not user_id or not token:
        return None

    # get_new_token_and_profile() will pass this function a temporary token with
    # which to fetch the profile info. We don't want to keep it around, just use
    # it here, once:
    if temptoken:
        headertoken = temptoken
    else:
        headertoken = token

    headers = {'Authorization': 'Bearer ' + headertoken}
    headers.update(aux_headers)
    params = {'client_id': get_urs_creds()['UrsId']}

    client = EdlClient()
    try:
        user_profile = client.request(
            'GET',
            f'/api/users/{user_id}',
            params=params,
            headers=headers,
        )
        return get_user_profile(user_profile, headertoken)
    except EdlException as e:
        log.warning('Error fetching profile: %s', e.inner)
        if not temptoken:  # This keeps get_new_token_and_profile() from calling this over and over
            log.debug('because error above, going to get_new_token_and_profile()')
            return get_new_token_and_profile(user_id, token, aux_headers)

        log.debug(
            f"We got that 401 above and we're using a temptoken ({temptoken}), "
            "so giving up and not getting a profile."
        )
    return None


def get_new_token_and_profile(
    user_id: str,
    cookietoken: str,
    aux_headers: dict = {},
) -> Optional[UserProfile]:
    # App U:P from URS Application
    auth = get_urs_creds()['UrsAuth']
    data = {'grant_type': 'client_credentials'}

    headers = {'Authorization': 'Basic ' + auth}
    headers.update(aux_headers)

    client = EdlClient()
    try:
        log.info('Attempting to get new Token')

        response = client.request(
            'POST',
            '/oauth/token',
            data=data,
            headers=headers,
        )
        new_token = response['access_token']

        log.info('Retrieved new token: %s', new_token)
        # Get user profile with new token
        return get_profile(
            user_id,
            cookietoken,
            new_token,
            aux_headers=aux_headers,
        )
    except EdlException:
        return None


def user_in_group_list(private_groups: list, user_groups: list) -> bool:
    client_id = get_urs_creds()['UrsId']
    log.info("Searching for private groups {0} in {1}".format(private_groups, user_groups))

    group_names = {group["name"] for group in user_groups if group["client_id"] == client_id}

    for group in private_groups:
        if group in group_names:
            log.info("User belongs to private group {}".format(group))
            return True
    return False


def user_in_group_urs(private_groups, user_id, token, user_profile=None, refresh_first=False, aux_headers=None):
    aux_headers = aux_headers or {}  # A safer default
    new_profile = {}

    if refresh_first or not user_profile:
        user_profile = get_profile(user_id, token, aux_headers=aux_headers)
        new_profile = user_profile

    if (
        isinstance(user_profile, dict)
        and 'user_groups' in user_profile
        and user_in_group_list(private_groups, user_profile['user_groups'])
    ):
        log.info("User {0} belongs to private group".format(user_id))
        return True, new_profile

    # Couldn't find user in provided groups, but we may as well look at a fresh group list:
    if not refresh_first:
        # we have a maybe not so fresh user_profile and we could try again to see if someone added a group to this user:
        log.debug(f"Could not validate user {user_id} belonging to groups {private_groups}, attempting profile refresh")

        return user_in_group_urs(private_groups, user_id, {}, refresh_first=True, aux_headers=aux_headers)
    log.debug("Even after profile refresh, user {0} does not belong to groups {1}".format(user_id, private_groups))

    return False, new_profile


def user_in_group(private_groups, user_profile: UserProfile, refresh_first=False, aux_headers=None):
    aux_headers = aux_headers or {}  # A safer default

    # If a new profile is fetched, it is assigned to this var, and returned so that a fresh jwt cookie can be set.
    new_profile = None

    if not private_groups:
        return False, new_profile

    if not user_profile:
        return False, new_profile

    if refresh_first:
        new_profile = get_profile(user_profile.user_id, user_profile.token, aux_headers=aux_headers)
        user_profile.groups = new_profile.groups

    in_group = user_in_group_list(private_groups, user_profile.groups)
    if in_group:
        return True, new_profile

    if not in_group and not refresh_first:
        # one last ditch effort to see if they were so very recently added to group:
        user_profile = get_profile(
            user_profile.user_id,
            user_profile.token,
            aux_headers=aux_headers
        )
        return user_in_group(private_groups, user_profile, refresh_first=True, aux_headers=aux_headers)

    return False, new_profile


def get_urs_creds() -> dict:
    """
    Fetches URS creds from secrets manager.
    :return: looks like:
            {
                "UrsId": "stringofseeminglyrandomcharacters",
                "UrsAuth": "verymuchlongerstringofseeminglyrandomcharacters"
            }
    :type: dict
    """
    secret_name = os.getenv('URS_CREDS_SECRET_NAME')

    if not secret_name:
        log.error('URS_CREDS_SECRET_NAME not set')
        return {}

    secret = retrieve_secret(secret_name)
    if not ('UrsId' in secret and 'UrsAuth' in secret):
        log.error('AWS secret {} does not contain required keys "UrsId" and "UrsAuth"'.format(secret_name))

    return secret


# This do_login() is mainly for chalice clients.
def do_login(args, context, jwt_manager: JwtManager, cookie_domain='', aux_headers=None):
    aux_headers = aux_headers or {}  # A safer default

    log.debug('the query_params: {}'.format(args))

    if not args:
        template_vars = {'contentstring': 'No params', 'title': 'Could Not Login'}
        headers = {}
        return 400, template_vars, headers

    if args.get('error', False):
        contentstring = 'An error occurred while trying to log into URS. URS says: "{}". '.format(args.get('error', ''))
        template_vars = {'contentstring': contentstring, 'title': 'Could Not Login'}
        if args.get('error') == 'access_denied':
            # This happens when user doesn't agree to EULA. Maybe other times too.
            return_status = 401
            template_vars['contentstring'] = 'Be sure to agree to the EULA.'
            template_vars['error_code'] = 'EULA_failure'
        else:
            return_status = 400

        return return_status, template_vars, {}

    if 'code' not in args:
        contentstring = 'Did not get the required CODE from URS'

        template_vars = {'contentstring': contentstring, 'title': 'Could Not Login'}
        headers = {}
        return 400, template_vars, headers

    log.debug('pre-do_auth() query params: {}'.format(args))
    redir_url = get_redirect_url(context)
    auth = do_auth(args.get('code', ''), redir_url, aux_headers=aux_headers)
    log.debug('auth: {}'.format(auth))
    if not auth:
        log.debug('no auth returned from do_auth()')

        template_vars = {'contentstring': 'There was a problem talking to URS Login', 'title': 'Could Not Login'}

        return 400, template_vars, {}

    user_id = auth['endpoint'].split('/')[-1]
    log_context(user_id=user_id)

    user_profile = get_profile(user_id, auth['access_token'], aux_headers={})
    log.debug('Got the user profile: {}'.format(user_profile))
    if user_profile is not None:
        log.debug('urs-access-token: {}'.format(auth['access_token']))
        if 'state' in args:
            redirect_to = args["state"]
        else:
            redirect_to = get_base_url(context)

        headers = {'Location': redirect_to}
        headers.update(jwt_manager.get_header_to_set_auth_cookie(user_profile, cookie_domain))
        return 301, {}, headers

    template_vars = {'contentstring': 'Could not get user profile from URS', 'title': 'Could Not Login'}
    return 400, template_vars, {}
