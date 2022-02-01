import base64
import contextlib
import functools
import json
import logging
import os
import urllib
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from time import time
from wsgiref.handlers import format_date_time as format_7231_date

import jwt
from boto3 import client as botoclient
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape

from rain_api_core.aws_util import retrieve_secret
from rain_api_core.general_util import duration, return_timing_object

# This warning is stupid
# pylint: disable=logging-fstring-interpolation

log = logging.getLogger(__name__)

HTML_TEMPLATE_STATUS = ''
HTML_TEMPLATE_LOCAL_CACHEDIR = '/tmp/templates/'  # nosec We want to leverage instance persistance
HTML_TEMPLATE_PROJECT_DIR = Path().resolve() / 'templates'

_HOURS_PER_WEEK = 7 * 24
SESSTTL = int(os.getenv('SESSION_TTL', _HOURS_PER_WEEK)) * 60 * 60

JWT_ALGO = os.getenv('JWT_ALGO', 'RS256')
JWT_COOKIE_NAME = os.getenv('JWT_COOKIENAME', 'asf-urs')

JWT_BLACKLIST = {}


@functools.lru_cache(maxsize=None)
def get_jwt_keys() -> dict:
    raw_keys = retrieve_secret(os.getenv('JWT_KEY_SECRET_NAME', ''))

    return {
        k: base64.b64decode(v.encode('utf-8'))
        for k, v in raw_keys.items()
    }


def cache_html_templates() -> str:
    try:
        os.mkdir(HTML_TEMPLATE_LOCAL_CACHEDIR, 0o700)
    except FileExistsError:
        # good.
        log.debug('somehow, {} exists already'.format(HTML_TEMPLATE_LOCAL_CACHEDIR))

    templatedir = os.getenv('HTML_TEMPLATE_DIR')
    if not templatedir:
        return 'DEFAULT'

    bucket = os.getenv('CONFIG_BUCKET')
    if not templatedir.endswith('/'):  # we need a trailing slash
        templatedir = f'{templatedir}/'

    timer = time()
    client = botoclient('s3')
    try:
        result = client.list_objects(Bucket=bucket, Prefix=templatedir, Delimiter='/')
        log.info(return_timing_object(
            service="s3",
            endpoint=f"client().list_objects(s3://{bucket}/{templatedir}/)",
            duration=duration(timer)
        ))

        for o in result.get('Contents'):
            filename = os.path.basename(o['Key'])
            if filename:
                log.debug('attempting to save {}'.format(os.path.join(HTML_TEMPLATE_LOCAL_CACHEDIR, filename)))
                timer = time()
                client.download_file(bucket, o['Key'], os.path.join(HTML_TEMPLATE_LOCAL_CACHEDIR, filename))
                log.info(return_timing_object(
                    service="s3",
                    endpoint=f"client().download_file(s3://{bucket}/{o['Key']})",
                    duration=duration(timer)
                ))
        return 'CACHED'
    except (TypeError, KeyError) as e:
        log.error(e)
        log.error('Trouble trying to download HTML templates from s3://{}/{}'.format(bucket, templatedir))
        return 'ERROR'


def get_html_body(template_vars: dict, templatefile: str = 'root.html') -> str:
    global HTML_TEMPLATE_STATUS  # pylint: disable=global-statement

    if HTML_TEMPLATE_STATUS == '':
        HTML_TEMPLATE_STATUS = cache_html_templates()

    jin_env = Environment(
        loader=FileSystemLoader([
            HTML_TEMPLATE_LOCAL_CACHEDIR,
            HTML_TEMPLATE_PROJECT_DIR,
            # For legacy compatibility with projects that don't install this module with pip and rely on this behavior
            os.path.join(os.path.dirname(__file__), '../', "templates")
        ]),
        autoescape=select_autoescape(['html', 'xml'])
    )
    try:
        template = jin_env.get_template(templatefile)
    except TemplateNotFound as e:
        log.error('Template not found: {}'.format(e))
        return 'Cannot find the HTML template directory'

    return template.render(**template_vars)


def get_cookie_vars(headers: dict) -> dict:
    """
    Extracts and decodes and returns relevant cookies from http headers
    :param headers: dict of http headers
    :return: on success dict with keys env value of 'JWT_COOKIENAME' containing decoded jwt, 'urs-user-id',
        'urs-access-token' on failure empty dict.
    :type: dict
    """
    cooks = get_cookies(headers)
    try:
        if JWT_COOKIE_NAME in cooks:
            decoded_payload = decode_jwt_payload(cooks[JWT_COOKIE_NAME], JWT_ALGO)
            return {JWT_COOKIE_NAME: decoded_payload}
        else:
            log.debug('could not find jwt cookie in get_cookie_vars()')
    except KeyError as e:
        log.debug('Key error trying to get cookie vars: {}'.format(e))

    return {}


def get_exp_time() -> int:
    return int(time() + SESSTTL)


def get_cookie_expiration_date_str() -> str:
    return format_7231_date(get_exp_time())


def get_cookies(hdrs: dict) -> dict:
    cookie_string = hdrs.get('cookie') or hdrs.get('Cookie') or hdrs.get('COOKIE')
    if not cookie_string:
        return {}

    cookie = SimpleCookie()
    with contextlib.suppress(CookieError):
        cookie.load(cookie_string)

    return {
        key: morsel.value
        for key, morsel in cookie.items()
    }


def make_jwt_payload(payload: dict, algo: str = JWT_ALGO) -> str:
    try:
        log.debug('using secret: {}'.format(os.getenv('JWT_KEY_SECRET_NAME', '')))
        timer = time()
        encoded = jwt.encode(payload, get_jwt_keys()['rsa_priv_key'], algorithm=algo)
        log.info(return_timing_object(service="jwt", endpoint="jwt.encode()", duration=duration(timer)))
        return encoded
    except KeyError as e:
        log.error('jwt_keys may be malformed: ')
        log.error(e)
        return ''
    except (ValueError, AttributeError) as e:
        # TODO(reweeden): how can these error types possibly be triggered!? jwt.encode will raise a TypeError on bad
        # input, but never ValueError or AttributeError.
        log.error('problem with encoding cookie: {}'.format(e))
        return ''


def decode_jwt_payload(jwt_payload: str, algo: str = JWT_ALGO) -> dict:
    try:
        rsa_pub_key = get_jwt_keys()['rsa_pub_key']
        timer = time()
        cookiedecoded = jwt.decode(jwt_payload, rsa_pub_key, [algo])
        log.info(return_timing_object(service="jwt", endpoint="jwt.decode()", duration=duration(timer)))
    except jwt.ExpiredSignatureError:
        # Signature has expired
        log.info('JWT has expired')
        # TODO what more to do with this, if anything?
        return {}
    except jwt.InvalidSignatureError:
        log.info('JWT has failed verification. returning empty dict')
        return {}

    if os.getenv("BLACKLIST_ENDPOINT"):
        if is_jwt_blacklisted(cookiedecoded):
            return {}
    else:
        log.debug('No environment variable BLACKLIST_ENDPOINT')

    log.debug('cookiedecoded {}'.format(cookiedecoded))
    return cookiedecoded


def craft_cookie_domain_payloadpiece(cookie_domain: str) -> str:
    if cookie_domain:
        return f'; Domain={cookie_domain}'

    return ''


def make_set_cookie_headers_jwt(payload: dict, expdate: str = '', cookie_domain: str = '') -> dict:
    jwt_payload = make_jwt_payload(payload)
    cookie_domain_payloadpiece = craft_cookie_domain_payloadpiece(cookie_domain)

    if not expdate:
        expdate = get_cookie_expiration_date_str()
    headers = {'SET-COOKIE': f'{JWT_COOKIE_NAME}={jwt_payload}; Expires={expdate}; Path=/{cookie_domain_payloadpiece}'}
    return headers


def is_jwt_blacklisted(decoded_jwt: dict) -> bool:
    try:
        set_jwt_blacklist()
        urs_user_id = decoded_jwt["urs-user-id"]
        blacklist = JWT_BLACKLIST["blacklist"]
        user_blacklist_time = blacklist.get(urs_user_id)

        if user_blacklist_time is not None:
            jwt_mint_time = decoded_jwt["iat"]
            log.debug(f"JWT was minted @:  {jwt_mint_time}, the Blacklist is for cookies BEFORE: {user_blacklist_time}")

            if user_blacklist_time >= jwt_mint_time:
                log.info(f"User {urs_user_id}'s JWT was minted before blacklist date and is INVALID")
                return True
            else:
                log.info(f"User {urs_user_id}s JWT was minted AFTER blacklist date and is still VALID")

        log.info(f"User {urs_user_id} is NOT in the blacklist")
        return False
    except Exception:
        log.debug("Error checking JWT against the blacklist", exc_info=True)
        return False


def set_jwt_blacklist() -> dict:
    global JWT_BLACKLIST  # pylint: disable=global-statement

    if JWT_BLACKLIST and time() - JWT_BLACKLIST["timestamp"] <= (10 * 60):  # If cached in the last 10 minutes
        return JWT_BLACKLIST

    endpoint = os.getenv("BLACKLIST_ENDPOINT")
    # Bandit complains with B310 on the line below. We know the URL, this is safe!
    timer = time()
    output = urllib.request.urlopen(endpoint).read().decode('utf-8')  # nosec
    log.info(return_timing_object(service="blacklist", endpoint=endpoint, duration=duration(timer)))
    blacklist = json.loads(output)["blacklist"]

    contents = {
        "blacklist": blacklist,
        "timestamp": time()
    }

    JWT_BLACKLIST = contents  # Cache it
    return contents
