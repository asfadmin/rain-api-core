import logging
import os

from boto3 import client as botoclient
from wsgiref.handlers import format_date_time as format_7231_date
from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateNotFound
from time import time

from .session_util import sessttl

log = logging.getLogger(__name__)

html_template_status = ''
html_template_local_cachedir = '/tmp/templates/'                                     #nosec We want to leverage instance persistance


def cache_html_templates():
    try:
        os.mkdir(html_template_local_cachedir, 0o700)
    except FileExistsError:
        # good.
        log.debug('somehow, {} exists already'.format(html_template_local_cachedir))

    if os.getenv('HTML_TEMPLATE_DIR', '') == '':
        return 'DEFAULT'

    bucket = os.getenv('CONFIG_BUCKET')
    templatedir = os.getenv('HTML_TEMPLATE_DIR')
    if not templatedir[-1] == '/': #we need a trailing slash
        templatedir = '{}/'.format(templatedir)

    client = botoclient('s3')
    try:
        result = client.list_objects(Bucket=bucket, Prefix=templatedir, Delimiter='/')

        for o in result.get('Contents'):
            filename = os.path.basename(o['Key'])
            if filename:
                log.debug('attempting to save {}'.format(os.path.join(html_template_local_cachedir, filename)))
                client.download_file(bucket, o['Key'], os.path.join(html_template_local_cachedir, filename))
        return 'CACHED'
    except (TypeError, KeyError) as e:
        log.error(e)
        log.error('Trouble trying to download HTML templates from s3://{}/{}'.format(bucket, templatedir))
        return 'ERROR'


def get_html_body(template_vars:dict, templatefile:str='root.html'):

    global html_template_status                                                       # pylint: disable=global-statement

    if html_template_status == '':
        html_template_status = cache_html_templates()

    jin_env = Environment(
        loader=FileSystemLoader([html_template_local_cachedir, os.path.join(os.path.dirname(__file__), '../', "templates")]),
        autoescape=select_autoescape(['html', 'xml'])
    )
    try:
        jin_tmp = jin_env.get_template(templatefile)

    except TemplateNotFound as e:
        log.error('Template not found: {}'.format(e))
        return 'Cannot find the HTML template directory'

    return jin_tmp.render(**template_vars)



def get_cookie_vars(headers):

    cooks = get_cookies(headers)
    log.debug('cooks: {}'.format(cooks))
    if 'urs-user-id' in cooks and 'urs-access-token' in cooks:
        return {'urs-user-id': cooks['urs-user-id'], 'urs-access-token': cooks['urs-access-token']}

    return {}




def get_cookie_expiration_date_str():

    return format_7231_date(time() + sessttl)
















def get_cookies(hdrs):

    cookies = {}
    pre_cookies = []
    if 'cookie' in hdrs:
        pre_cookies = hdrs['cookie'].split(';')
        for cook in pre_cookies:
            # print('x: {}'.format(cook))
            splitcook = cook.split('=')
            cookies.update({splitcook[0].strip(): splitcook[1].strip()})

    return cookies









def make_set_cookie_headers(user_id, access_token, expdate='', cookie_domain=''):
    if cookie_domain:
        cookie_domain_payloadpiece = '; Domain={}'.format(cookie_domain)
    else:
        cookie_domain_payloadpiece = ''

    log.debug('cookie domain: {}'.format(cookie_domain_payloadpiece))
    if not expdate:
        expdate = get_cookie_expiration_date_str()

    headers = {}
    # Interesting worklaround: api gateway will technically only accept one of each type of header, but if you
    # specify your set-cookies with different alpha cases, you can actually send multiple.
    headers['Set-Cookie'] = 'urs-access-token={}; Expires={}; Path=/{}'.format(access_token, expdate, cookie_domain_payloadpiece)
    headers['set-cookie'] = 'urs-user-id={}; Expires={}; Path=/{}'.format(user_id, expdate, cookie_domain_payloadpiece)
    #headers['SET-COOKIE'] = 'asf-auth={}; Expires={}; Path=/{}'.format(make_jwt_cookie({'asf': 'payload'}), get_cookie_expiration_date_str(), cookie_domain)
    log.debug('set-cookies: {}'.format(headers))
    return headers



