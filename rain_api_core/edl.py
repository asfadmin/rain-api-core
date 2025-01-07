import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from rain_api_core.general_util import return_timing_object
from rain_api_core.timer import Timer

log = logging.getLogger(__name__)


class EdlException(Exception):
    def __init__(
        self,
        inner: Exception,
        msg: dict,
        payload: Optional[bytes],
    ):
        self.inner = inner
        self.msg = msg
        self.payload = payload


class EulaException(EdlException):
    pass


class EdlClient:
    def __init__(
        self,
        base_url: str = os.getenv(
            'AUTH_BASE_URL',
            'https://urs.earthdata.nasa.gov',
        ),
    ):
        self.base_url = base_url

    def request(
        self,
        method: str,
        endpoint: str,
        params: dict = {},
        data: dict = {},
        headers: dict = {},
    ) -> dict:
        if params:
            params_encoded = urllib.parse.urlencode(params)
            url_params = f'?{params_encoded}'
        else:
            url_params = ''

        # Separate variables so we can log the url without params
        url = urllib.parse.urljoin(self.base_url, endpoint)
        url_with_params = url + url_params

        if data:
            data_encoded = urllib.parse.urlencode(data).encode()
        else:
            data_encoded = None

        request = urllib.request.Request(
            url=url_with_params,
            data=data_encoded,
            headers=headers,
            method=method,
        )

        log.debug(
            'Request(url=%r, data=%r, headers=%r)',
            url_with_params,
            data,
            headers,
        )

        timer = Timer()
        timer.mark(f'urlopen({url})')
        try:
            with urllib.request.urlopen(request) as f:
                payload = f.read()
                timer.mark('json.loads()')
                msg = json.loads(payload)
            timer.mark()

            log.info(
                return_timing_object(
                    service='EDL',
                    endpoint=url,
                    duration=timer.total.duration() * 1000,
                    unit='milliseconds',
                ),
            )
            timer.log_all(log)

            return msg
        except urllib.error.URLError as e:
            log.error('Error hitting endpoint %s: %s', url, e)
            timer.mark()
            log.debug('ET for the attempt: %.4f', timer.total.duration())

            self._parse_edl_error(e)
        except json.JSONDecodeError as e:
            raise EdlException(e, {}, payload)

    def _parse_edl_error(self, e: urllib.error.URLError):
        if isinstance(e, urllib.error.HTTPError):
            payload = e.read()
            try:
                msg = json.loads(payload)
            except json.JSONDecodeError:
                log.error('Could not get json message from payload: %s', payload)
                msg = {}

            if (
                e.code in (403, 401)
                and 'error_description' in msg
                and 'eula' in msg['error_description'].lower()
            ):
                # sample json in this case:
                # `{"status_code": 403, "error_description": "EULA Acceptance Failure",
                #   "resolution_url": "http://uat.urs.earthdata.nasa.gov/approve_app?client_id=LqWhtVpLmwaD4VqHeoN7ww"}`
                log.warning('user needs to sign the EULA')
                raise EulaException(e, msg, payload)
        else:
            payload = None
            msg = {}

        raise EdlException(e, msg, payload)
