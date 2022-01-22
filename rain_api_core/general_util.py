import contextlib
import json
import logging
import os
import re
import sys
import time

UNCENSORED_LOGGING = os.getenv("UNCENSORED_LOGGING")

LOG_CENSOR = [
        { "regex": r"(eyJ0e[A-Za-z0-9-_]{10})[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*([A-Za-z0-9-_]{10})",
          "replace": "\\g<1>XXX<JWTTOKEN>XXX\\g<2>",
          "description": "X-out JWT Token payload"
        },
        { "regex": r"(EDL-[A-Za-z0-9]+)[A-Za-z0-9]{40}([A-Za-z0-9]{10})",
          "replace": "\\g<1>XXX<EDLTOKEN>XXX\\g<2>",
          "description": "X-out non-JWT EDL token"
        },
        { "regex": r"(Basic )[A-Za-z0-9+/=]{4,}",
          "replace": "\\g<1>XXX<BASICAUTH>XXX",
          "description": "X-out Basic Auth Credentials"
        },
        { "regex": r"([^A-Za-z0-9/+=][A-Za-z0-9/+=]{5})[A-Za-z0-9/+=]{30}([A-Za-z0-9/+=]{5}[^A-Za-z0-9/+=])",
          "replace": "\\g<1>XXX<AWSSECRET>XXX\\g<2>",
          "description": "X-out AWS Secret"
        }
    ]


def return_timing_object(**timing):
    timing_object = {
        "service": "Unknown",
        "endpoint": "Unknown",
        "method": "GET",
        "duration": 0,
        "unit": "milliseconds"
    }
    timing_object.update({k.lower(): v for k, v in timing.items()})
    return {"timing": timing_object}


def duration(time_in):
    # Return the time duration in milliseconds
    delta = time.time() - time_in
    return round(delta * 1000, ndigits=2)


def filter_log_credentials(msg):
    if UNCENSORED_LOGGING:
        return msg

    for regex in LOG_CENSOR:
        result = re.sub(regex["regex"], regex["replace"], msg, 0, re.MULTILINE)
        if result:
            msg = str(result)

    return msg


def reformat_for_json(msg):
    if isinstance(msg, dict):
        return json.dumps(msg)
    if isinstance(msg, str):
        if '{' in msg:
            with contextlib.suppress(json.decoder.JSONDecodeError):
                return json.dumps(json.loads(msg))
        return msg
    return str(msg)


class CustomLogFilter(logging.Filter):
    def __init__(self,  *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params = {
            'build_vers': os.getenv("BUILD_VERSION", "NOBUILD"),
            'maturity': os.getenv('MATURITY', 'DEV'),
            'request_id': None,
            'origin_request_id': None,
            'user_id': None,
            'route': None
        }

    def filter(self, record):
        record.msg = filter_log_credentials(reformat_for_json(record.msg))
        record.build_vers = self.params['build_vers']
        record.maturity = self.params['maturity']
        record.request_id = self.params['request_id']
        record.origin_request_id = self.params['origin_request_id']
        record.user_id = self.params['user_id']
        record.route = self.params['route']
        return True

    def update(self, **context):
        self.params.update(context)


custom_log_filter = CustomLogFilter()


def log_context(**context):
    custom_log_filter.update(**context)


def get_log():
    loglevel = os.getenv('LOGLEVEL', 'INFO')
    logtype = os.getenv('LOGTYPE', 'json')
    if logtype == 'flat':
        log_fmt_str = (
            "%(levelname)s: %(message)s (%(filename)s line %(lineno)d/%(build_vers)s/%(maturity)s) - "
            "RequestId: %(request_id)s; OriginRequestId: %(origin_request_id)s; user_id: %(user_id)s; route: %(route)s"
        )
    else:
        log_fmt_str = (
            '{"level": "%(levelname)s",  '
            '"RequestId": "%(request_id)s", '
            '"OriginRequestId": "%(origin_request_id)s", '
            '"message": "%(message)s", '
            '"maturity": "%(maturity)s", '
            '"user_id": "%(user_id)s", '
            '"route": "%(route)s", '
            '"build": "%(build_vers)s", '
            '"filename": "%(filename)s", '
            '"lineno": %(lineno)d}'
        )

    logger = logging.getLogger()

    for h in logger.handlers:
        logger.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(log_fmt_str))
    handler.addFilter(custom_log_filter)

    logger.addHandler(handler)
    logger.setLevel(loglevel)

    if os.getenv("QUIETBOTO", 'TRUE').upper() == 'TRUE':
        # BOTO, be quiet plz
        logging.getLogger('boto3').setLevel(logging.ERROR)
        logging.getLogger('botocore').setLevel(logging.ERROR)
        logging.getLogger('nose').setLevel(logging.ERROR)
        logging.getLogger('elasticsearch').setLevel(logging.ERROR)
        logging.getLogger('s3transfer').setLevel(logging.ERROR)
        logging.getLogger('urllib3').setLevel(logging.ERROR)
        logging.getLogger('connectionpool').setLevel(logging.ERROR)
    return logger
