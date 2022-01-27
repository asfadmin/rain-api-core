import json
import logging
import os
import re
import sys

UNCENSORED_LOGGING = os.getenv("UNCENSORED_LOGGING")

LOG_CENSOR = [
    {
        "regex": r"(eyJ0e[A-Za-z0-9-_]{10})[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*([A-Za-z0-9-_]{10})",
        "replace": "\\g<1>XXX<JWTTOKEN>XXX\\g<2>",
        "description": "X-out JWT Token payload"
    },
    {
        "regex": r"(EDL-[A-Za-z0-9]+)[A-Za-z0-9]{40}([A-Za-z0-9]{10})",
        "replace": "\\g<1>XXX<EDLTOKEN>XXX\\g<2>",
        "description": "X-out non-JWT EDL token"
    },
    {
        "regex": r"(Basic )[A-Za-z0-9+/=]{4,}",
        "replace": "\\g<1>XXX<BASICAUTH>XXX",
        "description": "X-out Basic Auth Credentials"
    },
    {
        "regex": r"([^A-Za-z0-9/+=][A-Za-z0-9/+=]{5})[A-Za-z0-9/+=]{30}([A-Za-z0-9/+=]{5}[^A-Za-z0-9/+=])",
        "replace": "\\g<1>XXX<AWSSECRET>XXX\\g<2>",
        "description": "X-out AWS Secret"
    }
]


def get_log():
    loglevel = os.getenv('LOGLEVEL', 'INFO')
    logtype = os.getenv('LOGTYPE', 'json')
    if logtype == 'flat':
        formatter = logging.Formatter(
            "%(levelname)s: %(message)s (%(filename)s line %(lineno)d/%(build_vers)s/%(maturity)s) - "
            "RequestId: %(request_id)s; OriginRequestId: %(origin_request_id)s; user_id: %(user_id)s; route: %(route)s"
        )
    else:
        formatter = JSONFormatter({
            "level": "%(levelname)s",
            "RequestId": "%(request_id)s",
            "OriginRequestId": "%(origin_request_id)s",
            "message": "%(message)s",
            "maturity": "%(maturity)s",
            "user_id": "%(user_id)s",
            "route": "%(route)s",
            "build": "%(build_vers)s",
            "filename": "%(filename)s",
            "lineno": "%(lineno)s",
            "exception": "%(exc_obj)s"
        })

    logger = logging.getLogger()

    for h in logger.handlers:
        logger.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
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


class PercentPlaceholder():
    """A placeholder in a log format object

    The placeholder can be formatted with the % operator.

    >>> p = PercentPlaceholder("message")
    >>> assert p % {"message": "hello"} == "hello"
    """

    __slots__ = ("name", )

    def __init__(self, name: str):
        self.name = name

    def __mod__(self, args):
        if isinstance(args, dict):
            return args[self.name]


class JSONPercentStyle():
    default_format = {"message": "%(message)s"}
    asctime_search = '%(asctime)'
    placeholder_pattern = re.compile(r"^%\((\w+)\)s$")
    validation_pattern = re.compile(r'%\(\w+\)[#0+ -]*(\*|\d+)?(\.(\*|\d+))?[diouxefgcrsa%]', re.I)

    def __init__(self, fmt: dict):
        self._fmt = self._convert_placeholders(fmt or self.default_format)
        # Cached so we don't recompute it every time a record is emitted
        self._uses_time = self._usesTime()

    def _convert_placeholders(self, obj):
        """Convert '%(name)s' values into PercentPlaceholder objects"""
        def func(obj):
            if isinstance(obj, str):
                m = self.placeholder_pattern.match(obj)
                if m:
                    return PercentPlaceholder(m.group(1))
            return obj

        return _map_json_object(func, obj)

    def _usesTime(self):
        for val in _walk_json_values(self._fmt):
            if isinstance(val, str) and self.asctime_search in val:
                return True
            if isinstance(val, PercentPlaceholder) and val.name == "asctime":
                return True
        return False

    def usesTime(self):
        return self._uses_time

    def _format(self, record):
        return _fmt_json_object(self._fmt, record.__dict__)

    def format(self, record):
        try:
            return self._format(record)
        except KeyError as e:
            raise ValueError('Formatting field not found in record: %s' % e)


class JSONFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt: str = None):
        # Changing the type from the base class
        self._style: JSONPercentStyle = JSONPercentStyle(fmt)

        self._fmt = self._style._fmt
        self.datefmt = datefmt

    def format(self, record: logging.LogRecord) -> str:
        # Perform substitutions on the record itself
        record.message = _fmt_json_object(record.msg, record.args)
        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)

        record.exc_obj = self.formatException(record.exc_info).split("\n") if record.exc_info else None

        obj = self.formatMessage(record)
        assert not any(isinstance(val, PercentPlaceholder) for val in _walk_json_values(obj))

        return filter_log_credentials(json.dumps(obj))


class TaggingFilter(logging.Filter):
    """Add extra attributes to each log record"""

    def __init__(self,  *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params = {
            "build_vers": os.getenv("BUILD_VERSION", "NOBUILD"),
            "maturity": os.getenv("MATURITY", "DEV"),
            "request_id": None,
            "origin_request_id": None,
            "user_id": None,
            "route": None
        }

    def filter(self, record: logging.LogRecord):
        record.__dict__.update(self.params)
        return True

    def update(self, **context):
        self.params.update(context)


custom_log_filter = TaggingFilter()


def log_context(**context):
    custom_log_filter.update(**context)


def filter_log_credentials(msg):
    if UNCENSORED_LOGGING:
        return msg

    for regex in LOG_CENSOR:
        result = re.sub(regex["regex"], regex["replace"], msg, 0, re.MULTILINE)
        if result:
            msg = str(result)

    return msg


# Helpers for traversing json like structures of nested dict/lists

def _fmt_json_val(val, args):
    if isinstance(val, (str, PercentPlaceholder)) and args:
        return val % args
    return val


def _fmt_json_object(obj, args):
    return _map_json_object(lambda val: _fmt_json_val(val, args), obj)


def _map_json_object(func, obj):
    if isinstance(obj, dict):
        return {key: _map_json_object(func, val) for key, val in obj.items()}
    elif isinstance(obj, list):
        return [_map_json_object(func, val) for val in obj]
    else:
        return func(obj)


def _walk_json_values(obj):
    if isinstance(obj, dict):
        for val in obj.values():
            yield from _walk_json_values(val)
    elif isinstance(obj, list):
        for val in obj:
            yield from _walk_json_values(val)
    else:
        yield obj
