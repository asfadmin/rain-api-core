import logging
import os
import sys
import json

def return_timing_object(**timing):
    timing_object = { "service": "Unknown", "endpoint": "Unknown", "method": "GET", "duration": 0, "unit": "seconds"}
    timing_object.update({k.lower(): v for k,v in timing.items()})
    return {"timing":timing_object }
    
def reformat_for_json(msg):
    if type(msg) is dict:
        return json.dumps(msg).replace("'", '"')
    if '{' in msg:
        try:
            json_obj = json.loads(msg)
            return json.dumps(json_obj).replace("'", '"')
        except json.decoder.JSONDecodeError:
            # Not JSON.
            pass
    return '"{0}"'.format(msg)

class CustomLogFilter(logging.Filter):

    def __init__(self,  *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params = { 'build_vers': os.getenv("BUILD_VERSION", "NOBUILD"),
                        'maturity': os.getenv('MATURITY', 'DEV'),
                        'request_id': None,
                        'origin_request_id': None,
                        'user_id': None,
                        'route': None
                      }

    def filter(self, record):
        record.msg = reformat_for_json(record.msg)
        record.build_vers = self.params['build_vers']
        record.maturity = self.params['maturity']
        record.request_id = self.params['request_id']
        record.origin_request_id = self.params['origin_request_id']
        record.user_id = self.params['user_id']
        record.route = self.params['route']
        return True

    def update(self, **context):
        for key in context:
            self.params.update({key: context[key]})

custom_log_filter = CustomLogFilter()


def log_context(**context):
    custom_log_filter.update(**context)


def get_log():

    loglevel = os.getenv('LOGLEVEL', 'INFO')
    logtype = os.getenv('LOGTYPE', 'json')
    if logtype == 'flat':
        log_fmt_str = "%(levelname)s: %(message)s (%(filename)s line " + \
                      "%(lineno)d/%(build_vers)s/%(maturity)s) - " + \
                      "RequestId: %(request_id)s; OriginRequestId: %(origin_request_id)s; user_id: %(user_id)s; route: %(route)s"
    else:
        log_fmt_str = '{"level": "%(levelname)s",  ' + \
                      '"RequestId": "%(request_id)s", ' + \
                      '"OriginRequestId": "%(origin_request_id)s", ' + \
                      '"message": %(message)s, ' + \
                      '"maturity": "%(maturity)s", ' + \
                      '"user_id": "%(user_id)s", ' + \
                      '"route": "%(route)s", ' + \
                      '"build": "%(build_vers)s", ' + \
                      '"filename": "%(filename)s", ' + \
                      '"lineno": %(lineno)d } '

    logger = logging.getLogger()

    for h in logger.handlers:
        logger.removeHandler(h)

    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(log_fmt_str))
    h.addFilter(custom_log_filter)
    logger.addHandler(h)
    logger.setLevel(getattr(logging, loglevel))

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
