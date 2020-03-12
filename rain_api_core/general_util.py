import logging
import os
import sys


def get_log():
    loglevel = os.getenv('LOGLEVEL', 'INFO')
    log_fmt_str = "%(levelname)s: %(message)s (%(filename)s line %(lineno)d/" + \
                  os.getenv("BUILD_VERSION", "NOBUILD") + "/" + \
                  os.getenv('MATURITY', 'DEV') + ")"

    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)

    h = logging.StreamHandler(sys.stdout)

    h.setFormatter(logging.Formatter(log_fmt_str))
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
