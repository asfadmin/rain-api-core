import os

sessttl = int(os.getenv('SESSION_TTL', '168')) * 60 * 60
