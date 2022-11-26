import logging

import redis
from redis.backoff import ConstantBackoff
from redis.retry import Retry


class StoreConnect:
    def __init__(self, host, port, db):
        self.redis_client = redis.Redis(host,
                                        port,
                                        db,
                                        decode_responses=True,
                                        retry_on_error=[ConnectionError,
                                                        TimeoutError,
                                                        ConnectionResetError,
                                                        ConnectionRefusedError
                                                        ],
                                        retry=Retry(backoff=ConstantBackoff(0.5), retries=3)
                                        )

    def cache_get(self, name):
        with self.redis_client as conn:
            result = conn.get(name=name)
            return result


    def get(self, name):
        pass

    def cache_set(self, name, value, expire):
        with self.redis_client as conn:
            try:
                conn.set(name=name, value=value, ex=expire)
            except Exception as e:
                logging.exception("Unexpected error: %s" % e)
