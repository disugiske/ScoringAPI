import json
from logger_config import logger
from dataclasses import dataclass
import redis
from redis.backoff import ConstantBackoff
from redis.retry import Retry

exceptions = [ConnectionError,
              TimeoutError,
              ConnectionResetError,
              ConnectionRefusedError,
              redis.exceptions.ConnectionError,
              ]


@dataclass
class StoreConnect:
    host: str or int
    port: int
    db: int
    retry: int = 3
    timeout: int = 1

    def connection(self, db):
        return redis.Redis(self.host,
                           self.port,
                           db,
                           decode_responses=True,
                           retry_on_error=exceptions,
                           retry=Retry(backoff=ConstantBackoff(self.timeout), retries=self.retry)
                           )

    def cache_get(self, name):
        try:
            with self.connection(self.db) as conn:
                result = conn.get(name=name)
                return json.dumps(result)
        except redis.exceptions.ConnectionError:
            logger.error("Cannot connect to Redis!")
            return None

    def get(self, name):
        try:
            with self.connection(db=1) as conn:
                result = conn.get(name=name)
                return json.dumps(result)
        except redis.exceptions.ConnectionError:
            logger.error("Cannot connect to Redis!")
            return None

    def cache_set(self, name, value, expire):
        try:
            with self.connection(self.db) as conn:
                conn.set(name=name, value=value, ex=expire)
        except redis.exceptions.ConnectionError:
            logger.error("Cannot connect to Redis!")