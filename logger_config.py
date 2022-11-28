import logging
import sys

logger = logging.getLogger('API')
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname).1s %(message)s',
                    datefmt='%Y.%m.%d %H:%M:%S',
                    stream=sys.stdout
                    )
handler = logging.FileHandler(filename="opts.log", mode="w", encoding="utf-8")
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname).1s %(message)s"))
logger.addHandler(handler)