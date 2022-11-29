import json
import random


class MockConnect:
    @staticmethod
    def cache_get(name):
        return random.randrange(1, 5, 1)

    @staticmethod
    def get(name):
        interests = [
            "cars",
            "pets",
            "travel",
            "hi-tech",
            "sport",
            "music",
            "books",
            "tv",
            "cinema",
            "geek",
            "otus",
        ]
        return json.dumps(random.sample(interests, 3))

    @staticmethod
    def cache_set(name, value, expire):
        pass
