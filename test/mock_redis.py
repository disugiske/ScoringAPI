import json
import random


class MockConnect:
    def cache_get(self, name):
            return random.randrange(1, 5, 1)

    def get(self, name):
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

    def cache_set(self, name, value, expire):
        pass
