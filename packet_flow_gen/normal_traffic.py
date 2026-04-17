import requests
import time
import random

URLS = [
    "https://www.google.com",
    "https://api.github.com",
    "https://www.wikipedia.org",
    "https://httpbin.org/get"
]

while True:
    try:
        url = random.choice(URLS)
        print("Requesting:", url)
        requests.get(url, timeout=3)
    except:
        pass

    time.sleep(random.uniform(0.5, 2))