import requests
import threading

URL = "https://httpbin.org/get"

def hit():
    try:
        requests.get(URL, timeout=2)
    except:
        pass

while True:
    threads = []
    print("⚡ Burst started")

    for _ in range(50):  # burst size
        t = threading.Thread(target=hit)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("⏸ Cooling down...\n")
    import time
    time.sleep(5)