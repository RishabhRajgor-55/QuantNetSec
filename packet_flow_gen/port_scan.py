import socket
import time

target = "scanme.nmap.org"  # safe public test server

ports = range(20, 200)

for port in ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target, port))
        print(f"Port {port} open")
        s.close()
    except:
        pass

    time.sleep(0.01)