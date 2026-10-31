"""Benign handshakes and a Redis PING; no authentication attempts."""
import socket

for port in (2121, 1433, 3306, 3389, 6379, 27017):
    with socket.create_connection(('172.27.66.60', port), timeout=3) as client:
        if port == 2121:
            banner = client.recv(512).decode(errors='replace').strip()
            assert banner.startswith('220'), banner
            print('FTP:', banner)
        elif port == 6379:
            client.sendall(b'*1\r\n$4\r\nPING\r\n')
            response = client.recv(512)
            assert b'PONG' in response or b'NOAUTH' in response, response
            print('Redis:', response.decode().strip())
        else:
            print('TCP reachable:', port)
