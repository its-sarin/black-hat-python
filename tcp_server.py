import socket
import threading

bind_ip = "127.0.0.1"
bind_port = 9998

def main():
    # file deepcode ignore MissingClose: <please specify a reason of ignoring this>
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bind_ip, bind_port))
    server.listen(5)
    print(f"[*] Listening on {bind_ip}:{bind_port}")
    while True:
        client, addr = server.accept()
        print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
        # file deepcode ignore MissingAPI: <please specify a reason of ignoring this>
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print("[*] Received: %s" % request.decode())
        sock.send(b"ACK")

if __name__ == "__main__":
    main()