import sys
import socket
import threading

HEX_FILTER = "".join([(len(repr(chr(i))) == 3) and chr(i) or "." for i in range(256)])

def hexdump(src, length=16, show=True):
    if isinstance(src, bytes):
        src = src.decode()
    
    results = list()
    
    for i in range(0, len(src), length):
        word = str(src[i:i+length])
        printable = word.translate(HEX_FILTER)
        hexa = " ".join([f"{ord(c):02X}" for c in word])
        hexwidth = length*3
        results.append(f"{i:04x} {hexa:<{hexwidth}} {printable}")
    
    if show:
        for line in results:
            print(line)
    else:
        return results
    
def receive_from(connection):
    buffer = b""
    
    connection.settimeout(5)
    
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass
    
    return buffer

def request_handler(buffer):
    # Perform packet modifications
    return buffer

def response_handler(buffer):
    # Perform packet modifications
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    # Connect to the remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    
    # Receive data from the remote end if necessary
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)
        
        # Send it to our response handler
        remote_buffer = response_handler(remote_buffer)
        
        # If we have data to send to our local client, send it
        if remote_buffer:
            print(f"[<==] Sending {len(remote_buffer)} bytes to localhost.")
            client_socket.send(remote_buffer)
    
    # Now let's loop and read from local, send to remote, send to local, rinse, wash, repeat
    while True:
        # Read from local host
        local_buffer = receive_from(client_socket)
        
        if local_buffer:
            print(f"[==>] Received {len(local_buffer)} bytes from localhost.")
            hexdump(local_buffer)
            
            # Send it to our request handler
            local_buffer = request_handler(local_buffer)
            
            # Send off the data to the remote host
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")
        
        # Receive back the response
        remote_buffer = receive_from(remote_socket)
        
        if remote_buffer:
            print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
            hexdump(remote_buffer)
            
            # Send to our response handler
            remote_buffer = response_handler(remote_buffer)
            
            # Send the response to the local socket
            client_socket.send(remote_buffer)
            
            print("[<==] Sent to localhost.")
        
        # If no more data on either side, close the connections
        if not local_buffer or not remote_buffer:
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            
            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server.bind((local_host, local_port))
    except:
        print(f"[!!] Failed to listen on {local_host}:{local_port}")
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)
    
    print(f"[*] Listening on {local_host}:{local_port}")
    
    server.listen(5)
    
    while True:
        client_socket, addr = server.accept()
        
        # Print out the local connection information
        print(f"[==>] Received incoming connection from {addr[0]}:{addr[1]}")
        
        # Start a thread to talk to the remote host
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first)
        )
        
        proxy_thread.start()

def main():
    # No fancy command-line parsing here
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 True")
        sys.exit(0)

    # Setup local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])