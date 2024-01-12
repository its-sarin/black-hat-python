import socket
import os

# obtain host IP address
host = socket.gethostbyname(socket.gethostname())

def main(interface):
    # create raw socket and bind it to the public interface
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        # Set the interface to capture packets from
        sniffer.bind((interface, 0))
    else:
        sniffer.setsockopt(socket.SOL_SOCKET, 25, interface.encode("utf-8"))

    # include the IP headers in the captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == "nt":
        # set promiscuous mode on Windows
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # read in a single packet
    print(sniffer.recvfrom(65565))

    # turn off promiscuous mode if it's Windows
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main("tun0")
