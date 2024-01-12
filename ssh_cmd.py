import paramiko

def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    # client.load_host_keys("/home/sar1n/.ssh/known_hosts")
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)

    _, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()
    if output:
        print("--- Output ---")
        for line in output:
            print(line.strip())

if __name__ == "__main__":
    import getpass
    import sys

    # user = getpass.getuser()
    user = input("Username: ")
    passwd = getpass.getpass()

    ip = input("Server IP: ") or "192.168.124.164"
    port = int(input("Port: ") or 22)

    try:
        while True:
            cmd = input("#> ")
            if cmd == "exit":
                break
            ssh_command(ip, port, user, passwd, cmd)
    except KeyboardInterrupt:
        print("\nUser terminated.")
        sys.exit()