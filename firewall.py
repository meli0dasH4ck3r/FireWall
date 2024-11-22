import socket
import threading


class Rule:
    def __init__(self, action, ip=None, port=None, protocol=None):
        self.action = action
        self.ip = ip
        self.port = port
        self.protocol = protocol

    def matches(self, packet):
        ip, port, protocol = packet
        if self.ip and self.ip != ip:
            return False
        if self.port and self.port != port:
            return False
        if self.protocol and self.protocol != protocol:
            return False
        return True


class Firewall:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        self.rules.append(rule)

    def remove_rule(self, rule):
        if rule in self.rules:
            self.rules.remove(rule)

    def check_packet(self, packet):
        for rule in self.rules:
            if rule.matches(packet):
                return rule.action
        return 'allowed'


class FirewallServer:
    def __init__(self, host, port, firewall):
        self.host = host
        self.port = port
        self.firewall = firewall
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server running on {self.host}:{self.port}")

    def handle_client(self, client_socket, address):
        print(f"Connection from {address}")
        while True:
            try:
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                print(f"Received: {data}")
                ip, port, protocol = data.split(",")
                port = int(port)
                decision = self.firewall.check_packet((ip, port, protocol))
                client_socket.send(decision.encode())
                print(f"Packet decision: {decision}")
            except Exception as e:
                print(f"Error: {e}")
                break
        client_socket.close()
        print(f"Connection closed: {address}")

    def run(self):
        while True:
            client_socket, address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
            client_thread.start()


if __name__ == "__main__":
    firewall = Firewall()
    firewall.add_rule(Rule(action="block", ip="192.168.1.100", port=80, protocol="TCP"))
    firewall.add_rule(Rule(action="allow", ip="172.20.10.7", port=443, protocol="TCP"))
    server = FirewallServer(host="0.0.0.0", port=8080, firewall=firewall)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down the server.")
