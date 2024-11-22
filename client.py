import socket


def send_packet(server_ip, server_port, ip, port, protocol):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_ip, server_port))
        packet_data = f"{ip},{port},{protocol}"
        client_socket.send(packet_data.encode())
        response = client_socket.recv(1024).decode()
        print(f"Server response: {response}")


if __name__ == "__main__":
    server_ip = "127.0.0.1"
    server_port = 8080
    send_packet(server_ip, server_port, "192.168.1.100", 80, "TCP")
    send_packet(server_ip, server_port, "172.20.10.7", 443, "TCP")
    send_packet(server_ip, server_port, "8.8.8.8", 53, "UDP")
